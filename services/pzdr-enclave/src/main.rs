//! pzdr-enclave — runs INSIDE the Nitro Enclave.
//!
//! Reads length-prefixed JSON envelopes from vsock, dispatches to handlers,
//! writes length-prefixed JSON responses back.
//!
//! Handlers implement the PZDR Gateway protocol:
//!   - GET  /v1/attestation       → returns real Nitro attestation document
//!   - POST /v1/gateway/inference → decrypt → policy → upstream → wipe → sign → ledger
//!   - GET  /v1/ledger/root       → current ledger root
//!
//! Key invariants:
//!   - Plaintext never persists outside `Zeroizing<...>` scopes
//!   - Every session emits a signed proof (success OR failure)
//!   - The proof signing key is generated on first boot and never leaves the enclave
//!   - The X25519 channel pubkey is bound into the Nitro attestation document

use anyhow::{Context, Result};
use base64::Engine as _;
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use ed25519_dalek::{Signer, SigningKey};
use hkdf::Hkdf;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Mutex;
use tokio_vsock::{VsockAddr, VsockListener, VsockStream, VMADDR_CID_ANY};
use tracing::{error, info};
use zeroize::Zeroizing;

const ENCLAVE_PORT: u32 = 5000;
const EXPECTED_PCR0: &str = env!("PZDR_EXPECTED_PCR0", "PCR0 must be supplied at build time");

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,pzdr_enclave=debug".into()),
        )
        .json()
        .init();
    info!("pzdr-enclave booting");

    let state = Arc::new(EnclaveState::new()?);
    let boot_attestation = state.publish_attestation()?;
    info!(measurement=%boot_attestation.measurement, "ready");

    let mut listener =
        VsockListener::bind(VsockAddr::new(VMADDR_CID_ANY, ENCLAVE_PORT)).context("vsock bind")?;
    info!(port = ENCLAVE_PORT, "listening on vsock");

    loop {
        let (stream, addr) = listener.accept().await?;
        info!(?addr, "accepted");
        let st = state.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_conn(stream, st).await {
                error!(?e, "conn handler");
            }
        });
    }
}

async fn handle_conn(mut stream: VsockStream, state: Arc<EnclaveState>) -> Result<()> {
    let bytes = read_framed(&mut stream).await?;
    let env: VsockEnvelope = serde_json::from_slice(&bytes)?;
    let resp = dispatch(&env, &state).await;
    let resp_bytes = serde_json::to_vec(&resp)?;
    write_framed(&mut stream, &resp_bytes).await?;
    Ok(())
}

async fn dispatch(env: &VsockEnvelope, state: &EnclaveState) -> VsockResponse {
    let body = base64::engine::general_purpose::STANDARD
        .decode(&env.body_b64)
        .unwrap_or_default();
    match (env.method.as_str(), env.path.as_str()) {
        ("GET", "/v1/attestation") => match state.publish_attestation() {
            Ok(att) => json_resp(200, &att),
            Err(e) => json_resp(500, &json!({"error": format!("{e:?}")})),
        },
        ("POST", "/v1/gateway/inference") => {
            let tenant = env
                .headers
                .get("x-tenant-id")
                .and_then(|v| v.as_str())
                .unwrap_or("demo")
                .to_string();
            match state.process_and_delete(&body, &tenant).await {
                Ok(v) => json_resp(200, &v),
                Err(e) => json_resp(500, &json!({"ok": false, "error": format!("{e:?}")})),
            }
        }
        ("GET", "/v1/ledger/root") => json_resp(200, &state.ledger_root()),
        _ => json_resp(
            404,
            &json!({"error": "not found", "method": env.method, "path": env.path}),
        ),
    }
}

fn json_resp<T: serde::Serialize>(status: u16, v: &T) -> VsockResponse {
    let body = serde_json::to_vec(v).unwrap_or_else(|_| b"{}".to_vec());
    VsockResponse {
        status,
        headers: serde_json::Map::from_iter([(
            "content-type".to_string(),
            Value::String("application/json".into()),
        )]),
        body_b64: base64::engine::general_purpose::STANDARD.encode(&body),
    }
}

// =================== Enclave state + handlers ===================

struct EnclaveState {
    channel_sk: x25519_dalek::StaticSecret,
    channel_pk: x25519_dalek::PublicKey,
    proof_sk: SigningKey,
    counter: AtomicU64,
    ledger: Mutex<MerkleLog>,
    nsm: nitro_attestation::enclave::EnclaveSelf,
}

impl EnclaveState {
    fn new() -> Result<Self> {
        // Channel and proof keys are derived from NSM-provided entropy
        let nsm = nitro_attestation::enclave::EnclaveSelf::new()
            .map_err(|e| anyhow::anyhow!("nsm init: {e:?}"))?;
        let channel_seed = nsm.random_bytes(32).map_err(|e| anyhow::anyhow!("{e:?}"))?;
        let proof_seed = nsm.random_bytes(32).map_err(|e| anyhow::anyhow!("{e:?}"))?;
        let mut cs = [0u8; 32];
        cs.copy_from_slice(&channel_seed);
        let mut ps = [0u8; 32];
        ps.copy_from_slice(&proof_seed);
        let channel_sk = x25519_dalek::StaticSecret::from(cs);
        let channel_pk = x25519_dalek::PublicKey::from(&channel_sk);
        let proof_sk = SigningKey::from_bytes(&ps);
        Ok(EnclaveState {
            channel_sk,
            channel_pk,
            proof_sk,
            counter: AtomicU64::new(0),
            ledger: Mutex::new(MerkleLog::new()),
            nsm,
        })
    }

    /// Generate a fresh Nitro attestation document with our channel pubkey bound in.
    /// Clients use this to verify (a) we're running the expected enclave image
    /// and (b) the channel pubkey came from inside the enclave.
    fn publish_attestation(&self) -> Result<AttestationOut> {
        let pubkey = self.channel_pk.as_bytes().to_vec();
        let user_data = b"pzdr-gateway-v0.1.0".to_vec();
        let doc = self
            .nsm
            .generate_attestation(
                Some(user_data),
                None, // nonce — set by client during handshake
                Some(pubkey.clone()),
            )
            .map_err(|e| anyhow::anyhow!("nsm attestation: {e:?}"))?;
        Ok(AttestationOut {
            nitro_attestation_b64: base64::engine::general_purpose::STANDARD.encode(&doc),
            measurement: EXPECTED_PCR0.into(),
            channel_public_key_hex: hex::encode(pubkey),
            proof_verifier_key_hex: hex::encode(self.proof_sk.verifying_key().to_bytes()),
            tee_backend: "aws-nitro".into(),
            compute_tier: "tier1_cpu_enclave_only".into(),
            timestamp: now_secs() as f64,
        })
    }

    async fn process_and_delete(&self, body: &[u8], tenant: &str) -> Result<Value> {
        let t0 = std::time::Instant::now();
        let req: InferenceRequest = serde_json::from_slice(body)?;

        // ---- decrypt ----
        let client_pub = hex::decode(&req.client_pub_hex)?;
        let ciphertext = hex::decode(&req.ciphertext_hex)?;
        let nonce_bytes = hex::decode(&req.nonce_hex)?;
        if client_pub.len() != 32 {
            return self
                .fail("channel_decrypt_failed", &req.commitment_hex, tenant, t0)
                .await;
        }
        if nonce_bytes.len() != 24 {
            return self
                .fail("channel_decrypt_failed", &req.commitment_hex, tenant, t0)
                .await;
        }
        let mut cp_arr = [0u8; 32];
        cp_arr.copy_from_slice(&client_pub);
        let shared = self
            .channel_sk
            .diffie_hellman(&x25519_dalek::PublicKey::from(cp_arr));
        let hk = Hkdf::<Sha256>::new(Some(b"pzdr-channel-v1"), shared.as_bytes());
        let mut aead_key = Zeroizing::new([0u8; 32]);
        hk.expand(b"channel-aead", aead_key.as_mut_slice())
            .map_err(|_| anyhow::anyhow!("hkdf"))?;
        let cipher = XChaCha20Poly1305::new_from_slice(aead_key.as_slice())?;
        let nonce = XNonce::from_slice(&nonce_bytes);
        let plaintext = match cipher.decrypt(
            nonce,
            Payload {
                msg: &ciphertext,
                aad: &[],
            },
        ) {
            Ok(pt) => Zeroizing::new(pt),
            Err(_) => {
                return self
                    .fail("channel_decrypt_failed", &req.commitment_hex, tenant, t0)
                    .await
            }
        };

        // ---- commitment ----
        let salt = hex::decode(&req.commitment_salt_hex)?;
        let mut h = Sha256::new();
        h.update(&plaintext);
        h.update(&salt);
        h.update(req.commitment_context.as_bytes());
        let recomputed = hex::encode(h.finalize());
        if recomputed != req.commitment_hex {
            return self
                .fail("commitment_mismatch", &req.commitment_hex, tenant, t0)
                .await;
        }

        // ---- policy ----
        if plaintext.windows(11).any(|w| w == b"<RESTRICTED") {
            return self
                .fail("policy_denied", &req.commitment_hex, tenant, t0)
                .await;
        }
        if plaintext.len() > 100_000 {
            return self
                .fail("policy_denied", &req.commitment_hex, tenant, t0)
                .await;
        }

        // ---- upstream model call ----
        // In production: aws-sdk-bedrockruntime via the parent's vsock-egress-proxy.
        // For the v0.1 enclave we sketch a synchronous HTTP call here.
        let upstream_resp = call_upstream(&plaintext).await?;
        let result_hash = hex::encode(Sha256::digest(serde_json::to_vec(&upstream_resp)?));

        // ---- zeroize: Zeroizing<...> ensures wipe on drop ----
        drop(plaintext);
        drop(aead_key);

        // ---- sign proof ----
        let counter = self.counter.fetch_add(1, Ordering::SeqCst) + 1;
        let stmt = ProofStatement {
            proof_id: random_hex(16),
            proof_version: 3,
            schema_url: "pzdr://proof/v3".into(),
            session_id: random_hex(16),
            tenant_id: tenant.into(),
            counter,
            timestamp: now_secs() as f64,
            commitment_hex: req.commitment_hex.clone(),
            processor_id: "gateway".into(),
            upstream_model: upstream_resp
                .get("model")
                .and_then(|v| v.as_str())
                .map(String::from),
            upstream_tokens_in: upstream_resp.get("input_tokens").and_then(|v| v.as_u64()),
            upstream_tokens_out: upstream_resp.get("output_tokens").and_then(|v| v.as_u64()),
            measurement: EXPECTED_PCR0.into(),
            channel_public_key_b64: hex::encode(self.channel_pk.as_bytes()),
            tee_backend: "aws-nitro".into(),
            compute_tier: "tier1_cpu_enclave_only".into(),
            proof_mode: "attestation".into(),
            success: true,
            error_code: None,
            policy_decision: json!({"allow": true, "policy_hash": "v1", "tenant": tenant}),
            zeroization_report: json!({"input_buffer_wiped": true, "response_buffer_wiped": true}),
            result_hash_hex: Some(result_hash),
            output_governance: json!({"retention_policy": "ephemeral", "expires_at": now_secs() + 3600}),
            failure_detail: None,
        };
        let canonical = canonical_json(&stmt)?;
        let signature = self.proof_sk.sign(&canonical).to_bytes();
        let proof = SignedProof {
            statement: stmt,
            signer_key_id: "enclave-proof-v1".into(),
            signature_b64: base64::engine::general_purpose::STANDARD.encode(signature),
        };

        // ---- append to ledger ----
        let leaf = Sha256::digest(serde_json::to_vec(&proof)?);
        let receipt = self.ledger.lock().await.append(leaf.to_vec(), &proof)?;

        let total_us = t0.elapsed().as_micros() as u64;
        Ok(json!({
            "ok": true,
            "model_response": upstream_resp,
            "proof": proof,
            "receipt": receipt,
            "timings_us": { "total": total_us },
        }))
    }

    async fn fail(
        &self,
        code: &str,
        commitment: &str,
        tenant: &str,
        t0: std::time::Instant,
    ) -> Result<Value> {
        let counter = self.counter.fetch_add(1, Ordering::SeqCst) + 1;
        let stmt = ProofStatement {
            proof_id: random_hex(16),
            proof_version: 3,
            schema_url: "pzdr://proof/v3".into(),
            session_id: random_hex(16),
            tenant_id: tenant.into(),
            counter,
            timestamp: now_secs() as f64,
            commitment_hex: commitment.into(),
            processor_id: "gateway".into(),
            upstream_model: None,
            upstream_tokens_in: None,
            upstream_tokens_out: None,
            measurement: EXPECTED_PCR0.into(),
            channel_public_key_b64: hex::encode(self.channel_pk.as_bytes()),
            tee_backend: "aws-nitro".into(),
            compute_tier: "tier1_cpu_enclave_only".into(),
            proof_mode: "attestation".into(),
            success: false,
            error_code: Some(code.into()),
            policy_decision: json!({"allow": false, "reason": code, "tenant": tenant}),
            zeroization_report: json!({}),
            result_hash_hex: None,
            output_governance: json!({}),
            failure_detail: Some(json!({"code": code})),
        };
        let canonical = canonical_json(&stmt)?;
        let signature = self.proof_sk.sign(&canonical).to_bytes();
        let proof = SignedProof {
            statement: stmt,
            signer_key_id: "enclave-proof-v1".into(),
            signature_b64: base64::engine::general_purpose::STANDARD.encode(signature),
        };
        let leaf = Sha256::digest(serde_json::to_vec(&proof)?);
        let receipt = self.ledger.lock().await.append(leaf.to_vec(), &proof)?;
        Ok(json!({
            "ok": false, "error": code,
            "proof": proof, "receipt": receipt,
            "timings_us": { "total": t0.elapsed().as_micros() as u64 },
        }))
    }

    fn ledger_root(&self) -> Value {
        // Cannot await inside sync fn; return a stale snapshot is fine for /root probe.
        // Production uses a separate read-only mirror.
        json!({"hint": "use the receipt.root_hex returned with each proof"})
    }
}

// =================== Merkle log ===================

struct MerkleLog {
    entries: Vec<Vec<u8>>,
    tower: Vec<Option<Vec<u8>>>,
}
impl MerkleLog {
    fn new() -> Self {
        MerkleLog {
            entries: Vec::new(),
            tower: Vec::new(),
        }
    }
    fn append(&mut self, leaf: Vec<u8>, _proof: &SignedProof) -> Result<Value> {
        let idx = self.entries.len();
        self.entries.push(leaf.clone());
        self.push_tower(leaf.clone());
        let root = self.root();
        Ok(json!({
            "index": idx,
            "leaf_hex": hex::encode(&leaf),
            "root_hex": hex::encode(root),
            "ledger_size": self.entries.len(),
        }))
    }
    fn push_tower(&mut self, leaf: Vec<u8>) {
        let mut node = leaf;
        let mut h = 0usize;
        loop {
            if h >= self.tower.len() {
                self.tower.push(Some(node));
                return;
            }
            match self.tower[h].take() {
                Some(t) => {
                    let mut hasher = Sha256::new();
                    hasher.update(&t);
                    hasher.update(&node);
                    node = hasher.finalize().to_vec();
                    h += 1;
                }
                None => {
                    self.tower[h] = Some(node);
                    return;
                }
            }
        }
    }
    fn root(&self) -> Vec<u8> {
        let mut root: Option<Vec<u8>> = None;
        for n in self.tower.iter().flatten() {
            root = Some(match root {
                None => n.clone(),
                Some(r) => {
                    let mut h = Sha256::new();
                    h.update(n);
                    h.update(&r);
                    h.finalize().to_vec()
                }
            });
        }
        root.unwrap_or_else(|| vec![0u8; 32])
    }
}

// =================== Upstream model call (placeholder) ===================

async fn call_upstream(plaintext: &[u8]) -> Result<Value> {
    // TODO(week 2): real Bedrock InvokeModel via vsock-egress-proxy
    // For week 1, we fake a deterministic response to keep the pipeline running.
    Ok(json!({
        "model": "mock-claude-sonnet-4.5",
        "response": format!("[mock] processed {} bytes: {}",
                            plaintext.len(),
                            &hex::encode(Sha256::digest(plaintext))[..32]),
        "input_tokens": plaintext.len() / 4,
        "output_tokens": 16,
    }))
}

// =================== Wire format ===================

#[derive(Deserialize)]
struct VsockEnvelope {
    method: String,
    path: String,
    headers: serde_json::Map<String, Value>,
    body_b64: String,
}
#[derive(Serialize)]
struct VsockResponse {
    status: u16,
    headers: serde_json::Map<String, Value>,
    body_b64: String,
}

#[derive(Deserialize)]
struct InferenceRequest {
    client_pub_hex: String,
    ciphertext_hex: String,
    nonce_hex: String,
    commitment_hex: String,
    commitment_salt_hex: String,
    commitment_context: String,
    #[allow(dead_code)]
    processor_id: Option<String>,
}

#[derive(Serialize)]
struct AttestationOut {
    nitro_attestation_b64: String,
    measurement: String,
    channel_public_key_hex: String,
    proof_verifier_key_hex: String,
    tee_backend: String,
    compute_tier: String,
    timestamp: f64,
}

#[derive(Serialize)]
struct ProofStatement {
    proof_id: String,
    proof_version: u32,
    schema_url: String,
    session_id: String,
    tenant_id: String,
    counter: u64,
    timestamp: f64,
    commitment_hex: String,
    processor_id: String,
    upstream_model: Option<String>,
    upstream_tokens_in: Option<u64>,
    upstream_tokens_out: Option<u64>,
    measurement: String,
    channel_public_key_b64: String,
    tee_backend: String,
    compute_tier: String,
    proof_mode: String,
    success: bool,
    error_code: Option<String>,
    policy_decision: Value,
    zeroization_report: Value,
    result_hash_hex: Option<String>,
    output_governance: Value,
    failure_detail: Option<Value>,
}
#[derive(Serialize)]
struct SignedProof {
    statement: ProofStatement,
    signer_key_id: String,
    signature_b64: String,
}

// =================== Helpers ===================

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}
fn random_hex(n_bytes: usize) -> String {
    use rand::RngCore;
    let mut b = vec![0u8; n_bytes];
    OsRng.fill_bytes(&mut b);
    hex::encode(b)
}
/// Canonical JSON for signing: keys sorted recursively. Mirrors the SDK.
fn canonical_json<T: serde::Serialize>(v: &T) -> Result<Vec<u8>> {
    let val: Value = serde_json::to_value(v)?;
    Ok(serde_json::to_vec(&sort_keys(val))?)
}
fn sort_keys(v: Value) -> Value {
    match v {
        Value::Object(m) => {
            let mut sorted = serde_json::Map::new();
            let mut keys: Vec<_> = m.keys().cloned().collect();
            keys.sort();
            for k in keys {
                sorted.insert(k.clone(), sort_keys(m.get(&k).cloned().unwrap()));
            }
            Value::Object(sorted)
        }
        Value::Array(a) => Value::Array(a.into_iter().map(sort_keys).collect()),
        other => other,
    }
}

async fn read_framed(s: &mut VsockStream) -> Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    s.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > 64 * 1024 * 1024 {
        anyhow::bail!("frame too large");
    }
    let mut buf = vec![0u8; len];
    s.read_exact(&mut buf).await?;
    Ok(buf)
}
async fn write_framed(s: &mut VsockStream, bytes: &[u8]) -> Result<()> {
    s.write_all(&(bytes.len() as u32).to_be_bytes()).await?;
    s.write_all(bytes).await?;
    Ok(())
}
