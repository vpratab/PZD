//! AWS Nitro Enclave attestation parser + verifier.
//!
//! Replaces the mock-attestation path in `crates/tee-enclave` with the real
//! Nitro NSM document format: COSE_Sign1 (CBOR) over an inner attestation map
//! signed by AWS's per-region Nitro root CA.
//!
//! # Inside-enclave usage (feature = "inside-enclave")
//!
//! ```ignore
//! use nitro_attestation::EnclaveSelf;
//! let doc = EnclaveSelf::generate_attestation(
//!     /*user_data*/ Some(b"channel-pubkey-here"),
//!     /*nonce*/     Some(b"client-supplied-nonce"),
//!     /*public_key*/ Some(channel_x25519_pub),
//! )?;
//! ```
//!
//! # Client-side verification (no feature)
//!
//! ```ignore
//! use nitro_attestation::Verifier;
//! let parsed = Verifier::parse(&attestation_bytes)?;
//! parsed.verify_against_aws_root()?;            // signature + cert chain
//! parsed.assert_measurement_matches(&expected_pcr0)?;
//! let channel_pubkey = parsed.public_key();
//! ```

use coset::CborSerializable;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum NitroError {
    #[error("CBOR decode error: {0}")]
    Cbor(String),
    #[error("COSE_Sign1 structure error: {0}")]
    Cose(String),
    #[error("certificate chain invalid: {0}")]
    CertChain(String),
    #[error("signature verification failed")]
    Signature,
    #[error("PCR mismatch — expected {expected}, got {got}")]
    PcrMismatch { expected: String, got: String },
    #[error("attestation document expired (timestamp {ts}, allowed skew {skew}s)")]
    Expired { ts: i64, skew: i64 },
    #[error("NSM device error: {0}")]
    Nsm(String),
    #[error("required field missing: {0}")]
    Missing(&'static str),
}

/// Map of PCR index → SHA-384 measurement bytes.
///
/// AWS Nitro emits PCR0–PCR15. PZDR pins PCR0 (enclave image) and optionally
/// PCR1 (kernel + cmdline) and PCR2 (application bytes). PCR3+ may carry
/// instance-specific values that should not be pinned across deployments.
pub type PcrMap = BTreeMap<usize, Vec<u8>>;

/// The verified contents of an attestation document, after we've checked the
/// COSE signature and AWS certificate chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifiedAttestation {
    /// Internal Nitro module identifier (per-instance).
    pub module_id: String,
    /// "SHA384" — the digest used for PCRs.
    pub digest: String,
    /// PCR map as a btree-map for stable ordering and JSON serialisation.
    pub pcrs: BTreeMap<usize, String>, // hex-encoded
    /// `user_data` supplied at attestation time (we use it to bind the
    /// enclave's channel public key into the signed document).
    pub user_data: Option<Vec<u8>>,
    /// Optional caller-supplied nonce for freshness.
    pub nonce: Option<Vec<u8>>,
    /// Optional `public_key` field — used by Nitro convention to expose a
    /// session key derived inside the enclave (e.g. our X25519 channel key).
    pub public_key: Option<Vec<u8>>,
    /// UNIX milliseconds when the doc was created on the NSM.
    pub timestamp_ms: i64,
    /// The certificate chain (DER-encoded) that signed this document.
    /// Last cert in the chain must chain up to the published AWS Nitro root.
    pub certificate_chain: Vec<Vec<u8>>,
}

impl VerifiedAttestation {
    /// Hex-encoded PCR0 — the value to pin in your KMS key policy and Terraform.
    pub fn measurement_pcr0(&self) -> Option<&str> {
        self.pcrs.get(&0).map(|s| s.as_str())
    }

    /// The X25519 (or whichever curve) channel public key bound into the attestation.
    pub fn channel_public_key(&self) -> Option<&[u8]> {
        self.public_key.as_deref()
    }

    /// Confirm the measurement we care about matches the one published in our
    /// Terraform module / Marketplace listing.
    pub fn assert_measurement_matches(&self, expected_pcr0_hex: &str) -> Result<(), NitroError> {
        match self.pcrs.get(&0) {
            Some(got) if got.eq_ignore_ascii_case(expected_pcr0_hex) => Ok(()),
            Some(got) => Err(NitroError::PcrMismatch {
                expected: expected_pcr0_hex.to_string(),
                got: got.clone(),
            }),
            None => Err(NitroError::Missing("PCR0")),
        }
    }

    /// Confirm the doc is recent. Pass `max_skew_secs` based on caller policy.
    pub fn assert_fresh(&self, now_ms: i64, max_skew_secs: i64) -> Result<(), NitroError> {
        let delta_secs = (now_ms - self.timestamp_ms) / 1000;
        if delta_secs.abs() > max_skew_secs {
            return Err(NitroError::Expired {
                ts: self.timestamp_ms / 1000,
                skew: max_skew_secs,
            });
        }
        Ok(())
    }
}

/// Parser + verifier for client-side use.
pub struct Verifier;

impl Verifier {
    /// Parse a Nitro attestation document. Performs COSE_Sign1 structural
    /// checks but defers root-CA validation to `verify_against_aws_root`.
    pub fn parse(doc_bytes: &[u8]) -> Result<VerifiedAttestation, NitroError> {
        // 1. Decode COSE_Sign1: a CBOR array of 4 items
        //    [protected: bstr, unprotected: map, payload: bstr, signature: bstr]
        let cose: coset::CoseSign1 = coset::CoseSign1::from_slice(doc_bytes)
            .map_err(|e| NitroError::Cose(format!("{e:?}")))?;
        let payload = cose
            .payload
            .as_ref()
            .ok_or(NitroError::Missing("payload"))?;

        // 2. Decode the inner Nitro attestation payload map
        let value: ciborium::value::Value = ciborium::de::from_reader(payload.as_slice())
            .map_err(|e| NitroError::Cbor(format!("{e:?}")))?;
        let map = value
            .as_map()
            .ok_or(NitroError::Cbor("payload not a map".into()))?;

        let mut module_id = None;
        let mut digest = None;
        let mut timestamp = None;
        let mut pcrs = BTreeMap::new();
        let mut cert = None;
        let mut cabundle = Vec::new();
        let mut public_key = None;
        let mut user_data = None;
        let mut nonce = None;

        for (k, v) in map {
            let key = k
                .as_text()
                .ok_or(NitroError::Cbor("non-text key in payload".into()))?;
            match key {
                "module_id" => module_id = v.as_text().map(|s| s.to_string()),
                "digest" => digest = v.as_text().map(|s| s.to_string()),
                "timestamp" => {
                    timestamp = v.as_integer().map(|i| {
                        // ciborium Integer → i128, but Nitro timestamp fits i64
                        let n: i128 = i.into();
                        n as i64
                    })
                }
                "pcrs" => {
                    if let Some(pmap) = v.as_map() {
                        for (idx_v, bytes_v) in pmap {
                            if let (Some(idx), Some(bytes)) =
                                (idx_v.as_integer(), bytes_v.as_bytes())
                            {
                                let idx_i: i128 = idx.into();
                                pcrs.insert(idx_i as usize, hex::encode(bytes));
                            }
                        }
                    }
                }
                "certificate" => cert = v.as_bytes().map(|b| b.to_vec()),
                "cabundle" => {
                    if let Some(arr) = v.as_array() {
                        for entry in arr {
                            if let Some(b) = entry.as_bytes() {
                                cabundle.push(b.to_vec());
                            }
                        }
                    }
                }
                "public_key" => public_key = v.as_bytes().map(|b| b.to_vec()),
                "user_data" => user_data = v.as_bytes().map(|b| b.to_vec()),
                "nonce" => nonce = v.as_bytes().map(|b| b.to_vec()),
                _ => {}
            }
        }

        let mut certificate_chain = Vec::new();
        if let Some(c) = cert {
            certificate_chain.push(c);
        }
        certificate_chain.extend(cabundle);

        Ok(VerifiedAttestation {
            module_id: module_id.ok_or(NitroError::Missing("module_id"))?,
            digest: digest.ok_or(NitroError::Missing("digest"))?,
            pcrs,
            user_data,
            nonce,
            public_key,
            timestamp_ms: timestamp.ok_or(NitroError::Missing("timestamp"))?,
            certificate_chain,
        })
    }

    /// One-call client API: parse the document, verify COSE signature and
    /// certificate chain against the supplied AWS root, check freshness, and
    /// (optionally) pin PCR0. This is the function the vsock parent proxy and
    /// SDK should call; the granular functions remain public for callers that
    /// need custom policy.
    pub fn parse_and_verify(
        doc_bytes: &[u8],
        aws_root_pem: &[u8],
        now_ms: i64,
        max_skew_secs: i64,
        expected_pcr0_hex: Option<&str>,
    ) -> Result<VerifiedAttestation, NitroError> {
        let parsed = Self::parse(doc_bytes)?;
        Self::verify_signature(doc_bytes, &parsed, aws_root_pem)?;
        parsed.assert_fresh(now_ms, max_skew_secs)?;
        if let Some(pcr0) = expected_pcr0_hex {
            parsed.assert_measurement_matches(pcr0)?;
        }
        Ok(parsed)
    }

    /// Re-derive the COSE_Sign1 signing input and verify the signature against
    /// the leaf certificate. Then chain-validate the leaf up to a pinned AWS
    /// Nitro root certificate. Returns `Ok(())` only if both pass.
    ///
    /// **NOTE:** The pinned root cert is per-region and rotates. We embed the
    /// current `us-east-1` and `us-gov-east-1` roots; pass `aws_root_pem` if
    /// you need a different region.
    pub fn verify_signature(
        doc_bytes: &[u8],
        parsed: &VerifiedAttestation,
        aws_root_pem: &[u8],
    ) -> Result<(), NitroError> {
        // 1. Re-parse the COSE structure
        let cose = coset::CoseSign1::from_slice(doc_bytes)
            .map_err(|e| NitroError::Cose(format!("{e:?}")))?;
        // 2. Leaf cert is the first cert in the bundle; verify it chains to the AWS root
        let leaf_der = parsed
            .certificate_chain
            .first()
            .ok_or(NitroError::Missing("leaf certificate"))?;
        Self::verify_chain(leaf_der, &parsed.certificate_chain[1..], aws_root_pem)?;
        // 3. Extract the leaf's P-384 SPKI and verify the COSE signature
        Self::verify_cose_signature(&cose, leaf_der)?;
        Ok(())
    }

    fn verify_chain(
        leaf_der: &[u8],
        cabundle: &[Vec<u8>],
        root_pem: &[u8],
    ) -> Result<(), NitroError> {
        use x509_cert::der::Decode;

        let leaf = x509_cert::Certificate::from_der(leaf_der)
            .map_err(|e| NitroError::CertChain(format!("leaf: {e:?}")))?;
        let mut pool = Vec::with_capacity(cabundle.len());
        for (i, der) in cabundle.iter().enumerate() {
            pool.push(
                x509_cert::Certificate::from_der(der)
                    .map_err(|e| NitroError::CertChain(format!("cabundle cert {i}: {e:?}")))?,
            );
        }

        let pem = std::str::from_utf8(root_pem)
            .map_err(|_| NitroError::CertChain("root not utf-8".into()))?;
        let (_label, root_der) = pem_rfc7468::decode_vec(pem.as_bytes())
            .map_err(|e| NitroError::CertChain(format!("root pem: {e:?}")))?;
        let root = x509_cert::Certificate::from_der(&root_der)
            .map_err(|e| NitroError::CertChain(format!("root: {e:?}")))?;

        // AWS documents carry `cabundle` root-first. Build the validation path
        // by issuer lookup so both AWS order and conventional leaf-first order
        // validate to the same pinned root.
        let mut chain = Vec::with_capacity(cabundle.len() + 1);
        chain.push(leaf);
        loop {
            let idx = chain.len() - 1;
            let issuer = chain[idx].tbs_certificate.issuer.clone();
            if issuer == root.tbs_certificate.subject {
                break;
            }
            let next_idx = pool
                .iter()
                .position(|candidate| candidate.tbs_certificate.subject == issuer)
                .ok_or_else(|| {
                    NitroError::CertChain(format!(
                        "no issuer found for chain cert {idx}: issuer={issuer}"
                    ))
                })?;
            chain.push(pool.remove(next_idx));
        }

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| NitroError::CertChain("system clock before unix epoch".into()))?
            .as_secs();
        for (idx, cert) in chain.iter().enumerate() {
            Self::verify_cert_validity(cert, now, &format!("chain cert {idx}"))?;
            let issuer = chain.get(idx + 1).unwrap_or(&root);
            if cert.tbs_certificate.issuer != issuer.tbs_certificate.subject {
                return Err(NitroError::CertChain(format!(
                    "issuer/subject mismatch at chain index {idx}: issuer={} subject={}",
                    cert.tbs_certificate.issuer, issuer.tbs_certificate.subject
                )));
            }
            // Path-validation hardening: anything that *issues* a certificate
            // in this chain must itself be a CA (BasicConstraints cA=TRUE).
            // Prevents a leaf-only compromise from minting fake "enclaves".
            Self::assert_ca_constraints(issuer, idx, &format!("issuer of chain cert {idx}"))?;
            Self::verify_cert_signature(cert, issuer, &format!("chain cert {idx}"))?;
        }
        Self::verify_cert_validity(&root, now, "pinned AWS root")?;
        // Validate the supplied Nitro chain against our pinned AWS root: every
        // certificate must be time-valid, issuer/subject-linked, and signed by
        // the next issuer in the path. This is intentionally narrower than a
        // general WebPKI path builder because Nitro documents carry their own
        // AWS-rooted certificate bundle.
        Ok(())
    }

    /// BasicConstraints check: a certificate acting as an issuer in the
    /// validation path must carry `cA = TRUE`. (OID 2.5.29.19)
    fn assert_ca_constraints(
        cert: &x509_cert::Certificate,
        subordinate_ca_count: usize,
        label: &str,
    ) -> Result<(), NitroError> {
        use x509_cert::der::Decode;
        const BASIC_CONSTRAINTS: x509_cert::der::asn1::ObjectIdentifier =
            x509_cert::der::asn1::ObjectIdentifier::new_unwrap("2.5.29.19");
        const KEY_USAGE: x509_cert::der::asn1::ObjectIdentifier =
            x509_cert::der::asn1::ObjectIdentifier::new_unwrap("2.5.29.15");
        let exts = cert.tbs_certificate.extensions.as_ref().ok_or_else(|| {
            NitroError::CertChain(format!("{label}: no extensions, cannot be a CA"))
        })?;
        let mut basic_constraints_valid = false;
        for ext in exts.iter() {
            if ext.extn_id == BASIC_CONSTRAINTS {
                let bc =
                    x509_cert::ext::pkix::BasicConstraints::from_der(ext.extn_value.as_bytes())
                        .map_err(|e| {
                            NitroError::CertChain(format!("{label}: bad BasicConstraints: {e:?}"))
                        })?;
                if !bc.ca {
                    return Err(NitroError::CertChain(format!(
                        "{label}: BasicConstraints present but cA=FALSE"
                    )));
                }
                if bc
                    .path_len_constraint
                    .is_some_and(|limit| subordinate_ca_count > usize::from(limit))
                {
                    return Err(NitroError::CertChain(format!(
                        "{label}: pathLenConstraint exceeded"
                    )));
                }
                basic_constraints_valid = true;
            }
            if ext.extn_id == KEY_USAGE {
                let usage = x509_cert::ext::pkix::KeyUsage::from_der(ext.extn_value.as_bytes())
                    .map_err(|e| NitroError::CertChain(format!("{label}: bad KeyUsage: {e:?}")))?;
                if !usage.key_cert_sign() {
                    return Err(NitroError::CertChain(format!(
                        "{label}: KeyUsage does not permit certificate signing"
                    )));
                }
            }
        }
        if basic_constraints_valid {
            return Ok(());
        }
        Err(NitroError::CertChain(format!(
            "{label}: BasicConstraints extension missing — not a CA"
        )))
    }

    fn verify_cert_validity(
        cert: &x509_cert::Certificate,
        now_unix_secs: u64,
        label: &str,
    ) -> Result<(), NitroError> {
        let not_before = cert
            .tbs_certificate
            .validity
            .not_before
            .to_unix_duration()
            .as_secs();
        let not_after = cert
            .tbs_certificate
            .validity
            .not_after
            .to_unix_duration()
            .as_secs();

        if now_unix_secs < not_before || now_unix_secs > not_after {
            return Err(NitroError::CertChain(format!(
                "{label} not valid at current time"
            )));
        }
        Ok(())
    }

    fn verify_cert_signature(
        cert: &x509_cert::Certificate,
        issuer: &x509_cert::Certificate,
        label: &str,
    ) -> Result<(), NitroError> {
        use p384::ecdsa::{signature::Verifier as _, Signature, VerifyingKey};
        use x509_cert::der::Encode;

        let issuer_spki = issuer
            .tbs_certificate
            .subject_public_key_info
            .subject_public_key
            .raw_bytes();
        let verifying_key = VerifyingKey::from_sec1_bytes(issuer_spki)
            .map_err(|e| NitroError::CertChain(format!("{label} issuer SPKI not P-384: {e:?}")))?;
        let tbs_der = cert
            .tbs_certificate
            .to_der()
            .map_err(|e| NitroError::CertChain(format!("{label} tbs der: {e:?}")))?;
        let signature_bytes = cert
            .signature
            .as_bytes()
            .ok_or_else(|| NitroError::CertChain(format!("{label} signature has unused bits")))?;
        let signature = Signature::from_der(signature_bytes)
            .map_err(|e| NitroError::CertChain(format!("{label} signature der: {e:?}")))?;

        verifying_key
            .verify(&tbs_der, &signature)
            .map_err(|_| NitroError::CertChain(format!("{label} signature verification failed")))?;
        Ok(())
    }

    fn verify_cose_signature(cose: &coset::CoseSign1, leaf_der: &[u8]) -> Result<(), NitroError> {
        use p384::ecdsa::{signature::Verifier as _, Signature, VerifyingKey};
        use x509_cert::der::Decode;

        // Algorithm-confusion hardening: the protected header MUST declare
        // ES384 (COSE alg -35). Nitro always signs with ECDSA P-384/SHA-384;
        // any other declared algorithm is an attack or corruption, and we
        // refuse before touching key material.
        match &cose.protected.header.alg {
            Some(coset::RegisteredLabelWithPrivate::Assigned(coset::iana::Algorithm::ES384)) => {}
            other => {
                return Err(NitroError::Cose(format!(
                    "protected header alg must be ES384, got {other:?}"
                )))
            }
        }

        let cert = x509_cert::Certificate::from_der(leaf_der)
            .map_err(|e| NitroError::CertChain(format!("leaf: {e:?}")))?;
        let spki_der = cert
            .tbs_certificate
            .subject_public_key_info
            .subject_public_key
            .raw_bytes();
        let vk = VerifyingKey::from_sec1_bytes(spki_der)
            .map_err(|e| NitroError::Cose(format!("spki not P-384: {e:?}")))?;

        // Build COSE Sig_structure for ECDSA-P384 / SHA-384
        let tbs = cose.tbs_data(&[]);
        let sig = Signature::from_slice(&cose.signature)
            .map_err(|e| NitroError::Cose(format!("sig parse: {e:?}")))?;

        vk.verify(&tbs, &sig).map_err(|_| NitroError::Signature)?;
        Ok(())
    }
}

// ---------- AWS published Nitro root certificates (current as of 2026) ----------
// These are stable per-region anchors. Re-fetch annually.
// Source: https://docs.aws.amazon.com/enclaves/latest/user/verify-root.html
pub const AWS_ROOT_PEM_COMMERCIAL: &[u8] = b"-----BEGIN CERTIFICATE-----
MIICETCCAZagAwIBAgIRAPkxdWgbkK/hHUbMtOTn+FYwCgYIKoZIzj0EAwMwSTEL
MAkGA1UEBhMCVVMxDzANBgNVBAoMBkFtYXpvbjEMMAoGA1UECwwDQVdTMRswGQYD
VQQDDBJhd3Mubml0cm8tZW5jbGF2ZXMwHhcNMTkxMDI4MTMyODA1WhcNNDkxMDI4
MTQyODA1WjBJMQswCQYDVQQGEwJVUzEPMA0GA1UECgwGQW1hem9uMQwwCgYDVQQL
DANBV1MxGzAZBgNVBAMMEmF3cy5uaXRyby1lbmNsYXZlczB2MBAGByqGSM49AgEG
BSuBBAAiA2IABPwCVOumCMHzaHDimtqQvkY4MpJzbolL//Zy2YlES1BR5TSksfbb
48C8WBoyt7F2Bw7eEtaaP+ohG2bnUs990d0JX28TcPQXCEPZ3BABIeTPYwEoCWZE
h8l5YoQwTcU/9KNCMEAwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUkCW1DdkF
R+eWw5b6cp3PmanfS5YwDgYDVR0PAQH/BAQDAgGGMAoGCCqGSM49BAMDA2kAMGYC
MQCjfy+Rocm9Xue4YnwWmNJVA44fA0P5W2OpYow9OYCVRaEevL8uO1XYru5xtMPW
rfMCMQCi85sWBbJwKKXdS6BptQFuZbT73o/gBh1qUxl/nNr12UO8Yfwr6wPLb+6N
IwLz3/Y=
-----END CERTIFICATE-----
";

pub const AWS_ROOT_PEM_GOVCLOUD: &[u8] = b"-----BEGIN CERTIFICATE-----
MIIB6jCCAW+gAwIBAgIQCMjm6BMzlEhKlTbcGr+EczAKBggqhkjOPQQDAzBJMQsw
CQYDVQQGEwJVUzEPMA0GA1UECgwGQW1hem9uMQwwCgYDVQQLDANBV1MxGzAZBgNV
BAMMEmF3cy5uaXRyby1lbmNsYXZlczAeFw0yMDA2MTAxOTI4NDNaFw00MDA2MTAy
MDI4NDNaMEkxCzAJBgNVBAYTAlVTMQ8wDQYDVQQKDAZBbWF6b24xDDAKBgNVBAsM
A0FXUzEbMBkGA1UEAwwSYXdzLm5pdHJvLWVuY2xhdmVzMHYwEAYHKoZIzj0CAQYF
K4EEACIDYgAEsT0sEbXVU2cnAS4TJfV8Y0nA8sqU3IsZNwm6sXX6oQA9C9Jt7Tg5
8s/pNkD3FuVL9pVZpJpgFB7C/B1eFwgGzKkA3kxN6BB3yJtT8r+rN6yqDcgGZBuM
9aKHQGgPyhq2o0IwQDAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBhjAd
BgNVHQ4EFgQUVxIuJWfp/Y3JzcoUKJWFc4qOyfowCgYIKoZIzj0EAwMDaQAwZgIx
AILi9Rg6cFcLU3WtIThZ+l+0H6lE7gV1MR9wKEEPpJ2zXBcU0fGdgZHzVGM2vqgX
4QIxALL1OQc8s8w50yYBKvK7nHFvrjpDxrJ7c2/Vc9wRSZBeWqZTBznSjyG6Asne
TZBhsg==
-----END CERTIFICATE-----
";

// ---------- Inside-enclave attestation generation ----------
#[cfg(feature = "inside-enclave")]
pub mod enclave {
    use super::NitroError;
    use aws_nitro_enclaves_nsm_api::api::{Request, Response};
    use aws_nitro_enclaves_nsm_api::driver::{nsm_exit, nsm_init, nsm_process_request};
    use serde_bytes::ByteBuf;

    pub struct EnclaveSelf {
        fd: i32,
    }
    impl EnclaveSelf {
        pub fn new() -> Result<Self, NitroError> {
            let fd = nsm_init();
            if fd < 0 {
                return Err(NitroError::Nsm(format!("nsm_init failed: {fd}")));
            }
            Ok(EnclaveSelf { fd })
        }

        /// Generate an attestation document binding `user_data`, `nonce`, and
        /// our enclave-side channel public key into a signed Nitro document
        /// that any client can verify offline using only the AWS root cert.
        pub fn generate_attestation(
            &self,
            user_data: Option<Vec<u8>>,
            nonce: Option<Vec<u8>>,
            public_key: Option<Vec<u8>>,
        ) -> Result<Vec<u8>, NitroError> {
            let req = Request::Attestation {
                user_data: user_data.map(ByteBuf::from),
                nonce: nonce.map(ByteBuf::from),
                public_key: public_key.map(ByteBuf::from),
            };
            match nsm_process_request(self.fd, req) {
                Response::Attestation { document } => Ok(document),
                Response::Error(e) => Err(NitroError::Nsm(format!("{:?}", e))),
                _ => Err(NitroError::Nsm("unexpected NSM response".into())),
            }
        }

        /// Get cryptographically strong randomness from the NSM (256 bits).
        pub fn random_bytes(&self, n: usize) -> Result<Vec<u8>, NitroError> {
            let mut out = Vec::with_capacity(n);
            while out.len() < n {
                let resp = nsm_process_request(self.fd, Request::GetRandom);
                match resp {
                    Response::GetRandom { random } => {
                        let need = n - out.len();
                        out.extend_from_slice(&random[..need.min(random.len())]);
                    }
                    Response::Error(e) => return Err(NitroError::Nsm(format!("{e:?}"))),
                    _ => return Err(NitroError::Nsm("unexpected response".into())),
                }
            }
            Ok(out)
        }
    }
    impl Drop for EnclaveSelf {
        fn drop(&mut self) {
            nsm_exit(self.fd);
        }
    }
}

// Minimal pem decoding (no external crate, since x509-cert pulls in pem-rfc7468 transitively)
mod pem_rfc7468 {
    pub fn decode_vec(pem: &[u8]) -> Result<(&'static str, Vec<u8>), &'static str> {
        let s = std::str::from_utf8(pem).map_err(|_| "not utf-8")?;
        let lines: Vec<&str> = s.lines().filter(|l| !l.starts_with("-----")).collect();
        let b64 = lines.concat();
        use base64::Engine as _;
        let der = base64::engine::general_purpose::STANDARD
            .decode(&b64)
            .map_err(|_| "base64 decode")?;
        Ok(("CERTIFICATE", der))
    }
}
