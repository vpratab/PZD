/**
 * PZDR Gateway TypeScript SDK.
 *
 * Targets the v0.1 Nitro gateway wire format:
 *   GET  /v1/attestation
 *   POST /v1/gateway/inference
 */

import { canonicalJSON } from "./canonical.js";
import {
  AWS_NITRO_ROOT_PEM_COMMERCIAL,
  verifyNitroAttestation,
} from "./attestation.js";
import sodium from "./sodium.js";
import {
  entryBytesOf,
  leafHash,
  SignedCheckpoint,
  verifyCheckpoint,
  verifyInclusion,
} from "./transparency.js";

export { canonicalJSON } from "./canonical.js";
export * from "./attestation.js";
export * from "./transparency.js";

export interface AttestationDocument {
  nitro_attestation_b64: string;
  measurement: string;
  channel_public_key_hex: string;
  proof_verifier_key_hex: string;
  binding_format?: string;
  tee_backend: string;
  compute_tier: string;
  timestamp: number;
}

export interface DeletionProofStatement {
  proof_id: string;
  proof_version: number;
  schema_url?: string;
  session_id: string;
  tenant_id?: string;
  counter: number;
  /** Integer Unix seconds. Kept integral so Rust-signed proofs verify in JS. */
  timestamp: number;
  commitment_hex: string;
  processor_id?: string;
  upstream_model?: string;
  upstream_tokens_in?: number;
  upstream_tokens_out?: number;
  measurement: string;
  channel_public_key_hex?: string;
  proof_verifier_key_hex?: string;
  tee_backend?: string;
  compute_tier?: string;
  proof_mode?: string;
  success: boolean;
  error_code?: string;
  policy_decision?: Record<string, unknown>;
  zeroization_report?: Record<string, unknown>;
  result_hash_hex?: string;
  output_governance?: Record<string, unknown>;
  failure_detail?: Record<string, unknown>;
}

export interface SignedDeletionProof {
  statement: DeletionProofStatement;
  signer_key_id?: string;
  signature_b64: string;
}

export interface InferenceResult {
  ok: boolean;
  modelResponse?: unknown;
  error?: string;
  proof: SignedDeletionProof;
  receipt: {
    index: number;
    leaf_hash_hex: string;
    audit_path: string[];
    checkpoint: SignedCheckpoint;
  };
  timings_us: Record<string, number>;
}

export interface PZDRClientConfig {
  url: string;
  expectedPcr0: string;
  apiKey?: string;
  fetch?: typeof fetch;
  awsNitroRootPem?: string;
  maxAttestationAgeSeconds?: number;
}

export interface ProcessOptions {
  prompt: string | Uint8Array;
  processor?: string;
  tenant?: string;
  context?: string;
  attestation?: AttestationDocument;
}

export class PZDRClient {
  constructor(private cfg: PZDRClientConfig) {}

  private get fetchImpl(): typeof fetch {
    const fetchImpl = this.cfg.fetch ?? globalThis.fetch;
    if (!fetchImpl) {
      throw new Error("No fetch implementation available");
    }
    return fetchImpl;
  }

  private async req(path: string, init?: RequestInit): Promise<unknown> {
    const headers: Record<string, string> = {
      "Content-Type": "application/json",
      ...(this.cfg.apiKey ? { "X-PZDR-Api-Key": this.cfg.apiKey } : {}),
      ...((init?.headers as Record<string, string> | undefined) ?? {}),
    };
    const response = await this.fetchImpl(this.cfg.url + path, { ...init, headers });
    if (!response.ok) {
      throw new Error(`PZDR ${path} returned HTTP ${response.status}`);
    }
    return response.json();
  }

  async getAttestation(): Promise<AttestationDocument> {
    const attestation = await this.req("/v1/attestation") as AttestationDocument;
    this.verifyAttestation(attestation);
    return attestation;
  }

  verifyAttestation(attestation: AttestationDocument): void {
    verifyNitroAttestation(attestation, {
      expectedPcr0: this.cfg.expectedPcr0,
      awsRootPem: this.cfg.awsNitroRootPem ?? AWS_NITRO_ROOT_PEM_COMMERCIAL,
      maxAgeSeconds: this.cfg.maxAttestationAgeSeconds,
    });
  }

  async process(options: ProcessOptions): Promise<InferenceResult> {
    await sodium.ready;
    const attestation = options.attestation ?? (await this.getAttestation());
    this.verifyAttestation(attestation);
    const payload = typeof options.prompt === "string"
      ? new TextEncoder().encode(options.prompt)
      : options.prompt;
    const context = options.context ?? "default";

    const clientSecret = sodium.randombytes_buf(32);
    const clientPublic = sodium.crypto_scalarmult_base(clientSecret);
    const channelPublic = sodium.from_hex(attestation.channel_public_key_hex);
    const shared = sodium.crypto_scalarmult(clientSecret, channelPublic);
    const aeadKey = await hkdfSha256(
      shared,
      new TextEncoder().encode("pzdr-channel-v1"),
      new TextEncoder().encode("channel-aead"),
      32,
    );

    const nonce = sodium.randombytes_buf(24);
    const ciphertext = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
      payload,
      null,
      null,
      nonce,
      aeadKey,
    );

    const salt = sodium.randombytes_buf(16);
    const commitment = await sha256Hex(concat(
      payload,
      salt,
      new TextEncoder().encode(context),
    ));

    const body = {
      client_pub_hex: sodium.to_hex(clientPublic),
      ciphertext_hex: sodium.to_hex(ciphertext),
      nonce_hex: sodium.to_hex(nonce),
      commitment_hex: commitment,
      commitment_salt_hex: sodium.to_hex(salt),
      commitment_context: context,
      processor_id: options.processor ?? "gateway",
    };

    const headers: Record<string, string> = {};
    if (options.tenant) {
      headers["X-Tenant-Id"] = options.tenant;
    }

    const response = await this.req("/v1/gateway/inference", {
      method: "POST",
      body: JSON.stringify(body),
      headers,
    }) as {
      ok: boolean;
      model_response?: unknown;
      error?: string;
      proof: SignedDeletionProof;
      receipt: InferenceResult["receipt"];
      timings_us?: Record<string, number>;
    };

    return {
      ok: response.ok,
      modelResponse: response.model_response,
      error: response.error,
      proof: response.proof,
      receipt: response.receipt,
      timings_us: response.timings_us ?? {},
    };
  }

  async verifyProof(proof: SignedDeletionProof, verifierKeyHex: string): Promise<boolean> {
    await sodium.ready;
    const message = new TextEncoder().encode(canonicalJSON(proof.statement));
    return sodium.crypto_sign_verify_detached(
      b64ToBytes(proof.signature_b64),
      message,
      sodium.from_hex(verifierKeyHex),
    );
  }

  async verifyReceipt(
    proof: SignedDeletionProof,
    receipt: InferenceResult["receipt"],
    verifierKeyHex: string,
  ): Promise<boolean> {
    if (!await this.verifyProof(proof, verifierKeyHex)) return false;
    if (!await verifyCheckpoint(receipt.checkpoint, verifierKeyHex)) return false;
    const leaf = leafHash(entryBytesOf(proof));
    if (sodium.to_hex(leaf) !== receipt.leaf_hash_hex.toLowerCase()) return false;
    return verifyInclusion(
      leaf,
      receipt.index,
      receipt.checkpoint.size,
      receipt.audit_path,
      receipt.checkpoint.root_hex,
    );
  }
}

function concat(...chunks: Uint8Array[]): Uint8Array {
  const total = chunks.reduce((sum, chunk) => sum + chunk.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    out.set(chunk, offset);
    offset += chunk.length;
  }
  return out;
}

async function sha256Hex(bytes: Uint8Array): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", toArrayBuffer(bytes));
  return sodium.to_hex(new Uint8Array(digest));
}

async function hkdfSha256(
  ikm: Uint8Array,
  salt: Uint8Array,
  info: Uint8Array,
  length: number,
): Promise<Uint8Array> {
  const baseKey = await crypto.subtle.importKey("raw", toArrayBuffer(ikm), "HKDF", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    { name: "HKDF", hash: "SHA-256", salt: toArrayBuffer(salt), info: toArrayBuffer(info) },
    baseKey,
    length * 8,
  );
  return new Uint8Array(bits);
}

function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer;
}

function b64ToBytes(value: string): Uint8Array {
  const binary = atob(value);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}
