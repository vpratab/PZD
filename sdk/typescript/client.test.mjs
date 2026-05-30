import assert from "node:assert/strict";
import test from "node:test";

import { canonicalJSON, PZDRClient } from "./dist/client.js";

test("canonicalJSON keeps proof timestamps integral", () => {
  const statement = {
    commitment_hex: "aa",
    counter: 1,
    measurement: "00",
    proof_id: "proof",
    proof_version: 3,
    session_id: "session",
    success: true,
    timestamp: 1779984000,
  };

  const canonical = canonicalJSON(statement);
  assert.match(canonical, /"timestamp":1779984000/);
  assert.doesNotMatch(canonical, /1779984000\.0/);
});

const verifierKeyHex = "79b5562e8fe654f94078b112e8a98ba7901f853ae695bed7e0e3910bad049664";
const proof = {
  signature_b64: "OqX+D5zcnSuk67sDy8ih7O30+6C2LIe+O2J8HGLpIKhDQ/o42sakbFVYzmyZaNijT4TFnE/9abEJ7198jkqlCA==",
  statement: {
    channel_public_key_hex: "1111111111111111111111111111111111111111111111111111111111111111",
    commitment_hex: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    compute_tier: "tier1_cpu_enclave_only",
    counter: 42,
    error_code: null,
    failure_detail: null,
    measurement: "0000000000000000000000000000000000000000000000000000000000000000",
    output_governance: { expires_at: 1779987600, retention_policy: "ephemeral" },
    policy_decision: {
      allow: true,
      policy_hash: "2222222222222222222222222222222222222222222222222222222222222222",
      reason: "fixture",
      tenant: "tenant-a",
    },
    processor_id: "gateway",
    proof_id: "proof-fixture-001",
    proof_mode: "attestation",
    proof_version: 3,
    result_hash_hex: "3333333333333333333333333333333333333333333333333333333333333333",
    schema_url: "pzdr://proof/v3",
    session_id: "session-fixture-001",
    success: true,
    tee_backend: "aws-nitro",
    tenant_id: "tenant-a",
    timestamp: 1779984000,
    upstream_model: "mock://fixture",
    upstream_tokens_in: 3,
    upstream_tokens_out: 7,
    zeroization_report: { input_buffer_wiped: true, response_buffer_wiped: true },
  },
};

test("verifyProof accepts a deterministic signed v3 proof fixture", async () => {
  const client = new PZDRClient({ url: "http://127.0.0.1:8090" });
  assert.equal(await client.verifyProof(proof, verifierKeyHex), true);
});

test("verifyProof rejects a tampered deterministic proof fixture", async () => {
  const client = new PZDRClient({ url: "http://127.0.0.1:8090" });
  const tampered = {
    ...proof,
    statement: {
      ...proof.statement,
      counter: proof.statement.counter + 1,
    },
  };

  assert.equal(await client.verifyProof(tampered, verifierKeyHex), false);
});
