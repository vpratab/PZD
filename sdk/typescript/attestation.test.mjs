import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { createPrivateKey, sign } from "node:crypto";
import test from "node:test";
import cbor from "cbor";

import { verifyNitroAttestation } from "./dist/attestation.js";

const fixtures = join("..", "..", "crates", "nitro-attestation", "tests", "fixtures");
const rootPem = readFileSync(join(fixtures, "root_cert.pem"), "utf8");
const rootDer = readFileSync(join(fixtures, "root_cert.der"));
const leafDer = readFileSync(join(fixtures, "leaf_cert.der"));
const leafKey = createPrivateKey({
  format: "jwk",
  key: {
    crv: "P-384",
    d: "voT6JoXrMG4GbLExUt_iyluwFerVtn2aL2RlpEN0kUuKFk_L7KYnVUw122hcO4rj",
    kty: "EC",
    x: "x4_qccCU0hl-LjW1kbP_8zdGW9q2C6IxB7bydLJiCfsyK8TKsl4FlmnQPIAHnTXA",
    y: "GTjzNbO5tHwuy3kc3TiZQYUyWaXUk8NoGDMFKKYvNy0f9Q7z5GBmXRbR5z10Mfqs",
  },
});
const pcr0 = Buffer.alloc(48, 0xaa);
const channelKey = Buffer.alloc(32, 0xbb);
const proofKey = Buffer.alloc(32, 0xcc);

function syntheticAttestation() {
  const protectedBytes = cbor.encodeCanonical(new Map([[1, -35]]));
  const binding = Buffer.from(JSON.stringify({
    channel_public_key_hex: channelKey.toString("hex"),
    format: "pzdr-attestation-binding/v1",
    proof_verifier_key_hex: proofKey.toString("hex"),
  }));
  const payloadBytes = cbor.encodeCanonical(new Map([
    ["module_id", "synthetic"],
    ["digest", "SHA384"],
    ["timestamp", Date.now()],
    ["pcrs", new Map([[0, pcr0]])],
    ["certificate", leafDer],
    ["cabundle", [rootDer]],
    ["public_key", channelKey],
    ["user_data", binding],
  ]));
  const sigStructure = cbor.encodeCanonical([
    "Signature1",
    protectedBytes,
    Buffer.alloc(0),
    payloadBytes,
  ]);
  const signature = sign("sha384", sigStructure, {
    key: leafKey,
    dsaEncoding: "ieee-p1363",
  });
  const document = cbor.encodeCanonical(new cbor.Tagged(18, [
    protectedBytes,
    new Map(),
    payloadBytes,
    signature,
  ]));
  return {
    binding_format: "pzdr-attestation-binding/v1",
    channel_public_key_hex: channelKey.toString("hex"),
    measurement: pcr0.toString("hex"),
    nitro_attestation_b64: document.toString("base64"),
    proof_verifier_key_hex: proofKey.toString("hex"),
  };
}

test("verifies a COSE-tagged Nitro document and both bound keys", () => {
  const attestation = syntheticAttestation();
  const verified = verifyNitroAttestation(attestation, {
    awsRootPem: rootPem,
    expectedPcr0: pcr0.toString("hex"),
  });
  assert.equal(verified.channelPublicKeyHex, channelKey.toString("hex"));
  assert.equal(verified.proofVerifierKeyHex, proofKey.toString("hex"));
});

test("rejects the wrong PCR0 and an unbound advertised proof key", () => {
  const attestation = syntheticAttestation();
  assert.throws(
    () => verifyNitroAttestation(attestation, {
      awsRootPem: rootPem,
      expectedPcr0: "00".repeat(48),
    }),
    /PCR0/,
  );
  assert.throws(
    () => verifyNitroAttestation(
      { ...attestation, proof_verifier_key_hex: "dd".repeat(32) },
      { awsRootPem: rootPem, expectedPcr0: pcr0.toString("hex") },
    ),
    /Proof verifier key/,
  );
});

test("rejects a certificate path under an untrusted root", () => {
  const attestation = syntheticAttestation();
  assert.throws(
    () => verifyNitroAttestation(attestation, {
      expectedPcr0: pcr0.toString("hex"),
    }),
    /pinned AWS CA/,
  );
});
