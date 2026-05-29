#!/usr/bin/env bash
# Day 2 canary: pin PCR0, run one inference, verify the signed proof.
# Fail loudly if the enclave running is not the one the operator expected.
#
# Required environment:
#   PZDR_EXPECTED_PCR0    Hex-encoded PCR0 from eif/build-eif.sh measurements.json
#                         Set in /etc/pzdr/pzdr.env after every release.
#
# Optional arg:
#   $1                    Gateway URL (default http://127.0.0.1:8090)

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
GATEWAY_URL="${1:-http://127.0.0.1:8090}"

: "${PZDR_EXPECTED_PCR0:?PZDR_EXPECTED_PCR0 must be set (hex PCR0 from build-eif.sh)}"

cd "$ROOT/sdk/typescript"
if [ ! -d node_modules ] || [ ! -d dist ]; then
  npm ci
  npm run build
fi

PZDR_EXPECTED_PCR0="$PZDR_EXPECTED_PCR0" \
GATEWAY_URL="$GATEWAY_URL" \
node --input-type=module <<'EOF'
import { PZDRClient } from "./dist/client.js";

const expected = process.env.PZDR_EXPECTED_PCR0;
const gateway = process.env.GATEWAY_URL;

const client = new PZDRClient({ url: gateway });
const attestation = await client.getAttestation();

// Hard pin: PCR0 must match the value the operator expected.
if (attestation.measurement.toLowerCase() !== expected.toLowerCase()) {
  console.error(JSON.stringify({
    error: "pcr0_mismatch",
    expected_pcr0: expected,
    actual_pcr0: attestation.measurement,
    detail: "Refusing to send a canary to an enclave whose measurement does not match the pinned release.",
  }));
  process.exit(3);
}

const result = await client.process({
  prompt: "PZDR canary request",
  tenant: "day2-canary",
  context: "day2-canary",
});

const valid = await client.verifyProof(result.proof, attestation.proof_verifier_key_hex);

const out = {
  ok: result.ok,
  proof_valid: valid,
  pcr0: attestation.measurement,
  counter: result.proof.statement.counter,
  receipt: result.receipt,
};
console.log(JSON.stringify(out, null, 2));

if (!result.ok || !valid) {
  process.exit(1);
}
EOF
