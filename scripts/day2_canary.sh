#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
GATEWAY_URL="${1:-http://127.0.0.1:8090}"

if [ -z "${PZDR_EXPECTED_PCR0:-}" ] && [ -f /etc/pzdr/pzdr.env ]; then
  set -a
  # shellcheck disable=SC1091
  . /etc/pzdr/pzdr.env
  set +a
fi

cd "$ROOT/sdk/typescript"
npm ci >&2
npm run build >&2

PZDR_CANARY_GATEWAY_URL="$GATEWAY_URL" node --input-type=module <<'EOF'
import { PZDRClient } from "./dist/client.js";

const gatewayUrl = process.env.PZDR_CANARY_GATEWAY_URL;
const expectedPcr0 = process.env.PZDR_EXPECTED_PCR0;

if (!expectedPcr0) {
  console.error("PZDR_EXPECTED_PCR0 not set");
  process.exit(2);
}

const client = new PZDRClient({ url: gatewayUrl });
const attestation = await client.getAttestation();

if (attestation.measurement !== expectedPcr0) {
  console.error(`PCR0 mismatch: got ${attestation.measurement}, expected ${expectedPcr0}`);
  process.exit(3);
}

const result = await client.process({
  prompt: "PZDR canary request",
  tenant: "day2-canary",
  context: "day2-canary",
});

const proofValid = await client.verifyProof(result.proof, attestation.proof_verifier_key_hex);

const evidence = {
  ok: result.ok,
  proof_valid: proofValid,
  measurement: attestation.measurement,
  proof_verifier_key_hex: attestation.proof_verifier_key_hex,
  model_response: result.modelResponse,
  proof: result.proof,
  receipt: result.receipt,
  timings_us: result.timings_us,
};

console.log(JSON.stringify(evidence, null, 2));

if (!result.ok || !proofValid) {
  process.exit(1);
}
EOF
