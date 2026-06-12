#!/usr/bin/env bash
# One-command PZDR provability gate. Re-generates the golden vectors, runs the
# adversarial self-test, verifies the full audit bundle, and (if node is present)
# runs the cross-language TS conformance test. Exit non-zero on any failure.
set -euo pipefail
cd "$(dirname "$0")"

echo "== regenerate golden vectors =="
python3 pzdr_gen_vectors.py

echo; echo "== adversarial self-test =="
python3 pzdr_verify.py self-test

echo; echo "== verify full audit bundle =="
python3 pzdr_verify.py verify-bundle conformance/bundle.json

echo; echo "== single proofs =="
KEY=$(cat conformance/enclave_key.hex)
python3 pzdr_verify.py verify-proof conformance/proof_success.json --key "$KEY"
python3 pzdr_verify.py verify-proof conformance/proof_failure.json --key "$KEY"
python3 pzdr_verify.py verify-policy conformance/proof_success.json conformance/policy.json

echo; echo "== dependency fail-closed control =="
if python3 -S pzdr_verify.py verify-proof conformance/proof_success.json --key "$KEY"; then
  echo "ERROR: verifier passed without its Ed25519 dependency"
  exit 1
else
  echo "PASS: missing Ed25519 support fails closed"
fi

if command -v node >/dev/null 2>&1; then
  echo; echo "== cross-language TS conformance =="
  node ../sdk/typescript/transparency.conformance.mjs
fi

echo; echo "ALL PZDR PROVABILITY CHECKS PASSED"
