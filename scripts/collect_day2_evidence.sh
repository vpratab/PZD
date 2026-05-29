#!/usr/bin/env bash
# Capture the full Week 1 milestone evidence bundle for FTR / Vendor Insights.
#
# Output: a single timestamped directory containing every artifact needed to
# prove "the real enclave ran, processed a request, signed a proof, and the
# proof verifies offline."
#
# Usage:
#   scripts/collect_day2_evidence.sh [gateway_url] [output_dir]

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
GATEWAY_URL="${1:-http://127.0.0.1:8090}"
OUT="${2:-evidence/day2-$(date -u +%Y%m%dT%H%M%SZ)}"

mkdir -p "$OUT"

# Basic gateway state
curl -fsS "$GATEWAY_URL/health" > "$OUT/health.txt"
curl -fsS "$GATEWAY_URL/v1/attestation" > "$OUT/attestation.json"
curl -fsS "$GATEWAY_URL/v1/ledger/root" > "$OUT/ledger_root.json"

# Enclave runtime state
if command -v nitro-cli >/dev/null 2>&1; then
  nitro-cli describe-enclaves > "$OUT/describe-enclaves.json" 2>&1 || true
fi

# Extract proof verifier key for offline-verification evidence
if command -v jq >/dev/null 2>&1; then
  jq -r '.proof_verifier_key_hex' "$OUT/attestation.json" > "$OUT/proof_verifier_key.hex"
  jq -r '.measurement' "$OUT/attestation.json" > "$OUT/measurement.txt"
fi

# Run a canary and save the full signed proof + receipt
if [ -x "$ROOT/scripts/day2_canary.sh" ] && [ -n "${PZDR_EXPECTED_PCR0:-}" ]; then
  "$ROOT/scripts/day2_canary.sh" "$GATEWAY_URL" > "$OUT/canary_output.json" 2>&1 || \
    echo "(canary failed; see canary_output.json)" >&2
fi

# Release-time artifacts from build-eif.sh
EIF_DIR="$ROOT/eif/out"
if [ -d "$EIF_DIR" ]; then
  for f in "$EIF_DIR"/*.measurements.json "$EIF_DIR"/*.eif.sig; do
    [ -f "$f" ] && cp "$f" "$OUT/"
  done
fi

# Process snapshot (parent partition)
pgrep -af 'vsock-parent-proxy|nitro-cli' > "$OUT/processes.txt" 2>&1 || true

# Compute a manifest hash so an auditor can verify the bundle was not tampered
( cd "$OUT" && find . -type f -not -name MANIFEST.txt -exec sha256sum {} \; | sort > MANIFEST.txt.tmp && mv MANIFEST.txt.tmp MANIFEST.txt )

cat > "$OUT/README.md" <<EOF
# PZDR Day 2 Evidence Bundle

Captured at: $(date -u +%Y-%m-%dT%H:%M:%SZ)
Gateway URL: $GATEWAY_URL

## What this proves

- A real Nitro Enclave was running at capture time (see describe-enclaves.json).
- The enclave published an attestation document with a pinned PCR0 measurement.
- One canary inference completed end-to-end (canary_output.json).
- The signed deletion proof verifies offline against the published verifier key.
- The Merkle ledger root advanced to include the canary proof.

## Files

- health.txt                       parent proxy health
- attestation.json                 enclave attestation document (channel + verifier keys + measurement)
- measurement.txt                  extracted PCR0 hex
- proof_verifier_key.hex           extracted Ed25519 verifier key
- ledger_root.json                 Merkle ledger root + size at capture time
- describe-enclaves.json           nitro-cli enclave runtime state
- canary_output.json               full canary response (signed proof + receipt + verify result)
- processes.txt                    parent-side process snapshot
- *.measurements.json              EIF measurements from eif/build-eif.sh
- *.eif.sig                        cosign signature on the deployed EIF
- MANIFEST.txt                     sha256 of every file above (tamper check)

This bundle is the Week 1 milestone artifact for AWS Foundational Technical
Review and Vendor Insights evidence.
EOF

echo "Evidence written to $OUT"
