#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
GATEWAY_URL="${1:-http://127.0.0.1:8090}"
OUT="${2:-evidence/day2-$(date -u +%Y%m%dT%H%M%SZ)}"

if [ -z "${PZDR_EXPECTED_PCR0:-}" ] && [ -f /etc/pzdr/pzdr.env ]; then
  set -a
  # shellcheck disable=SC1091
  . /etc/pzdr/pzdr.env
  set +a
fi

case "$OUT" in
  /*) ;;
  *) OUT="$ROOT/$OUT" ;;
esac

mkdir -p "$OUT"
curl -fsS "$GATEWAY_URL/health" > "$OUT/health.txt"
curl -fsS "$GATEWAY_URL/v1/attestation" | tee "$OUT/attestation.json" >/dev/null
curl -fsS "$GATEWAY_URL/v1/ledger/root" > "$OUT/ledger_root.json" || true
nitro-cli describe-enclaves > "$OUT/describe-enclaves.json" 2>/dev/null || true

jq -r '.proof_verifier_key_hex // empty' "$OUT/attestation.json" > "$OUT/proof_verifier_key.txt"

"$ROOT/scripts/day2_canary.sh" "$GATEWAY_URL" > "$OUT/canary_output.json" 2> "$OUT/canary_stderr.log" || {
  echo "canary failed; see canary_stderr.log" > "$OUT/canary_failed.txt"
}

cp "$ROOT/eif/out/pzdr-enclave-v0.1.0.measurements.json" "$OUT/" 2>/dev/null || true
cp "$ROOT/eif/out/pzdr-enclave-v0.1.0.eif.sig" "$OUT/" 2>/dev/null || true

cat > "$OUT/MANIFEST.txt.tmp" <<EOF
captured_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
gateway_url=$GATEWAY_URL
health=health.txt
attestation=attestation.json
proof_verifier_key=proof_verifier_key.txt
ledger_root=ledger_root.json
nitro_describe=describe-enclaves.json
canary_stdout=canary_output.json
canary_stderr=canary_stderr.log
measurements=pzdr-enclave-v0.1.0.measurements.json if available
eif_signature=pzdr-enclave-v0.1.0.eif.sig if available
EOF
mv "$OUT/MANIFEST.txt.tmp" "$OUT/MANIFEST.txt"

cat > "$OUT/README.md.tmp" <<EOF
# PZDR Day 2 Evidence

- Captured at: $(date -u +%Y-%m-%dT%H:%M:%SZ)
- Gateway URL: $GATEWAY_URL

Files:

- MANIFEST.txt
- health.txt
- attestation.json
- proof_verifier_key.txt
- ledger_root.json
- describe-enclaves.json
- canary_output.json
- canary_stderr.log
- pzdr-enclave-v0.1.0.measurements.json, if available
- pzdr-enclave-v0.1.0.eif.sig, if available
EOF
mv "$OUT/README.md.tmp" "$OUT/README.md"

tar -czf "$OUT.tar.gz" -C "$(dirname "$OUT")" "$(basename "$OUT")"
echo "Evidence written to $OUT"
echo "Archive written to $OUT.tar.gz"
