#!/usr/bin/env bash
# Produce a signed PZDR Enclave Image File (EIF).
#
# Requires nitro-cli, docker, jq, and optionally cosign.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$ROOT/eif/out"
mkdir -p "$OUT"

PZDR_VERSION="${PZDR_VERSION:-v0.1.0}"
COSIGN_KEY="${COSIGN_KEY:-$ROOT/eif/signing-key.pem}"
IMAGE_TAG="pzdr/enclave:${PZDR_VERSION}"
EIF_PATH="$OUT/pzdr-enclave-${PZDR_VERSION}.eif"
MEAS_PATH="$OUT/pzdr-enclave-${PZDR_VERSION}.measurements.json"

echo "==> pass 1: provisional build"
docker build --target runtime \
  --build-arg PZDR_EXPECTED_PCR0="provisional" \
  -t "${IMAGE_TAG}-prov" \
  -f "$ROOT/eif/Dockerfile.enclave" \
  "$ROOT"

echo "==> pass 1: provisional EIF"
PROV_EIF="$OUT/pzdr-enclave-${PZDR_VERSION}-prov.eif"
sudo nitro-cli build-enclave \
  --docker-uri "${IMAGE_TAG}-prov" \
  --output-file "$PROV_EIF" \
  | sudo tee "$OUT/prov-output.json" >/dev/null

REAL_PCR0="$(jq -r .Measurements.PCR0 "$OUT/prov-output.json")"
echo "real PCR0: $REAL_PCR0"

echo "==> pass 2: rebuild with PCR0 baked in"
docker build --target runtime \
  --build-arg PZDR_EXPECTED_PCR0="$REAL_PCR0" \
  -t "${IMAGE_TAG}" \
  -f "$ROOT/eif/Dockerfile.enclave" \
  "$ROOT"

echo "==> pass 2: final EIF"
sudo nitro-cli build-enclave \
  --docker-uri "${IMAGE_TAG}" \
  --output-file "$EIF_PATH" \
  | sudo tee "$OUT/output.json" >/dev/null

jq .Measurements "$OUT/output.json" > "$MEAS_PATH"
jq . "$MEAS_PATH"

if [ -f "$COSIGN_KEY" ]; then
  cosign sign-blob --yes --key "$COSIGN_KEY" --output-signature "$EIF_PATH.sig" "$EIF_PATH"
else
  echo "WARNING: no cosign key at $COSIGN_KEY; skipping signing."
fi

FINAL_PCR0="$(jq -r .PCR0 "$MEAS_PATH")"
if [ "$FINAL_PCR0" != "$REAL_PCR0" ]; then
  echo "ERROR: PCR0 drift between passes ($REAL_PCR0 vs $FINAL_PCR0)" >&2
  echo "The build is not deterministic enough for baked-in PCR0." >&2
  exit 1
fi

cat <<EOF

Build complete.
  EIF:           $EIF_PATH
  Signature:     $EIF_PATH.sig
  Measurements:  $MEAS_PATH

Next:
  1. Set pzdr_measurement in aws/terraform/terraform.tfvars.
  2. Copy the EIF to /opt/pzdr/eif/pzdr-enclave-v0.1.0.eif on the parent host.
  3. Start pzdr-enclave.service and vsock-parent-proxy.service.
EOF
