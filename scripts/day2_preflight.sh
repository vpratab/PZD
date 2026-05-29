#!/usr/bin/env bash
# Verify the EC2 parent partition is ready before starting PZDR services.

set -euo pipefail

ENV_FILE="${1:-/etc/pzdr/pzdr.env}"

step() {
  printf '\n==> %s\n' "$1"
}

fail() {
  echo "ERROR: $*" >&2
  exit 1
}

need() {
  command -v "$1" >/dev/null 2>&1 || fail "missing command: $1"
}

require_env() {
  local name="$1"
  local value="${!name:-}"
  [ -n "$value" ] || fail "$name is not set in $ENV_FILE"
}

step "Commands"
need curl
need jq
need systemctl
need nitro-cli
need docker

step "Environment"
[ -f "$ENV_FILE" ] || fail "environment file not found: $ENV_FILE"
set -a
# shellcheck disable=SC1090
. "$ENV_FILE"
set +a

for name in \
  PROXY_ADDR \
  ENCLAVE_CID \
  ENCLAVE_PORT \
  ENCLAVE_TIMEOUT_MS \
  PZDR_EIF_PATH \
  PZDR_ENCLAVE_MEMORY_MIB \
  PZDR_ENCLAVE_CPU_COUNT \
  PZDR_EXPECTED_PCR0
do
  require_env "$name"
done

case "$PZDR_EXPECTED_PCR0" in
  replace-*|provisional)
    fail "PZDR_EXPECTED_PCR0 is still a placeholder"
    ;;
esac

if ! [[ "$PZDR_EXPECTED_PCR0" =~ ^[0-9a-fA-F]{96}$ ]]; then
  fail "PZDR_EXPECTED_PCR0 must be a 96-hex-character Nitro PCR0/ImageSha384 value"
fi

step "Host services"
systemctl is-active --quiet docker || fail "docker is not active"
systemctl is-active --quiet nitro-enclaves-allocator.service || fail "nitro allocator is not active"

step "PZDR files"
[ -s "$PZDR_EIF_PATH" ] || fail "EIF missing or empty: $PZDR_EIF_PATH"
[ -x /usr/local/bin/vsock-parent-proxy ] || fail "missing executable: /usr/local/bin/vsock-parent-proxy"
[ -f /etc/systemd/system/pzdr-enclave.service ] || fail "missing pzdr-enclave.service"
[ -f /etc/systemd/system/vsock-parent-proxy.service ] || fail "missing vsock-parent-proxy.service"
[ -f /etc/systemd/system/pzdr-enclave-watchdog.timer ] || fail "missing pzdr-enclave-watchdog.timer"

step "Nitro allocator"
nitro-cli describe-enclaves >/tmp/pzdr-preflight-enclaves.json 2>/tmp/pzdr-preflight-nitro.err || {
  cat /tmp/pzdr-preflight-nitro.err >&2
  fail "nitro-cli describe-enclaves failed"
}
jq . /tmp/pzdr-preflight-enclaves.json >/dev/null

step "Ports and resources"
if command -v ss >/dev/null 2>&1 && ss -ltn "( sport = :${PROXY_ADDR##*:} )" | grep -q LISTEN; then
  echo "WARNING: proxy port ${PROXY_ADDR##*:} is already listening." >&2
fi

if [ "${PZDR_ENCLAVE_MEMORY_MIB}" -lt 512 ]; then
  fail "PZDR_ENCLAVE_MEMORY_MIB looks too small: $PZDR_ENCLAVE_MEMORY_MIB"
fi

if [ "${PZDR_ENCLAVE_CPU_COUNT}" -lt 1 ]; then
  fail "PZDR_ENCLAVE_CPU_COUNT must be at least 1"
fi

printf '\nPreflight passed. Start services next:\n'
printf '  sudo systemctl enable --now pzdr-enclave.service\n'
printf '  sudo systemctl enable --now vsock-parent-proxy.service\n'
printf '  sudo systemctl enable --now pzdr-enclave-watchdog.timer\n'
