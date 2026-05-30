#!/usr/bin/env bash
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
  echo "Run as root: sudo $0"
  exit 1
fi

ROOT="$(cd "$(dirname "$0")/.." && pwd)"

if ! command -v dnf >/dev/null; then
  echo "This setup script expects Amazon Linux 2023 or another dnf-based Nitro host."
  exit 1
fi

dnf install -y aws-nitro-enclaves-cli aws-nitro-enclaves-cli-devel docker jq curl git rust cargo nodejs npm
systemctl enable --now docker nitro-enclaves-allocator.service

id -u pzdr >/dev/null 2>&1 || useradd --system --home /var/lib/pzdr --create-home --shell /sbin/nologin pzdr

install -d -m 0755 /opt/pzdr/bin /opt/pzdr/eif /etc/pzdr /var/lib/pzdr/metering
install -m 0644 "$ROOT/ops/pzdr.env.example" /etc/pzdr/pzdr.env
install -m 0644 "$ROOT/ops/systemd/pzdr-enclave.service" /etc/systemd/system/pzdr-enclave.service
install -m 0644 "$ROOT/ops/systemd/pzdr-enclave-watchdog.service" /etc/systemd/system/pzdr-enclave-watchdog.service
install -m 0644 "$ROOT/ops/systemd/pzdr-enclave-watchdog.timer" /etc/systemd/system/pzdr-enclave-watchdog.timer
install -m 0644 "$ROOT/ops/systemd/vsock-parent-proxy.service" /etc/systemd/system/vsock-parent-proxy.service
install -m 0755 "$ROOT/scripts/pzdr-terminate-enclave" /usr/local/bin/pzdr-terminate-enclave
install -m 0755 "$ROOT/scripts/pzdr-enclave-watchdog" /usr/local/bin/pzdr-enclave-watchdog
chown -R pzdr:pzdr /var/lib/pzdr

if [ -f /etc/nitro_enclaves/allocator.yaml ]; then
  cp /etc/nitro_enclaves/allocator.yaml "/etc/nitro_enclaves/allocator.yaml.bak.$(date +%Y%m%d%H%M%S)"
fi

cat >/etc/nitro_enclaves/allocator.yaml <<'YAML'
---
memory_mib: 2048
cpu_count: 2
YAML

systemctl restart nitro-enclaves-allocator.service
for _ in {1..30}; do
  systemctl is-active --quiet nitro-enclaves-allocator.service && break
  sleep 1
done
systemctl is-active --quiet nitro-enclaves-allocator.service || {
  echo "nitro-enclaves-allocator.service failed to become active" >&2
  exit 1
}
systemctl daemon-reload

cat <<'EOF'
PZDR Nitro host setup complete.

Next:
  1. Copy the signed EIF to the PZDR_EIF_PATH configured in /etc/pzdr/pzdr.env
  2. Copy vsock-parent-proxy to /usr/local/bin/vsock-parent-proxy
  3. Review /etc/pzdr/pzdr.env
  4. systemctl enable --now pzdr-enclave.service
  5. systemctl enable --now vsock-parent-proxy.service
  6. systemctl enable --now pzdr-enclave-watchdog.timer
EOF
