#!/bin/bash
# PZDR Gateway EC2 parent partition bootstrap.
#
# This prepares the Nitro host. It does not fetch or run unsigned release
# artifacts; deploy the signed EIF and parent proxy binary after instance boot.
set -euxo pipefail

dnf install -y aws-nitro-enclaves-cli aws-nitro-enclaves-cli-devel docker jq curl
systemctl enable --now docker nitro-enclaves-allocator.service

id -u pzdr >/dev/null 2>&1 || useradd --system --home /var/lib/pzdr --create-home --shell /sbin/nologin pzdr
install -d -m 0755 /opt/pzdr/bin /opt/pzdr/eif /etc/pzdr /var/lib/pzdr/metering
chown -R pzdr:pzdr /var/lib/pzdr

cat >/etc/nitro_enclaves/allocator.yaml <<EOF
---
memory_mib: ${enclave_memory}
cpu_count: ${enclave_cpu}
EOF
systemctl restart nitro-enclaves-allocator.service

cat >/etc/pzdr/pzdr.env <<EOF
PROXY_ADDR=0.0.0.0:8090
ENCLAVE_CID=16
ENCLAVE_PORT=5000
ENCLAVE_TIMEOUT_MS=30000
RUST_LOG=info
PZDR_EIF_PATH=/opt/pzdr/eif/pzdr-enclave-v0.1.6.eif
PZDR_ENCLAVE_MEMORY_MIB=${enclave_memory}
PZDR_ENCLAVE_CPU_COUNT=${enclave_cpu}
PZDR_EXPECTED_PCR0=${measurement}
PZDR_KMS_KEY_ARN=${kms_key_arn}
PZDR_METERING_SPOOL=/var/lib/pzdr/metering/events.jsonl
EOF

cat >/etc/motd <<'EOF'
PZDR Nitro parent host is bootstrapped.

Next:
  1. Copy signed EIF to /opt/pzdr/eif/pzdr-enclave-v0.1.6.eif
  2. Copy vsock-parent-proxy to /usr/local/bin/vsock-parent-proxy
  3. Install systemd units from ops/systemd/
  4. Start pzdr-enclave.service and vsock-parent-proxy.service
EOF
