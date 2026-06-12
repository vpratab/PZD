# Day 2 Nitro Bring-Up

This is the next engineering milestone after Marketplace registration is
started.

## Goal

By the end of Day 2, prove that a real EC2 Nitro Enclave can:

1. Boot the PZDR EIF.
2. Serve attestation through the parent proxy.
3. Accept one encrypted SDK request.
4. Return a signed proof and Merkle receipt.
5. Save the first evidence bundle.

## EC2 Requirements

- Nitro Enclaves enabled on the instance.
- Amazon Linux 2023.
- At least 2 spare vCPUs and 2048 MiB memory for the enclave.
- Security group allowing ALB or operator access to parent port `8090`.

If using Terraform, copy `aws/terraform/terraform.tfvars.example` to
`terraform.tfvars` and fill in VPC, subnet, certificate, domain, and PCR0
values before `terraform apply`.

## Host Setup

From the repository root on the EC2 parent instance:

```bash
chmod +x scripts/*.sh scripts/pzdr-terminate-enclave
sudo scripts/day2_nitro_host_setup.sh
```

Then build binaries:

```bash
cargo build --release --bin vsock-parent-proxy
sudo install -m 0755 target/release/vsock-parent-proxy /usr/local/bin/vsock-parent-proxy
```

## Build EIF

```bash
PZDR_VERSION="${PZDR_VERSION:-$(git describe --tags --abbrev=0 2>/dev/null || echo v0.1.6)}"
(cd eif && PZDR_VERSION="$PZDR_VERSION" ./build-eif.sh)
```

Copy the signed EIF into place:

```bash
sudo install -m 0644 "eif/out/pzdr-enclave-${PZDR_VERSION}.eif" \
  "/opt/pzdr/eif/pzdr-enclave-${PZDR_VERSION}.eif"
sudo sed -i \
  "s#^PZDR_EIF_PATH=.*#PZDR_EIF_PATH=/opt/pzdr/eif/pzdr-enclave-${PZDR_VERSION}.eif#" \
  /etc/pzdr/pzdr.env
```

Update `/etc/pzdr/pzdr.env` with the real path, CID, CPU count, and memory.
Also pin the PCR0 expected by the canary:

```bash
PCR0=$(jq -r .PCR0 "eif/out/pzdr-enclave-${PZDR_VERSION}.measurements.json")
sudo sed -i "s/^PZDR_EXPECTED_PCR0=.*/PZDR_EXPECTED_PCR0=$PCR0/" /etc/pzdr/pzdr.env
```

## Preflight

Run the host readiness check before starting services:

```bash
sudo scripts/day2_preflight.sh
```

This verifies Nitro CLI availability, allocator state, EIF placement, PCR0
pinning, systemd unit installation, and parent proxy binary placement.

## Start Services

```bash
sudo systemctl enable --now pzdr-enclave.service
sudo systemctl enable --now vsock-parent-proxy.service
sudo systemctl enable --now pzdr-enclave-watchdog.timer
sudo systemctl status pzdr-enclave.service vsock-parent-proxy.service
```

## Canary

```bash
scripts/day2_canary.sh http://127.0.0.1:8090
```

Expected result:

- `ok: true`
- `proof_valid: true`
- `measurement` matches `PZDR_EXPECTED_PCR0`
- receipt contains `leaf_hash_hex`, an RFC 6962 `audit_path`, and a signed `checkpoint`
- the SDK reports both `proof_valid: true` and `receipt_valid: true`

## Evidence

```bash
scripts/collect_day2_evidence.sh http://127.0.0.1:8090
```

Keep the generated `evidence/day2-*` folder with the release artifact and PCR0
measurement.

## Stop

```bash
sudo systemctl stop vsock-parent-proxy.service
sudo systemctl stop pzdr-enclave-watchdog.timer
sudo systemctl stop pzdr-enclave.service
```

The stop path terminates only the enclave with the configured `ENCLAVE_CID`.
