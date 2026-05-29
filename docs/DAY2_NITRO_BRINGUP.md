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
cd eif
PZDR_EXPECTED_PCR0=provisional ./build-eif.sh
```

Copy the signed EIF into place:

```bash
sudo install -m 0644 out/pzdr-enclave-v0.1.0.eif /opt/pzdr/eif/pzdr-enclave-v0.1.0.eif
```

Update `/etc/pzdr/pzdr.env` with the real path, CID, CPU count, and memory.

## Pin PCR0 Before Starting

The canary refuses to send traffic if the running enclave's PCR0 does not match
the value pinned in the environment. Read the measurement that `build-eif.sh`
emitted and set it in `/etc/pzdr/pzdr.env`:

```bash
PCR0=$(jq -r .PCR0 eif/out/pzdr-enclave-v0.1.0.measurements.json)
sudo sed -i "s|^PZDR_EXPECTED_PCR0=.*|PZDR_EXPECTED_PCR0=$PCR0|" /etc/pzdr/pzdr.env
```

## Start Services

```bash
sudo systemctl enable --now pzdr-enclave.service
sudo systemctl enable --now vsock-parent-proxy.service
sudo systemctl enable --now pzdr-enclave-watchdog.timer
sudo systemctl status pzdr-enclave.service vsock-parent-proxy.service
sudo systemctl list-timers pzdr-enclave-watchdog.timer
```

The watchdog timer fires every 15 seconds. If the enclave ever leaves the
`RUNNING` state (crash inside the VM, OOM, etc.) the watchdog will restart
`pzdr-enclave.service`. Without this, a silent enclave death produces 502s at
the parent proxy until a human notices.

## Canary

```bash
scripts/day2_canary.sh http://127.0.0.1:8090
```

Expected result:

- `ok: true`
- `proof_valid: true`
- receipt contains `leaf_hex`, `root_hex`, and `ledger_size`

## Evidence

```bash
scripts/collect_day2_evidence.sh http://127.0.0.1:8090
```

Keep the generated `evidence/day2-*` folder with the release artifact and PCR0
measurement.

## Stop

```bash
sudo systemctl stop vsock-parent-proxy.service
sudo systemctl stop pzdr-enclave.service
```

The stop path terminates only the enclave with the configured `ENCLAVE_CID`.
