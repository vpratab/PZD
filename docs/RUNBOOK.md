# PZDR Gateway Operational Runbook

## Daily Checks

- Confirm parent proxy health: `curl http://127.0.0.1:8090/health`.
- Confirm enclave is running: `sudo nitro-cli describe-enclaves`.
- Fetch attestation and compare `measurement` to the expected PCR0.
- Send a canary inference and verify the returned proof offline.
- Confirm ledger size increases after canary traffic.

## Deploy

1. Build the enclave image with `eif/build-eif.sh`.
2. Record the emitted measurement in the release notes and KMS policy.
3. Launch the EIF with fixed memory, CPU count, and enclave CID.
4. Start `vsock-parent-proxy` with matching `ENCLAVE_CID` and `ENCLAVE_PORT`.
5. Run the canary proof verification before routing customer traffic.

See `docs/DAY2_NITRO_BRINGUP.md` for the first bring-up sequence.

## Systemd Services

- `ops/systemd/pzdr-enclave.service` launches the EIF through `nitro-cli`.
- `ops/systemd/pzdr-enclave-watchdog.timer` checks every 15 seconds that the
  enclave with the configured CID is still `RUNNING` and restarts it if not.
- `ops/systemd/vsock-parent-proxy.service` runs the parent HTTP to vsock proxy.
  The proxy sends `sd_notify` readiness and watchdog heartbeats to systemd.
- `/etc/pzdr/pzdr.env` stores CID, port, EIF path, memory, CPU count, and
  Marketplace product code.

## Metering

- Queue Marketplace events outside the enclave after a billable success proof.
- Build `BatchMeterUsage` payloads with `crates/marketplace-metering`.
- Keep AWS metering responses with the proof id and receipt root.

## Incident Response

- If attestation measurement changes unexpectedly, stop routing traffic and
  compare the deployed EIF against the signed release artifact.
- If proof signing fails, treat all affected requests as failed and preserve
  parent logs, enclave boot logs, and deployment artifacts.
- If ledger append fails, stop accepting writes until the ledger state is
  recovered or a new ledger is explicitly started with customer notification.
- If Marketplace metering fails, queue usage records and retry within AWS
  Marketplace metering time limits.

## Backup And Evidence

- Store signed EIF artifacts, measurements, and release hashes.
- Store proof receipts and externally anchored ledger roots.
- Store Marketplace metering delivery logs and CloudTrail events.
- Store customer support tickets and incident timelines.
