# Patch v2-reviewed-035a0523-patched

Applied on top of `pzdr-ship-bundle-v2-reviewed-035a0523.zip`. Six fixes
addressing the gaps identified after the Codex Day 2 ops pass.

## What changed

### 1. `scripts/day2_canary.sh` — PCR0 pin
The canary now reads `PZDR_EXPECTED_PCR0` from the environment and refuses to
send a request if the running enclave's measurement does not match. Without
this pin, a canary could pass against the wrong enclave.

Exit codes:
- `0` success
- `1` proof verification failed
- `2` `PZDR_EXPECTED_PCR0` unset
- `3` PCR0 mismatch (most important — never push past this)

### 2. `scripts/collect_day2_evidence.sh` — full evidence bundle
Now captures the artifacts AWS FTR / Vendor Insights actually want:
- `attestation.json`, `measurement.txt`, `proof_verifier_key.hex`
- `ledger_root.json` (size + root at capture time)
- `canary_output.json` (full signed proof + receipt from the canary)
- `*.measurements.json` and `*.eif.sig` from the EIF build
- `describe-enclaves.json`, `processes.txt`
- `MANIFEST.txt` (sha256 of every file — tamper detection)
- `README.md` describing what each file proves

### 3. `scripts/day2_nitro_host_setup.sh` — allocator race fix
Waits for `nitro-enclaves-allocator.service` to actually become active before
returning. The allocator stays in `activating` for 5–15s on a fresh host while
it reserves hugepages; skipping the wait causes silent EIF launch failures.

Also now installs the new watchdog units and references the watchdog timer in
the closing instructions.

### 4. `ops/systemd/pzdr-enclave-watchdog.service` + `.timer` (new)
Catches the case where `nitro-cli run-enclave` returned success but the enclave
subsequently died inside the VM. The original `pzdr-enclave.service` uses
`Type=oneshot, RemainAfterExit=yes` which masks this — systemd thinks the unit
is still active even after the enclave is gone.

Fires every 15 seconds, queries `nitro-cli describe-enclaves` for the pinned
CID, and restarts `pzdr-enclave.service` if the state is anything other than
`RUNNING`.

Enable with:
```bash
sudo systemctl enable --now pzdr-enclave-watchdog.timer
```

### 5. `crates/marketplace-metering` — cross-field idempotency test
The existing test only confirmed that two events with the same `request_id`
collide. Added `idempotency_key_changes_when_any_field_changes` which proves
that changing `tenant`, `product_code`, `customer_aws_account_id`, or
`proof_id` produces a distinct key. Prevents future refactors from quietly
collapsing inputs and triggering `DuplicateRecordException` from AWS.

### 6. `ops/pzdr.env.example` — `PZDR_EXPECTED_PCR0` placeholder
Added a commented placeholder so operators know to fill it in after every EIF
build. The canary will refuse to run without it (correct behavior).

## Documentation updates
- `docs/DAY2_NITRO_BRINGUP.md` — adds a "Pin PCR0 Before Starting" section and
  the `systemctl enable --now pzdr-enclave-watchdog.timer` step.
- `docs/RUNBOOK.md` — adds watchdog and PCR0 drift to the daily checks list.

## Validation
Static structural checks pass (braces/parens balanced, 4 unit tests in the
metering crate). Run on a Linux host before tagging:

```bash
cargo fmt --all -- --check
cargo check --workspace --target x86_64-unknown-linux-gnu
cargo clippy --workspace --target x86_64-unknown-linux-gnu --all-targets -- -D warnings
cargo test -p marketplace-metering
```

## What's still TODO before EC2 bring-up
- Real `cargo test --workspace` on the GitHub Actions Ubuntu runner.
- `WatchdogSec=30` + `sd-notify` integration in `vsock-parent-proxy` (nice-to-have).
- Set `PZDR_EXPECTED_PCR0` in `/etc/pzdr/pzdr.env` after the first build-eif.sh run.
