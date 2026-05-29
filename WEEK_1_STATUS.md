# PZDR Week 1 Status

Date: 2026-05-29

## Done Today

- Recovered `pzdr-ship-bundle-v2.zip` from the Claude local session output.
- Added a root Cargo workspace for the v2 ship bundle.
- Fixed the Nitro attestation crate so it compiles.
- Fixed the parent proxy so `/v1/attestation`, `/v1/gateway/inference`, and
  `/v1/ledger/root` forward to the correct enclave paths.
- Fixed the enclave binary compile blockers.
- Changed proof signatures to actually use base64 in `signature_b64`.
- Rebuilt the TypeScript SDK to match the v2 Nitro gateway wire format.
- Added missing docs needed for Marketplace/Vendor Insights prep:
  `docs/ARCHITECTURE.md`, `docs/SECURITY.md`, and `docs/RUNBOOK.md`.
- Rewrote the README and Marketplace listing draft to avoid premature
  compliance claims.
- Rewrote the AWS Marketplace registration checklist with safer, current
  guidance.
- Replaced CI with checks that match this v2 bundle.
- Made `push_to_github.sh` safer.
- Added Marketplace metering payload helpers and docs.
- Added Day 2 Nitro host setup, systemd, canary, and evidence scripts.
- Downloaded a local Terraform binary and validated the starter AWS stack.
- Added PCR0 pinning to the Day 2 canary and expanded evidence capture.
- Added an enclave watchdog timer and systemd watchdog heartbeats for the
  parent proxy.
- Fixed the EIF build script so `sudo nitro-cli build-enclave` output is
  captured through `sudo tee`.
- Renamed the deletion proof channel key field to `channel_public_key_hex` so
  the proof schema matches the actual encoding.
- Added `scripts/validate_linux.sh` for native Linux/WSL validation.
- Added `scripts/day2_preflight.sh` for EC2 parent-host readiness checks.
- Added `scripts/prepare_release.ps1` and `scripts/publish_to_github.ps1`.
- Installed portable GitHub CLI `2.93.0` under the workspace tools directory.
- Initialized a local Git repository and committed the engineering release.
- Rebuilt the final reviewed zip with `.git` and generated artifacts excluded.

## Verification Completed

- `cargo fmt --all -- --check`
- `cargo check --workspace --target x86_64-unknown-linux-gnu`
- `cargo clippy --workspace --target x86_64-unknown-linux-gnu --all-targets -- -D warnings`
- `npm install`
- `npm run build`
- `npm test`
- `docker compose config --quiet`
- `terraform init -backend=false`
- `terraform fmt -check -diff`
- `terraform validate`
- `powershell -ExecutionPolicy Bypass -File .\scripts\validate_release.ps1`
- `scripts/validate_linux.sh` under WSL with Rust `1.96.0`
- `cargo test --workspace` under WSL with a dummy PCR0
- `shellcheck -x` on the shell scripts and Terraform userdata
- OpenAPI, Docker Compose, GitHub Actions, and package JSON parse checks

The local WSL validation warns that native Linux Node, Terraform, and Docker
integration are not installed in WSL. The Windows release validator covers the
TypeScript SDK, Terraform, and Docker Compose config paths successfully.

## Current Technical Status

This bundle is now a cleaner engineering release candidate for Week 1 Nitro
bring-up. It is not yet a production compliance product.

Works at compile/check level:

- Nitro attestation crate
- Parent HTTP to vsock proxy
- Enclave-side proof pipeline
- TypeScript SDK
- CI definition
- Marketplace metering payload generation
- Day 2 host setup scripts
- EC2 Day 2 preflight script
- Local release commit and zip packaging

Still needs real environment validation:

- Launch a real Nitro-enabled EC2 instance.
- Build and run the EIF with `nitro-cli`.
- Capture the real PCR0 measurement.
- Verify `/v1/attestation` from the running enclave.
- Send one SDK-encrypted inference through the parent proxy to the enclave.
- Verify the returned proof offline.

## Human-Only AWS Marketplace Work

Codex cannot do these because they require account, legal, tax, or banking
authority:

- Submit seller registration.
- Complete W-9/tax interview.
- Enter LLC bank payout details.
- Accept seller agreements.
- Create the SaaS product in the portal.
- Submit final listing/EULA.

Use `AWS_MARKETPLACE_REGISTRATION.md` for the portal pass.

## Day 2 Engineering Checklist

1. Launch Nitro-enabled EC2 with enclaves enabled.
2. Install Nitro Enclaves CLI and Docker.
3. Configure enclave allocator for 2 vCPUs and 2048 MiB.
4. Build the EIF with `eif/build-eif.sh`.
5. Launch the enclave with CID 16 and port 5000.
6. Run `vsock-parent-proxy` on the parent partition.
7. Fetch `/v1/attestation`.
8. Run the TypeScript SDK canary request.
9. Save the proof, receipt, and measurement as the first release evidence.
10. Run `scripts/day2_preflight.sh` before enabling the services.

See `docs/DAY2_NITRO_BRINGUP.md` for the exact command sequence.

## Revenue Reality

Marketplace registration is worth starting now because review cycles take time,
but revenue is not automatic. The realistic first commercial milestone is one
paid pilot or design partner after the Nitro demo works and the claims are
tight enough for a security buyer to trust.
