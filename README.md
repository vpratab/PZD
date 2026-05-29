# PZDR Gateway

Provable Zero Data Retention Gateway for AI inference.

This repository contains a v0.1 Nitro Enclave shipping bundle for a gateway
that encrypts client payloads to an attested enclave channel, processes an
inference request inside the enclave boundary, signs a deletion proof, and
returns a Merkle receipt.

## What Is In This Bundle

- `crates/nitro-attestation`: AWS Nitro attestation parsing and enclave NSM
  attestation generation support.
- `crates/vsock-parent-proxy`: parent-partition HTTP to vsock proxy.
- `services/pzdr-enclave`: enclave-side request handler, channel decryption,
  policy gate, mock upstream response, proof signing, and Merkle append.
- `sdk/typescript`: TypeScript client for attestation, encryption, inference,
  and offline proof verification.
- `crates/marketplace-metering`: helpers for AWS Marketplace usage events and
  `BatchMeterUsage` payload generation.
- `eif`: Nitro Enclave image build scripts.
- `ops` and `scripts`: Day 2 host setup, systemd units, canary, and evidence
  collection helpers.
- `aws/terraform`: starter infrastructure for AWS deployment.
- `docs`: quickstart, OpenAPI, architecture, security notes, and runbook.

## Current Status

This is an engineering release candidate, not a compliance-certified product.

Working locally:

- Rust compile checks for the Nitro attestation crate.
- Linux-target compile checks for the parent vsock proxy.
- Linux-target compile checks for the enclave binary.
- TypeScript SDK build.
- Docker Compose syntax validation.
- Terraform format and validation for the starter AWS stack.

Still required before public production launch:

- Real Nitro EC2 bring-up and EIF measurement capture.
- KMS decrypt bound to Nitro attestation conditions.
- Bedrock or other model-provider integration.
- Persistent and externally anchored ledger storage.
- AWS Marketplace onboarding, entitlement checks, and live `BatchMeterUsage`
  submission.
- Legal review for EULA, DPA, privacy policy, and regulated-industry claims.

## Quick Start

See `docs/QUICKSTART.md`.

For the real Nitro bring-up sequence, see `docs/DAY2_NITRO_BRINGUP.md`.
Run `scripts/day2_preflight.sh` on the EC2 parent partition before starting
the systemd services.

## Validate

On Windows from the repository root:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\validate_release.ps1
```

On Linux or WSL:

```bash
scripts/validate_linux.sh
```

To prepare a local release commit and zip:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\prepare_release.ps1
```

To publish after GitHub authentication:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\publish_to_github.ps1 -Repo assurezero/pzdr
```

## API

The v0.1 Nitro gateway exposes:

- `GET /health`
- `GET /v1/attestation`
- `POST /v1/gateway/inference`
- `GET /v1/ledger/root`
- `GET /v1/ledger/proof/{idx}`

See `docs/openapi.yaml` for request and response schemas.

## Security

See `docs/SECURITY.md`. This repository does not by itself create HIPAA,
FedRAMP, SOC 2, ISO 27001, GDPR, or attorney-client privilege compliance.
Those require deployment evidence, contracts, controls, audits, and counsel.

## Marketplace

Start with `AWS_MARKETPLACE_REGISTRATION.md`, then use
`docs/MARKETPLACE_METERING.md` for the metering implementation plan.

## License

Apache-2.0.
