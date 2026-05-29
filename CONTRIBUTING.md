# Contributing to PZDR

Thanks for your interest. This project is operated by AssureZero LLC under
Apache 2.0. We accept contributions under the [DCO](https://developercertificate.org/)
(`git commit -s`).

## Quick start for development

```bash
git clone https://github.com/assurezero/pzdr
cd pzdr
cargo build --release
cargo test
```

## Where to file things

| Kind | Where |
|---|---|
| Bug | GitHub Issues with `bug` template |
| Security vulnerability | security@assurezero.com (don't open a public issue) |
| Feature request | GitHub Discussions or Issues with `enhancement` |
| Question | GitHub Discussions |
| Design proposal | `docs/proposals/` PR |

## What we are explicitly looking for

- Real-hardware Nitro Enclave integration (replacing the mock backend in
  `crates/tee-enclave`)
- Real NVIDIA H100 / Blackwell confidential-computing attestation
  (replacing the dev-scaffold in `crates/gpu-attestation`)
- Additional ledger backends: Azure Confidential Ledger, Amazon Managed
  Blockchain, public-chain anchors
- SDKs in Go, Java, .NET, Ruby
- Compliance framework support beyond the current 5 (e.g., HITRUST, CMMC L3, NIS2)

## What we are not interested in

- ML training / fine-tuning pipelines
- General-purpose confidential computing tooling (use Anjuna / Fortanix)
- Anything that breaks the proof envelope contract without a versioned schema bump

## Code style

- Rust: `cargo fmt`, `cargo clippy --all-targets -- -D warnings` must pass
- Python: `ruff` + `mypy --strict`
- TypeScript: ESM, strict mode, no `any`

## Cryptography changes require an RFC

Any change to the proof envelope schema, channel encryption, commitment
construction, or signature scheme requires a proposal PR with a security review
before code is merged. Do not break audit-chain compatibility silently.

## DCO sign-off

```
git commit -s -m "your message"
```

Adds a `Signed-off-by:` trailer attesting you have the right to contribute
under the Apache 2.0 license.

## Releases

Tag with `v0.x.y`. CI signs the Docker image with cosign and publishes to
`ghcr.io/assurezero/pzdr/gateway`.
