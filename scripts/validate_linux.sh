#!/usr/bin/env bash
# Full Linux/WSL validation path for the PZDR engineering bundle.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DUMMY_PCR0="000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
export PZDR_EXPECTED_PCR0="${PZDR_EXPECTED_PCR0:-$DUMMY_PCR0}"

step() {
  printf '\n==> %s\n' "$1"
}

need() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "missing required command: $1" >&2
    exit 127
  fi
}

need cargo
need python3

cd "$ROOT"

if command -v rustup >/dev/null 2>&1; then
  rustup component add rustfmt clippy >/dev/null
fi

step "Rust format"
cargo fmt --all -- --check

step "Rust check"
cargo check --workspace

step "Rust clippy"
cargo clippy --workspace --all-targets -- -D warnings

step "Rust tests"
cargo test --workspace

step "Shell scripts"
if command -v shellcheck >/dev/null 2>&1; then
  shellcheck -x \
    eif/build-eif.sh \
    scripts/*.sh \
    scripts/pzdr-terminate-enclave \
    scripts/pzdr-enclave-watchdog \
    aws/terraform/userdata.sh \
    -e SC2154
else
  echo "WARNING: shellcheck not found; skipping shell lint." >&2
fi
bash -n \
  eif/build-eif.sh \
  scripts/*.sh \
  scripts/pzdr-terminate-enclave \
  scripts/pzdr-enclave-watchdog \
  aws/terraform/userdata.sh

step "TypeScript SDK"
if npm --version >/dev/null 2>&1; then
  (
    cd sdk/typescript
    npm ci
    npm run build
    npm test
  )
else
  echo "WARNING: native Linux npm is unavailable; run scripts/validate_release.ps1 on Windows for the TypeScript SDK." >&2
fi

step "Structured docs"
python3 - <<'PY'
import json
import pathlib
import yaml

base = pathlib.Path(".")
for rel in [
    "docs/openapi.yaml",
    "docker-compose.yml",
    ".github/workflows/ci.yml",
    "sdk/typescript/package.json",
    "sdk/typescript/tsconfig.json",
]:
    path = base / rel
    text = path.read_text(encoding="utf-8")
    if path.suffix in {".yaml", ".yml"}:
        yaml.safe_load(text)
    else:
        json.loads(text)
print("structured docs ok")
PY

step "Docker Compose config"
if command -v docker >/dev/null 2>&1; then
  if ! docker compose -f docker-compose.yml config --quiet; then
    echo "WARNING: docker compose config failed; Docker Desktop or WSL integration may be unavailable." >&2
  fi
else
  echo "WARNING: docker not found; skipping compose syntax check." >&2
fi

step "Terraform"
if command -v terraform >/dev/null 2>&1; then
  terraform -chdir=aws/terraform init -backend=false
  terraform -chdir=aws/terraform fmt -check -diff
  terraform -chdir=aws/terraform validate
else
  echo "WARNING: terraform not found; skipping Terraform validation." >&2
fi

printf '\nLinux validation complete.\n'
