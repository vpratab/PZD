#!/usr/bin/env bash
# Initialize and push the PZDR ship folder to GitHub.
#
# Usage:
#   ./push_to_github.sh
#   ./push_to_github.sh vpratab/PZD
#   ./push_to_github.sh vpratab/PZD --private
#   ./push_to_github.sh --private

set -euo pipefail

REPO="vpratab/PZD"
VIS="--public"
ROOT="$(cd "$(dirname "$0")" && pwd)"

for arg in "$@"; do
  case "$arg" in
    --public|--private)
      VIS="$arg"
      ;;
    *)
      REPO="$arg"
      ;;
  esac
done

if ! command -v gh >/dev/null; then
  echo "ERROR: GitHub CLI is not installed."
  echo "Install it, then run: gh auth login"
  exit 1
fi

if ! gh auth status >/dev/null 2>&1; then
  echo "Logging into GitHub..."
  gh auth login
fi

cd "$ROOT"

if [ ! -d .git ]; then
  git init
  git branch -M main
fi

touch .gitignore
for pattern in \
  "target/" \
  "node_modules/" \
  "data/" \
  ".DS_Store" \
  "*.log" \
  "*.eif" \
  "*.eif.sig" \
  ".env" \
  ".env.local" \
  "__pycache__/" \
  "*.pyc" \
  "dist/" \
  "build/"
do
  grep -qxF "$pattern" .gitignore || echo "$pattern" >> .gitignore
done

git add .

if ! git rev-parse --verify HEAD >/dev/null 2>&1; then
  git commit -m "Initial PZDR Gateway engineering release

- AWS Nitro Enclave attestation parser
- Parent-partition HTTP to vsock proxy
- Enclave-side binary with encrypted channel and signed deletion proofs
- EIF build scripts
- Starter AWS Terraform
- TypeScript SDK
- OpenAPI and Marketplace registration docs"
else
  git commit -m "Update PZDR ship artifacts" || echo "(nothing to commit)"
fi

if ! gh repo view "$REPO" >/dev/null 2>&1; then
  echo "Creating repository $REPO ..."
  gh repo create "$REPO" "$VIS" \
    --description "Provable Zero Data Retention for AI inference with signed deletion proofs and Merkle receipts." \
    --homepage "https://assurezero.com" \
    --source . \
    --push
else
  echo "Repository $REPO already exists; pushing to it."
  git remote remove origin 2>/dev/null || true
  git remote add origin "https://github.com/$REPO.git"
  git push -u origin main
fi

if git rev-parse --verify v0.1.6 >/dev/null 2>&1; then
  echo "Tag v0.1.6 already exists; leaving it unchanged."
else
  git tag -a v0.1.6 -m "PZDR Gateway v0.1.6 - verifiable transparency release"
  git push origin v0.1.6
fi

cat <<EOF

Pushed to: https://github.com/$REPO
Release:  https://github.com/$REPO/releases/tag/v0.1.6

Next steps:
  - Add repo topics: confidential-computing, attestation, aws-nitro, ai-inference
  - Enable branch protection before accepting external contributions
  - Publish the AWS Marketplace link only after the listing is live
EOF
