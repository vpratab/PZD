param(
  [string]$TerraformPath = ""
)

$ErrorActionPreference = "Stop"
$Root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path

function Step($Name) {
  Write-Host ""
  Write-Host "==> $Name"
}

function Run($Exe, [string[]]$CmdArgs) {
  & $Exe @CmdArgs
  if ($LASTEXITCODE -ne 0) {
    throw "Command failed ($LASTEXITCODE): $Exe $($CmdArgs -join ' ')"
  }
}

if (-not $TerraformPath) {
  $Candidate = Join-Path $Root "..\..\tools\terraform\terraform.exe"
  if (Test-Path -LiteralPath $Candidate) {
    $TerraformPath = (Resolve-Path -LiteralPath $Candidate).Path
  } elseif (Get-Command terraform -ErrorAction SilentlyContinue) {
    $TerraformPath = "terraform"
  }
}

$env:PZDR_EXPECTED_PCR0 = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"

Step "Rust format"
Push-Location $Root
Run "cargo" @("fmt", "--all", "--", "--check")

Step "Rust check"
Run "cargo" @("check", "--workspace", "--target", "x86_64-unknown-linux-gnu")

Step "Rust clippy"
Run "cargo" @("clippy", "--workspace", "--target", "x86_64-unknown-linux-gnu", "--all-targets", "--", "-D", "warnings")

Step "Marketplace metering tests"
Run "cargo" @("test", "-p", "marketplace-metering")
Pop-Location

Step "TypeScript SDK"
Push-Location (Join-Path $Root "sdk\typescript")
Run "npm" @("ci")
Run "npm" @("run", "build")
Run "npm" @("test")
Pop-Location

Step "Cross-language provability"
Push-Location $Root
Run "python" @("tools\pzdr_gen_vectors.py")
Run "python" @("tools\pzdr_verify.py", "self-test")
Run "python" @("tools\pzdr_verify.py", "verify-bundle", "tools\conformance\bundle.json")
Run "node" @("sdk\typescript\transparency.conformance.mjs")
$VerifierKey = (Get-Content -LiteralPath (Join-Path $Root "tools\conformance\enclave_key.hex") -Raw).Trim()
& python -S tools\pzdr_verify.py verify-proof tools\conformance\proof_success.json --key $VerifierKey
if ($LASTEXITCODE -eq 0) {
  throw "Verifier failed open without its Ed25519 dependency"
}
Write-Host "Missing Ed25519 dependency fails closed."
Pop-Location

Step "Docker Compose config"
Run "docker" @("compose", "-f", (Join-Path $Root "docker-compose.yml"), "config", "--quiet")

Step "Structured docs"
@"
import json, pathlib, yaml
base = pathlib.Path(r"$Root")
for rel in ["docs/openapi.yaml", "docker-compose.yml", ".github/workflows/ci.yml"]:
    yaml.safe_load((base / rel).read_text(encoding="utf-8"))
json.loads((base / "sdk/typescript/package.json").read_text(encoding="utf-8"))
print("structured docs ok")
"@ | python -

if ($TerraformPath) {
  Step "Terraform"
  $tfDir = Join-Path $Root "aws\terraform"
  Run $TerraformPath @("-chdir=$tfDir", "init", "-backend=false")
  Run $TerraformPath @("-chdir=$tfDir", "fmt", "-check", "-diff")
  Run $TerraformPath @("-chdir=$tfDir", "validate")
} else {
  Write-Warning "Terraform not found; skipping Terraform validation."
}

Write-Host ""
Write-Host "Release validation complete."
