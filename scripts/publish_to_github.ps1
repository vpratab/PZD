param(
  [string]$Repo = "assurezero/pzdr",
  [switch]$Public
)

$ErrorActionPreference = "Stop"
$Root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$LocalGh = Join-Path (Split-Path $Root -Parent | Split-Path -Parent) "tools\gh\extract\bin\gh.exe"

if (Get-Command gh -ErrorAction SilentlyContinue) {
  $Gh = "gh"
} elseif (Test-Path -LiteralPath $LocalGh) {
  $Gh = (Resolve-Path -LiteralPath $LocalGh).Path
} else {
  throw "GitHub CLI not found. Install with winget or download a portable gh release."
}

$OldErrorActionPreference = $ErrorActionPreference
$ErrorActionPreference = "Continue"
& $Gh auth status *> $null
$AuthStatus = $LASTEXITCODE
$ErrorActionPreference = $OldErrorActionPreference
if ($AuthStatus -ne 0) {
  Write-Host "GitHub CLI is installed but not authenticated."
  Write-Host "Run this first:"
  Write-Host "  `"$Gh`" auth login"
  exit 2
}

Push-Location $Root
try {
  if (-not (Test-Path -LiteralPath ".git")) {
    git init
    git branch -M main
  }
  git config core.autocrlf false
  git config core.eol lf

  git config user.name *> $null
  if ($LASTEXITCODE -ne 0) {
    git config user.name "Codex"
  }
  git config user.email *> $null
  if ($LASTEXITCODE -ne 0) {
    git config user.email "codex@local"
  }

  git add .
  $hasHead = Test-Path -LiteralPath (Join-Path $Root ".git\refs\heads\main")
  if ($hasHead) {
    $OldErrorActionPreference = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    git commit -m "Prepare PZDR engineering release" *> $null
    $CommitStatus = $LASTEXITCODE
    $ErrorActionPreference = $OldErrorActionPreference
    if ($CommitStatus -ne 0) {
      Write-Host "No git changes to commit."
    }
  } else {
    git commit -m "Initial PZDR Gateway engineering release"
  }

  $visibility = if ($Public) { "--public" } else { "--private" }
  $OldErrorActionPreference = $ErrorActionPreference
  $ErrorActionPreference = "Continue"
  & $Gh repo view $Repo *> $null
  $RepoViewStatus = $LASTEXITCODE
  $ErrorActionPreference = $OldErrorActionPreference
  if ($RepoViewStatus -ne 0) {
    & $Gh repo create $Repo $visibility `
      --description "Provable Zero Data Retention for AI inference with signed deletion proofs and Merkle receipts." `
      --homepage "https://assurezero.com" `
      --source . `
      --remote origin `
      --push
  } else {
    git remote remove origin 2>$null
    git remote add origin "https://github.com/$Repo.git"
    git push -u origin main
  }

  $OldErrorActionPreference = $ErrorActionPreference
  $ErrorActionPreference = "Continue"
  git rev-parse --verify v0.1.0 *> $null
  $TagStatus = $LASTEXITCODE
  $ErrorActionPreference = $OldErrorActionPreference
  if ($TagStatus -ne 0) {
    git tag -a v0.1.0 -m "PZDR Gateway v0.1.0 - initial engineering release"
  }
  git push origin v0.1.0
} finally {
  Pop-Location
}
