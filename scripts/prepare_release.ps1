param(
  [string]$Repo = "vpratab/PZD",
  [switch]$SkipValidation
)

$ErrorActionPreference = "Stop"
$Root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path

if (-not $SkipValidation) {
  powershell -ExecutionPolicy Bypass -File (Join-Path $Root "scripts\validate_release.ps1")
}

powershell -ExecutionPolicy Bypass -File (Join-Path $Root "scripts\make_reviewed_zip.ps1")

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

  $LocalGh = Join-Path (Split-Path $Root -Parent | Split-Path -Parent) "tools\gh\extract\bin\gh.exe"
  if (Get-Command gh -ErrorAction SilentlyContinue) {
    Write-Host ""
    Write-Host "GitHub CLI is installed. To publish:"
    Write-Host "  gh auth login"
    Write-Host "  powershell -ExecutionPolicy Bypass -File .\scripts\publish_to_github.ps1 -Repo $Repo"
  } elseif (Test-Path -LiteralPath $LocalGh) {
    Write-Host ""
    Write-Host "Portable GitHub CLI is installed. To publish:"
    Write-Host "  `"$LocalGh`" auth login"
    Write-Host "  powershell -ExecutionPolicy Bypass -File .\scripts\publish_to_github.ps1 -Repo $Repo"
  } else {
    Write-Host ""
    Write-Host "GitHub CLI is not installed. To publish later:"
    Write-Host "  winget install --id GitHub.cli -e"
    Write-Host "  gh auth login"
    Write-Host "  powershell -ExecutionPolicy Bypass -File .\scripts\publish_to_github.ps1 -Repo $Repo"
  }
} finally {
  Pop-Location
}
