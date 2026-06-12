param(
  [string]$Out = ""
)

$ErrorActionPreference = "Stop"
$Root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$DefaultOut = Join-Path (Split-Path $Root -Parent | Split-Path -Parent) "pzdr-ship-bundle-v2-reviewed.zip"
if (-not $Out) {
  $Out = $DefaultOut
}

$generated = @(
  "target",
  "sdk\typescript\node_modules",
  "sdk\typescript\dist",
  "aws\terraform\.terraform"
)

foreach ($rel in $generated) {
  $path = Join-Path $Root $rel
  if (Test-Path -LiteralPath $path) {
    $resolved = (Resolve-Path -LiteralPath $path).Path
    if (-not $resolved.StartsWith($Root, [StringComparison]::OrdinalIgnoreCase)) {
      throw "Refusing to remove outside bundle: $resolved"
    }
    [System.IO.Directory]::Delete("\\?\" + $resolved, $true)
  }
}

if (Test-Path -LiteralPath $Out) {
  Remove-Item -LiteralPath $Out -Force
}

Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem
$archive = [System.IO.Compression.ZipFile]::Open($Out, [System.IO.Compression.ZipArchiveMode]::Create)
try {
  $top = Split-Path -Leaf $Root
  $skipPrefixes = @(
    "target\",
    "sdk\typescript\node_modules\",
    "sdk\typescript\dist\",
    "aws\terraform\.terraform\",
    "tools\__pycache__\",
    ".git\"
  )

  $files = Get-ChildItem -LiteralPath $Root -Recurse -File -Force | Where-Object {
    $full = $_.FullName
    $rel = $full.Substring($Root.Length + 1)
    $skip = $false
    foreach ($prefix in $skipPrefixes) {
      if ($rel.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) {
        $skip = $true
        break
      }
    }
    if ($rel -match '(^|\\)__pycache__(\\|$)' -or $rel -match '\.pyc$') {
      $skip = $true
    }
    -not $skip
  }

  foreach ($file in $files) {
    $rel = $file.FullName.Substring($Root.Length + 1).Replace("\", "/")
    $entryName = "$top/$rel"
    [System.IO.Compression.ZipFileExtensions]::CreateEntryFromFile(
      $archive,
      $file.FullName,
      $entryName,
      [System.IO.Compression.CompressionLevel]::Optimal
    ) | Out-Null
  }
} finally {
  $archive.Dispose()
}

$archive = [System.IO.Compression.ZipFile]::OpenRead($Out)
try {
    $bad = $archive.Entries | Where-Object {
      $_.FullName -match '(^|/)(target|node_modules|dist|\.terraform|\.git|__pycache__)(/|$)' -or
      $_.FullName -match '\.pyc$'
    }
  if ($bad) {
    throw "Generated artifacts leaked into zip: $($bad[0].FullName)"
  }
  Write-Host "Wrote $Out"
  Write-Host "Entries: $($archive.Entries.Count)"
  Write-Host "Bytes: $((Get-Item -LiteralPath $Out).Length)"
} finally {
  $archive.Dispose()
}
