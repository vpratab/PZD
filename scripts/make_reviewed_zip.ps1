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

Compress-Archive -LiteralPath $Root -DestinationPath $Out -CompressionLevel Optimal

Add-Type -AssemblyName System.IO.Compression.FileSystem
$archive = [System.IO.Compression.ZipFile]::OpenRead($Out)
try {
  $bad = $archive.Entries | Where-Object { $_.FullName -match '(^|/)(target|node_modules|dist|\.terraform)(/|$)' }
  if ($bad) {
    throw "Generated artifacts leaked into zip: $($bad[0].FullName)"
  }
  Write-Host "Wrote $Out"
  Write-Host "Entries: $($archive.Entries.Count)"
  Write-Host "Bytes: $((Get-Item -LiteralPath $Out).Length)"
} finally {
  $archive.Dispose()
}
