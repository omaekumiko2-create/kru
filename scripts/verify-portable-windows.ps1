param([Parameter(Mandatory = $true)][string]$Archive)

$ErrorActionPreference = "Stop"

$projectRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))
$archivePath = [System.IO.Path]::GetFullPath($Archive)
$work = Join-Path ([System.IO.Path]::GetTempPath()) ("kru-portable-verify-" + [guid]::NewGuid().ToString("N"))

try {
  Expand-Archive -LiteralPath $archivePath -DestinationPath $work
  $roots = @(Get-ChildItem -LiteralPath $work -Directory)
  if ($roots.Count -ne 1) { throw "Archive must contain exactly one top-level directory." }
  $root = $roots[0].FullName
  @("README.md", "LICENSE", "browser-extension\manifest.json", "SHA256SUMS.txt", "kru.exe") | ForEach-Object {
    if (-not (Test-Path -LiteralPath (Join-Path $root $_) -PathType Leaf)) { throw "Missing package file: $_" }
  }

  Get-Content -LiteralPath (Join-Path $root "SHA256SUMS.txt") | ForEach-Object {
    if ($_ -notmatch '^([0-9a-fA-F]{64})  (.+)$') { throw "Invalid internal checksum line: $_" }
    $file = Join-Path $root ($Matches[2] -replace '/', '\')
    if (-not (Test-Path -LiteralPath $file -PathType Leaf)) { throw "Missing checksummed file: $($Matches[2])" }
    $actual = (Get-FileHash -Algorithm SHA256 -LiteralPath $file).Hash
    if ($actual -ne $Matches[1]) { throw "Internal checksum mismatch: $($Matches[2])" }
  }

  node (Join-Path $projectRoot "scripts\smoke-cli.mjs") (Join-Path $root "kru.exe")
  if ($LASTEXITCODE -ne 0) { throw "Packaged KRU CLI/MCP smoke failed." }
} finally {
  if (Test-Path -LiteralPath $work) { Remove-Item -LiteralPath $work -Recurse -Force }
}
