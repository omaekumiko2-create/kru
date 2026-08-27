$ErrorActionPreference = "Stop"

$projectRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))
$version = (Get-Content (Join-Path $projectRoot "package.json") -Raw | ConvertFrom-Json).version
$packageName = "KRU_${version}_windows-x64"
$releaseExe = if ($env:KRU_RELEASE_EXE) {
  [System.IO.Path]::GetFullPath($env:KRU_RELEASE_EXE)
} else {
  Join-Path $projectRoot "src-tauri\target\release\kru.exe"
}
$distRoot = Join-Path $projectRoot "dist"
$stageRoot = Join-Path $distRoot ".portable-stage"
$packageRoot = Join-Path $stageRoot $packageName
$archivePath = Join-Path $distRoot "${packageName}-portable.zip"
$checksumPath = "${archivePath}.sha256"

function Get-Sha256([string]$Path) {
  $stream = [System.IO.File]::OpenRead($Path)
  try {
    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    try {
      return ([System.BitConverter]::ToString($sha256.ComputeHash($stream))).Replace("-", "").ToLowerInvariant()
    } finally {
      $sha256.Dispose()
    }
  } finally {
    $stream.Dispose()
  }
}

if (-not (Test-Path -LiteralPath $releaseExe -PathType Leaf)) {
  throw "Release executable is missing. Run npm run build first."
}

$resolvedDistRoot = [System.IO.Path]::GetFullPath($distRoot)
$resolvedStageRoot = [System.IO.Path]::GetFullPath($stageRoot)
if (-not $resolvedStageRoot.StartsWith($resolvedDistRoot + [System.IO.Path]::DirectorySeparatorChar)) {
  throw "Portable staging path escaped the dist directory."
}

if (Test-Path -LiteralPath $stageRoot) {
  Remove-Item -LiteralPath $stageRoot -Recurse -Force
}
New-Item -ItemType Directory -Path $packageRoot -Force | Out-Null
Copy-Item -LiteralPath $releaseExe -Destination (Join-Path $packageRoot "kru.exe")
Copy-Item -LiteralPath (Join-Path $projectRoot "README.md") -Destination $packageRoot
Copy-Item -LiteralPath (Join-Path $projectRoot "LICENSE") -Destination $packageRoot
Copy-Item -LiteralPath (Join-Path $projectRoot "browser-extension") -Destination $packageRoot -Recurse

$checksums = Get-ChildItem -LiteralPath $packageRoot -Recurse -File |
  Sort-Object FullName |
  ForEach-Object {
    $relative = $_.FullName.Substring($packageRoot.Length + 1).Replace("\", "/")
    "$(Get-Sha256 $_.FullName)  $relative"
  }
Set-Content -LiteralPath (Join-Path $packageRoot "SHA256SUMS.txt") -Encoding ascii -Value $checksums

if (Test-Path -LiteralPath $archivePath) {
  Remove-Item -LiteralPath $archivePath -Force
}
Compress-Archive -LiteralPath $packageRoot -DestinationPath $archivePath -CompressionLevel Optimal
$archiveHash = Get-Sha256 $archivePath
Set-Content -LiteralPath $checksumPath -Encoding ascii -Value "$archiveHash  $([System.IO.Path]::GetFileName($archivePath))"
Remove-Item -LiteralPath $stageRoot -Recurse -Force

Get-Item -LiteralPath $archivePath, $checksumPath |
  Select-Object FullName, Length
