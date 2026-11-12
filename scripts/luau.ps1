# Fetches the pinned Luau release and drops luau-compile.exe in vendor/luau.
#
# The compiler is part of the trust boundary: the client's VM only accepts the
# bytecode version it was built with, so this script pins both the release tag
# and the archive hash, verifies both, and refuses to install anything else.
# See vendor/luau/README.md for the current pin and how to move it.
param(
    [string]$Tag = "0.746",
    [string]$Sha256 = "E149FDB4FE78A52CE457FBD40741484EAAB1DBF9907E7F878C6D8A9A3DAC2DDD",
    [switch]$Force
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$dest = Join-Path $root "vendor\luau"
$exe = Join-Path $dest "luau-compile.exe"

if ((Test-Path $exe) -and -not $Force) {
    Write-Host "vendor/luau/luau-compile.exe already present; -Force to replace"
    exit 0
}

$url = "https://github.com/luau-lang/luau/releases/download/$Tag/luau-windows.zip"
$zip = Join-Path $env:TEMP "luau-windows-$Tag.zip"
Write-Host "fetch $url"
Invoke-WebRequest -Uri $url -OutFile $zip -UseBasicParsing

$got = (Get-FileHash $zip -Algorithm SHA256).Hash
if ($got -ne $Sha256) {
    Remove-Item $zip -Force
    throw "luau-windows.zip hash mismatch: got $got, pinned $Sha256"
}

New-Item -ItemType Directory -Force $dest | Out-Null
Add-Type -AssemblyName System.IO.Compression.FileSystem
$archive = [IO.Compression.ZipFile]::OpenRead($zip)
try {
    $entry = $archive.Entries | Where-Object { $_.Name -eq "luau-compile.exe" } | Select-Object -First 1
    if (-not $entry) { throw "luau-compile.exe missing from $url" }
    [IO.Compression.ZipFileExtensions]::ExtractToFile($entry, $exe, $true)
}
finally {
    $archive.Dispose()
    Remove-Item $zip -Force
}

$exeHash = (Get-FileHash $exe -Algorithm SHA256).Hash
Write-Host "installed $exe"
Write-Host "sha256 $exeHash"
