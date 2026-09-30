<#
.SYNOPSIS
  Install or update WinVault to the latest GitHub release.

.DESCRIPTION
  Downloads winvault.exe and WinVault-GUI.exe from the latest release, checks
  both against the release's SHA256SUMS.txt (it stops if either doesn't match),
  then runs `winvault install`:
    - copies both to C:\Program Files\WinVault (from an Administrator terminal)
    - puts winvault on PATH
    - adds WinVault to the Start menu (pinnable to the taskbar)

  Safe to run again for every new version. Snapshots are never touched.

.EXAMPLE
  .\Update-WinVault.ps1
  .\Update-WinVault.ps1 -Version v1.0.1
#>
[CmdletBinding()]
param([string]$Version = "latest")

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'          # much faster Invoke-WebRequest
$repo = 'M7MD-2030/WinVault'
$base = if ($Version -eq 'latest') { "https://github.com/$repo/releases/latest/download" }
        else { "https://github.com/$repo/releases/download/$Version" }

$work = Join-Path $env:TEMP "winvault-update-$([guid]::NewGuid().ToString('N').Substring(0,8))"
New-Item -ItemType Directory -Path $work | Out-Null
try {
    Write-Host "Downloading WinVault ($Version)..." -ForegroundColor Cyan
    foreach ($f in 'winvault.exe', 'WinVault-GUI.exe', 'SHA256SUMS.txt') {
        Invoke-WebRequest -Uri "$base/$f" -OutFile (Join-Path $work $f) -UseBasicParsing
    }

    Write-Host 'Verifying SHA-256...' -ForegroundColor Cyan
    $expected = @{}
    Get-Content (Join-Path $work 'SHA256SUMS.txt') | ForEach-Object {
        $hash, $name = $_ -split '\s+', 2
        if ($name) { $expected[$name.Trim()] = $hash.Trim().ToLower() }
    }
    foreach ($f in 'winvault.exe', 'WinVault-GUI.exe') {
        $actual = (Get-FileHash (Join-Path $work $f) -Algorithm SHA256).Hash.ToLower()
        if ($expected[$f] -ne $actual) { throw "$f checksum mismatch — download is corrupt or tampered. Nothing was installed." }
        Write-Host "  OK  $f  $actual"
        Unblock-File (Join-Path $work $f)          # verified: skip the SmartScreen prompt
    }

    & (Join-Path $work 'winvault.exe') install
    if ($LASTEXITCODE -ne 0) { throw "winvault install failed (exit $LASTEXITCODE)" }
    Write-Host "`nDone. Open a NEW terminal and run: winvault status" -ForegroundColor Green
}
finally {
    Remove-Item $work -Recurse -Force -ErrorAction SilentlyContinue
}
