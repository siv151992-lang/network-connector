# WireMesh for Windows: uninstaller (run as Administrator).
#   powershell -ExecutionPolicy Bypass -File "$env:ProgramFiles\WireMesh\uninstall.ps1" [-KeepState]
param([switch]$KeepState)
$ErrorActionPreference = "Stop"
$dst = Join-Path $env:ProgramFiles "WireMesh"
Get-Process wiremesh-tray -ErrorAction SilentlyContinue | Stop-Process -Force
if (-not $KeepState) { & (Join-Path $dst "wiremesh.exe") logout 2>$null }
& (Join-Path $dst "wiremeshd.exe") uninstall
Remove-Item -Force -ErrorAction SilentlyContinue (Join-Path $env:ProgramData "Microsoft\Windows\Start Menu\Programs\StartUp\WireMesh.lnk")
$path = [Environment]::GetEnvironmentVariable("Path", "Machine")
[Environment]::SetEnvironmentVariable("Path", (($path -split ";") | Where-Object { $_ -ne $dst }) -join ";", "Machine")
Remove-Item -Recurse -Force $dst
if (-not $KeepState) { Remove-Item -Recurse -Force -ErrorAction SilentlyContinue (Join-Path $env:ProgramData "WireMesh") }
Write-Host "WireMesh removed."
Remove-NetFirewallRule -DisplayName "WireMesh file sharing" -ErrorAction SilentlyContinue
