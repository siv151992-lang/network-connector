# WireMesh for Windows: installer. Run in an elevated PowerShell from the
# extracted release folder:
#   powershell -ExecutionPolicy Bypass -File .\install.ps1 [-Server 192.168.1.100]
param([string]$Server = "")
$ErrorActionPreference = "Stop"

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run this script as Administrator."
}
$src = Split-Path -Parent $MyInvocation.MyCommand.Path
$dst = Join-Path $env:ProgramFiles "WireMesh"
$arch = if ($env:PROCESSOR_ARCHITECTURE -eq "ARM64") { "arm64" } else { "amd64" }

# 1. Wintun driver DLL (signed by WireGuard LLC). Use a bundled copy if present,
#    otherwise download the official release and verify its Authenticode signature.
$wintun = Join-Path $src "wintun.dll"
if (-not (Test-Path $wintun)) {
    Write-Host "Downloading Wintun from https://www.wintun.net ..."
    $zip = Join-Path $env:TEMP "wintun.zip"
    Invoke-WebRequest -UseBasicParsing -Uri "https://www.wintun.net/builds/wintun-0.14.1.zip" -OutFile $zip
    $tmp = Join-Path $env:TEMP "wintun-extract"
    Expand-Archive -Force -Path $zip -DestinationPath $tmp
    $wintun = Join-Path $tmp "wintun\bin\$arch\wintun.dll"
}
$sig = Get-AuthenticodeSignature -FilePath $wintun
if ($sig.Status -ne "Valid" -or $sig.SignerCertificate.Subject -notmatch "WireGuard LLC") {
    throw "wintun.dll signature check failed ($($sig.Status), $($sig.SignerCertificate.Subject)). Download it from https://www.wintun.net."
}

# 2. Install binaries (stop an existing service first so files aren't locked).
if (Get-Service -Name WireMesh -ErrorAction SilentlyContinue) {
    Stop-Service -Name WireMesh -Force -ErrorAction SilentlyContinue
    & (Join-Path $dst "wiremeshd.exe") uninstall | Out-Null
}
Get-Process wiremesh-tray -ErrorAction SilentlyContinue | Stop-Process -Force
Start-Sleep -Milliseconds 500
New-Item -ItemType Directory -Force -Path $dst | Out-Null
foreach ($f in "wiremesh.exe", "wiremeshd.exe", "wiremesh-tray.exe", "uninstall.ps1") {
    Copy-Item -Force (Join-Path $src $f) $dst
}
Copy-Item -Force $wintun $dst

# 3. Machine PATH, service, tray at sign-in.
$path = [Environment]::GetEnvironmentVariable("Path", "Machine")
if ($path -notlike "*$dst*") {
    [Environment]::SetEnvironmentVariable("Path", "$path;$dst", "Machine")
}
& (Join-Path $dst "wiremeshd.exe") install
$startup = Join-Path $env:ProgramData "Microsoft\Windows\Start Menu\Programs\StartUp\WireMesh.lnk"
$sh = (New-Object -ComObject WScript.Shell).CreateShortcut($startup)
$sh.TargetPath = Join-Path $dst "wiremesh-tray.exe"
$sh.Save()
Start-Process (Join-Path $dst "wiremesh-tray.exe")

# File sharing (\\100.64.x.x\share) from WireMesh devices only. Windows puts
# the WireMesh adapter in the Public profile, where file sharing is blocked.
if (-not (Get-NetFirewallRule -DisplayName "WireMesh file sharing" -ErrorAction SilentlyContinue)) {
    New-NetFirewallRule -DisplayName "WireMesh file sharing" -Direction Inbound -Protocol TCP -LocalPort 445 `
        -RemoteAddress 100.64.0.0/10 -Action Allow | Out-Null
}

Write-Host "`nWireMesh installed."
if ($Server -ne "") {
    & (Join-Path $dst "wiremesh.exe") up --server $Server
} else {
    Write-Host "Click the WireMesh tray icon (bottom right) and enter your server address."
}
