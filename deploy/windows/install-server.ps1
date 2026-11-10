# Installs WireMesh Server as a Windows service (no Docker needed).
$dst = Join-Path $env:ProgramFiles "WireMesh Server"
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "Please run Install.bat (it asks for administrator rights)." -ForegroundColor Red
    exit 1
}

# Stop an existing installation so its files can be replaced.
if (Get-Service -Name WireMeshServer -ErrorAction SilentlyContinue) {
    Write-Host "Stopping the running WireMesh Server..."
    Stop-Service -Name WireMeshServer -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 3
}
# A database left running by an earlier failed start would block the new one.
Get-Process postgres -ErrorAction SilentlyContinue |
    Where-Object { $_.Path -like "*WireMesh Server*" } |
    Stop-Process -Force -ErrorAction SilentlyContinue

Write-Host "Copying files to $dst ..."
New-Item -ItemType Directory -Force -Path $dst | Out-Null
foreach ($item in "wiremesh-server.exe", "postgres-windows-amd64.txz", "web", "uninstall-server.ps1", "README.txt") {
    Copy-Item -Recurse -Force (Join-Path $PSScriptRoot $item) $dst
}

& (Join-Path $dst "wiremesh-server.exe") standalone install
if ($LASTEXITCODE -ne 0) {
    Write-Host "Installing the service failed (see the message above)." -ForegroundColor Red
    exit 1
}

Write-Host "Starting... the first start sets up the database (about a minute)."
$ready = $false
for ($i = 0; $i -lt 90; $i++) {
    try { Invoke-WebRequest -UseBasicParsing -TimeoutSec 3 "http://127.0.0.1/readyz" | Out-Null; $ready = $true; break } catch { Start-Sleep -Seconds 2 }
}
$ip = (Find-NetRoute -RemoteIPAddress 192.0.2.1 -ErrorAction SilentlyContinue | Select-Object -First 1).IPAddress
if (-not $ip) { $ip = "localhost" }
if (-not $ready) {
    Write-Host "The server did not start. Last lines of its log:" -ForegroundColor Yellow
    Get-Content "$env:ProgramData\WireMesh Server\server.log" -Tail 15 -ErrorAction SilentlyContinue
    exit 1
}
Write-Host ""
Write-Host "WireMesh Server is running." -ForegroundColor Green
Write-Host "Server address for your devices:  $ip" -ForegroundColor Green
Write-Host "Opening http://$ip - create your admin account there."
Start-Process "http://$ip"
