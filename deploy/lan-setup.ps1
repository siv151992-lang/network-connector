# WireMesh server on a Windows PC for a home/office LAN (Docker Desktop).
#
# Run in an elevated PowerShell inside the deploy folder:
#   powershell -ExecutionPolicy Bypass -File .\lan-setup.ps1 -Ip 192.168.1.100 -Email you@example.com
#
# It creates .env with random secrets (first run only), builds and starts the
# containers, opens the firewall and creates the admin account.
param(
    [Parameter(Mandatory = $true)][string]$Ip,
    [Parameter(Mandatory = $true)][string]$Email
)
Set-Location $PSScriptRoot

function Check($what) { if ($LASTEXITCODE -ne 0) { throw "$what failed (exit code $LASTEXITCODE)" } }
function RandomBytes($n) { $b = New-Object byte[] $n; [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($b); return $b }

$ErrorActionPreference = "Continue"
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run this script as Administrator."
}
if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    throw "Docker is not installed. Install Docker Desktop (https://www.docker.com/products/docker-desktop/), start it, then run this again."
}
cmd /c "docker info >nul 2>&1"
if ($LASTEXITCODE -ne 0) { throw "Docker Desktop is not running. Start it, wait until it says 'Engine running', then run this again." }

$dc = @("compose", "-f", "docker-compose.yml", "-f", "docker-compose.lan.yml")

# 1. Settings (.env). Secrets are generated once and kept.
if (-not (Test-Path .env)) {
    $pg = -join ((RandomBytes 24) | ForEach-Object { $_.ToString("x2") })
    $secret = [Convert]::ToBase64String((RandomBytes 32))
    $lines = @(
        "WIREMESH_DOMAIN=$Ip",
        "POSTGRES_PASSWORD=$pg",
        "WIREMESH_SECRET_KEY=$secret",
        "ACME_EMAIL=$Email",
        "WIREMESH_RELAY_CONTROL_KEY="
    )
    [IO.File]::WriteAllLines((Join-Path $PSScriptRoot ".env"), $lines)
    Write-Host "Created .env. BACK IT UP: it holds the secret key."
} else {
    $envText = (Get-Content .env) -replace '^WIREMESH_DOMAIN=.*$', "WIREMESH_DOMAIN=$Ip"
    [IO.File]::WriteAllLines((Join-Path $PSScriptRoot ".env"), $envText)
}

# 2. Build images (first time takes several minutes).
Write-Host "Building images..."
docker @dc build
Check "docker compose build"

# 3. Relay key (derived from the secret key).
$key = (docker @dc run --rm --no-deps server relay-pubkey | Where-Object { $_.Trim() -ne "" } | Select-Object -Last 1).Trim()
Check "relay-pubkey"
$envText = (Get-Content .env) -replace '^WIREMESH_RELAY_CONTROL_KEY=.*$', "WIREMESH_RELAY_CONTROL_KEY=$key"
[IO.File]::WriteAllLines((Join-Path $PSScriptRoot ".env"), $envText)

# 4. Start.
docker @dc up -d
Check "docker compose up"

# 5. Firewall: dashboard/API/relay (TCP 80) and STUN (UDP 3478).
if (-not (Get-NetFirewallRule -DisplayName "WireMesh HTTP" -ErrorAction SilentlyContinue)) {
    New-NetFirewallRule -DisplayName "WireMesh HTTP" -Direction Inbound -Protocol TCP -LocalPort 80 -Action Allow | Out-Null
}
if (-not (Get-NetFirewallRule -DisplayName "WireMesh STUN" -ErrorAction SilentlyContinue)) {
    New-NetFirewallRule -DisplayName "WireMesh STUN" -Direction Inbound -Protocol UDP -LocalPort 3478 -Action Allow | Out-Null
}

# 6. Wait for the server, then create the admin (asks for a password).
Write-Host "Waiting for the server..."
$ready = $false
for ($i = 0; $i -lt 60; $i++) {
    try { Invoke-WebRequest -UseBasicParsing -TimeoutSec 3 "http://$Ip/readyz" | Out-Null; $ready = $true; break } catch { Start-Sleep -Seconds 2 }
}
if (-not $ready) { throw "Server did not start. See: docker compose logs server caddy" }

Write-Host "`nCreate the admin account for $Email (password: at least 12 characters):"
docker @dc run --rm server create-admin --email $Email
if ($LASTEXITCODE -ne 0) { Write-Host "(If the admin already exists, ignore this.)" }

Write-Host "`nDone. Dashboard: http://$Ip"
Write-Host "Connect a device:  wiremesh up --server http://$Ip"
