# Removes the WireMesh Server service and program files. Data (database,
# keys) stays in %ProgramData%\WireMesh Server; delete that folder to wipe it.
$dst = Join-Path $env:ProgramFiles "WireMesh Server"
$exe = Join-Path $dst "wiremesh-server.exe"
if (Test-Path $exe) { & $exe standalone uninstall }
Start-Sleep -Seconds 3
Remove-Item -Recurse -Force $dst -ErrorAction SilentlyContinue
Write-Host "WireMesh Server removed. Your data is kept in $env:ProgramData\WireMesh Server"
