WireMesh for Windows (Windows 10 1809+ / Windows 11, amd64 or arm64)

Install (elevated PowerShell, in this folder):
  powershell -ExecutionPolicy Bypass -File .\install.ps1 -Server https://vpn.example.com

This installs to C:\Program Files\WireMesh, registers the "WireMesh" service
(starts at boot), adds the tray app at sign-in, and downloads the Wintun
driver from wintun.net (its WireGuard LLC signature is verified). To install
offline, put wintun.dll from the official Wintun zip next to install.ps1.

Use: the tray icon (green = connected), or in an elevated terminal:
  wiremesh up | down | status | logout

Uninstall: powershell -ExecutionPolicy Bypass -File "C:\Program Files\WireMesh\uninstall.ps1"

Not yet on Windows: automatic MagicDNS (use the tunnel IPs or query <your tunnel IP>:53 directly).
