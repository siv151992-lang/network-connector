WireMesh Server for Windows (no Docker needed)

Install:   double-click Install.bat (click Yes when Windows asks).
           When it finishes, your browser opens the dashboard:
           create your admin account, then a network.

Connect devices: install the WireMesh app on each device and enter this
           server's address (shown at the end of the install, e.g. 192.168.1.100).

Uninstall: double-click Uninstall.bat. Your data stays in
           C:\ProgramData\WireMesh Server (delete it to wipe everything).

Back up C:\ProgramData\WireMesh Server (it holds the database and secret key).
Ports opened in Windows Firewall: TCP 80 (dashboard/devices), UDP 3478.
Log: C:\ProgramData\WireMesh Server\server.log
