package main

import (
	"os"
	"os/exec"
	"strings"
	"syscall"
)

// A small always-on-top WinForms dialog. The current value is passed in an
// environment variable, so nothing is spliced into the script.
const askScript = `
Add-Type -AssemblyName System.Windows.Forms, System.Drawing
[System.Windows.Forms.Application]::EnableVisualStyles()
$f = New-Object System.Windows.Forms.Form
$f.Text = 'Connect to WireMesh'; $f.TopMost = $true; $f.StartPosition = 'CenterScreen'
$f.FormBorderStyle = 'FixedDialog'; $f.MaximizeBox = $false; $f.MinimizeBox = $false
$f.ClientSize = New-Object System.Drawing.Size(360, 120)
$l = New-Object System.Windows.Forms.Label
$l.Text = 'Server address (for example 192.168.1.100):'; $l.AutoSize = $true
$l.Location = New-Object System.Drawing.Point(12, 14)
$t = New-Object System.Windows.Forms.TextBox
$t.Text = $env:WM_CURRENT; $t.Location = New-Object System.Drawing.Point(12, 40); $t.Width = 336
$ok = New-Object System.Windows.Forms.Button
$ok.Text = 'Connect'; $ok.DialogResult = 'OK'; $ok.Location = New-Object System.Drawing.Point(192, 80)
$cancel = New-Object System.Windows.Forms.Button
$cancel.Text = 'Cancel'; $cancel.DialogResult = 'Cancel'; $cancel.Location = New-Object System.Drawing.Point(273, 80)
$f.Controls.AddRange(@($l, $t, $ok, $cancel)); $f.AcceptButton = $ok; $f.CancelButton = $cancel
$f.Add_Shown({ [void]$f.Activate(); [void]$t.Focus() })
if ($f.ShowDialog() -eq 'OK') { [Console]::Out.Write($t.Text) }
`

func askServer(current string) (string, bool) {
	cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", askScript)
	cmd.Env = append(os.Environ(), "WM_CURRENT="+current)
	// CREATE_NO_WINDOW hides only PowerShell's console; unlike HideWindow it
	// doesn't make the dialog's first ShowWindow call hide the dialog too.
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: 0x08000000}
	out, err := cmd.Output()
	s := strings.TrimSpace(string(out))
	return s, err == nil && s != ""
}
