package main

import (
	"os/exec"
	"strings"
	"syscall"
)

// askServer shows a small input box (PowerShell + VisualBasic InputBox; no CGO).
func askServer(current string) (string, bool) {
	cur := strings.ReplaceAll(current, "'", "")
	script := "Add-Type -AssemblyName Microsoft.VisualBasic; " +
		"[Microsoft.VisualBasic.Interaction]::InputBox('Server address (for example 192.168.1.100)', 'Connect to WireMesh', '" + cur + "')"
	cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", script)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	out, err := cmd.Output()
	s := strings.TrimSpace(string(out))
	return s, err == nil && s != ""
}
