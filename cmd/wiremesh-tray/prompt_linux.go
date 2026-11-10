package main

import (
	"os/exec"
	"strings"
)

// askServer shows an input dialog with zenity (or kdialog) if installed.
func askServer(current string) (string, bool) {
	var cmd *exec.Cmd
	if p, err := exec.LookPath("zenity"); err == nil {
		cmd = exec.Command(p, "--entry", "--title=Connect to WireMesh", "--text=Server address (for example 192.168.1.100)", "--entry-text="+current)
	} else if p, err := exec.LookPath("kdialog"); err == nil {
		cmd = exec.Command(p, "--title", "Connect to WireMesh", "--inputbox", "Server address (for example 192.168.1.100)", current)
	} else {
		return "", false
	}
	out, err := cmd.Output()
	s := strings.TrimSpace(string(out))
	return s, err == nil && s != ""
}
