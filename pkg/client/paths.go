package client

import (
	"os"
	"path/filepath"
	"runtime"
)

// DefaultStatePath is where the device's keys and credential live.
func DefaultStatePath() string {
	if runtime.GOOS == "windows" {
		return filepath.Join(programData(), "WireMesh", "state.json")
	}
	return "/var/lib/wiremesh/state.json"
}

// DefaultSocketPath is the daemon's local API socket (Unix domain socket on
// every platform; Windows 10+ supports them).
func DefaultSocketPath() string {
	if runtime.GOOS == "windows" {
		return filepath.Join(programData(), "WireMesh", "wiremeshd.sock")
	}
	return "/run/wiremesh/wiremeshd.sock"
}

func programData() string {
	if p := os.Getenv("ProgramData"); p != "" {
		return p
	}
	return `C:\ProgramData`
}
