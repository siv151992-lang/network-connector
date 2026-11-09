// Package version exposes build metadata injected via -ldflags, e.g.
//
//	go build -ldflags "-X github.com/siv151992-lang/network-connector/internal/version.Version=v0.2.0 \
//	  -X github.com/siv151992-lang/network-connector/internal/version.Commit=$(git rev-parse --short HEAD)"
package version

import "runtime"

var (
	Version = "dev"
	Commit  = "unknown"
	Date    = "unknown"
)

// Info is the JSON shape returned by GET /api/v1/version.
type Info struct {
	Version   string `json:"version"`
	Commit    string `json:"commit"`
	BuildDate string `json:"build_date"`
	GoVersion string `json:"go_version"`
	API       string `json:"api"`
}

// Get returns the current build info.
func Get() Info {
	return Info{Version: Version, Commit: Commit, BuildDate: Date, GoVersion: runtime.Version(), API: "v1"}
}
