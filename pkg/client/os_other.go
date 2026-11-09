//go:build !linux || android

package client

import (
	"errors"
	"io"
	"log/slog"

	"golang.zx2c4.com/wireguard/device"
)

// Windows (Phase 8) and Android (Phase 7) provide their own configurators.
func newOSConfigurator(name string, log *slog.Logger) (OSConfigurator, error) {
	return nil, errors.New("interface configuration is not implemented on this platform yet")
}

func startUAPI(string, *device.Device, *slog.Logger) (io.Closer, error) {
	return nil, errors.New("UAPI not supported on this platform")
}
