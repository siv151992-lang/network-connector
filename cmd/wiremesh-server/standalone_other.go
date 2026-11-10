//go:build !windows

package main

import (
	"context"
	"errors"
)

func runServerService(func(context.Context) error) (bool, error) { return false, nil }

func installServerService([]string) error {
	return errors.New("service install is Windows-only; on Linux use the Docker setup or a systemd unit")
}

func uninstallServerService() error { return installServerService(nil) }

func secureDataDir(string) error { return nil } // created with mode 0700
