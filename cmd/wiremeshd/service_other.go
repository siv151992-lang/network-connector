//go:build !windows

package main

import "context"

// On Unix, systemd manages the service; there are no extra subcommands.
func platformCommand([]string) (bool, error) { return false, nil }

func runAsService(func(context.Context) error) (bool, error) { return false, nil }

// secureDir: on Unix the socket's own mode/group restrict access.
func secureDir(string) error { return nil }

func secureSocket(string) error { return nil }
