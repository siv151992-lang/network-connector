// Command wiremeshd is the WireMesh background service (systemd on Linux;
// see clients/linux/wiremeshd.service). It owns the tunnel and serves a local
// API on a Unix socket for the `wiremesh` CLI.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"os/user"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"github.com/siv151992-lang/network-connector/internal/version"
	"github.com/siv151992-lang/network-connector/pkg/client"
)

func main() {
	state := flag.String("state", client.DefaultStatePath(), "state file (keys + credential)")
	sock := flag.String("socket", client.DefaultSocketPath(), "local API socket")
	iface := flag.String("iface", "wm0", "tunnel interface name")
	port := flag.Uint("port", 51820, "WireGuard UDP port")
	level := flag.String("log-level", "info", "debug|info|warn|error")
	flag.Parse()
	var lvl slog.Level
	if err := lvl.UnmarshalText([]byte(*level)); err != nil || *port > 65535 {
		fmt.Fprintln(os.Stderr, "invalid --log-level or --port")
		os.Exit(2)
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: lvl}))
	if err := run(log, *state, *sock, *iface, uint16(*port)); err != nil {
		log.Error("wiremeshd failed", "error", err)
		os.Exit(1)
	}
}

func run(log *slog.Logger, state, sock, iface string, port uint16) error {
	d := &client.Daemon{StatePath: state, InterfaceName: iface, ListenPort: port, Version: version.Version, Log: log}

	if err := os.MkdirAll(filepath.Dir(sock), 0o755); err != nil {
		return err
	}
	_ = os.Remove(sock) // stale socket from a previous run
	l, err := net.Listen("unix", sock)
	if err != nil {
		return err
	}
	// Only root and members of the "wiremesh" group may control the daemon.
	mode := os.FileMode(0o600)
	if g, err := user.LookupGroup("wiremesh"); err == nil {
		if gid, err := strconv.Atoi(g.Gid); err == nil && os.Chown(sock, 0, gid) == nil {
			mode = 0o660
		}
	}
	if err := os.Chmod(sock, mode); err != nil {
		return err
	}
	srv := &http.Server{Handler: d.Handler(), ReadHeaderTimeout: 10 * time.Second}
	go func() {
		if err := srv.Serve(l); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("local API stopped", "error", err)
		}
	}()
	log.Info("wiremeshd started", "socket", sock, "version", version.Version)
	d.AutoStart()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	<-ctx.Done()
	log.Info("shutting down")
	d.Down(false) // the tunnel comes back on next start
	sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = srv.Shutdown(sctx)
	_ = os.Remove(sock)
	return nil
}
