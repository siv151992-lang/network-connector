// Command wiremesh-relay runs WireMesh's NAT-traversal helpers.
//
// Phase 5: a STUN server (UDP) devices use to discover their public address.
// Phase 6 adds the encrypted packet relay to this same binary.
//
//	wiremesh-relay --stun-addr :3478
//
// Then tell the control server about it:
//
//	WIREMESH_STUN_SERVERS=relay1.example.com:3478
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/siv151992-lang/network-connector/internal/version"
	"github.com/siv151992-lang/network-connector/pkg/stun"
)

func main() {
	addr := flag.String("stun-addr", ":3478", "UDP address for the STUN server")
	level := flag.String("log-level", "info", "debug|info|warn|error")
	showVersion := flag.Bool("version", false, "print version")
	flag.Parse()
	if *showVersion {
		fmt.Println("wiremesh-relay", version.Version)
		return
	}
	var lvl slog.Level
	if err := lvl.UnmarshalText([]byte(*level)); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	log := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: lvl}))

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	s := &stun.Server{Log: log}
	if err := s.Listen(*addr); err != nil {
		log.Error("stun listen failed", "addr", *addr, "error", err)
		os.Exit(1)
	}
	log.Info("STUN server listening", "addr", s.Addr().String(), "version", version.Version)
	go func() {
		t := time.NewTicker(5 * time.Minute)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				log.Info("stun stats", "requests", s.Requests.Load(), "invalid", s.Invalid.Load())
			}
		}
	}()
	if err := s.Serve(ctx); err != nil {
		log.Error("stun server stopped", "error", err)
		os.Exit(1)
	}
}
