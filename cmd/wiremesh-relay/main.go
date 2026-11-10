// Command wiremesh-relay runs WireMesh's NAT-traversal helpers.
//
//   - STUN server (UDP) so devices learn their public address
//
//   - packet relay (HTTP/WebSocket at /relay; put TLS in front, e.g. Caddy)
//
//     wiremesh-relay --stun-addr :3478 --relay-addr :8443 --control-key "$(wiremesh-server relay-pubkey)"
//
// Then tell the control server about it:
//
//	WIREMESH_STUN_SERVERS=relay1.example.com:3478
//	WIREMESH_RELAY_URLS=https://relay1.example.com/relay
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/siv151992-lang/network-connector/internal/version"
	"github.com/siv151992-lang/network-connector/pkg/relayproto"
	"github.com/siv151992-lang/network-connector/pkg/stun"
	"github.com/siv151992-lang/network-connector/relay"
)

func main() {
	addr := flag.String("stun-addr", ":3478", "UDP address for the STUN server")
	relayAddr := flag.String("relay-addr", "", "HTTP address for the packet relay, e.g. :8443 (empty = STUN only)")
	controlKey := flag.String("control-key", os.Getenv("WIREMESH_RELAY_CONTROL_KEY"),
		"control server's relay public key (base64; `wiremesh-server relay-pubkey`); env WIREMESH_RELAY_CONTROL_KEY")
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
	if *relayAddr != "" {
		pub, err := relayproto.ParsePublicKey(*controlKey)
		if err != nil {
			log.Error("relay needs --control-key", "error", err)
			os.Exit(1)
		}
		rs := &relay.Server{ControlKey: pub, Log: log}
		mux := http.NewServeMux()
		mux.Handle("/relay", rs)
		mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok\n")) })
		hs := &http.Server{Addr: *relayAddr, Handler: mux, ReadHeaderTimeout: 10 * time.Second}
		go func() {
			log.Info("relay listening", "addr", *relayAddr)
			if err := hs.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Error("relay server failed", "error", err)
				os.Exit(1)
			}
		}()
		go func() {
			<-ctx.Done()
			sctx, c := context.WithTimeout(context.Background(), 5*time.Second)
			defer c()
			_ = hs.Shutdown(sctx)
		}()
		go func() {
			t := time.NewTicker(5 * time.Minute)
			defer t.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-t.C:
					log.Info("relay stats", "clients", rs.Clients(), "forwarded", rs.Forwarded.Load(), "dropped", rs.Dropped.Load())
				}
			}
		}()
	}
	if err := s.Serve(ctx); err != nil {
		log.Error("stun server stopped", "error", err)
		os.Exit(1)
	}
}
