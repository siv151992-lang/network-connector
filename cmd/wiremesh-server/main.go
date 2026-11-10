// Command wiremesh-server is the WireMesh control server.
//
// Usage:
//
//	wiremesh-server serve            # run migrations (if WIREMESH_AUTO_MIGRATE) and serve HTTP
//	wiremesh-server migrate up       # apply pending migrations and exit
//	wiremesh-server migrate status   # list applied and pending migrations
//	wiremesh-server create-admin --email you@example.com [--name "Your Name"]
//	                                 # password from WIREMESH_ADMIN_PASSWORD or stdin
//	wiremesh-server version
//
// All configuration comes from WIREMESH_* environment variables; see .env.example.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/siv151992-lang/network-connector/internal/api"
	"github.com/siv151992-lang/network-connector/internal/api/middleware"
	"github.com/siv151992-lang/network-connector/internal/auth"
	"github.com/siv151992-lang/network-connector/internal/config"
	"github.com/siv151992-lang/network-connector/internal/db"
	"github.com/siv151992-lang/network-connector/internal/logging"
	"github.com/siv151992-lang/network-connector/internal/secretbox"
	"github.com/siv151992-lang/network-connector/internal/store"
	"github.com/siv151992-lang/network-connector/internal/version"
	"github.com/siv151992-lang/network-connector/pkg/relayproto"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	cmd := "serve"
	if len(args) > 0 {
		cmd = args[0]
	}
	switch cmd {
	case "version", "-v", "--version":
		v := version.Get()
		fmt.Printf("wiremesh-server %s (commit %s, built %s, %s)\n", v.Version, v.Commit, v.BuildDate, v.GoVersion)
		return nil
	case "relay-pubkey":
		cfg, err := config.Load()
		if err != nil {
			return fmt.Errorf("invalid configuration:\n%w", err)
		}
		if cfg.SecretKey == nil {
			return errors.New("WIREMESH_SECRET_KEY must be set: the relay key is derived from it")
		}
		k, err := relayproto.SigningKey(cfg.SecretKey)
		if err != nil {
			return err
		}
		fmt.Println(base64.StdEncoding.EncodeToString(k.Public().(ed25519.PublicKey)))
		return nil
	case "serve", "migrate", "create-admin":
	case "help", "-h", "--help":
		fmt.Println("usage: wiremesh-server [serve | migrate up | migrate status | create-admin --email E [--name N] | version]")
		return nil
	default:
		return fmt.Errorf("unknown command %q (try: serve, migrate up, migrate status, create-admin, version)", cmd)
	}

	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("invalid configuration:\n%w", err)
	}
	log := logging.New(os.Stderr, cfg.LogLevel, cfg.LogFormat)
	slog.SetDefault(log)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	pool, err := db.Open(ctx, cfg.DatabaseURL, db.Options{
		MaxConns: cfg.DBMaxConns, MaxConnLifetime: time.Hour, ConnectTimeout: 10 * time.Second,
	})
	if err != nil {
		return err
	}
	defer pool.Close()

	if cmd == "migrate" {
		sub := "up"
		if len(args) > 1 {
			sub = args[1]
		}
		return runMigrate(ctx, pool, log, sub)
	}
	if cmd == "create-admin" {
		return createAdmin(ctx, cfg, pool, args[1:])
	}
	return serve(ctx, cfg, log, pool)
}

func runMigrate(ctx context.Context, pool *pgxpool.Pool, log *slog.Logger, sub string) error {
	switch sub {
	case "up":
		n, err := db.Migrate(ctx, pool, log)
		if err != nil {
			return err
		}
		log.Info("migrations complete", "applied", n)
		return nil
	case "status":
		applied, pending, err := db.Status(ctx, pool)
		for _, a := range applied {
			fmt.Printf("applied  %04d_%s  %s\n", a.Version, a.Name, a.AppliedAt.Format(time.RFC3339))
		}
		for _, p := range pending {
			fmt.Printf("pending  %04d_%s\n", p.Version, p.Name)
		}
		return err
	default:
		return fmt.Errorf("unknown migrate subcommand %q (use up or status)", sub)
	}
}

func serve(ctx context.Context, cfg *config.Config, log *slog.Logger, pool *pgxpool.Pool) error {
	if cfg.AutoMigrate {
		if _, err := db.Migrate(ctx, pool, log); err != nil {
			return fmt.Errorf("auto-migrate: %w", err)
		}
	} else {
		_, pending, err := db.Status(ctx, pool)
		if err != nil {
			return err
		}
		if len(pending) > 0 {
			return fmt.Errorf("%d pending migration(s); run `wiremesh-server migrate up` or set WIREMESH_AUTO_MIGRATE=true", len(pending))
		}
	}

	if cfg.SecretKey == nil {
		// Only reachable in development (production config validation requires a key).
		cfg.SecretKey = make([]byte, 32)
		if _, err := rand.Read(cfg.SecretKey); err != nil {
			return err
		}
		log.Warn("WIREMESH_SECRET_KEY not set: using an ephemeral key; encrypted data (e.g. TOTP secrets) will be unreadable after restart")
	}

	box, err := secretbox.New(cfg.SecretKey)
	if err != nil {
		return err
	}
	mailer, err := newMailer(cfg, log)
	if err != nil {
		return err
	}
	defer mailer.Close() // drains queued email on shutdown

	limiter := middleware.NewLimiter(cfg.RateLimitRPS, cfg.RateLimitBurst)
	defer limiter.Stop()
	authLimiter := middleware.NewLimiter(cfg.AuthRateLimitPerMin/60, int(cfg.AuthRateLimitPerMin))
	defer authLimiter.Stop()

	st := store.New(pool)
	go janitor(ctx, st, log)
	hub := api.NewHub(st, cfg, log, nil)
	if len(cfg.STUNServers) == 0 {
		log.Warn("WIREMESH_STUN_SERVERS not set: devices can only connect directly over reachable addresses (no NAT traversal)")
	}

	handler := api.NewHandler(api.Deps{
		Config: cfg, Log: log, Store: st, DB: pool, Limiter: limiter, AuthLimiter: authLimiter,
		Hasher: auth.NewHasher(auth.DefaultArgon2Params, cfg.MaxConcurrentHashes),
		Mailer: mailer, Box: box, Hub: hub,
	})

	srv := &http.Server{
		Addr:              cfg.HTTPAddr,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		// WriteTimeout is left at 0 because device streams are long-lived
		// WebSockets; per-handler deadlines are set via http.ResponseController.
		IdleTimeout:    120 * time.Second,
		MaxHeaderBytes: 64 << 10,
		ErrorLog:       slog.NewLogLogger(log.Handler(), slog.LevelWarn),
	}

	errCh := make(chan error, 1)
	go func() {
		log.Info("control server listening", "addr", cfg.HTTPAddr, "env", cfg.Env,
			"public_url", cfg.PublicURL.String(), "version", version.Version)
		errCh <- srv.ListenAndServe()
	}()

	select {
	case err := <-errCh:
		if !errors.Is(err, http.ErrServerClosed) {
			return err
		}
		return nil
	case <-ctx.Done():
	}

	log.Info("shutting down", "timeout", cfg.ShutdownTimeout)
	hub.CloseAll() // device streams are hijacked connections; Shutdown doesn't track them
	shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("graceful shutdown: %w", err)
	}
	return nil
}
