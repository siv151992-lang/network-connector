package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/siv151992-lang/network-connector/internal/auth"
	"github.com/siv151992-lang/network-connector/internal/config"
	"github.com/siv151992-lang/network-connector/internal/db"
	"github.com/siv151992-lang/network-connector/internal/store"
)

// createAdmin bootstraps a verified system administrator. This is the
// recommended way to create the first account: it needs shell access to the
// server, so nobody on the internet can race you to it.
func createAdmin(ctx context.Context, cfg *config.Config, pool *pgxpool.Pool, args []string) error {
	fs := flag.NewFlagSet("create-admin", flag.ContinueOnError)
	email := fs.String("email", "", "admin email address (required)")
	name := fs.String("name", "", "display name")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *email == "" {
		return errors.New("--email is required")
	}
	if _, err := db.Migrate(ctx, pool, nil); err != nil {
		return err
	}

	password := os.Getenv("WIREMESH_ADMIN_PASSWORD")
	if password == "" {
		fmt.Fprint(os.Stderr, "Password (input is echoed; use `read -s` and the env var to avoid that): ")
		line, err := bufio.NewReader(os.Stdin).ReadString('\n')
		if err != nil && line == "" {
			return fmt.Errorf("read password: %w", err)
		}
		password = strings.TrimRight(line, "\r\n")
	}
	if msg := auth.ValidatePassword(password, *email); msg != "" {
		return errors.New(msg)
	}
	hash, err := auth.NewHasher(auth.DefaultArgon2Params, 1).Hash(ctx, password)
	if err != nil {
		return err
	}
	u, err := store.New(pool).CreateUser(ctx, store.NewUser{
		Email: *email, PasswordHash: hash, DisplayName: *name, SystemRole: store.SystemRoleAdmin, Verified: true,
	})
	if errors.Is(err, store.ErrConflict) {
		return fmt.Errorf("a user with email %s already exists", store.NormalizeEmail(*email))
	}
	if err != nil {
		return err
	}
	fmt.Printf("created system admin %s (id %s); sign in at %s\n", u.Email, u.ID, cfg.PublicURL)
	return nil
}

// newMailer picks SMTP when configured; otherwise logs emails in development
// (links included) and drops them in production.
func newMailer(cfg *config.Config, log *slog.Logger) (*auth.AsyncMailer, error) {
	var base auth.Mailer
	switch {
	case cfg.SMTPHost != "":
		m, err := auth.NewSMTPMailer(auth.SMTPConfig{
			Host: cfg.SMTPHost, Port: cfg.SMTPPort, Username: cfg.SMTPUsername,
			Password: cfg.SMTPPassword, From: cfg.SMTPFrom, TLS: cfg.SMTPTLS,
		})
		if err != nil {
			return nil, err
		}
		base = m
	case cfg.IsProduction():
		base = auth.DiscardMailer{Log: log}
	default:
		log.Warn("WIREMESH_SMTP_HOST not set: emails (with their secret links) are written to the log")
		base = auth.LogMailer{Log: log}
	}
	return auth.NewAsyncMailer(base, log, 256), nil
}

// janitor periodically purges expired sessions and one-time tokens.
func janitor(ctx context.Context, s *store.Store, log *slog.Logger) {
	t := time.NewTicker(time.Hour)
	defer t.Stop()
	for {
		cutoff := time.Now().Add(-7 * 24 * time.Hour) // keep a week for forensics
		if n, err := s.DeleteStaleSessions(ctx, cutoff); err != nil && ctx.Err() == nil {
			log.Warn("janitor: delete sessions", "error", err)
		} else if n > 0 {
			log.Info("janitor: deleted stale sessions", "count", n)
		}
		if _, err := s.DeleteExpiredDeviceLogins(ctx); err != nil && ctx.Err() == nil {
			log.Warn("janitor: delete device logins", "error", err)
		}
		if n, err := s.DeleteStaleUserTokens(ctx, cutoff); err != nil && ctx.Err() == nil {
			log.Warn("janitor: delete tokens", "error", err)
		} else if n > 0 {
			log.Info("janitor: deleted stale tokens", "count", n)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
