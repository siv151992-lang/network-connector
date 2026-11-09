// Package testutil provides helpers for integration tests that need a real
// PostgreSQL. Set WIREMESH_TEST_DATABASE_URL to a role that may CREATE
// DATABASE (e.g. postgres://postgres:postgres@localhost:5432/postgres);
// otherwise the tests are skipped.
package testutil

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/siv151992-lang/network-connector/internal/db"
)

// EnvTestDatabaseURL names the environment variable holding the admin DSN.
const EnvTestDatabaseURL = "WIREMESH_TEST_DATABASE_URL"

// NewDB creates an isolated, fully migrated database for one test and drops it
// on cleanup. Each test gets its own database, so tests can run in parallel.
func NewDB(t testing.TB) *pgxpool.Pool {
	t.Helper()
	adminURL := os.Getenv(EnvTestDatabaseURL)
	if adminURL == "" {
		t.Skipf("%s not set; skipping integration test", EnvTestDatabaseURL)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	admin, err := pgx.Connect(ctx, adminURL)
	if err != nil {
		t.Fatalf("connect admin db: %v", err)
	}
	defer admin.Close(ctx)

	var b [6]byte
	_, _ = rand.Read(b[:])
	name := "wiremesh_test_" + hex.EncodeToString(b[:])
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+pgx.Identifier{name}.Sanitize()); err != nil {
		t.Fatalf("create test database: %v", err)
	}

	u, err := url.Parse(adminURL)
	if err != nil || (u.Scheme != "postgres" && u.Scheme != "postgresql") {
		t.Fatalf("%s must be a postgres:// URL", EnvTestDatabaseURL)
	}
	u.Path = "/" + name
	pool, err := db.Open(ctx, u.String(), db.Options{MaxConns: 8})
	if err != nil {
		t.Fatalf("open test database: %v", err)
	}
	if _, err := db.Migrate(ctx, pool, nil); err != nil {
		pool.Close()
		t.Fatalf("migrate test database: %v", err)
	}

	t.Cleanup(func() {
		pool.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		c, err := pgx.Connect(ctx, adminURL)
		if err != nil {
			t.Logf("cleanup connect: %v", err)
			return
		}
		defer c.Close(ctx)
		if _, err := c.Exec(ctx, "DROP DATABASE IF EXISTS "+pgx.Identifier{name}.Sanitize()+" WITH (FORCE)"); err != nil {
			t.Logf("drop test database %s: %v", name, err)
		}
	})
	return pool
}
