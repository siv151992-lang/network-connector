package db_test

import (
	"context"
	"strings"
	"sync"
	"testing"

	"github.com/siv151992-lang/network-connector/internal/db"
	"github.com/siv151992-lang/network-connector/internal/testutil"
)

func TestEmbeddedMigrationsAreWellFormed(t *testing.T) {
	ms, err := db.LoadMigrations()
	if err != nil {
		t.Fatal(err)
	}
	if len(ms) == 0 || ms[0].Version != 1 {
		t.Fatalf("expected migrations starting at 1, got %+v", ms)
	}
	for i, m := range ms {
		if m.Version != i+1 {
			t.Errorf("migration versions must be contiguous: index %d has version %d", i, m.Version)
		}
		if len(m.Checksum) != 64 || strings.TrimSpace(m.SQL) == "" {
			t.Errorf("migration %d malformed", m.Version)
		}
	}
}

func TestMigrateIsIdempotentAndConcurrencySafe(t *testing.T) {
	pool := testutil.NewDB(t) // already migrated once
	ctx := context.Background()

	// Several "replicas" migrating at once must not fail or double-apply.
	var wg sync.WaitGroup
	errs := make(chan error, 4)
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			n, err := db.Migrate(ctx, pool, nil)
			if err == nil && n != 0 {
				t.Errorf("re-run applied %d migrations", n)
			}
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}

	applied, pending, err := db.Status(ctx, pool)
	if err != nil || len(pending) != 0 || len(applied) == 0 {
		t.Fatalf("status: applied=%d pending=%d err=%v", len(applied), len(pending), err)
	}
}

func TestMigrateDetectsTampering(t *testing.T) {
	pool := testutil.NewDB(t)
	ctx := context.Background()
	if _, err := pool.Exec(ctx, `UPDATE schema_migrations SET checksum = 'deadbeef' WHERE version = 1`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Migrate(ctx, pool, nil); err == nil || !strings.Contains(err.Error(), "checksum mismatch") {
		t.Fatalf("want checksum mismatch, got %v", err)
	}

	if _, err := pool.Exec(ctx, `INSERT INTO schema_migrations (version, name, checksum) VALUES (9999, 'future', 'x')`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Migrate(ctx, pool, nil); err == nil {
		t.Fatal("expected error for unknown applied migration")
	}
}
