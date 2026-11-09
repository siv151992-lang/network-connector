package db

import (
	"context"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"fmt"
	"io/fs"
	"log/slog"
	"regexp"
	"sort"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed migrations/*.sql
var migrationFS embed.FS

// migrationLockID is an arbitrary constant used with pg_advisory_lock so that
// only one server replica applies migrations at a time.
const migrationLockID int64 = 0x5749_5245_4d45_5348 // "WIREMESH"

var migrationName = regexp.MustCompile(`^(\d{4})_([a-z0-9_]+)\.sql$`)

// Migration is a single embedded SQL file.
type Migration struct {
	Version  int
	Name     string
	SQL      string
	Checksum string
}

// AppliedMigration is a row of schema_migrations.
type AppliedMigration struct {
	Version   int
	Name      string
	Checksum  string
	AppliedAt time.Time
}

// LoadMigrations parses the embedded migration files, sorted by version.
func LoadMigrations() ([]Migration, error) {
	return loadMigrations(migrationFS, "migrations")
}

func loadMigrations(fsys fs.FS, dir string) ([]Migration, error) {
	entries, err := fs.ReadDir(fsys, dir)
	if err != nil {
		return nil, fmt.Errorf("read migrations: %w", err)
	}
	var out []Migration
	seen := map[int]string{}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		m := migrationName.FindStringSubmatch(e.Name())
		if m == nil {
			return nil, fmt.Errorf("invalid migration file name %q (want NNNN_name.sql)", e.Name())
		}
		v, _ := strconv.Atoi(m[1])
		if prev, dup := seen[v]; dup {
			return nil, fmt.Errorf("duplicate migration version %d: %s and %s", v, prev, e.Name())
		}
		seen[v] = e.Name()
		body, err := fs.ReadFile(fsys, dir+"/"+e.Name())
		if err != nil {
			return nil, err
		}
		sum := sha256.Sum256(body)
		out = append(out, Migration{Version: v, Name: m[2], SQL: string(body), Checksum: hex.EncodeToString(sum[:])})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Version < out[j].Version })
	return out, nil
}

const createMigrationsTable = `
CREATE TABLE IF NOT EXISTS schema_migrations (
    version    integer PRIMARY KEY,
    name       text        NOT NULL,
    checksum   text        NOT NULL,
    applied_at timestamptz NOT NULL DEFAULT now()
)`

// Migrate applies all pending migrations. It holds a session-level advisory
// lock for the duration, so concurrent replicas serialize safely, and it
// refuses to proceed if an already-applied migration's checksum has changed.
// It returns the number of migrations applied.
func Migrate(ctx context.Context, pool *pgxpool.Pool, log *slog.Logger) (int, error) {
	migrations, err := LoadMigrations()
	if err != nil {
		return 0, err
	}
	conn, err := pool.Acquire(ctx)
	if err != nil {
		return 0, fmt.Errorf("acquire connection: %w", err)
	}
	defer conn.Release()

	if _, err := conn.Exec(ctx, "SELECT pg_advisory_lock($1)", migrationLockID); err != nil {
		return 0, fmt.Errorf("acquire migration lock: %w", err)
	}
	defer func() {
		// Use a fresh context: ctx may already be cancelled.
		unlockCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, _ = conn.Exec(unlockCtx, "SELECT pg_advisory_unlock($1)", migrationLockID)
	}()

	if _, err := conn.Exec(ctx, createMigrationsTable); err != nil {
		return 0, fmt.Errorf("create schema_migrations: %w", err)
	}

	applied, err := appliedMigrations(ctx, conn.Conn())
	if err != nil {
		return 0, err
	}
	if err := verifyApplied(migrations, applied); err != nil {
		return 0, err
	}

	count := 0
	for _, m := range migrations {
		if _, ok := applied[m.Version]; ok {
			continue
		}
		start := time.Now()
		err := pgx.BeginFunc(ctx, conn.Conn(), func(tx pgx.Tx) error {
			if _, err := tx.Exec(ctx, m.SQL); err != nil {
				return err
			}
			_, err := tx.Exec(ctx,
				"INSERT INTO schema_migrations (version, name, checksum) VALUES ($1, $2, $3)",
				m.Version, m.Name, m.Checksum)
			return err
		})
		if err != nil {
			return count, fmt.Errorf("apply migration %04d_%s: %w", m.Version, m.Name, err)
		}
		count++
		if log != nil {
			log.Info("applied migration", "version", m.Version, "name", m.Name, "duration", time.Since(start))
		}
	}
	return count, nil
}

// Status returns the migrations recorded in the database plus the embedded
// migrations that are still pending.
func Status(ctx context.Context, pool *pgxpool.Pool) (applied []AppliedMigration, pending []Migration, err error) {
	migrations, err := LoadMigrations()
	if err != nil {
		return nil, nil, err
	}
	conn, err := pool.Acquire(ctx)
	if err != nil {
		return nil, nil, err
	}
	defer conn.Release()
	if _, err := conn.Exec(ctx, createMigrationsTable); err != nil {
		return nil, nil, err
	}
	am, err := appliedMigrations(ctx, conn.Conn())
	if err != nil {
		return nil, nil, err
	}
	for _, m := range migrations {
		if a, ok := am[m.Version]; ok {
			applied = append(applied, a)
		} else {
			pending = append(pending, m)
		}
	}
	return applied, pending, verifyApplied(migrations, am)
}

func appliedMigrations(ctx context.Context, conn *pgx.Conn) (map[int]AppliedMigration, error) {
	rows, err := conn.Query(ctx, "SELECT version, name, checksum, applied_at FROM schema_migrations ORDER BY version")
	if err != nil {
		return nil, fmt.Errorf("query schema_migrations: %w", err)
	}
	defer rows.Close()
	out := map[int]AppliedMigration{}
	for rows.Next() {
		var a AppliedMigration
		if err := rows.Scan(&a.Version, &a.Name, &a.Checksum, &a.AppliedAt); err != nil {
			return nil, err
		}
		out[a.Version] = a
	}
	return out, rows.Err()
}

func verifyApplied(migrations []Migration, applied map[int]AppliedMigration) error {
	known := map[int]Migration{}
	for _, m := range migrations {
		known[m.Version] = m
	}
	for v, a := range applied {
		m, ok := known[v]
		if !ok {
			return fmt.Errorf("database has migration %04d_%s that this binary does not know about (downgrade?)", v, a.Name)
		}
		if m.Checksum != a.Checksum {
			return fmt.Errorf("checksum mismatch for migration %04d_%s: shipped migrations must never be edited", v, a.Name)
		}
	}
	return nil
}
