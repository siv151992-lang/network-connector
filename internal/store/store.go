// Package store is the data-access layer. It wraps hand-written SQL over pgx
// and maps PostgreSQL errors to the sentinel errors below. Higher layers
// (auth, devices, coord, …) depend on Store and never write SQL themselves.
package store

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/siv151992-lang/network-connector/internal/db"
)

var (
	// ErrNotFound is returned when a row does not exist (or is not visible to
	// the caller's scope, e.g. a device in another network).
	ErrNotFound = errors.New("not found")
	// ErrConflict is returned on unique-constraint violations.
	ErrConflict = errors.New("conflict")
	// ErrInvalid is returned when the database rejects a value via a CHECK or
	// foreign-key constraint, or a requested state transition is not allowed.
	ErrInvalid = errors.New("invalid")
)

// ConflictError carries the violated constraint so callers can produce a
// precise message (e.g. "email already registered").
type ConflictError struct{ Constraint string }

func (e *ConflictError) Error() string { return "conflict on " + e.Constraint }
func (e *ConflictError) Unwrap() error { return ErrConflict }

// InvalidError carries the violated constraint or reason.
type InvalidError struct{ Reason string }

func (e *InvalidError) Error() string { return "invalid: " + e.Reason }
func (e *InvalidError) Unwrap() error { return ErrInvalid }

// DBTX is satisfied by *pgxpool.Pool and pgx.Tx, so every query method works
// both standalone and inside a transaction.
type DBTX interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// Store provides all repository methods.
type Store struct {
	pool *pgxpool.Pool
	q    DBTX
}

// New returns a Store backed by pool.
func New(pool *pgxpool.Pool) *Store { return &Store{pool: pool, q: pool} }

// Pool exposes the underlying pool (used for health checks).
func (s *Store) Pool() *pgxpool.Pool { return s.pool }

// WithTx runs fn with a Store bound to a single transaction. Calls nested
// inside an existing transaction reuse it.
func (s *Store) WithTx(ctx context.Context, fn func(tx *Store) error) error {
	if _, inTx := s.q.(pgx.Tx); inTx {
		return fn(s)
	}
	return db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		return fn(&Store{pool: s.pool, q: tx})
	})
}

// mapErr converts driver errors into store sentinels.
func mapErr(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	if c, ok := db.IsUniqueViolation(err); ok {
		return &ConflictError{Constraint: c}
	}
	if c, ok := db.IsCheckViolation(err); ok {
		return &InvalidError{Reason: "constraint " + c}
	}
	if c, ok := db.IsForeignKeyViolation(err); ok {
		return &InvalidError{Reason: "reference " + c}
	}
	return err
}

func wrap(op string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%s: %w", op, mapErr(err))
}

// clampLimit bounds page sizes for list queries.
func clampLimit(limit, def, max int) int {
	if limit <= 0 {
		return def
	}
	if limit > max {
		return max
	}
	return limit
}
