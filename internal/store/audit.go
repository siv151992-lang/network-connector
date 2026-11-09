package store

import (
	"context"
	"encoding/json"
	"net/netip"
	"time"

	"github.com/google/uuid"
)

// AuditEntry is one row of the audit log.
type AuditEntry struct {
	ID            int64           `json:"id"`
	NetworkID     *uuid.UUID      `json:"network_id,omitempty"`
	ActorUserID   *uuid.UUID      `json:"actor_user_id,omitempty"`
	ActorDeviceID *uuid.UUID      `json:"actor_device_id,omitempty"`
	Action        string          `json:"action"`
	TargetType    string          `json:"target_type"`
	TargetID      string          `json:"target_id"`
	IP            *netip.Addr     `json:"ip,omitempty"`
	UserAgent     string          `json:"user_agent"`
	Metadata      json.RawMessage `json:"metadata"`
	CreatedAt     time.Time       `json:"created_at"`
}

// NewAuditEntry is the input to InsertAudit.
type NewAuditEntry struct {
	NetworkID     *uuid.UUID
	ActorUserID   *uuid.UUID
	ActorDeviceID *uuid.UUID
	Action        string
	TargetType    string
	TargetID      string
	IP            *netip.Addr
	UserAgent     string
	Metadata      map[string]any // never put secrets here
}

// InsertAudit appends an entry to the audit log.
func (s *Store) InsertAudit(ctx context.Context, e NewAuditEntry) error {
	meta := e.Metadata
	if meta == nil {
		meta = map[string]any{}
	}
	_, err := s.q.Exec(ctx, `
		INSERT INTO audit_logs (network_id, actor_user_id, actor_device_id, action, target_type, target_id,
		                        ip, user_agent, metadata)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
		e.NetworkID, e.ActorUserID, e.ActorDeviceID, e.Action, e.TargetType, e.TargetID,
		addrPtrArg(e.IP), truncate(e.UserAgent, 512), meta)
	return wrap("insert audit", err)
}

// AuditQuery filters and paginates ListAudit. Pagination is keyset-based
// (BeforeID = smallest ID of the previous page), which stays fast on large tables.
type AuditQuery struct {
	NetworkID *uuid.UUID
	Action    string
	BeforeID  int64
	Limit     int
}

// ListAudit returns entries newest first.
func (s *Store) ListAudit(ctx context.Context, q AuditQuery) ([]*AuditEntry, error) {
	limit := clampLimit(q.Limit, 50, 200)
	rows, err := s.q.Query(ctx, `
		SELECT id, network_id, actor_user_id, actor_device_id, action, target_type, target_id,
		       ip, user_agent, metadata, created_at
		FROM audit_logs
		WHERE ($1::uuid IS NULL OR network_id = $1)
		  AND ($2 = '' OR action = $2)
		  AND ($3 = 0 OR id < $3)
		ORDER BY id DESC LIMIT $4`, q.NetworkID, q.Action, q.BeforeID, limit)
	if err != nil {
		return nil, wrap("list audit", err)
	}
	defer rows.Close()
	out := []*AuditEntry{}
	for rows.Next() {
		var a AuditEntry
		var ip *netip.Prefix
		if err := rows.Scan(&a.ID, &a.NetworkID, &a.ActorUserID, &a.ActorDeviceID, &a.Action, &a.TargetType,
			&a.TargetID, &ip, &a.UserAgent, &a.Metadata, &a.CreatedAt); err != nil {
			return nil, wrap("scan audit", err)
		}
		if ip != nil {
			addr := ip.Addr()
			a.IP = &addr
		}
		out = append(out, &a)
	}
	return out, wrap("list audit", rows.Err())
}
