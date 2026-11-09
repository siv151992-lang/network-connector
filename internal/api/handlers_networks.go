package api

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/siv151992-lang/network-connector/internal/api/httpx"
	"github.com/siv151992-lang/network-connector/internal/auth"
	"github.com/siv151992-lang/network-connector/internal/devices"
	"github.com/siv151992-lang/network-connector/internal/ipam"
	"github.com/siv151992-lang/network-connector/internal/store"
)

func (s *Server) networkRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/networks", s.handle(s.user(s.handleListNetworks)))
	mux.HandleFunc("POST /api/v1/networks", s.handle(s.user(s.handleCreateNetwork)))
	mux.HandleFunc("GET /api/v1/networks/{nid}", s.handle(s.member(s.handleGetNetwork)))
	mux.HandleFunc("PATCH /api/v1/networks/{nid}", s.handle(s.netAdmin(s.handleUpdateNetwork)))
	mux.HandleFunc("DELETE /api/v1/networks/{nid}", s.handle(s.member(s.handleDeleteNetwork)))

	mux.HandleFunc("GET /api/v1/networks/{nid}/members", s.handle(s.member(s.handleListMembers)))
	mux.HandleFunc("POST /api/v1/networks/{nid}/members", s.handle(s.netAdmin(s.handleAddMember)))
	mux.HandleFunc("PATCH /api/v1/networks/{nid}/members/{uid}", s.handle(s.netAdmin(s.handleSetMemberRole)))
	mux.HandleFunc("DELETE /api/v1/networks/{nid}/members/{uid}", s.handle(s.member(s.handleRemoveMember)))

	mux.HandleFunc("GET /api/v1/networks/{nid}/auth-keys", s.handle(s.netAdmin(s.handleListAuthKeys)))
	mux.HandleFunc("POST /api/v1/networks/{nid}/auth-keys", s.handle(s.netAdmin(s.handleCreateAuthKey)))
	mux.HandleFunc("DELETE /api/v1/networks/{nid}/auth-keys/{kid}", s.handle(s.netAdmin(s.handleRevokeAuthKey)))

	mux.HandleFunc("GET /api/v1/networks/{nid}/audit-logs", s.handle(s.member(s.handleListAudit)))
}

var slugPattern = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

func (s *Server) netAudit(r *http.Request, n *netCtx, action, targetType, targetID string, meta map[string]any) {
	s.audit(r, store.NewAuditEntry{NetworkID: &n.Network.ID, ActorUserID: &n.User.ID, Action: action,
		TargetType: targetType, TargetID: targetID, Metadata: meta})
}

// ---------------------------------------------------------------------------
// Networks
// ---------------------------------------------------------------------------

func (s *Server) handleListNetworks(w http.ResponseWriter, r *http.Request, p *principal) error {
	list, err := s.store.ListNetworksForUser(r.Context(), p.User.ID)
	if err != nil {
		return err
	}
	if list == nil {
		list = []*store.NetworkWithRole{}
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"networks": list})
	return nil
}

type createNetworkReq struct {
	Name                   string `json:"name"`
	Slug                   string `json:"slug"`
	DeviceApprovalRequired *bool  `json:"device_approval_required"`
	KeyExpiryDays          *int   `json:"key_expiry_days"`
}

func validateNetworkFields(f fieldErrors, name string, keyExpiry *int) {
	if n := utf8.RuneCountInString(strings.TrimSpace(name)); n < 1 || n > 100 {
		f.add("name", "must be 1-100 characters")
	}
	if keyExpiry != nil && (*keyExpiry < 0 || *keyExpiry > 3650) {
		f.add("key_expiry_days", "must be between 0 (never) and 3650")
	}
}

func (s *Server) handleCreateNetwork(w http.ResponseWriter, r *http.Request, p *principal) error {
	var req createNetworkReq
	if err := httpx.DecodeJSON(r, &req); err != nil {
		return err
	}
	f := fieldErrors{}
	validateNetworkFields(f, req.Name, req.KeyExpiryDays)
	explicitSlug := req.Slug != ""
	if explicitSlug && !slugPattern.MatchString(req.Slug) {
		f.add("slug", "must be lowercase letters, digits and dashes (max 63)")
	}
	if err := f.err(); err != nil {
		return err
	}
	slug := req.Slug
	if !explicitSlug {
		slug = devices.SanitizeName(req.Name)
		if slug == "device" {
			slug = "network"
		}
	}
	nn := store.NewNetwork{
		Name: strings.TrimSpace(req.Name), Slug: slug, IPv4CIDR: s.cfg.DefaultIPv4Range,
		DeviceApprovalRequired: true, KeyExpiryDays: 180, OwnerID: p.User.ID,
	}
	if req.DeviceApprovalRequired != nil {
		nn.DeviceApprovalRequired = *req.DeviceApprovalRequired
	}
	if req.KeyExpiryDays != nil {
		nn.KeyExpiryDays = *req.KeyExpiryDays
	}
	var n *store.Network
	for attempt := 0; ; attempt++ {
		v6, err := ipam.RandomULA48()
		if err != nil {
			return err
		}
		nn.IPv6CIDR = v6
		n, err = s.store.CreateNetwork(r.Context(), nn)
		if err == nil {
			break
		}
		var ce *store.ConflictError
		if !errors.As(err, &ce) || ce.Constraint != "networks_slug_key" {
			return err
		}
		if explicitSlug || attempt >= 3 {
			return httpx.Conflict("a network with this slug already exists")
		}
		// Derived slug collided: append a short random suffix.
		var b [2]byte
		_, _ = rand.Read(b[:])
		base := slug
		if len(base) > 58 {
			base = strings.TrimRight(base[:58], "-")
		}
		nn.Slug = base + "-" + hex.EncodeToString(b[:])
	}
	s.audit(r, store.NewAuditEntry{NetworkID: &n.ID, ActorUserID: &p.User.ID, Action: "network.create", TargetType: "network", TargetID: n.ID.String()})
	httpx.WriteJSON(w, http.StatusCreated, map[string]any{"network": n, "role": store.RoleOwner})
	return nil
}

func (s *Server) handleGetNetwork(w http.ResponseWriter, r *http.Request, n *netCtx) error {
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"network": n.Network, "role": n.Role})
	return nil
}

type updateNetworkReq struct {
	Name                   *string `json:"name"`
	DeviceApprovalRequired *bool   `json:"device_approval_required"`
	KeyExpiryDays          *int    `json:"key_expiry_days"`
}

func (s *Server) handleUpdateNetwork(w http.ResponseWriter, r *http.Request, n *netCtx) error {
	var req updateNetworkReq
	if err := httpx.DecodeJSON(r, &req); err != nil {
		return err
	}
	name, approval, expiry := n.Network.Name, n.Network.DeviceApprovalRequired, n.Network.KeyExpiryDays
	if req.Name != nil {
		name = strings.TrimSpace(*req.Name)
	}
	if req.DeviceApprovalRequired != nil {
		approval = *req.DeviceApprovalRequired
	}
	if req.KeyExpiryDays != nil {
		expiry = *req.KeyExpiryDays
	}
	f := fieldErrors{}
	validateNetworkFields(f, name, &expiry)
	if err := f.err(); err != nil {
		return err
	}
	updated, err := s.store.UpdateNetworkSettings(r.Context(), n.Network.ID, name, approval, expiry)
	if err != nil {
		return err
	}
	s.netAudit(r, n, "network.update", "network", n.Network.ID.String(), map[string]any{
		"name": name, "device_approval_required": approval, "key_expiry_days": expiry})
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"network": updated, "role": n.Role})
	return nil
}

func (s *Server) handleDeleteNetwork(w http.ResponseWriter, r *http.Request, n *netCtx) error {
	if !n.isOwner() {
		return httpx.Forbidden("only an owner can delete a network")
	}
	if err := s.store.DeleteNetwork(r.Context(), n.Network.ID); err != nil {
		return err
	}
	// network_id becomes NULL on the audit row via ON DELETE SET NULL; keep the ID in metadata.
	s.audit(r, store.NewAuditEntry{ActorUserID: &n.User.ID, Action: "network.delete", TargetType: "network",
		TargetID: n.Network.ID.String(), Metadata: map[string]any{"name": n.Network.Name}})
	w.WriteHeader(http.StatusNoContent)
	return nil
}

// ---------------------------------------------------------------------------
// Members
// ---------------------------------------------------------------------------

func (s *Server) handleListMembers(w http.ResponseWriter, r *http.Request, n *netCtx) error {
	list, err := s.store.ListMembers(r.Context(), n.Network.ID)
	if err != nil {
		return err
	}
	if list == nil {
		list = []*store.Member{}
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"members": list})
	return nil
}

type memberReq struct {
	Email string `json:"email"`
	Role  string `json:"role"`
}

func (s *Server) handleAddMember(w http.ResponseWriter, r *http.Request, n *netCtx) error {
	var req memberReq
	if err := httpx.DecodeJSON(r, &req); err != nil {
		return err
	}
	if req.Role == "" {
		req.Role = store.RoleMember
	}
	if !store.ValidNetworkRole(req.Role) {
		return httpx.Validation(map[string]string{"role": "must be owner, admin, member or auditor"})
	}
	if req.Role == store.RoleOwner && !n.isOwner() {
		return httpx.Forbidden("only an owner can add another owner")
	}
	u, err := s.store.GetUserByEmail(r.Context(), req.Email)
	if errors.Is(err, store.ErrNotFound) {
		return httpx.NotFound("no user with that email address; they must have an account first")
	}
	if err != nil {
		return err
	}
	if err := s.store.AddMember(r.Context(), n.Network.ID, u.ID, req.Role); err != nil {
		if errors.Is(err, store.ErrConflict) {
			return httpx.Conflict("user is already a member")
		}
		return err
	}
	s.netAudit(r, n, "member.add", "user", u.ID.String(), map[string]any{"role": req.Role})
	httpx.WriteJSON(w, http.StatusCreated, map[string]any{"member": store.Member{
		NetworkID: n.Network.ID, UserID: u.ID, Email: u.Email, DisplayName: u.DisplayName, Role: req.Role}})
	return nil
}

func (s *Server) handleSetMemberRole(w http.ResponseWriter, r *http.Request, n *netCtx) error {
	uid, err := pathUUID(r, "uid")
	if err != nil {
		return err
	}
	var req struct {
		Role string `json:"role"`
	}
	if err := httpx.DecodeJSON(r, &req); err != nil {
		return err
	}
	if !store.ValidNetworkRole(req.Role) {
		return httpx.Validation(map[string]string{"role": "must be owner, admin, member or auditor"})
	}
	cur, err := s.store.GetMemberRole(r.Context(), n.Network.ID, uid)
	if err != nil {
		return err
	}
	if (cur == store.RoleOwner || req.Role == store.RoleOwner) && !n.isOwner() {
		return httpx.Forbidden("only an owner can grant or remove the owner role")
	}
	if err := s.store.SetMemberRole(r.Context(), n.Network.ID, uid, req.Role); err != nil {
		return err
	}
	s.netAudit(r, n, "member.role_change", "user", uid.String(), map[string]any{"from": cur, "to": req.Role})
	w.WriteHeader(http.StatusNoContent)
	return nil
}

// handleRemoveMember lets admins remove members, and any member leave. The
// user's devices in the network are deleted in the same transaction, so a
// removed user keeps no network access.
func (s *Server) handleRemoveMember(w http.ResponseWriter, r *http.Request, n *netCtx) error {
	uid, err := pathUUID(r, "uid")
	if err != nil {
		return err
	}
	self := uid == n.User.ID
	if !self && !n.isAdmin() {
		return httpx.Forbidden("network admin role required")
	}
	cur, err := s.store.GetMemberRole(r.Context(), n.Network.ID, uid)
	if err != nil {
		return err
	}
	if cur == store.RoleOwner && !n.isOwner() {
		return httpx.Forbidden("only an owner can remove an owner")
	}
	var removed int64
	err = s.store.WithTx(r.Context(), func(tx *store.Store) error {
		if err := tx.RemoveMember(r.Context(), n.Network.ID, uid); err != nil {
			return err
		}
		removed, err = tx.DeleteUserDevices(r.Context(), n.Network.ID, uid)
		return err
	})
	if err != nil {
		return err
	}
	action := "member.remove"
	if self {
		action = "member.leave"
	}
	s.netAudit(r, n, action, "user", uid.String(), map[string]any{"devices_deleted": removed})
	w.WriteHeader(http.StatusNoContent)
	return nil
}

// ---------------------------------------------------------------------------
// Auth keys
// ---------------------------------------------------------------------------

func (s *Server) handleListAuthKeys(w http.ResponseWriter, r *http.Request, n *netCtx) error {
	keys, err := s.store.ListAuthKeys(r.Context(), n.Network.ID)
	if err != nil {
		return err
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"auth_keys": keys})
	return nil
}

type createAuthKeyReq struct {
	Description    string   `json:"description"`
	Reusable       bool     `json:"reusable"`
	Ephemeral      bool     `json:"ephemeral"`
	Preauthorized  bool     `json:"preauthorized"`
	Tags           []string `json:"tags"`
	ExpiresInHours int      `json:"expires_in_hours"`
}

const maxAuthKeyHours = 90 * 24

func (s *Server) handleCreateAuthKey(w http.ResponseWriter, r *http.Request, n *netCtx) error {
	var req createAuthKeyReq
	if err := httpx.DecodeJSON(r, &req); err != nil {
		return err
	}
	if req.ExpiresInHours == 0 {
		req.ExpiresInHours = 24
	}
	f := fieldErrors{}
	if req.ExpiresInHours < 1 || req.ExpiresInHours > maxAuthKeyHours {
		f.add("expires_in_hours", "must be between 1 and %d", maxAuthKeyHours)
	}
	if utf8.RuneCountInString(req.Description) > 200 {
		f.add("description", "must be at most 200 characters")
	}
	if len(req.Tags) > 16 {
		f.add("tags", "at most 16 tags")
	}
	seen := map[string]bool{}
	for _, t := range req.Tags {
		if !devices.ValidTag(t) {
			f.add("tags", "tags must look like tag:servers (lowercase letters, digits, dashes)")
		}
		if seen[t] {
			f.add("tags", "duplicate tag %s", t)
		}
		seen[t] = true
	}
	if err := f.err(); err != nil {
		return err
	}
	raw, hash, err := auth.NewToken(auth.PrefixAuthKey)
	if err != nil {
		return err
	}
	k, err := s.store.CreateAuthKey(r.Context(), store.NewAuthKey{
		NetworkID: n.Network.ID, CreatedBy: n.User.ID, KeyHash: hash, Prefix: raw[:len(auth.PrefixAuthKey)+6],
		Description: req.Description, Reusable: req.Reusable, Ephemeral: req.Ephemeral,
		Preauthorized: req.Preauthorized, Tags: req.Tags,
		ExpiresAt: s.now().Add(time.Duration(req.ExpiresInHours) * time.Hour),
	})
	if err != nil {
		return err
	}
	s.netAudit(r, n, "auth_key.create", "auth_key", k.ID.String(), map[string]any{
		"reusable": k.Reusable, "ephemeral": k.Ephemeral, "preauthorized": k.Preauthorized, "tags": k.Tags})
	// The raw key is returned exactly once.
	httpx.WriteJSON(w, http.StatusCreated, map[string]any{"auth_key": k, "key": raw})
	return nil
}

func (s *Server) handleRevokeAuthKey(w http.ResponseWriter, r *http.Request, n *netCtx) error {
	kid, err := pathUUID(r, "kid")
	if err != nil {
		return err
	}
	if err := s.store.RevokeAuthKey(r.Context(), n.Network.ID, kid); err != nil {
		return err
	}
	s.netAudit(r, n, "auth_key.revoke", "auth_key", kid.String(), nil)
	w.WriteHeader(http.StatusNoContent)
	return nil
}

// ---------------------------------------------------------------------------
// Audit log
// ---------------------------------------------------------------------------

func (s *Server) handleListAudit(w http.ResponseWriter, r *http.Request, n *netCtx) error {
	if !n.canViewAll() {
		return httpx.Forbidden("admin or auditor role required")
	}
	q := store.AuditQuery{NetworkID: &n.Network.ID, Action: r.URL.Query().Get("action")}
	if v := r.URL.Query().Get("before"); v != "" {
		id, err := strconv.ParseInt(v, 10, 64)
		if err != nil || id < 0 {
			return httpx.BadRequest("before must be a positive integer")
		}
		q.BeforeID = id
	}
	if v := r.URL.Query().Get("limit"); v != "" {
		l, err := strconv.Atoi(v)
		if err != nil {
			return httpx.BadRequest("limit must be an integer")
		}
		q.Limit = l
	}
	entries, err := s.store.ListAudit(r.Context(), q)
	if err != nil {
		return err
	}
	resp := map[string]any{"entries": entries}
	if len(entries) > 0 {
		resp["next_before"] = entries[len(entries)-1].ID
	}
	httpx.WriteJSON(w, http.StatusOK, resp)
	return nil
}
