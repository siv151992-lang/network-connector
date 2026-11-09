package api

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/siv151992-lang/network-connector/internal/api/httpx"
	"github.com/siv151992-lang/network-connector/internal/auth"
	"github.com/siv151992-lang/network-connector/internal/devices"
	"github.com/siv151992-lang/network-connector/internal/ipam"
	"github.com/siv151992-lang/network-connector/internal/store"
)

func (s *Server) deviceRoutes(mux *http.ServeMux) {
	// Dashboard (user session)
	mux.HandleFunc("GET /api/v1/networks/{nid}/devices", s.handle(s.member(s.handleListDevices)))
	mux.HandleFunc("GET /api/v1/networks/{nid}/devices/{did}", s.handle(s.member(s.handleGetDevice)))
	mux.HandleFunc("PATCH /api/v1/networks/{nid}/devices/{did}", s.handle(s.member(s.handleUpdateDevice)))
	mux.HandleFunc("DELETE /api/v1/networks/{nid}/devices/{did}", s.handle(s.member(s.handleDeleteDevice)))
	mux.HandleFunc("POST /api/v1/networks/{nid}/devices/{did}/approve", s.handle(s.netAdmin(s.deviceStatus(store.DeviceStatusApproved))))
	mux.HandleFunc("POST /api/v1/networks/{nid}/devices/{did}/reject", s.handle(s.netAdmin(s.deviceStatus(store.DeviceStatusRejected))))
	mux.HandleFunc("POST /api/v1/networks/{nid}/devices/{did}/revoke", s.handle(s.member(s.deviceStatus(store.DeviceStatusRevoked))))

	// Device control plane (device bearer credential)
	mux.HandleFunc("POST /api/v1/device/register", s.handle(s.limited(s.handleDeviceRegister)))
	mux.HandleFunc("GET /api/v1/device/self", s.handle(s.device(s.handleDeviceSelf)))
	mux.HandleFunc("POST /api/v1/device/rotate-key", s.handle(s.device(s.handleDeviceRotateKey)))
	mux.HandleFunc("POST /api/v1/device/logout", s.handle(s.device(s.handleDeviceLogout)))
}

// ---------------------------------------------------------------------------
// Dashboard device management
// ---------------------------------------------------------------------------

// loadDevice resolves {did} and applies visibility: members see only their
// own devices; admins and auditors see all. Invisible devices are 404.
func (s *Server) loadDevice(r *http.Request, n *netCtx) (*store.Device, error) {
	did, err := pathUUID(r, "did")
	if err != nil {
		return nil, err
	}
	d, err := s.store.GetDevice(r.Context(), n.Network.ID, did)
	if errors.Is(err, store.ErrNotFound) {
		return nil, httpx.NotFound("device not found")
	}
	if err != nil {
		return nil, err
	}
	if !n.canViewAll() && d.UserID != n.User.ID {
		return nil, httpx.NotFound("device not found")
	}
	return d, nil
}

func (s *Server) handleListDevices(w http.ResponseWriter, r *http.Request, n *netCtx) error {
	f := store.DeviceFilter{Status: r.URL.Query().Get("status")}
	switch f.Status {
	case "", store.DeviceStatusPending, store.DeviceStatusApproved, store.DeviceStatusRejected, store.DeviceStatusRevoked:
	default:
		return httpx.BadRequest("status must be pending, approved, rejected or revoked")
	}
	if !n.canViewAll() {
		f.UserID = &n.User.ID
	}
	list, err := s.store.ListDevices(r.Context(), n.Network.ID, f)
	if err != nil {
		return err
	}
	for _, d := range list {
		d.Online = s.hub.Online(d.ID)
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"devices": list})
	return nil
}

func (s *Server) handleGetDevice(w http.ResponseWriter, r *http.Request, n *netCtx) error {
	d, err := s.loadDevice(r, n)
	if err != nil {
		return err
	}
	d.Online = s.hub.Online(d.ID)
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"device": d})
	return nil
}

type updateDeviceReq struct {
	Name *string   `json:"name"`
	Tags *[]string `json:"tags"`
}

func (s *Server) handleUpdateDevice(w http.ResponseWriter, r *http.Request, n *netCtx) error {
	d, err := s.loadDevice(r, n)
	if err != nil {
		return err
	}
	var req updateDeviceReq
	if err := httpx.DecodeJSON(r, &req); err != nil {
		return err
	}
	owner := d.UserID == n.User.ID
	f := fieldErrors{}
	if req.Name != nil {
		if !owner && !n.isAdmin() {
			return httpx.Forbidden("only the device owner or a network admin can rename a device")
		}
		if !devices.ValidName(*req.Name) {
			f.add("name", "must be a DNS label: lowercase letters, digits and dashes, max 63")
		}
	}
	if req.Tags != nil {
		if !n.isAdmin() {
			return httpx.Forbidden("only network admins can change device tags")
		}
		if len(*req.Tags) > 16 {
			f.add("tags", "at most 16 tags")
		}
		for _, t := range *req.Tags {
			if !devices.ValidTag(t) {
				f.add("tags", "tags must look like tag:servers")
			}
		}
	}
	if err := f.err(); err != nil {
		return err
	}
	if req.Name != nil && *req.Name != d.Name {
		if d, err = s.store.RenameDevice(r.Context(), n.Network.ID, d.ID, *req.Name); err != nil {
			if errors.Is(err, store.ErrConflict) {
				return httpx.Conflict("another device already uses this name")
			}
			return err
		}
		s.netAudit(r, n, "device.rename", "device", d.ID.String(), map[string]any{"name": d.Name})
	}
	if req.Tags != nil {
		if d, err = s.store.SetDeviceTags(r.Context(), n.Network.ID, d.ID, *req.Tags); err != nil {
			return err
		}
		s.netAudit(r, n, "device.tags", "device", d.ID.String(), map[string]any{"tags": d.Tags})
	}
	s.notify(n.Network.ID)
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"device": d})
	return nil
}

func (s *Server) handleDeleteDevice(w http.ResponseWriter, r *http.Request, n *netCtx) error {
	d, err := s.loadDevice(r, n)
	if err != nil {
		return err
	}
	if d.UserID != n.User.ID && !n.isAdmin() {
		return httpx.Forbidden("only the device owner or a network admin can delete a device")
	}
	if err := s.store.DeleteDevice(r.Context(), n.Network.ID, d.ID); err != nil {
		return err
	}
	s.kick(d.ID, true)
	s.notify(n.Network.ID)
	s.netAudit(r, n, "device.delete", "device", d.ID.String(), map[string]any{"name": d.Name, "ipv4": d.IPv4.String()})
	w.WriteHeader(http.StatusNoContent)
	return nil
}

var statusAction = map[string]string{
	store.DeviceStatusApproved: "device.approve",
	store.DeviceStatusRejected: "device.reject",
	store.DeviceStatusRevoked:  "device.revoke",
}

// deviceStatus approves, rejects or revokes. Approve/reject are routed via
// netAdmin; revoke is also allowed for the device's owner (e.g. lost phone).
func (s *Server) deviceStatus(to string) netFunc {
	return func(w http.ResponseWriter, r *http.Request, n *netCtx) error {
		d, err := s.loadDevice(r, n)
		if err != nil {
			return err
		}
		if !n.isAdmin() && !(to == store.DeviceStatusRevoked && d.UserID == n.User.ID) {
			return httpx.Forbidden("network admin role required")
		}
		updated, err := s.store.SetDeviceStatus(r.Context(), n.Network.ID, d.ID, to, &n.User.ID)
		if err != nil {
			return err
		}
		if to == store.DeviceStatusRevoked {
			s.kick(d.ID, true)
		}
		s.notify(n.Network.ID)
		s.netAudit(r, n, statusAction[to], "device", d.ID.String(),
			map[string]any{"from": d.Status, "to": to, "name": d.Name})
		httpx.WriteJSON(w, http.StatusOK, map[string]any{"device": updated})
		return nil
	}
}

// ---------------------------------------------------------------------------
// Device control plane
// ---------------------------------------------------------------------------

type deviceRegisterReq struct {
	AuthKey       string `json:"auth_key"`
	NetworkID     string `json:"network_id"`
	NodeKey       string `json:"node_key"`
	DiscoKey      string `json:"disco_key"`
	Name          string `json:"name"`
	Hostname      string `json:"hostname"`
	OS            string `json:"os"`
	OSVersion     string `json:"os_version"`
	ClientVersion string `json:"client_version"`
}

type networkSummary struct {
	ID       uuid.UUID `json:"id"`
	Name     string    `json:"name"`
	IPv4CIDR string    `json:"ipv4_cidr"`
	IPv6CIDR string    `json:"ipv6_cidr"`
}

func summarize(n *store.Network) networkSummary {
	return networkSummary{ID: n.ID, Name: n.Name, IPv4CIDR: n.IPv4CIDR.String(), IPv6CIDR: n.IPv6CIDR.String()}
}

// handleDeviceRegister enrolls a device, authorized either by an auth key in
// the body (unattended) or by the caller's dashboard session (+ network_id).
func (s *Server) handleDeviceRegister(w http.ResponseWriter, r *http.Request) error {
	var req deviceRegisterReq
	if err := httpx.DecodeJSON(r, &req); err != nil {
		return err
	}
	f := fieldErrors{}
	nodeKey, err := devices.ParseKey(req.NodeKey)
	if err != nil {
		f.add("node_key", "%s", err.Error())
	}
	discoKey, err := devices.ParseKey(req.DiscoKey)
	if err != nil {
		f.add("disco_key", "%s", err.Error())
	}
	if req.Name != "" && !devices.ValidName(req.Name) {
		f.add("name", "must be a DNS label: lowercase letters, digits and dashes, max 63")
	}
	for field, v := range map[string]string{"hostname": req.Hostname, "os": req.OS, "os_version": req.OSVersion, "client_version": req.ClientVersion} {
		if len(v) > 255 || strings.ContainsAny(v, "\x00\r\n") {
			f.add(field, "must be at most 255 characters on one line")
		}
	}
	if err := f.err(); err != nil {
		return err
	}
	if nodeKey != nil && discoKey != nil && string(nodeKey) == string(discoKey) {
		return httpx.Validation(map[string]string{"disco_key": "must differ from node_key"})
	}

	rr := devices.Request{AuthKey: req.AuthKey, NodeKey: nodeKey, DiscoKey: discoKey, Name: req.Name,
		Hostname: req.Hostname, OS: req.OS, OSVersion: req.OSVersion, ClientVersion: req.ClientVersion}
	var actor *uuid.UUID
	if req.AuthKey == "" {
		// Interactive enrollment by a signed-in user.
		p, err := s.loadSession(r)
		if err != nil {
			return httpx.Unauthorized("provide auth_key, or sign in and pass network_id")
		}
		if !p.Session.MFAPassed {
			return &httpx.Error{Status: http.StatusUnauthorized, Code: "mfa_required", Message: "two-factor authentication required"}
		}
		if err := s.checkCSRF(r, p); err != nil {
			return err
		}
		nid, err := uuid.Parse(req.NetworkID)
		if err != nil {
			return httpx.Validation(map[string]string{"network_id": "required when no auth_key is given"})
		}
		role, err := s.store.GetMemberRole(r.Context(), nid, p.User.ID)
		if errors.Is(err, store.ErrNotFound) {
			return httpx.NotFound("network not found")
		}
		if err != nil {
			return err
		}
		if role == store.RoleAuditor {
			return httpx.Forbidden("auditors cannot add devices")
		}
		rr.UserID, rr.NetworkID, actor = p.User.ID, nid, &p.User.ID
	}

	res, err := s.registrar.Register(r.Context(), rr)
	switch {
	case errors.Is(err, store.ErrAuthKeyUnusable), errors.Is(err, devices.ErrNoOwner):
		return &httpx.Error{Status: http.StatusUnauthorized, Code: "invalid_auth_key", Message: "auth key is invalid, expired or already used"}
	case errors.Is(err, devices.ErrNodeKeyInUse):
		return httpx.Conflict("this node key is already registered; generate a new key pair")
	case errors.Is(err, ipam.ErrExhausted):
		return &httpx.Error{Status: http.StatusConflict, Code: "address_space_exhausted", Message: "the network has no free addresses"}
	case err != nil:
		return err
	}
	d := res.Device
	s.notify(d.NetworkID)
	s.audit(r, store.NewAuditEntry{NetworkID: &d.NetworkID, ActorUserID: actor, ActorDeviceID: &d.ID, Action: "device.register",
		TargetType: "device", TargetID: d.ID.String(), Metadata: map[string]any{
			"name": d.Name, "os": d.OS, "status": d.Status, "ipv4": d.IPv4.String(), "via_auth_key": res.AuthKeyID != nil}})
	httpx.WriteJSON(w, http.StatusCreated, map[string]any{
		"device":     d,
		"credential": res.Credential, // returned once; the client stores it in its keystore
		"network":    summarize(res.Network),
	})
	return nil
}

type deviceFunc func(w http.ResponseWriter, r *http.Request, d *store.Device) error

// device authenticates "Authorization: Bearer wmd_…". Revoked devices have
// their credential cleared, so they fail here with 401.
func (s *Server) device(f deviceFunc) apiFunc {
	return func(w http.ResponseWriter, r *http.Request) error {
		raw, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !ok {
			return httpx.Unauthorized("device credential required")
		}
		hash, ok := auth.ParseToken(strings.TrimSpace(raw), auth.PrefixDevice)
		if !ok {
			return httpx.Unauthorized("invalid device credential")
		}
		d, err := s.store.GetDeviceByCredentialHash(r.Context(), hash)
		if errors.Is(err, store.ErrNotFound) {
			return httpx.Unauthorized("invalid device credential")
		}
		if err != nil {
			return err
		}
		// Defense in depth: revocation also clears the credential, but never
		// trust a credential attached to a revoked device.
		if d.Status == store.DeviceStatusRevoked {
			return httpx.Unauthorized("invalid device credential")
		}
		return f(w, r, d)
	}
}

func (s *Server) handleDeviceSelf(w http.ResponseWriter, r *http.Request, d *store.Device) error {
	if err := s.store.TouchDevice(r.Context(), d.ID); err != nil {
		return err
	}
	d.LastSeenAt = ptr(s.now())
	n, err := s.store.GetNetwork(r.Context(), d.NetworkID)
	if err != nil {
		return err
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"device": d, "network": summarize(n)})
	return nil
}

func (s *Server) handleDeviceRotateKey(w http.ResponseWriter, r *http.Request, d *store.Device) error {
	var req struct {
		NodeKey  string `json:"node_key"`
		DiscoKey string `json:"disco_key"`
	}
	if err := httpx.DecodeJSON(r, &req); err != nil {
		return err
	}
	f := fieldErrors{}
	nodeKey, err := devices.ParseKey(req.NodeKey)
	if err != nil {
		f.add("node_key", "%s", err.Error())
	}
	discoKey, err := devices.ParseKey(req.DiscoKey)
	if err != nil {
		f.add("disco_key", "%s", err.Error())
	}
	if err := f.err(); err != nil {
		return err
	}
	if d.Status != store.DeviceStatusApproved {
		return httpx.Forbidden("only approved devices can rotate keys")
	}
	n, err := s.store.GetNetwork(r.Context(), d.NetworkID)
	if err != nil {
		return err
	}
	var exp *time.Time
	if n.KeyExpiryDays > 0 {
		exp = ptr(s.now().Add(time.Duration(n.KeyExpiryDays) * 24 * time.Hour))
	}
	if err := s.store.RotateNodeKey(r.Context(), d.ID, nodeKey, discoKey, exp); err != nil {
		if errors.Is(err, store.ErrConflict) {
			return httpx.Conflict("this node key is already registered")
		}
		return err
	}
	s.notify(d.NetworkID)
	s.audit(r, store.NewAuditEntry{NetworkID: &d.NetworkID, ActorDeviceID: &d.ID, Action: "device.rotate_key", TargetType: "device", TargetID: d.ID.String()})
	updated, err := s.store.GetDevice(r.Context(), d.NetworkID, d.ID)
	if err != nil {
		return err
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"device": updated})
	return nil
}

// handleDeviceLogout ends the device's control-plane credential. Ephemeral
// devices are deleted outright (their address is released).
func (s *Server) handleDeviceLogout(w http.ResponseWriter, r *http.Request, d *store.Device) error {
	var err error
	if d.Ephemeral {
		err = s.store.DeleteDevice(r.Context(), d.NetworkID, d.ID)
	} else {
		err = s.store.ClearDeviceCredential(r.Context(), d.ID)
	}
	if err != nil {
		return err
	}
	s.kick(d.ID, true)
	s.notify(d.NetworkID)
	actor := &d.ID
	if d.Ephemeral {
		actor = nil // the row is gone; the audit FK must not point at it
	}
	s.audit(r, store.NewAuditEntry{NetworkID: &d.NetworkID, ActorDeviceID: actor, Action: "device.logout", TargetType: "device",
		TargetID: d.ID.String(), Metadata: map[string]any{"ephemeral_deleted": d.Ephemeral}})
	w.WriteHeader(http.StatusNoContent)
	return nil
}
