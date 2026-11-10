package api

import (
	"crypto/rand"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/siv151992-lang/network-connector/internal/api/httpx"
	"github.com/siv151992-lang/network-connector/internal/auth"
	"github.com/siv151992-lang/network-connector/internal/devices"
	"github.com/siv151992-lang/network-connector/internal/store"
)

// Device-code login: a headless device (CLI, server, TV) starts a login and
// shows a short code; the user opens <public URL>/activate, signs in, picks a
// network and approves. The device polls with a secret token and receives
// its credential once. Private keys still never leave the device.

const (
	deviceLoginTTL  = 10 * time.Minute
	codeAlphabet    = "BCDFGHJKLMNPQRSTVWXZ" // no vowels (no words), no lookalikes
	pollTokenPrefix = "wml_"
)

func (s *Server) loginRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/v1/device/login/start", s.handle(s.limited(s.handleLoginStart)))
	mux.HandleFunc("POST /api/v1/device/login/poll", s.handle(s.handleLoginPoll))
	mux.HandleFunc("GET /api/v1/device/login/{code}", s.handle(s.user(s.handleLoginInfo)))
	mux.HandleFunc("POST /api/v1/device/login/approve", s.handle(s.limited(s.user(s.handleLoginApprove))))
}

func newCode() (string, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	out := make([]byte, 0, 9)
	for i, x := range b {
		if i == 4 {
			out = append(out, '-')
		}
		out = append(out, codeAlphabet[int(x)%len(codeAlphabet)]) // 256 % 20 bias is negligible for a 10-minute code
	}
	return string(out), nil
}

// normalizeCode accepts "bcdf ghjk", "BCDFGHJK", "bcdf-ghjk".
func normalizeCode(c string) string {
	c = strings.ToUpper(strings.NewReplacer("-", "", " ", "").Replace(strings.TrimSpace(c)))
	if len(c) != 8 {
		return c
	}
	return c[:4] + "-" + c[4:]
}

type loginStartReq struct {
	NodeKey       string `json:"node_key"`
	DiscoKey      string `json:"disco_key"`
	Hostname      string `json:"hostname"`
	OS            string `json:"os"`
	OSVersion     string `json:"os_version"`
	ClientVersion string `json:"client_version"`
}

func (s *Server) handleLoginStart(w http.ResponseWriter, r *http.Request) error {
	var req loginStartReq
	if err := httpx.DecodeJSON(r, &req); err != nil {
		return err
	}
	nk, err1 := devices.ParseKey(req.NodeKey)
	dk, err2 := devices.ParseKey(req.DiscoKey)
	if err1 != nil || err2 != nil {
		return httpx.Validation(map[string]string{"node_key": "node_key and disco_key must be base64 32-byte keys"})
	}
	if _, err := s.store.GetDeviceByNodeKey(r.Context(), nk); err == nil {
		return httpx.Conflict("this node key is already registered")
	}
	poll, pollHash, err := auth.NewToken(pollTokenPrefix)
	if err != nil {
		return err
	}
	exp := s.now().Add(deviceLoginTTL)
	var l *store.DeviceLogin
	for attempt := 0; attempt < 5; attempt++ {
		code, err := newCode()
		if err != nil {
			return err
		}
		l, err = s.store.CreateDeviceLogin(r.Context(), store.DeviceLogin{
			Code: code, NodeKey: nk, DiscoKey: dk, Hostname: req.Hostname, OS: req.OS,
			OSVersion: req.OSVersion, ClientVersion: req.ClientVersion, ExpiresAt: exp,
		}, pollHash)
		if err == nil {
			break
		}
		if !errors.Is(err, store.ErrConflict) {
			return err
		}
	}
	if l == nil {
		return errors.New("could not allocate a login code")
	}
	u := *s.cfg.PublicURL
	u.Path += "/activate"
	u.RawQuery = "code=" + l.Code
	httpx.WriteJSON(w, http.StatusCreated, map[string]any{
		"code": l.Code, "poll_token": poll, "verify_url": u.String(), "expires_at": exp, "interval": "3s",
	})
	return nil
}

func (s *Server) handleLoginPoll(w http.ResponseWriter, r *http.Request) error {
	var req struct {
		PollToken string `json:"poll_token"`
	}
	if err := httpx.DecodeJSON(r, &req); err != nil {
		return err
	}
	hash, ok := auth.ParseToken(req.PollToken, pollTokenPrefix)
	if !ok {
		return httpx.BadRequest("invalid poll token")
	}
	l, err := s.store.GetDeviceLoginByPoll(r.Context(), hash)
	if errors.Is(err, store.ErrNotFound) {
		return &httpx.Error{Status: http.StatusGone, Code: "login_expired", Message: "login expired or already completed; start again"}
	}
	if err != nil {
		return err
	}
	if l.ApprovedBy == nil || l.CredentialEnc == nil {
		httpx.WriteJSON(w, http.StatusOK, map[string]string{"status": "pending"})
		return nil
	}
	cred, err := s.box.Open(l.CredentialEnc, []byte("devlogin:"+l.ID.String()))
	if err != nil {
		return err
	}
	// Hand the credential out exactly once.
	if err := s.store.DeleteDeviceLogin(r.Context(), l.ID); err != nil {
		return err
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"status": "approved", "credential": string(cred), "device_id": l.DeviceID})
	return nil
}

func (s *Server) handleLoginInfo(w http.ResponseWriter, r *http.Request, p *principal) error {
	l, err := s.store.GetDeviceLoginByCode(r.Context(), normalizeCode(r.PathValue("code")))
	if errors.Is(err, store.ErrNotFound) {
		return httpx.NotFound("no pending login with that code (it may have expired)")
	}
	if err != nil {
		return err
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"login": l})
	return nil
}

func (s *Server) handleLoginApprove(w http.ResponseWriter, r *http.Request, p *principal) error {
	var req struct {
		Code      string `json:"code"`
		NetworkID string `json:"network_id"`
	}
	if err := httpx.DecodeJSON(r, &req); err != nil {
		return err
	}
	nid, err := uuid.Parse(req.NetworkID)
	if err != nil {
		return httpx.Validation(map[string]string{"network_id": "required"})
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

	var dev *store.Device
	err = s.store.WithTx(r.Context(), func(tx *store.Store) error {
		l, err := tx.LockDeviceLoginByCode(r.Context(), normalizeCode(req.Code))
		if errors.Is(err, store.ErrNotFound) {
			return httpx.NotFound("no pending login with that code (it may have expired)")
		}
		if err != nil {
			return err
		}
		res, err := (&devices.Registrar{Store: tx, Now: s.now}).Register(r.Context(), devices.Request{
			UserID: p.User.ID, NetworkID: nid, NodeKey: l.NodeKey, DiscoKey: l.DiscoKey,
			Hostname: l.Hostname, OS: l.OS, OSVersion: l.OSVersion, ClientVersion: l.ClientVersion,
		})
		if errors.Is(err, devices.ErrNodeKeyInUse) {
			return httpx.Conflict("this device is already registered")
		}
		if err != nil {
			return err
		}
		// An owner/admin approving the code has approved this exact device.
		if store.IsNetworkAdmin(role) && res.Device.Status == store.DeviceStatusPending {
			if res.Device, err = tx.SetDeviceStatus(r.Context(), nid, res.Device.ID, store.DeviceStatusApproved, &p.User.ID); err != nil {
				return err
			}
		}
		enc, err := s.box.Seal([]byte(res.Credential), []byte("devlogin:"+l.ID.String()))
		if err != nil {
			return err
		}
		dev = res.Device
		return tx.ApproveDeviceLogin(r.Context(), l.ID, p.User.ID, res.Device.ID, enc)
	})
	if err != nil {
		return err
	}
	s.notify(nid)
	s.audit(r, store.NewAuditEntry{NetworkID: &nid, ActorUserID: &p.User.ID, ActorDeviceID: &dev.ID, Action: "device.register",
		TargetType: "device", TargetID: dev.ID.String(), Metadata: map[string]any{"name": dev.Name, "via": "device_code", "status": dev.Status}})
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"device": dev})
	return nil
}
