package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/netip"
	"strings"

	"github.com/siv151992-lang/network-connector/internal/acl"
	"github.com/siv151992-lang/network-connector/internal/api/httpx"
	"github.com/siv151992-lang/network-connector/internal/coord"
	"github.com/siv151992-lang/network-connector/internal/store"
	"github.com/siv151992-lang/network-connector/pkg/protocol"
)

func (s *Server) aclRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/networks/{nid}/acl", s.handle(s.member(s.handleGetACL)))
	mux.HandleFunc("PUT /api/v1/networks/{nid}/acl", s.handle(s.netAdmin(s.handlePutACL)))
	mux.HandleFunc("POST /api/v1/networks/{nid}/acl/test", s.handle(s.member(s.handleTestACL)))

	mux.HandleFunc("GET /api/v1/device/netmap", s.handle(s.device(s.handleNetmap)))
	mux.HandleFunc("POST /api/v1/device/endpoints", s.handle(s.device(s.handleEndpoints)))
	mux.HandleFunc("GET /api/v1/device/stream", s.handle(s.device(s.handleStream)))
}

func policyError(err error) error {
	var ve *acl.ValidationError
	if errors.As(err, &ve) {
		return &httpx.Error{Status: http.StatusUnprocessableEntity, Code: "invalid_policy",
			Message: strings.Join(ve.Problems, "; ")}
	}
	return err
}

func (s *Server) handleGetACL(w http.ResponseWriter, r *http.Request, n *netCtx) error {
	p, err := s.store.GetACLPolicy(r.Context(), n.Network.ID)
	if errors.Is(err, store.ErrNotFound) {
		httpx.WriteJSON(w, http.StatusOK, map[string]any{
			"policy": json.RawMessage(acl.DefaultPolicyJSON), "version": 0, "is_default": true})
		return nil
	}
	if err != nil {
		return err
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"policy": p.Policy, "version": p.Version, "is_default": false, "updated_at": p.UpdatedAt, "updated_by": p.UpdatedBy})
	return nil
}

type putACLReq struct {
	Policy  json.RawMessage `json:"policy"`
	Version *int            `json:"version"` // the version you edited; required (optimistic concurrency)
}

func (s *Server) handlePutACL(w http.ResponseWriter, r *http.Request, n *netCtx) error {
	var req putACLReq
	if err := httpx.DecodeJSON(r, &req); err != nil {
		return err
	}
	if req.Version == nil {
		return httpx.Validation(map[string]string{"version": "required: the version you loaded (0 for the default policy)"})
	}
	pol, err := acl.Parse(req.Policy)
	if err != nil {
		return policyError(err)
	}
	canonical, err := json.Marshal(pol)
	if err != nil {
		return err
	}
	saved, err := s.store.PutACLPolicy(r.Context(), n.Network.ID, *req.Version, canonical, n.User.ID)
	if errors.Is(err, store.ErrStaleVersion) {
		return &httpx.Error{Status: http.StatusConflict, Code: "stale_version", Message: err.Error()}
	}
	if err != nil {
		return err
	}
	s.notify(n.Network.ID)
	s.netAudit(r, n, "acl.update", "acl", n.Network.ID.String(), map[string]any{"version": saved.Version, "rules": len(pol.ACLs)})
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"policy": saved.Policy, "version": saved.Version, "updated_at": saved.UpdatedAt})
	return nil
}

type testACLReq struct {
	Src    string          `json:"src"`    // device name or address
	Dst    string          `json:"dst"`    // device name or address
	Proto  string          `json:"proto"`  // tcp (default) | udp | icmp
	Port   uint16          `json:"port"`   // ignored for icmp
	Policy json.RawMessage `json:"policy"` // optional draft to test instead of the saved policy
}

// handleTestACL answers "may src reach dst:port?", using the exact filter
// that the destination device would enforce.
func (s *Server) handleTestACL(w http.ResponseWriter, r *http.Request, n *netCtx) error {
	if !n.canViewAll() {
		return httpx.Forbidden("admin or auditor role required")
	}
	var req testACLReq
	if err := httpx.DecodeJSON(r, &req); err != nil {
		return err
	}
	proto := protocol.ProtoTCP
	switch strings.ToLower(req.Proto) {
	case "", "tcp":
	case "udp":
		proto = protocol.ProtoUDP
	case "icmp":
		proto = protocol.ProtoICMP
	default:
		return httpx.Validation(map[string]string{"proto": "must be tcp, udp or icmp"})
	}
	b := s.builder
	var policy *acl.Compiled
	var err error
	if len(req.Policy) > 0 {
		pol, err := acl.Parse(req.Policy)
		if err != nil {
			return policyError(err)
		}
		if policy, err = acl.Compile(pol); err != nil {
			return policyError(err)
		}
	} else if policy, err = b.Policy(r.Context(), n.Network.ID); err != nil {
		return err
	}
	all, _, _, err := b.Members(r.Context(), n.Network.ID)
	if err != nil {
		return err
	}
	find := func(field, q string) (acl.Device, error) {
		for _, d := range all {
			if d.ID == q {
				return d, nil
			}
		}
		if a, err := netip.ParseAddr(q); err == nil {
			for _, d := range all {
				for _, da := range d.Addrs {
					if da == a {
						return d, nil
					}
				}
			}
		}
		devs, err := s.store.ListDevices(r.Context(), n.Network.ID, store.DeviceFilter{Status: store.DeviceStatusApproved})
		if err != nil {
			return acl.Device{}, err
		}
		for _, d := range devs {
			if d.Name == q {
				for _, ad := range all {
					if ad.ID == d.ID.String() {
						return ad, nil
					}
				}
			}
		}
		return acl.Device{}, httpx.Validation(map[string]string{field: "no approved, unexpired device with that name, id or address"})
	}
	src, err := find("src", req.Src)
	if err != nil {
		return err
	}
	dst, err := find("dst", req.Dst)
	if err != nil {
		return err
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"allowed": policy.Check(src, dst, all, proto, req.Port),
		"src":     src.ID, "dst": dst.ID,
	})
	return nil
}

// ---------------------------------------------------------------------------
// Device side
// ---------------------------------------------------------------------------

// handleNetmap returns the device's compiled network map. Clients send
// If-None-Match with the last version; unchanged maps cost a 304.
func (s *Server) handleNetmap(w http.ResponseWriter, r *http.Request, d *store.Device) error {
	if err := s.store.TouchDevice(r.Context(), d.ID); err != nil {
		return err
	}
	nm, err := s.builder.Build(r.Context(), d)
	if errors.Is(err, coord.ErrNotApproved) {
		return &httpx.Error{Status: http.StatusForbidden, Code: "device_not_approved",
			Message: "device status is " + d.Status + "; an admin must approve it"}
	}
	if err != nil {
		return err
	}
	etag := `"` + nm.Version + `"`
	w.Header().Set("ETag", etag)
	if r.Header.Get("If-None-Match") == etag {
		w.WriteHeader(http.StatusNotModified)
		return nil
	}
	httpx.WriteJSON(w, http.StatusOK, nm)
	return nil
}

const maxEndpoints = 16

// handleEndpoints records where the device can be reached (REST form; the
// stream carries the same message). Clients report interface addresses and
// STUN-discovered public addresses.
func (s *Server) handleEndpoints(w http.ResponseWriter, r *http.Request, d *store.Device) error {
	var req protocol.EndpointsUpdate
	if err := httpx.DecodeJSON(r, &req); err != nil {
		return err
	}
	if err := s.storeEndpoints(r.Context(), d, req); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}
