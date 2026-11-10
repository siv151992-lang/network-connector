package client

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/siv151992-lang/network-connector/pkg/protocol"
)

// Daemon manages the tunnel for wiremeshd (Linux) and the Windows service.
// It exposes a small local HTTP API (served on a Unix socket or named pipe,
// never on TCP) used by the `wiremesh` CLI and GUIs:
//
//	GET  /status            DaemonStatus
//	POST /up      UpRequest  start (enrolls via auth key or device-code login)
//	POST /down               stop and stay stopped across restarts
//	POST /logout             stop, revoke the credential, forget the device
type Daemon struct {
	StatePath     string
	InterfaceName string
	ListenPort    uint16
	Version       string
	Log           *slog.Logger

	mu        sync.Mutex
	state     string
	errMsg    string
	loginURL  string
	loginCode string
	server    string
	nm        *protocol.NetworkMap
	eng       *Engine
	cancel    context.CancelFunc
	done      chan struct{}
}

// Daemon states.
const (
	StateStopped       = "stopped"
	StateStarting      = "starting"
	StateNeedsLogin    = "needs_login"
	StateNeedsApproval = "needs_approval"
	StateRunning       = "running"
	StateError         = "error"
)

// UpRequest starts the tunnel.
type UpRequest struct {
	ServerURL string `json:"server_url,omitempty"`
	AuthKey   string `json:"auth_key,omitempty"`
	Hostname  string `json:"hostname,omitempty"`
}

// PeerStatus is one peer as shown by `wiremesh status`.
type PeerStatus struct {
	Name          string     `json:"name"`
	DNSName       string     `json:"dns_name,omitempty"`
	Addresses     []string   `json:"addresses"`
	OS            string     `json:"os,omitempty"`
	Online        bool       `json:"online"`
	Path          string     `json:"path,omitempty"` // ip:port (direct) or "relay"
	LastHandshake *time.Time `json:"last_handshake,omitempty"`
	RxBytes       uint64     `json:"rx_bytes"`
	TxBytes       uint64     `json:"tx_bytes"`
}

// DaemonStatus is returned by GET /status.
type DaemonStatus struct {
	State     string       `json:"state"`
	Error     string       `json:"error,omitempty"`
	LoginURL  string       `json:"login_url,omitempty"`
	LoginCode string       `json:"login_code,omitempty"`
	ServerURL string       `json:"server_url,omitempty"`
	Self      *PeerStatus  `json:"self,omitempty"`
	Network   string       `json:"network,omitempty"`
	Domain    string       `json:"domain,omitempty"`
	DNS       string       `json:"dns,omitempty"`
	Peers     []PeerStatus `json:"peers"`
}

func (d *Daemon) set(f func()) { d.mu.Lock(); f(); d.mu.Unlock() }

// AutoStart brings the tunnel up at boot if the device is enrolled and the
// user did not run `wiremesh down`.
func (d *Daemon) AutoStart() {
	st, err := LoadState(d.StatePath)
	if err != nil || st.Down {
		d.set(func() {
			d.state = StateStopped
			if st != nil {
				d.server = st.ServerURL
			}
		})
		return
	}
	_ = d.Up(UpRequest{ServerURL: st.ServerURL})
}

// Up starts the tunnel (no-op if already running).
func (d *Daemon) Up(req UpRequest) error {
	if req.ServerURL != "" {
		u, err := ResolveServerURL(context.Background(), req.ServerURL)
		if err != nil {
			d.set(func() { d.state, d.errMsg = StateError, err.Error() })
			return err
		}
		req.ServerURL = u
	}
	d.mu.Lock()
	if d.cancel != nil {
		d.mu.Unlock()
		return nil
	}
	st, err := LoadOrCreateState(d.StatePath, req.ServerURL)
	if err == nil && st.ServerURL == "" {
		err = errors.New("no server URL: run `wiremesh up --server https://…` the first time")
	}
	if err != nil {
		d.state, d.errMsg = StateError, err.Error()
		d.mu.Unlock()
		return err
	}
	if st.Down {
		st.Down = false
		_ = st.Save(d.StatePath)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	d.cancel, d.done = cancel, done
	d.state, d.errMsg, d.loginURL, d.loginCode, d.server, d.nm, d.eng = StateStarting, "", "", "", st.ServerURL, nil, nil
	d.mu.Unlock()

	go func() {
		defer close(done)
		err := Run(ctx, Options{
			ServerURL: st.ServerURL, AuthKey: req.AuthKey, StatePath: d.StatePath, InterfaceName: d.InterfaceName,
			ListenPort: d.ListenPort, Hostname: req.Hostname, Version: d.Version, Log: d.Log,
			OnLogin: func(url, code string) {
				d.set(func() { d.state, d.loginURL, d.loginCode = StateNeedsLogin, url, code })
			},
			OnEngine:        func(e *Engine) { d.set(func() { d.eng = e }) },
			OnNeedsApproval: func() { d.set(func() { d.state, d.loginURL, d.loginCode = StateNeedsApproval, "", "" }) },
			OnMap: func(nm *protocol.NetworkMap) {
				d.set(func() { d.nm, d.state, d.loginURL, d.loginCode = nm, StateRunning, "", "" })
				d.Log.Info("network map applied", "self", nm.Self.Name, "peers", len(nm.Peers), "rules", len(nm.PacketFilter), "version", nm.Version)
			},
		})
		d.set(func() {
			d.cancel, d.eng = nil, nil
			switch {
			case ctx.Err() != nil:
				d.state = StateStopped
			case errors.Is(err, ErrUnauthorized):
				d.state, d.errMsg = StateError, "this device was revoked or logged out; run `wiremesh logout` then `wiremesh up` to enroll again"
			case err != nil:
				d.state, d.errMsg = StateError, err.Error()
			default:
				d.state = StateStopped
			}
		})
		if err != nil && ctx.Err() == nil {
			d.Log.Error("tunnel stopped", "error", err)
		}
	}()
	return nil
}

// Down stops the tunnel; persist=true keeps it down across restarts.
func (d *Daemon) Down(persist bool) {
	d.mu.Lock()
	cancel, done := d.cancel, d.done
	d.mu.Unlock()
	if cancel != nil {
		cancel()
		<-done
	}
	if persist {
		if st, err := LoadState(d.StatePath); err == nil {
			st.Down = true
			_ = st.Save(d.StatePath)
		}
	}
	d.set(func() { d.state, d.errMsg = StateStopped, "" })
}

// Logout stops the tunnel, revokes the credential server-side (best effort)
// and deletes local state, including private keys.
func (d *Daemon) Logout(ctx context.Context) error {
	d.Down(false)
	st, err := LoadState(d.StatePath)
	if err == nil {
		if ctl, err := NewControl(st.ServerURL, st.Credential, d.Version); err == nil {
			_ = ctl.Logout(ctx)
		}
	}
	if err := os.Remove(d.StatePath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// Status reports the current state, peers and live WireGuard statistics.
func (d *Daemon) Status() DaemonStatus {
	d.mu.Lock()
	s := DaemonStatus{State: d.state, Error: d.errMsg, LoginURL: d.loginURL, LoginCode: d.loginCode, ServerURL: d.server, Peers: []PeerStatus{}}
	nm, eng := d.nm, d.eng
	d.mu.Unlock()
	if s.State == "" {
		s.State = StateStopped
	}
	if nm == nil || s.State != StateRunning {
		return s
	}
	var stats map[protocol.Key]PeerStats
	if eng != nil {
		stats, _ = eng.Stats()
		if a := eng.DNSAddr(); a.IsValid() {
			s.DNS = a.String()
		}
	}
	dom := nm.Network.Domain
	conv := func(n protocol.Node) PeerStatus {
		p := PeerStatus{Name: n.Name, OS: n.OS, Online: n.Online, Addresses: []string{}}
		if dom != "" {
			p.DNSName = n.Name + "." + dom
		}
		for _, a := range n.Addresses {
			p.Addresses = append(p.Addresses, a.Addr().String())
		}
		if st, ok := stats[n.NodeKey]; ok {
			if !strings.HasPrefix(st.Endpoint, "wm:") {
				p.Path = st.Endpoint
			}
			if !st.LastHandshake.IsZero() {
				t := st.LastHandshake
				p.LastHandshake = &t
			}
			p.RxBytes, p.TxBytes = st.RxBytes, st.TxBytes
		}
		return p
	}
	self := conv(nm.Self)
	s.Self, s.Network, s.Domain = &self, nm.Network.Name, dom
	for _, n := range nm.Peers {
		s.Peers = append(s.Peers, conv(n))
	}
	sort.Slice(s.Peers, func(i, j int) bool { return s.Peers[i].Name < s.Peers[j].Name })
	return s
}

// Handler serves the local API.
func (d *Daemon) Handler() http.Handler {
	mux := http.NewServeMux()
	reply := func(w http.ResponseWriter, code int, v any) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		_ = json.NewEncoder(w).Encode(v)
	}
	mux.HandleFunc("GET /status", func(w http.ResponseWriter, r *http.Request) { reply(w, 200, d.Status()) })
	mux.HandleFunc("POST /up", func(w http.ResponseWriter, r *http.Request) {
		var req UpRequest
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil && err.Error() != "EOF" {
			reply(w, 400, map[string]string{"error": "bad request"})
			return
		}
		if err := d.Up(req); err != nil {
			reply(w, 409, map[string]string{"error": err.Error()})
			return
		}
		reply(w, 200, d.Status())
	})
	mux.HandleFunc("POST /down", func(w http.ResponseWriter, r *http.Request) {
		d.Down(true)
		reply(w, 200, d.Status())
	})
	mux.HandleFunc("POST /logout", func(w http.ResponseWriter, r *http.Request) {
		if err := d.Logout(r.Context()); err != nil {
			reply(w, 500, map[string]string{"error": err.Error()})
			return
		}
		reply(w, 200, d.Status())
	})
	return mux
}
