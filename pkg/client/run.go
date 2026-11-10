package client

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"runtime"
	"slices"
	"time"

	"github.com/siv151992-lang/network-connector/pkg/protocol"
)

// Options configures Run.
type Options struct {
	ServerURL     string
	AuthKey       string // needed only for the first run
	StatePath     string
	InterfaceName string
	ListenPort    uint16
	Hostname      string
	Version       string
	Log           *slog.Logger
	// OnMap, if set, is called after each successfully applied network map.
	OnMap func(*protocol.NetworkMap)
	// OnLogin, if set, enables device-code login when there is no auth key:
	// it receives the URL and code the user must open/enter.
	OnLogin func(url, code string)
	// OnEngine is called once the tunnel exists (daemon status uses it).
	OnEngine func(*Engine)
	// OnNeedsApproval is called while an admin still has to approve the device.
	OnNeedsApproval func()
}

// Run enrolls the device if needed, brings up the tunnel and keeps it in sync
// with the control server until ctx is cancelled or the device is revoked.
func Run(ctx context.Context, o Options) error {
	log := o.Log
	if log == nil {
		log = slog.Default()
	}
	st, err := LoadOrCreateState(o.StatePath, o.ServerURL)
	if err != nil {
		return err
	}
	if o.ServerURL == "" {
		o.ServerURL = st.ServerURL
	}
	if o.ServerURL == "" {
		return errors.New("no server URL: pass --server on first run")
	}
	if st.ServerURL == "" {
		st.ServerURL = o.ServerURL
	}
	ctl, err := NewControl(o.ServerURL, st.Credential, o.Version)
	if err != nil {
		return err
	}

	host := o.Hostname
	if host == "" {
		host, _ = os.Hostname()
	}
	if st.Credential == "" && o.AuthKey == "" && o.OnLogin != nil {
		cred, err := deviceCodeLogin(ctx, ctl, st, host, o.Version, o.OnLogin, log)
		if err != nil {
			return err
		}
		st.Credential = cred
		if err := st.Save(o.StatePath); err != nil {
			return fmt.Errorf("save state: %w", err)
		}
		ctl.SetCredential(cred)
		log.Info("logged in with device code")
	}
	if st.Credential == "" {
		if o.AuthKey == "" {
			return errors.New("device is not enrolled: pass --auth-key (create one in the dashboard or via POST /networks/{id}/auth-keys)")
		}
		res, err := ctl.Register(ctx, RegisterRequest{
			AuthKey: o.AuthKey, NodeKey: st.NodePrivate.Public().String(), DiscoKey: st.DiscoPrivate.Public().String(),
			Hostname: host, OS: runtime.GOOS, ClientVersion: o.Version,
		})
		if err != nil {
			return fmt.Errorf("enroll: %w", err)
		}
		st.Credential, st.DeviceID, st.NetworkID = res.Credential, res.Device.ID, res.Device.NetworkID
		if err := st.Save(o.StatePath); err != nil {
			return fmt.Errorf("save state (the server has enrolled this device; keep the credential safe): %w", err)
		}
		ctl.SetCredential(st.Credential)
		log.Info("enrolled", "name", res.Device.Name, "ipv4", res.Device.IPv4, "ipv6", res.Device.IPv6, "status", res.Device.Status)
	}

	// Wait for approval before creating any interface.
	nm, err := waitForMap(ctx, ctl, log, o.OnNeedsApproval)
	if err != nil {
		return err
	}

	eng, err := NewEngine(EngineConfig{InterfaceName: o.InterfaceName, PrivateKey: st.NodePrivate,
		DiscoPrivate: st.DiscoPrivate, ListenPort: o.ListenPort, Log: log, RelayToken: ctl.RelayToken})
	if err != nil {
		return err
	}
	defer eng.Close()
	if o.OnEngine != nil {
		o.OnEngine(eng)
	}
	apply := func(m *protocol.NetworkMap) {
		if err := eng.Apply(m); err != nil {
			log.Error("applying network map failed", "error", err)
			return
		}
		if o.OnMap != nil {
			o.OnMap(m)
		}
	}
	apply(nm)

	// Endpoint changes (STUN, interface changes) wake the stream loop.
	epChanged := make(chan struct{}, 1)
	eng.Magic().OnEndpointsChanged(func() {
		select {
		case epChanged <- struct{}{}:
		default:
		}
	})

	backoff := time.Second
	for {
		err := runStream(ctx, ctl, eng, log, apply, epChanged)
		switch {
		case ctx.Err() != nil:
			return nil
		case errors.Is(err, ErrUnauthorized):
			log.Error("device credential revoked; shutting tunnel down")
			return err
		case errors.Is(err, ErrNotApproved):
			log.Warn("device no longer approved; removing all peers")
			cleared := *nm
			cleared.Peers, cleared.PacketFilter = nil, nil
			apply(&cleared)
		}
		// Keep the tunnel running with the last map while reconnecting.
		log.Warn("control stream down; reconnecting", "error", err, "in", backoff)
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(jitter(backoff)):
		}
		backoff = min(backoff*2, 30*time.Second)
		if err == nil {
			backoff = time.Second
		}
	}
}

func jitter(d time.Duration) time.Duration {
	return d/2 + time.Duration(time.Now().UnixNano()%int64(d/2+1))
}

// runStream holds one control-stream session: receives maps and
// call-me-maybe, reports endpoints, and relays our call-me-maybe requests.
func runStream(ctx context.Context, ctl *Control, eng *Engine, log *slog.Logger,
	apply func(*protocol.NetworkMap), epChanged <-chan struct{}) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	st, err := ctl.Stream(ctx)
	if err != nil {
		return err
	}
	defer st.Close()
	log.Info("control stream connected")

	ms := eng.Magic()
	ms.SetCallMeMaybeSender(func(to protocol.Key, eps []netip.AddrPort, quiesce bool) {
		_ = st.Send(ctx, protocol.StreamMessage{Type: protocol.StreamCallMeMaybe,
			CallMeMaybe: &protocol.CallMeMaybe{To: to, Endpoints: eps, Quiesce: quiesce}})
	})
	defer ms.SetCallMeMaybeSender(nil)

	errc := make(chan error, 3)
	go func() { errc <- st.KeepAlive(ctx, 25*time.Second) }()

	// Writer: endpoint reports (now, and whenever they change).
	go func() {
		var last []netip.AddrPort
		report := func() error {
			eps := ms.Endpoints()
			if slices.Equal(eps, last) {
				return nil
			}
			if err := st.Send(ctx, protocol.StreamMessage{Type: protocol.StreamEndpoints,
				Endpoints: &protocol.EndpointsUpdate{Endpoints: eps, ListenPort: eng.ListenPort()}}); err != nil {
				return err
			}
			last = eps
			log.Info("reported endpoints", "endpoints", fmt.Sprint(eps))
			return nil
		}
		if err := report(); err != nil {
			errc <- err
			return
		}
		for {
			select {
			case <-ctx.Done():
				return
			case <-epChanged:
				if err := report(); err != nil {
					errc <- err
					return
				}
			}
		}
	}()

	// Reader.
	go func() {
		for {
			m, err := st.Recv(ctx)
			if err != nil {
				errc <- err
				return
			}
			switch m.Type {
			case protocol.StreamMap:
				if m.Map != nil {
					apply(m.Map)
				}
			case protocol.StreamCallMeMaybe:
				if m.CallMeMaybe != nil {
					ms.HandleCallMeMaybe(m.CallMeMaybe.From, m.CallMeMaybe.Endpoints, m.CallMeMaybe.Quiesce)
				}
			case protocol.StreamRevoked:
				errc <- ErrUnauthorized
				return
			}
		}
	}()
	return <-errc
}

// waitForMap polls until the device is approved and returns its first map.
func waitForMap(ctx context.Context, ctl *Control, log *slog.Logger, onWait func()) (*protocol.NetworkMap, error) {
	logged := false
	for {
		nm, err := ctl.Netmap(ctx, "")
		switch {
		case err == nil:
			return nm, nil
		case errors.Is(err, ErrNotApproved):
			if !logged {
				log.Info("waiting for an admin to approve this device in the dashboard")
				logged = true
				if onWait != nil {
					onWait()
				}
			}
		case errors.Is(err, ErrUnauthorized):
			return nil, err
		default:
			log.Warn("control server unreachable; retrying", "error", err)
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(5 * time.Second):
		}
	}
}

// deviceCodeLogin runs the device-code flow: start, show the code, poll
// until a user approves it in the dashboard. Expired codes are renewed.
func deviceCodeLogin(ctx context.Context, ctl *Control, st *State, host, version string, show func(url, code string), log *slog.Logger) (string, error) {
	for {
		start, err := ctl.LoginStart(ctx, LoginStartRequest{
			NodeKey: st.NodePrivate.Public().String(), DiscoKey: st.DiscoPrivate.Public().String(),
			Hostname: host, OS: runtime.GOOS, ClientVersion: version,
		})
		if err != nil {
			return "", fmt.Errorf("start login: %w", err)
		}
		show(start.VerifyURL, start.Code)
		log.Info("waiting for login approval", "url", start.VerifyURL, "code", start.Code)
		for {
			select {
			case <-ctx.Done():
				return "", ctx.Err()
			case <-time.After(3 * time.Second):
			}
			cred, err := ctl.LoginPoll(ctx, start.PollToken)
			if errors.Is(err, ErrLoginExpired) {
				break // new code
			}
			if err != nil {
				log.Warn("login poll failed; retrying", "error", err)
				continue
			}
			if cred != "" {
				return cred, nil
			}
		}
	}
}
