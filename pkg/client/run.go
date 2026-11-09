package client

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"runtime"
	"slices"
	"sort"
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

	if st.Credential == "" {
		if o.AuthKey == "" {
			return errors.New("device is not enrolled: pass --auth-key (create one in the dashboard or via POST /networks/{id}/auth-keys)")
		}
		host := o.Hostname
		if host == "" {
			host, _ = os.Hostname()
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
	nm, err := waitForMap(ctx, ctl, log)
	if err != nil {
		return err
	}

	eng, err := NewEngine(EngineConfig{InterfaceName: o.InterfaceName, PrivateKey: st.NodePrivate, ListenPort: o.ListenPort, Log: log})
	if err != nil {
		return err
	}
	defer eng.Close()

	var lastEndpoints []netip.AddrPort
	var applied *protocol.NetworkMap
	version := ""
	for {
		// Report endpoints whenever local addresses change (e.g. Wi-Fi -> LTE).
		eps := LocalEndpoints(eng.ListenPort(), eng.Name())
		if !slices.Equal(eps, lastEndpoints) {
			if err := ctl.ReportEndpoints(ctx, protocol.EndpointsUpdate{Endpoints: eps, ListenPort: eng.ListenPort()}); err != nil {
				if errors.Is(err, ErrUnauthorized) {
					return err
				}
				log.Warn("reporting endpoints failed", "error", err)
			} else {
				lastEndpoints = eps
				log.Info("reported endpoints", "endpoints", fmt.Sprint(eps))
				version = "" // our own endpoints changed: refetch so peers' view is current
			}
		}

		if nm != nil {
			if err := eng.Apply(nm); err != nil {
				log.Error("applying network map failed", "error", err)
			} else {
				version = nm.Version
				applied = nm
				if o.OnMap != nil {
					o.OnMap(nm)
				}
			}
		}

		interval := 10 * time.Second
		if nm != nil && nm.PollInterval > 0 {
			interval = time.Duration(nm.PollInterval)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(interval):
		}

		next, err := ctl.Netmap(ctx, version)
		switch {
		case errors.Is(err, ErrUnauthorized):
			log.Error("device credential revoked; shutting tunnel down")
			return err
		case errors.Is(err, ErrNotApproved):
			log.Warn("device no longer approved; removing all peers")
			nm = nil
			if applied != nil && len(applied.Peers) > 0 {
				cleared := *applied // keep addresses and routes, drop peers and rules
				cleared.Peers, cleared.PacketFilter, cleared.Version = nil, nil, ""
				nm = &cleared
			}
		case err != nil:
			log.Warn("fetching network map failed; keeping current config", "error", err)
			nm = nil
		default:
			nm = next // nil when unchanged
		}
	}
}

// waitForMap polls until the device is approved and returns its first map.
func waitForMap(ctx context.Context, ctl *Control, log *slog.Logger) (*protocol.NetworkMap, error) {
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

// LocalEndpoints lists this machine's usable unicast addresses with the
// WireGuard port: the direct candidates peers on the same network can use.
// Phase 5 adds the STUN-discovered public endpoint.
func LocalEndpoints(port uint16, exclude string) []netip.AddrPort {
	var out []netip.AddrPort
	ifaces, err := net.Interfaces()
	if err != nil || port == 0 {
		return nil
	}
	for _, ifc := range ifaces {
		if ifc.Name == exclude || ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, _ := ifc.Addrs()
		for _, a := range addrs {
			ipn, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			ip, ok := netip.AddrFromSlice(ipn.IP)
			if !ok {
				continue
			}
			ip = ip.Unmap()
			if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsMulticast() || ip.IsUnspecified() {
				continue
			}
			out = append(out, netip.AddrPortFrom(ip, port))
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Addr().Is4() != out[j].Addr().Is4() {
			return out[i].Addr().Is4()
		}
		return out[i].String() < out[j].String()
	})
	if len(out) > 16 {
		out = out[:16]
	}
	return out
}
