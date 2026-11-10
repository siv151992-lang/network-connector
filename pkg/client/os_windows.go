//go:build windows

package client

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"

	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/ipc"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

// windowsConfigurator sets addresses and routes on the Wintun adapter via
// the IP Helper API (winipcfg), identified by its LUID.
type windowsConfigurator struct {
	luid winipcfg.LUID
}

func newOSConfigurator(name string, tdev tun.Device, log *slog.Logger) (OSConfigurator, error) {
	nt, ok := tdev.(*tun.NativeTun)
	if !ok {
		return nil, errors.New("unexpected TUN device type on Windows")
	}
	return &windowsConfigurator{luid: winipcfg.LUID(nt.LUID())}, nil
}

func split(ps []netip.Prefix) (v4, v6 []netip.Prefix) {
	for _, p := range ps {
		if !p.IsValid() {
			continue
		}
		if p.Addr().Is4() {
			v4 = append(v4, p)
		} else {
			v6 = append(v6, p)
		}
	}
	return
}

func routes(ps []netip.Prefix, nextHop netip.Addr) []*winipcfg.RouteData {
	var out []*winipcfg.RouteData
	for _, p := range ps {
		out = append(out, &winipcfg.RouteData{Destination: p.Masked(), NextHop: nextHop, Metric: 0})
	}
	return out
}

func (c *windowsConfigurator) Set(addrs, rts []netip.Prefix) error {
	a4, a6 := split(addrs)
	r4, r6 := split(rts)
	if err := c.luid.SetIPAddressesForFamily(winipcfg.AddressFamily(2) /* AF_INET */, a4); err != nil {
		return fmt.Errorf("set IPv4 addresses: %w", err)
	}
	if err := c.luid.SetRoutesForFamily(winipcfg.AddressFamily(2), routes(r4, netip.IPv4Unspecified())); err != nil {
		return fmt.Errorf("set IPv4 routes: %w", err)
	}
	if len(a6) > 0 {
		// IPv6 may be disabled on the host: degrade to IPv4-only like Linux.
		if err := c.luid.SetIPAddressesForFamily(winipcfg.AddressFamily(23) /* AF_INET6 */, a6); err == nil {
			_ = c.luid.SetRoutesForFamily(winipcfg.AddressFamily(23), routes(r6, netip.IPv6Unspecified()))
		}
	}
	return nil
}

// Close needs no work: removing the adapter removes its addresses and routes.
func (c *windowsConfigurator) Close() error { return nil }

// startUAPI serves WireGuard's UAPI on the named pipe \\.\pipe\ProtectedPrefix\Administrators\WireGuard\<name>.
func startUAPI(name string, dev *device.Device, log *slog.Logger) (io.Closer, error) {
	l, err := ipc.UAPIListen(name)
	if err != nil {
		return nil, err
	}
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				if !errors.Is(err, net.ErrClosed) {
					log.Debug("uapi accept", "error", err)
				}
				return
			}
			go dev.IpcHandle(c)
		}
	}()
	return l, nil
}

// Split-horizon DNS on Windows needs NRPT rules; until then MagicDNS names
// are served (query <tunnel IP>:53 directly) but not wired into the resolver.
func configureSystemDNS(string, netip.Addr, string) error {
	return errors.New("automatic DNS configuration is not implemented on Windows yet (NRPT)")
}
