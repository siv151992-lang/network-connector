//go:build linux && !android

package client

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"os/exec"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/ipc"
	"golang.zx2c4.com/wireguard/tun"
)

// linuxConfigurator manages addresses and routes with netlink (no shelling
// out to `ip`), remembering what it added so updates remove stale entries.
type linuxConfigurator struct {
	log    *slog.Logger
	ipv6   bool // false on kernels booted without IPv6 (ipv6.disable=1)
	warned bool
	link   netlink.Link
	addrs  []netip.Prefix
	routes []netip.Prefix
}

func newOSConfigurator(name string, _ tun.Device, log *slog.Logger) (OSConfigurator, error) {
	link, err := netlink.LinkByName(name)
	if err != nil {
		return nil, fmt.Errorf("find interface %s: %w", name, err)
	}
	_, err = os.Stat("/proc/sys/net/ipv6")
	return &linuxConfigurator{link: link, log: log, ipv6: err == nil}, nil
}

// family drops IPv6 prefixes when the kernel has no IPv6, so the tunnel
// still works over IPv4 instead of failing to configure.
func (c *linuxConfigurator) family(ps []netip.Prefix) []netip.Prefix {
	if c.ipv6 {
		return ps
	}
	var out []netip.Prefix
	for _, p := range ps {
		if p.Addr().Is4() {
			out = append(out, p)
		} else if !c.warned {
			c.warned = true
			c.log.Warn("kernel has no IPv6 support; using IPv4 only on the tunnel")
		}
	}
	return out
}

func ipnet(p netip.Prefix) *net.IPNet {
	return &net.IPNet{IP: p.Addr().AsSlice(), Mask: net.CIDRMask(p.Bits(), p.Addr().BitLen())}
}

func (c *linuxConfigurator) Set(addrs, routes []netip.Prefix) error {
	addrs, routes = c.family(addrs), c.family(routes)
	if err := netlink.LinkSetUp(c.link); err != nil {
		return fmt.Errorf("link up: %w", err)
	}
	want := map[netip.Prefix]bool{}
	for _, a := range addrs {
		want[a] = true
		na := &netlink.Addr{IPNet: ipnet(a)}
		if a.Addr().Is6() {
			na.Flags = unix.IFA_F_NODAD // no duplicate-address detection delay on a point-to-point tunnel
		}
		if err := netlink.AddrReplace(c.link, na); err != nil {
			return fmt.Errorf("add address %s: %w", a, err)
		}
	}
	for _, a := range c.addrs {
		if !want[a] {
			_ = netlink.AddrDel(c.link, &netlink.Addr{IPNet: ipnet(a)})
		}
	}
	c.addrs = addrs

	wantR := map[netip.Prefix]bool{}
	for _, r := range routes {
		if !r.IsValid() {
			continue
		}
		wantR[r] = true
		if err := netlink.RouteReplace(&netlink.Route{LinkIndex: c.link.Attrs().Index, Dst: ipnet(r.Masked()), Scope: netlink.SCOPE_LINK}); err != nil {
			return fmt.Errorf("add route %s: %w", r, err)
		}
	}
	for _, r := range c.routes {
		if !wantR[r] {
			_ = netlink.RouteDel(&netlink.Route{LinkIndex: c.link.Attrs().Index, Dst: ipnet(r.Masked())})
		}
	}
	c.routes = routes
	return nil
}

// Close needs no work: deleting the TUN interface removes its addresses and routes.
func (c *linuxConfigurator) Close() error { return nil }

// startUAPI serves WireGuard's UAPI on /var/run/wireguard/<iface>.sock.
func startUAPI(name string, dev *device.Device, log *slog.Logger) (io.Closer, error) {
	f, err := ipc.UAPIOpen(name)
	if err != nil {
		return nil, err
	}
	l, err := ipc.UAPIListen(name, f)
	if err != nil {
		f.Close()
		return nil, err
	}
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				if !errors.Is(err, net.ErrClosed) && !errors.Is(err, os.ErrClosed) {
					log.Debug("uapi accept", "error", err)
				}
				return
			}
			go dev.IpcHandle(c)
		}
	}()
	return l, nil
}

// configureSystemDNS routes queries for domain to our MagicDNS server via
// systemd-resolved (per-link DNS + routing-only domain). The settings vanish
// with the interface, so there is nothing to undo.
func configureSystemDNS(iface string, server netip.Addr, domain string) error {
	path, err := exec.LookPath("resolvectl")
	if err != nil {
		return errors.New("systemd-resolved (resolvectl) not available")
	}
	if out, err := exec.Command(path, "dns", iface, server.String()).CombinedOutput(); err != nil {
		return fmt.Errorf("resolvectl dns: %v: %s", err, out)
	}
	if out, err := exec.Command(path, "domain", iface, "~"+domain).CombinedOutput(); err != nil {
		return fmt.Errorf("resolvectl domain: %v: %s", err, out)
	}
	return nil
}
