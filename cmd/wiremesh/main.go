// Command wiremesh is the Linux client (Phase 4 foreground version; Phase 9
// adds the wiremeshd systemd daemon, local API, DNS and packaging).
//
//	sudo wiremesh up --server https://vpn.example.com --auth-key wmk_…   # first run
//	sudo wiremesh up                                                     # later runs
//	sudo wiremesh status
//	sudo wiremesh logout
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/siv151992-lang/network-connector/internal/version"
	"github.com/siv151992-lang/network-connector/pkg/client"
	"github.com/siv151992-lang/network-connector/pkg/protocol"
)

const defaultState = "/var/lib/wiremesh/state.json"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "up":
		err = cmdUp(os.Args[2:])
	case "status":
		err = cmdStatus(os.Args[2:])
	case "logout":
		err = cmdLogout(os.Args[2:])
	case "version", "--version":
		fmt.Println("wiremesh", version.Version)
	case "help", "-h", "--help":
		usage()
	default:
		usage()
		err = fmt.Errorf("unknown command %q", os.Args[1])
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `usage: wiremesh <command> [flags]

commands:
  up       enroll (first run) and run the tunnel in the foreground
  status   show this device, its peers and live WireGuard state
  logout   revoke this device's credential and forget it
  version`)
}

func cmdUp(args []string) error {
	fs := flag.NewFlagSet("up", flag.ExitOnError)
	server := fs.String("server", "", "control server URL, e.g. https://vpn.example.com (first run)")
	authKey := fs.String("auth-key", "", "auth key for enrollment (first run); or set WIREMESH_AUTH_KEY to keep it out of `ps`")
	state := fs.String("state", defaultState, "state file (private keys + credential)")
	iface := fs.String("iface", "wm0", "tunnel interface name")
	port := fs.Uint("port", 51820, "WireGuard UDP listen port (0 = random)")
	hostname := fs.String("hostname", "", "name to register (default: OS hostname)")
	level := fs.String("log-level", "info", "debug|info|warn|error")
	_ = fs.Parse(args)
	if *authKey == "" {
		*authKey = os.Getenv("WIREMESH_AUTH_KEY")
	}
	if *port > 65535 {
		return errors.New("--port out of range")
	}
	var lvl slog.Level
	if err := lvl.UnmarshalText([]byte(*level)); err != nil {
		return err
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: lvl}))

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	err := client.Run(ctx, client.Options{
		ServerURL: *server, AuthKey: *authKey, StatePath: *state, InterfaceName: *iface,
		ListenPort: uint16(*port), Hostname: *hostname, Version: version.Version, Log: log,
		OnMap: func(nm *protocol.NetworkMap) {
			log.Info("network map applied", "self", nm.Self.Name, "peers", len(nm.Peers), "rules", len(nm.PacketFilter), "version", nm.Version)
		},
	})
	if errors.Is(err, context.Canceled) {
		return nil
	}
	return err
}

func cmdStatus(args []string) error {
	fs := flag.NewFlagSet("status", flag.ExitOnError)
	state := fs.String("state", defaultState, "state file")
	iface := fs.String("iface", "wm0", "tunnel interface name")
	asJSON := fs.Bool("json", false, "machine-readable output")
	_ = fs.Parse(args)

	st, err := client.LoadState(*state)
	if err != nil {
		return err
	}
	ctl, err := client.NewControl(st.ServerURL, st.Credential, version.Version)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	nm, err := ctl.Netmap(ctx, "")
	if errors.Is(err, client.ErrNotApproved) {
		fmt.Println("enrolled; waiting for admin approval")
		return nil
	}
	if err != nil {
		return err
	}
	stats := readUAPI(*iface)
	if *asJSON {
		type peerJSON struct {
			Name          string   `json:"name"`
			Addresses     []string `json:"addresses"`
			Online        bool     `json:"online"`
			Endpoint      string   `json:"endpoint,omitempty"` // current WireGuard path
			LastHandshake string   `json:"last_handshake,omitempty"`
			RxBytes       uint64   `json:"rx_bytes"`
			TxBytes       uint64   `json:"tx_bytes"`
		}
		out := struct {
			Self    string     `json:"self"`
			Running bool       `json:"running"`
			Peers   []peerJSON `json:"peers"`
		}{Self: nm.Self.Name, Running: stats != nil, Peers: []peerJSON{}}
		for _, p := range nm.Peers {
			pj := peerJSON{Name: p.Name, Online: p.Online}
			for _, a := range p.Addresses {
				pj.Addresses = append(pj.Addresses, a.Addr().String())
			}
			if s, ok := stats[p.NodeKey]; ok {
				if !strings.HasPrefix(s.Endpoint, "wm:") {
					pj.Endpoint = s.Endpoint
				}
				if !s.LastHandshake.IsZero() {
					pj.LastHandshake = s.LastHandshake.UTC().Format(time.RFC3339)
				}
				pj.RxBytes, pj.TxBytes = s.RxBytes, s.TxBytes
			}
			out.Peers = append(out.Peers, pj)
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(out)
	}

	fmt.Printf("%s  %s  network %q\n", nm.Self.Name, joinAddrs(nm.Self.Addresses), nm.Network.Name)
	if stats == nil {
		fmt.Println("tunnel: not running (start it with `wiremesh up`)")
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "\nPEER\tADDRESSES\tOS\tENDPOINT\tHANDSHAKE\tRX\tTX")
	for _, p := range nm.Peers {
		ep, hs, rx, tx := "-", "never", "-", "-"
		if s, ok := stats[p.NodeKey]; ok {
			if s.Endpoint != "" && !strings.HasPrefix(s.Endpoint, "wm:") {
				ep = s.Endpoint
			}
			if !s.LastHandshake.IsZero() {
				hs = time.Since(s.LastHandshake).Round(time.Second).String() + " ago"
			}
			rx, tx = bytesHuman(s.RxBytes), bytesHuman(s.TxBytes)
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n", p.Name, joinAddrs(p.Addresses), p.OS, ep, hs, rx, tx)
	}
	return tw.Flush()
}

func cmdLogout(args []string) error {
	fs := flag.NewFlagSet("logout", flag.ExitOnError)
	state := fs.String("state", defaultState, "state file")
	_ = fs.Parse(args)
	st, err := client.LoadState(*state)
	if err != nil {
		return err
	}
	ctl, err := client.NewControl(st.ServerURL, st.Credential, version.Version)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := ctl.Logout(ctx); err != nil && !errors.Is(err, client.ErrUnauthorized) {
		return err
	}
	if err := os.Remove(*state); err != nil {
		return err
	}
	fmt.Println("logged out; state removed")
	return nil
}

// readUAPI queries a running tunnel over WireGuard's UAPI socket. It returns
// nil if the tunnel isn't running.
func readUAPI(iface string) map[protocol.Key]client.PeerStats {
	c, err := net.DialTimeout("unix", filepath.Join("/var/run/wireguard", iface+".sock"), 2*time.Second)
	if err != nil {
		return nil
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := c.Write([]byte("get=1\n\n")); err != nil {
		return nil
	}
	var b strings.Builder
	sc := bufio.NewScanner(c)
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "errno=") {
			break
		}
		b.WriteString(line + "\n")
	}
	return client.ParseUAPIStats(b.String())
}

func joinAddrs(ps []netip.Prefix) string {
	var s []string
	for _, p := range ps {
		s = append(s, p.Addr().String())
	}
	return strings.Join(s, ", ")
}

func bytesHuman(n uint64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := uint64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}
