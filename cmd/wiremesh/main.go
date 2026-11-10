// Command wiremesh controls the WireMesh daemon (wiremeshd / Windows service).
//
//	wiremesh up [ADDRESS] [--auth-key KEY]        connect (first time: server address, then log in in the browser)
//	wiremesh down                                 disconnect (stays down after reboot)
//	wiremesh status [--json]                      peers, paths, traffic
//	wiremesh logout                               forget this device
//	wiremesh run --server URL [--auth-key KEY]    foreground mode without a daemon (containers, tests)
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/siv151992-lang/network-connector/internal/version"
	"github.com/siv151992-lang/network-connector/pkg/client"
	"github.com/siv151992-lang/network-connector/pkg/protocol"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	args := os.Args[2:]
	switch os.Args[1] {
	case "up":
		err = cmdUp(args)
	case "down":
		err = cmdSimple("down", args)
	case "logout":
		err = cmdSimple("logout", args)
	case "status":
		err = cmdStatus(args)
	case "run":
		err = cmdRun(args)
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

  up       connect. First time: wiremesh up 192.168.1.100 (your server's
           address); a browser opens to log in. Or pass --auth-key.
  down     disconnect (stays disconnected across reboots)
  status   show this device, peers, connection paths and traffic (--json)
  logout   disconnect and forget this device (deletes its keys)
  run      run the tunnel in the foreground without wiremeshd
  version`)
}

// --- daemon client ------------------------------------------------------------

type daemonClient struct{ *client.LocalClient }

func newDaemonClient(sock string) *daemonClient { return &daemonClient{client.NewLocalClient(sock)} }

func (c *daemonClient) call(method, path string, body any) (*client.DaemonStatus, error) {
	st, err := c.Call(method, path, body)
	if errors.Is(err, client.ErrDaemonUnreachable) {
		return nil, fmt.Errorf("%w (is it running? Linux: `sudo systemctl start wiremeshd`; are you root or in the wiremesh group?)", err)
	}
	return st, err
}

func socketFlag(fs *flag.FlagSet) *string {
	return fs.String("socket", client.DefaultSocketPath(), "wiremeshd socket")
}

// --- commands -------------------------------------------------------------------

func cmdUp(args []string) error {
	fs := flag.NewFlagSet("up", flag.ExitOnError)
	sock := socketFlag(fs)
	server := fs.String("server", "", "control server URL (first time)")
	authKey := fs.String("auth-key", os.Getenv("WIREMESH_AUTH_KEY"), "auth key for unattended enrollment (or WIREMESH_AUTH_KEY)")
	hostname := fs.String("hostname", "", "device name (default: hostname)")
	timeout := fs.Duration("timeout", 10*time.Minute, "how long to wait for login/connection")
	// Allow the address first or last: `wiremesh up 192.168.1.100 [--flags]`.
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		*server, args = args[0], args[1:]
	}
	_ = fs.Parse(args)
	if fs.NArg() > 0 {
		*server = fs.Arg(0)
	}
	if *server != "" {
		fmt.Println("connecting to", *server, "…")
	}
	c := newDaemonClient(*sock)
	st, err := c.call("POST", "/up", client.UpRequest{ServerURL: *server, AuthKey: *authKey, Hostname: *hostname})
	if err != nil {
		return err
	}
	shown := ""
	deadline := time.Now().Add(*timeout)
	for time.Now().Before(deadline) {
		switch st.State {
		case client.StateRunning:
			fmt.Printf("connected to %q as %s (%s)\n", st.Network, st.Self.Name, join(st.Self.Addresses))
			return nil
		case client.StateNeedsLogin:
			if st.LoginCode != shown {
				shown = st.LoginCode
				fmt.Printf("\nLog in in your browser to connect this device (opening it now):\n\n    %s\n\nand confirm the code %s\n\n", st.LoginURL, st.LoginCode)
				client.OpenBrowser(st.LoginURL)
			}
		case client.StateNeedsApproval:
			if shown != "approval" {
				shown = "approval"
				fmt.Println("enrolled; waiting for a network admin to approve this device in the dashboard…")
			}
		case client.StateError:
			return errors.New(st.Error)
		case client.StateStopped:
			return errors.New("the tunnel stopped; see `journalctl -u wiremeshd`")
		}
		time.Sleep(time.Second)
		if st, err = c.call("GET", "/status", nil); err != nil {
			return err
		}
	}
	return errors.New("timed out waiting for the connection")
}

func cmdSimple(cmd string, args []string) error {
	fs := flag.NewFlagSet(cmd, flag.ExitOnError)
	sock := socketFlag(fs)
	_ = fs.Parse(args)
	if _, err := newDaemonClient(*sock).call("POST", "/"+cmd, nil); err != nil {
		return err
	}
	fmt.Println(map[string]string{"down": "disconnected", "logout": "logged out; this device's keys were deleted"}[cmd])
	return nil
}

func cmdStatus(args []string) error {
	fs := flag.NewFlagSet("status", flag.ExitOnError)
	sock := socketFlag(fs)
	asJSON := fs.Bool("json", false, "machine-readable output")
	_ = fs.Parse(args)
	st, err := newDaemonClient(*sock).call("GET", "/status", nil)
	if err != nil {
		return err
	}
	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(st)
	}
	switch st.State {
	case client.StateRunning:
	case client.StateNeedsLogin:
		fmt.Printf("waiting for login: open %s (code %s)\n", st.LoginURL, st.LoginCode)
		return nil
	case client.StateNeedsApproval:
		fmt.Println("waiting for a network admin to approve this device")
		return nil
	case client.StateError:
		fmt.Println("error:", st.Error)
		return nil
	default:
		fmt.Println(st.State)
		return nil
	}
	fmt.Printf("%s  %s  network %q", st.Self.Name, join(st.Self.Addresses), st.Network)
	if st.Domain != "" {
		fmt.Printf("  dns: *.%s", st.Domain)
	}
	fmt.Println()
	tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "\nPEER\tADDRESS\tSTATUS\tPATH\tHANDSHAKE\tRX\tTX")
	for _, p := range st.Peers {
		state, path, hs := "offline", p.Path, "never"
		if p.Online {
			state = "online"
		}
		if path == "" {
			path = "-"
		}
		if p.LastHandshake != nil {
			hs = time.Since(*p.LastHandshake).Round(time.Second).String() + " ago"
		}
		addr := ""
		if len(p.Addresses) > 0 {
			addr = p.Addresses[0]
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n", p.Name, addr, state, path, hs, bytesHuman(p.RxBytes), bytesHuman(p.TxBytes))
	}
	return tw.Flush()
}

// cmdRun is the daemon-less foreground mode (formerly `wiremesh up`).
func cmdRun(args []string) error {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	server := fs.String("server", "", "control server URL (first run)")
	authKey := fs.String("auth-key", os.Getenv("WIREMESH_AUTH_KEY"), "auth key (or WIREMESH_AUTH_KEY)")
	state := fs.String("state", client.DefaultStatePath(), "state file (private keys + credential)")
	iface := fs.String("iface", "wm0", "tunnel interface name")
	port := fs.Uint("port", 51820, "WireGuard UDP listen port (0 = random)")
	hostname := fs.String("hostname", "", "name to register (default: OS hostname)")
	level := fs.String("log-level", "info", "debug|info|warn|error")
	_ = fs.Parse(args)
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
		OnLogin: func(url, code string) {
			fmt.Fprintf(os.Stderr, "\nTo connect this device, open %s and confirm the code %s\n\n", url, code)
		},
		OnMap: func(nm *protocol.NetworkMap) {
			log.Info("network map applied", "self", nm.Self.Name, "peers", len(nm.Peers), "rules", len(nm.PacketFilter), "version", nm.Version)
		},
	})
	if errors.Is(err, context.Canceled) {
		return nil
	}
	return err
}

func join(s []string) string {
	out := ""
	for i, x := range s {
		if i > 0 {
			out += ", "
		}
		out += x
	}
	return out
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
