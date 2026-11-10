//go:build windows || linux

// Command wiremesh-tray is the WireMesh system-tray app (primarily for
// Windows; also works on Linux desktops with a StatusNotifier tray). It is a
// thin GUI over the daemon's local API: it shows the connection state and
// offers Connect / Disconnect / Log in / Open dashboard.
package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"net/url"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"fyne.io/systray"

	"github.com/siv151992-lang/network-connector/pkg/client"
)

func main() { systray.Run(onReady, func() {}) }

func onReady() {
	lc := client.NewLocalClient(client.DefaultSocketPath())
	systray.SetTitle("WireMesh")
	systray.SetTooltip("WireMesh")
	setIcon(color.RGBA{0x94, 0xa3, 0xb8, 0xff})

	status := systray.AddMenuItem("Starting…", "")
	status.Disable()
	systray.AddSeparator()
	connect := systray.AddMenuItem("Connect", "Bring the tunnel up")
	change := systray.AddMenuItem("Change server…", "Connect to a different WireMesh server")
	disconnect := systray.AddMenuItem("Disconnect", "Bring the tunnel down")
	login := systray.AddMenuItem("Log in…", "Open the login page for this device")
	dashboard := systray.AddMenuItem("Open dashboard", "Open the WireMesh dashboard")
	systray.AddSeparator()
	quit := systray.AddMenuItem("Quit tray", "The VPN keeps running in the background")
	login.Hide()

	var last *client.DaemonStatus
	opened := "" // login code we already opened the browser for
	refresh := func() {
		st, err := lc.Call("GET", "/status", nil)
		if err != nil {
			status.SetTitle("WireMesh service not running")
			setIcon(color.RGBA{0xef, 0x44, 0x44, 0xff})
			connect.Disable()
			disconnect.Disable()
			return
		}
		last = st
		connect.Enable()
		disconnect.Enable()
		login.Hide()
		switch st.State {
		case client.StateRunning:
			online := 0
			for _, p := range st.Peers {
				if p.Online {
					online++
				}
			}
			status.SetTitle(fmt.Sprintf("Connected to %s as %s · %d/%d peers online", st.Network, st.Self.Name, online, len(st.Peers)))
			setIcon(color.RGBA{0x10, 0xb9, 0x81, 0xff})
			connect.Hide()
			disconnect.Show()
		case client.StateNeedsLogin:
			status.SetTitle("Log in in your browser: code " + st.LoginCode)
			setIcon(color.RGBA{0xf5, 0x9e, 0x0b, 0xff})
			if st.LoginCode != opened {
				opened = st.LoginCode
				openURL(st.LoginURL)
			}
			login.Show()
			connect.Hide()
			disconnect.Show()
		case client.StateNeedsApproval:
			status.SetTitle("Waiting for an admin to approve this device")
			setIcon(color.RGBA{0xf5, 0x9e, 0x0b, 0xff})
		case client.StateError:
			status.SetTitle("Error: " + st.Error)
			setIcon(color.RGBA{0xef, 0x44, 0x44, 0xff})
			connect.Show()
			disconnect.Hide()
		default:
			status.SetTitle("Disconnected")
			setIcon(color.RGBA{0x94, 0xa3, 0xb8, 0xff})
			connect.Show()
			disconnect.Hide()
		}
	}
	// connectTo asks for the server address when needed and starts the tunnel.
	connectTo := func(ask bool) {
		server := ""
		if ask {
			cur := ""
			if last != nil {
				cur = last.ServerURL
			}
			s, ok := askServer(cur)
			if !ok {
				return
			}
			server = s
			// Switching servers: leave the old one (forgets this device there).
			if last != nil && last.ServerURL != "" && !sameServer(last.ServerURL, s) {
				_, _ = lc.Call("POST", "/logout", nil)
			} else {
				_, _ = lc.Call("POST", "/down", nil) // restart with the address as typed
			}
			status.SetTitle("Connecting to " + s + "…")
		}
		if _, err := lc.Call("POST", "/up", client.UpRequest{ServerURL: server}); err != nil {
			status.SetTitle("Connect failed: " + err.Error())
			return
		}
		refresh()
	}

	refresh()
	// First run: no server configured yet, so ask right away.
	if last != nil && last.ServerURL == "" && last.State == client.StateStopped {
		go connectTo(true)
	}
	tick := time.NewTicker(3 * time.Second)
	go func() {
		for {
			select {
			case <-tick.C:
				refresh()
			case <-connect.ClickedCh:
				connectTo(last == nil || last.ServerURL == "" || last.State == client.StateError)
			case <-change.ClickedCh:
				connectTo(true)
			case <-disconnect.ClickedCh:
				_, _ = lc.Call("POST", "/down", nil)
				refresh()
			case <-login.ClickedCh:
				if last != nil {
					openURL(last.LoginURL)
				}
			case <-dashboard.ClickedCh:
				if last != nil {
					openURL(last.ServerURL)
				}
			case <-quit.ClickedCh:
				systray.Quit()
				return
			}
		}
	}()
}

// sameServer compares a stored URL with what the user typed ("1.2.3.4" vs "http://1.2.3.4").
func sameServer(stored, typed string) bool {
	typed = strings.TrimRight(strings.TrimSpace(typed), "/")
	if strings.Contains(typed, "://") {
		return stored == typed
	}
	return stored == "https://"+typed || stored == "http://"+typed
}

// openURL opens an http(s) URL in the default browser. Other schemes are
// refused: the URL comes from the server and must not launch arbitrary handlers.
func openURL(raw string) {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return
	}
	if runtime.GOOS == "windows" {
		_ = exec.Command("rundll32", "url.dll,FileProtocolHandler", u.String()).Start()
	} else {
		_ = exec.Command("xdg-open", u.String()).Start()
	}
}

// setIcon draws a 16x16 filled circle (no binary assets in the repo).
func setIcon(c color.RGBA) {
	img := image.NewRGBA(image.Rect(0, 0, 16, 16))
	for y := 0; y < 16; y++ {
		for x := 0; x < 16; x++ {
			if dx, dy := x-8, y-8; dx*dx+dy*dy <= 49 {
				img.Set(x, y, c)
			}
		}
	}
	var pngBuf bytes.Buffer
	_ = png.Encode(&pngBuf, img)
	if runtime.GOOS != "windows" {
		systray.SetIcon(pngBuf.Bytes())
		return
	}
	// Windows wants ICO; an ICO may embed a PNG image directly.
	ico := new(bytes.Buffer)
	_ = binary.Write(ico, binary.LittleEndian, []uint16{0, 1, 1}) // reserved, type=icon, count
	ico.Write([]byte{16, 16, 0, 0})                               // width, height, colors, reserved
	_ = binary.Write(ico, binary.LittleEndian, []uint16{1, 32})   // planes, bpp
	_ = binary.Write(ico, binary.LittleEndian, []uint32{uint32(pngBuf.Len()), 22})
	ico.Write(pngBuf.Bytes())
	systray.SetIcon(ico.Bytes())
}
