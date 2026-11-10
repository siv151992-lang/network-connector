package client

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

// ResolveServerURL turns what a user typed ("192.168.1.100", "vpn.example.com",
// "https://vpn.example.com/") into a server URL. With no scheme, it tries
// HTTPS first and falls back to HTTP, keeping whichever answers /healthz.
func ResolveServerURL(ctx context.Context, s string) (string, error) {
	s = strings.TrimRight(strings.TrimSpace(s), "/")
	if s == "" {
		return "", fmt.Errorf("enter the server address, e.g. 192.168.1.100 or vpn.example.com")
	}
	if strings.Contains(s, "://") {
		u, err := url.Parse(s)
		if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
			return "", fmt.Errorf("invalid server address %q", s)
		}
		return s, nil
	}
	if strings.ContainsAny(s, "/?# ") {
		return "", fmt.Errorf("invalid server address %q", s)
	}
	hc := &http.Client{Timeout: 5 * time.Second}
	var lastErr error
	for _, scheme := range []string{"https", "http"} {
		cand := scheme + "://" + s
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, cand+"/healthz", nil)
		if err != nil {
			return "", fmt.Errorf("invalid server address %q", s)
		}
		resp, err := hc.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			return cand, nil
		}
		lastErr = fmt.Errorf("%s answered %s", cand, resp.Status)
	}
	return "", fmt.Errorf("can't reach a WireMesh server at %s (is it running and is the address right?): %v", s, lastErr)
}

// OpenBrowser opens an http(s) URL in the default browser (best effort).
// Other schemes are refused: the URL comes from the server.
func OpenBrowser(raw string) {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return
	}
	switch runtime.GOOS {
	case "windows":
		_ = exec.Command("rundll32", "url.dll,FileProtocolHandler", u.String()).Start()
	case "darwin":
		_ = exec.Command("open", u.String()).Start()
	default:
		_ = exec.Command("xdg-open", u.String()).Start()
	}
}
