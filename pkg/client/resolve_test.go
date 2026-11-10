package client

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestResolveServerURL(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" {
			w.WriteHeader(200)
			return
		}
		w.WriteHeader(404)
	}))
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "http://")
	ctx := context.Background()

	// Bare address: HTTPS fails (plain-HTTP server), falls back to HTTP.
	if got, err := ResolveServerURL(ctx, " "+host+"/ "); err != nil || got != srv.URL {
		t.Fatalf("bare: %q %v", got, err)
	}
	// Explicit scheme is kept without probing.
	if got, err := ResolveServerURL(ctx, "https://vpn.example.com/"); err != nil || got != "https://vpn.example.com" {
		t.Fatalf("explicit: %q %v", got, err)
	}
	for _, bad := range []string{"", "ftp://x", "a b", "host/path"} {
		if _, err := ResolveServerURL(ctx, bad); err == nil {
			t.Fatalf("%q accepted", bad)
		}
	}
	// Nothing listening.
	if _, err := ResolveServerURL(ctx, "127.0.0.1:1"); err == nil || !strings.Contains(err.Error(), "can't reach") {
		t.Fatalf("unreachable: %v", err)
	}
}
