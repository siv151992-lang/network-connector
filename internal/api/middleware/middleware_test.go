package middleware

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/siv151992-lang/network-connector/internal/api/httpx"
)

func TestClientIP(t *testing.T) {
	trusted := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}
	cases := []struct {
		name, remote string
		xff          []string
		want         string
	}{
		{"direct client ignores XFF", "203.0.113.5:1234", []string{"1.2.3.4"}, "203.0.113.5"},
		{"trusted proxy uses XFF", "10.0.0.2:443", []string{"198.51.100.9"}, "198.51.100.9"},
		{"spoofed left-most entry ignored", "10.0.0.2:443", []string{"6.6.6.6, 198.51.100.9"}, "198.51.100.9"},
		{"multiple trusted hops skipped", "10.0.0.2:443", []string{"198.51.100.9, 10.1.1.1"}, "198.51.100.9"},
		{"multiple headers combined", "10.0.0.2:443", []string{"6.6.6.6", "198.51.100.9"}, "198.51.100.9"},
		{"garbage XFF falls back to peer", "10.0.0.2:443", []string{"not-an-ip"}, "10.0.0.2"},
		{"no XFF from proxy", "10.0.0.2:443", nil, "10.0.0.2"},
		{"ipv6 peer", "[2001:db8::1]:443", nil, "2001:db8::1"},
		{"v4-mapped unmapped", "[::ffff:203.0.113.5]:1", nil, "203.0.113.5"},
	}
	for _, c := range cases {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.RemoteAddr = c.remote
		for _, h := range c.xff {
			r.Header.Add("X-Forwarded-For", h)
		}
		if got := ClientIP(r, trusted).String(); got != c.want {
			t.Errorf("%s: got %s want %s", c.name, got, c.want)
		}
	}
}

func TestRequestID(t *testing.T) {
	var seen string
	h := RequestID()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = httpx.RequestID(r.Context())
	}))

	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))
	if len(seen) != 24 || w.Header().Get("X-Request-ID") != seen {
		t.Fatalf("generated id %q / header %q", seen, w.Header().Get("X-Request-ID"))
	}

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("X-Request-ID", "proxy-abc-12345")
	h.ServeHTTP(httptest.NewRecorder(), r)
	if seen != "proxy-abc-12345" {
		t.Fatalf("valid inbound id not kept: %q", seen)
	}

	r = httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("X-Request-ID", "bad id\nwith newline")
	h.ServeHTTP(httptest.NewRecorder(), r)
	if strings.Contains(seen, " ") {
		t.Fatalf("invalid inbound id accepted: %q", seen)
	}
}

func TestRecover(t *testing.T) {
	var buf bytes.Buffer
	log := slog.New(slog.NewJSONHandler(&buf, nil))
	h := Recover(log)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { panic("kaboom") }))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))
	if w.Code != 500 || !strings.Contains(w.Body.String(), `"internal"`) {
		t.Fatalf("got %d %s", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), "kaboom") {
		t.Fatal("panic value leaked to client")
	}
	if !strings.Contains(buf.String(), "kaboom") {
		t.Fatal("panic not logged")
	}
}

func TestCORS(t *testing.T) {
	h := CORS([]string{"https://admin.example.com"})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))

	// Preflight from allowed origin.
	r := httptest.NewRequest(http.MethodOptions, "/api/v1/x", nil)
	r.Header.Set("Origin", "https://admin.example.com")
	r.Header.Set("Access-Control-Request-Method", "POST")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 204 || w.Header().Get("Access-Control-Allow-Origin") != "https://admin.example.com" ||
		w.Header().Get("Access-Control-Allow-Credentials") != "true" {
		t.Fatalf("allowed preflight: %d %v", w.Code, w.Header())
	}

	// Preflight from other origin is refused.
	r.Header.Set("Origin", "https://evil.example")
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 403 || w.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Fatalf("disallowed preflight: %d %v", w.Code, w.Header())
	}

	// Simple request from other origin gets no CORS headers.
	r = httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Origin", "https://evil.example")
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Fatal("CORS header leaked to disallowed origin")
	}
}

func TestMaxBody(t *testing.T) {
	h := MaxBody(16)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var v map[string]any
		if err := httpx.DecodeJSON(r, &v); err != nil {
			httpx.WriteError(w, r, nil, err)
			return
		}
		w.WriteHeader(200)
	}))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"a":"`+strings.Repeat("x", 64)+`"}`)))
	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("got %d", w.Code)
	}
}

func TestLimiter(t *testing.T) {
	l := NewLimiter(1, 3)
	defer l.Stop()
	now := time.Unix(1_000_000, 0)
	l.now = func() time.Time { return now }

	for i := 0; i < 3; i++ {
		if ok, _ := l.Allow("a"); !ok {
			t.Fatalf("request %d within burst denied", i)
		}
	}
	ok, retry := l.Allow("a")
	if ok || retry <= 0 || retry > time.Second {
		t.Fatalf("4th request: ok=%v retry=%v", ok, retry)
	}
	if ok, _ := l.Allow("b"); !ok {
		t.Fatal("independent key denied")
	}
	now = now.Add(time.Second)
	if ok, _ := l.Allow("a"); !ok {
		t.Fatal("token not refilled after 1s")
	}

	now = now.Add(11 * time.Minute)
	l.evictIdle()
	if l.Len() != 0 {
		t.Fatalf("idle buckets not evicted: %d", l.Len())
	}
}

func TestRateLimitMiddleware(t *testing.T) {
	l := NewLimiter(0.001, 1)
	defer l.Stop()
	h := Chain(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }),
		RealIP(nil), RateLimit(l, "/healthz"))

	do := func(path, remote string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodGet, path, nil)
		r.RemoteAddr = remote
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	if do("/x", "198.51.100.1:1").Code != 200 {
		t.Fatal("first request denied")
	}
	w := do("/x", "198.51.100.1:2")
	if w.Code != 429 || w.Header().Get("Retry-After") == "" {
		t.Fatalf("second request: %d", w.Code)
	}
	if do("/healthz", "198.51.100.1:3").Code != 200 {
		t.Fatal("exempt path limited")
	}
	// IPv6 addresses in the same /64 share a bucket.
	if do("/x", "[2001:db8:1:2::1]:1").Code != 200 {
		t.Fatal("first v6 request denied")
	}
	if do("/x", "[2001:db8:1:2::ffff]:1").Code != 429 {
		t.Fatal("same /64 should share bucket")
	}
}

func TestSecurityHeaders(t *testing.T) {
	h := SecurityHeaders(true)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))
	for _, k := range []string{"X-Content-Type-Options", "X-Frame-Options", "Content-Security-Policy", "Strict-Transport-Security"} {
		if w.Header().Get(k) == "" {
			t.Errorf("missing %s", k)
		}
	}
}
