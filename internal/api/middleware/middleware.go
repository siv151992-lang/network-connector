// Package middleware provides the HTTP middleware chain used by the API server.
package middleware

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"regexp"
	"runtime/debug"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/siv151992-lang/network-connector/internal/api/httpx"
)

// Middleware wraps an http.Handler.
type Middleware func(http.Handler) http.Handler

// Chain applies middlewares so that the first one listed is the outermost.
func Chain(h http.Handler, mws ...Middleware) http.Handler {
	for i := len(mws) - 1; i >= 0; i-- {
		h = mws[i](h)
	}
	return h
}

// ---------------------------------------------------------------------------
// Request ID
// ---------------------------------------------------------------------------

var validRequestID = regexp.MustCompile(`^[A-Za-z0-9._-]{8,64}$`)

// RequestID accepts a well-formed inbound X-Request-ID (from the reverse proxy)
// or generates one, stores it in the context and echoes it in the response.
func RequestID() Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			id := r.Header.Get("X-Request-ID")
			if !validRequestID.MatchString(id) {
				var b [12]byte
				_, _ = rand.Read(b[:])
				id = hex.EncodeToString(b[:])
			}
			w.Header().Set("X-Request-ID", id)
			next.ServeHTTP(w, r.WithContext(httpx.WithRequestID(r.Context(), id)))
		})
	}
}

// ---------------------------------------------------------------------------
// Client IP (trusted-proxy aware)
// ---------------------------------------------------------------------------

type ipKey struct{}

// ClientIPFrom returns the client IP computed by RealIP.
func ClientIPFrom(r *http.Request) (netip.Addr, bool) {
	a, ok := r.Context().Value(ipKey{}).(netip.Addr)
	return a, ok && a.IsValid()
}

// ClientIP determines the real client address. X-Forwarded-For is only
// honoured when the direct peer is a trusted proxy; the list is walked right
// to left, skipping trusted hops, so a client cannot spoof its address by
// sending its own X-Forwarded-For header.
func ClientIP(r *http.Request, trusted []netip.Prefix) netip.Addr {
	peer := parseHostAddr(r.RemoteAddr)
	if !peer.IsValid() || !isTrusted(peer, trusted) {
		return peer
	}
	var hops []string
	for _, h := range r.Header.Values("X-Forwarded-For") {
		hops = append(hops, strings.Split(h, ",")...)
	}
	for i := len(hops) - 1; i >= 0; i-- {
		a, err := netip.ParseAddr(strings.TrimSpace(hops[i]))
		if err != nil {
			return peer // malformed chain: fall back to the proxy itself
		}
		a = a.Unmap()
		if !isTrusted(a, trusted) {
			return a
		}
	}
	return peer
}

func parseHostAddr(hostport string) netip.Addr {
	host, _, err := net.SplitHostPort(hostport)
	if err != nil {
		host = hostport
	}
	a, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}
	}
	return a.Unmap()
}

func isTrusted(a netip.Addr, trusted []netip.Prefix) bool {
	for _, p := range trusted {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// RealIP stores the client IP in the request context.
func RealIP(trusted []netip.Prefix) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip := ClientIP(r, trusted)
			ctx := r.Context()
			if ip.IsValid() {
				ctx = contextWithIP(ctx, ip)
			}
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// ---------------------------------------------------------------------------
// Logging + recovery
// ---------------------------------------------------------------------------

// statusWriter records the status code and size. It forwards Flush and Hijack
// so streaming responses and WebSocket upgrades keep working.
type statusWriter struct {
	http.ResponseWriter
	status int
	bytes  int64
}

func (w *statusWriter) WriteHeader(code int) {
	if w.status == 0 {
		w.status = code
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusWriter) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	n, err := w.ResponseWriter.Write(b)
	w.bytes += int64(n)
	return n, err
}

func (w *statusWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (w *statusWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	h, ok := w.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, errors.New("hijacking not supported")
	}
	if w.status == 0 {
		w.status = http.StatusSwitchingProtocols
	}
	return h.Hijack()
}

func (w *statusWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// Logger logs one structured line per request. It never logs query strings
// or headers, which may carry tokens.
func Logger(log *slog.Logger) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			sw := &statusWriter{ResponseWriter: w}
			next.ServeHTTP(sw, r)
			if sw.status == 0 {
				sw.status = http.StatusOK
			}
			level := slog.LevelInfo
			switch {
			case sw.status >= 500:
				level = slog.LevelError
			case r.URL.Path == "/healthz" || r.URL.Path == "/readyz":
				level = slog.LevelDebug
			}
			ip, _ := ClientIPFrom(r)
			log.Log(r.Context(), level, "http request",
				"request_id", httpx.RequestID(r.Context()),
				"method", r.Method,
				"path", r.URL.Path,
				"status", sw.status,
				"bytes", sw.bytes,
				"duration_ms", time.Since(start).Milliseconds(),
				"ip", ip.String(),
			)
		})
	}
}

// Recover converts panics into 500 responses and logs the stack trace.
func Recover(log *slog.Logger) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if p := recover(); p != nil {
					if p == http.ErrAbortHandler {
						panic(p) // let net/http abort the connection as intended
					}
					log.ErrorContext(r.Context(), "panic serving request",
						"request_id", httpx.RequestID(r.Context()), "panic", fmt.Sprint(p), "stack", string(debug.Stack()))
					httpx.WriteError(w, r, nil, httpx.Internal(fmt.Errorf("panic: %v", p)))
				}
			}()
			next.ServeHTTP(w, r)
		})
	}
}

// ---------------------------------------------------------------------------
// Security headers, CORS, body limit
// ---------------------------------------------------------------------------

// SecurityHeaders sets conservative headers for a JSON API. hsts enables
// Strict-Transport-Security (production behind TLS only).
func SecurityHeaders(hsts bool) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			h := w.Header()
			h.Set("X-Content-Type-Options", "nosniff")
			h.Set("X-Frame-Options", "DENY")
			h.Set("Referrer-Policy", "no-referrer")
			h.Set("Cross-Origin-Opener-Policy", "same-origin")
			h.Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
			h.Set("Cache-Control", "no-store")
			if hsts {
				h.Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
			}
			next.ServeHTTP(w, r)
		})
	}
}

// CORS allows credentialed cross-origin requests from an explicit allow-list
// only. With an empty list, no CORS headers are emitted (same-origin only),
// which is the recommended deployment: Caddy serves dashboard and API on one origin.
func CORS(allowed []string) Middleware {
	allowedSet := make(map[string]bool, len(allowed))
	for _, o := range allowed {
		allowedSet[strings.TrimRight(o, "/")] = true
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")
			if origin == "" || !allowedSet[origin] {
				if r.Method == http.MethodOptions && r.Header.Get("Access-Control-Request-Method") != "" {
					w.WriteHeader(http.StatusForbidden)
					return
				}
				next.ServeHTTP(w, r)
				return
			}
			h := w.Header()
			h.Add("Vary", "Origin")
			h.Set("Access-Control-Allow-Origin", origin)
			h.Set("Access-Control-Allow-Credentials", "true")
			h.Set("Access-Control-Expose-Headers", "X-Request-ID, Retry-After")
			if r.Method == http.MethodOptions && r.Header.Get("Access-Control-Request-Method") != "" {
				h.Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE")
				h.Set("Access-Control-Allow-Headers", "Content-Type, X-CSRF-Token, X-Request-ID, If-Match")
				h.Set("Access-Control-Max-Age", "600")
				w.WriteHeader(http.StatusNoContent)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// MaxBody caps request body size; DecodeJSON turns overflow into a 413.
func MaxBody(n int64) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.ContentLength > n {
				httpx.WriteError(w, r, nil, &httpx.Error{Status: http.StatusRequestEntityTooLarge, Code: "body_too_large", Message: "request body too large"})
				return
			}
			if r.Body != nil {
				r.Body = http.MaxBytesReader(w, r.Body, n)
			}
			next.ServeHTTP(w, r)
		})
	}
}

// ---------------------------------------------------------------------------
// Rate limiting
// ---------------------------------------------------------------------------

// RateLimit applies limiter keyed by client IP. Paths in exempt bypass it
// (health checks from the orchestrator).
func RateLimit(l *Limiter, exempt ...string) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if slices.Contains(exempt, r.URL.Path) {
				next.ServeHTTP(w, r)
				return
			}
			key := "unknown"
			if ip, ok := ClientIPFrom(r); ok {
				key = rateKey(ip)
			}
			if ok, retry := l.Allow(key); !ok {
				w.Header().Set("Retry-After", strconv.Itoa(int(retry.Seconds()+0.999)))
				httpx.WriteError(w, r, nil, httpx.TooManyRequests())
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// rateKey buckets IPv6 clients by /64, since a single host usually controls a
// whole /64 and could otherwise rotate addresses to evade the limit.
func rateKey(ip netip.Addr) string {
	if ip.Is6() && !ip.Is4In6() {
		p, _ := ip.Prefix(64)
		return p.String()
	}
	return ip.String()
}
