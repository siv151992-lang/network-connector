// Package api assembles the HTTP handler: middleware chain plus routes.
// Handlers live in handlers_*.go; session and permission helpers in session.go.
package api

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"github.com/siv151992-lang/network-connector/internal/api/httpx"
	"github.com/siv151992-lang/network-connector/internal/api/middleware"
	"github.com/siv151992-lang/network-connector/internal/auth"
	"github.com/siv151992-lang/network-connector/internal/config"
	"github.com/siv151992-lang/network-connector/internal/devices"
	"github.com/siv151992-lang/network-connector/internal/secretbox"
	"github.com/siv151992-lang/network-connector/internal/store"
	"github.com/siv151992-lang/network-connector/internal/version"
)

// Pinger checks a dependency's health (implemented by *pgxpool.Pool).
type Pinger interface {
	Ping(ctx context.Context) error
}

// Deps are the server's dependencies.
type Deps struct {
	Config      *config.Config
	Log         *slog.Logger
	Store       *store.Store // nil only in tests that exercise system routes
	DB          Pinger
	Limiter     *middleware.Limiter // global per-IP limit
	AuthLimiter *middleware.Limiter // stricter per-IP limit for credential endpoints
	Hasher      *auth.Hasher
	Mailer      auth.Mailer
	Box         *secretbox.Box // encrypts TOTP secrets at rest
	Now         func() time.Time
}

// Server holds dependencies shared by handlers.
type Server struct {
	cfg       *config.Config
	log       *slog.Logger
	store     *store.Store
	db        Pinger
	authLim   *middleware.Limiter
	hasher    *auth.Hasher
	mailer    auth.Mailer
	box       *secretbox.Box
	registrar *devices.Registrar
	now       func() time.Time
}

// Login lockout policy: after maxFailedLogins consecutive failures (password
// or TOTP), the account refuses logins for lockoutDuration.
const (
	maxFailedLogins = 10
	lockoutDuration = 15 * time.Minute
	mfaPendingTTL   = 10 * time.Minute // lifetime of a password-only session awaiting TOTP
)

// NewHandler builds the root http.Handler.
func NewHandler(d Deps) http.Handler {
	s := &Server{
		cfg: d.Config, log: d.Log, store: d.Store, db: d.DB, authLim: d.AuthLimiter,
		hasher: d.Hasher, mailer: d.Mailer, box: d.Box, now: d.Now,
	}
	if s.now == nil {
		s.now = time.Now
	}
	if d.Store != nil {
		s.registrar = &devices.Registrar{Store: d.Store, Now: s.now}
	}
	mux := http.NewServeMux()
	s.routes(mux)

	return middleware.Chain(mux,
		middleware.RequestID(),
		middleware.RealIP(d.Config.TrustedProxies),
		middleware.Logger(d.Log),
		middleware.Recover(d.Log),
		middleware.SecurityHeaders(d.Config.IsProduction()),
		middleware.CORS(d.Config.CORSOrigins),
		middleware.RateLimit(d.Limiter, "/healthz", "/readyz"),
		middleware.MaxBody(d.Config.MaxBodyBytes),
	)
}

func (s *Server) routes(mux *http.ServeMux) {
	// System
	mux.HandleFunc("GET /healthz", s.handleHealthz)
	mux.HandleFunc("GET /readyz", s.handleReadyz)
	mux.HandleFunc("GET /api/v1/version", s.handleVersion)

	if s.store != nil {
		s.authRoutes(mux)
		s.networkRoutes(mux)
		s.deviceRoutes(mux)
		s.adminRoutes(mux)
	}

	// JSON 404 for everything else.
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		httpx.WriteError(w, r, s.log, httpx.NotFound("no such endpoint"))
	})
}

// apiFunc is a handler that returns an error instead of writing it.
type apiFunc func(w http.ResponseWriter, r *http.Request) error

// handle adapts an apiFunc, writing any returned error as the JSON envelope.
func (s *Server) handle(f apiFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := f(w, r); err != nil {
			httpx.WriteError(w, r, s.log, err)
		}
	}
}

// limited applies the strict credential-endpoint rate limit.
func (s *Server) limited(f apiFunc) apiFunc {
	return func(w http.ResponseWriter, r *http.Request) error {
		if s.authLim != nil {
			key := "unknown"
			if ip, ok := middleware.ClientIPFrom(r); ok {
				key = ip.String()
			}
			if ok, retry := s.authLim.Allow(key); !ok {
				w.Header().Set("Retry-After", itoaCeil(retry.Seconds()))
				return httpx.TooManyRequests()
			}
		}
		return f(w, r)
	}
}

// handleHealthz is a liveness probe: the process is up and serving.
func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	httpx.WriteJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// handleReadyz is a readiness probe: dependencies are reachable.
func (s *Server) handleReadyz(w http.ResponseWriter, r *http.Request) {
	checks := map[string]string{}
	status := http.StatusOK
	if s.db != nil {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		if err := s.db.Ping(ctx); err != nil {
			s.log.WarnContext(r.Context(), "readiness: database unreachable", "error", err)
			checks["database"] = "unavailable"
			status = http.StatusServiceUnavailable
		} else {
			checks["database"] = "ok"
		}
	}
	state := "ready"
	if status != http.StatusOK {
		state = "not_ready"
	}
	httpx.WriteJSON(w, status, map[string]any{"status": state, "checks": checks})
}

func (s *Server) handleVersion(w http.ResponseWriter, r *http.Request) {
	httpx.WriteJSON(w, http.StatusOK, version.Get())
}
