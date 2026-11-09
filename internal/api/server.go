// Package api assembles the HTTP handler: middleware chain plus routes.
// Feature handlers (auth, devices, networks, …) are added phase by phase in
// sibling files and registered in routes().
package api

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"github.com/siv151992-lang/network-connector/internal/api/httpx"
	"github.com/siv151992-lang/network-connector/internal/api/middleware"
	"github.com/siv151992-lang/network-connector/internal/config"
	"github.com/siv151992-lang/network-connector/internal/store"
	"github.com/siv151992-lang/network-connector/internal/version"
)

// Pinger checks a dependency's health (implemented by *pgxpool.Pool).
type Pinger interface {
	Ping(ctx context.Context) error
}

// Deps are the server's dependencies.
type Deps struct {
	Config  *config.Config
	Log     *slog.Logger
	Store   *store.Store // may be nil in tests that only exercise system routes
	DB      Pinger
	Limiter *middleware.Limiter
}

// Server holds dependencies shared by handlers.
type Server struct {
	cfg   *config.Config
	log   *slog.Logger
	store *store.Store
	db    Pinger
}

// NewHandler builds the root http.Handler.
func NewHandler(d Deps) http.Handler {
	s := &Server{cfg: d.Config, log: d.Log, store: d.Store, db: d.DB}
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

	// Phase 3+: auth, networks, devices, device control plane, ACL, audit, admin.

	// JSON 404 for everything else.
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		httpx.WriteError(w, r, s.log, httpx.NotFound("no such endpoint"))
	})
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
