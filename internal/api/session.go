package api

import (
	"errors"
	"fmt"
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/siv151992-lang/network-connector/internal/api/httpx"
	"github.com/siv151992-lang/network-connector/internal/api/middleware"
	"github.com/siv151992-lang/network-connector/internal/auth"
	"github.com/siv151992-lang/network-connector/internal/store"
)

// principal is an authenticated dashboard user.
type principal struct {
	User    *store.User
	Session *store.Session
}

func (p *principal) csrf(secret []byte) string { return auth.CSRFToken(secret, p.Session.ID.String()) }

// cookieName uses the __Host- prefix over HTTPS: browsers then require
// Secure, Path=/ and no Domain, so subdomains can't plant or overwrite it.
func (s *Server) cookieName() string {
	if s.secureCookies() {
		return "__Host-wm_session"
	}
	return "wm_session"
}

func (s *Server) secureCookies() bool { return s.cfg.PublicURL.Scheme == "https" }

func (s *Server) setSessionCookie(w http.ResponseWriter, raw string, expires time.Time) {
	http.SetCookie(w, &http.Cookie{
		Name: s.cookieName(), Value: raw, Path: "/", Expires: expires,
		HttpOnly: true, Secure: s.secureCookies(), SameSite: http.SameSiteStrictMode,
	})
}

func (s *Server) clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name: s.cookieName(), Value: "", Path: "/", MaxAge: -1,
		HttpOnly: true, Secure: s.secureCookies(), SameSite: http.SameSiteStrictMode,
	})
}

var errNoSession = httpx.Unauthorized("authentication required")

// loadSession authenticates the session cookie. It does not check MFA or CSRF.
func (s *Server) loadSession(r *http.Request) (*principal, error) {
	c, err := r.Cookie(s.cookieName())
	if err != nil {
		return nil, errNoSession
	}
	hash, ok := auth.ParseToken(c.Value, auth.PrefixSession)
	if !ok {
		return nil, errNoSession
	}
	sess, err := s.store.GetSessionByTokenHash(r.Context(), hash)
	if errors.Is(err, store.ErrNotFound) {
		return nil, errNoSession
	}
	if err != nil {
		return nil, err
	}
	now := s.now()
	if !sess.Active(now) {
		return nil, errNoSession
	}
	u, err := s.store.GetUser(r.Context(), sess.UserID)
	if errors.Is(err, store.ErrNotFound) {
		return nil, errNoSession
	}
	if err != nil {
		return nil, err
	}
	if u.DisabledAt != nil {
		return nil, errNoSession
	}
	// Sliding expiry, written at most every 5 minutes to limit DB writes, and
	// capped by the absolute session lifetime.
	if sess.MFAPassed && now.Sub(sess.LastSeenAt) > 5*time.Minute {
		exp := now.Add(s.cfg.SessionIdleTimeout)
		if max := sess.CreatedAt.Add(s.cfg.SessionMaxLifetime); exp.After(max) {
			exp = max
		}
		if err := s.store.TouchSession(r.Context(), sess.ID, exp); err != nil && !errors.Is(err, store.ErrNotFound) {
			s.log.WarnContext(r.Context(), "touch session failed", "error", err)
		}
	}
	return &principal{User: u, Session: sess}, nil
}

func isUnsafeMethod(m string) bool {
	return m != http.MethodGet && m != http.MethodHead && m != http.MethodOptions
}

// checkCSRF protects cookie-authenticated, state-changing requests: the
// X-CSRF-Token header must carry the session-bound token, and a browser Origin
// header (when present) must be our own origin or an allowed CORS origin.
func (s *Server) checkCSRF(r *http.Request, p *principal) error {
	if !isUnsafeMethod(r.Method) {
		return nil
	}
	if origin := r.Header.Get("Origin"); origin != "" && !s.allowedOrigin(origin) {
		return &httpx.Error{Status: http.StatusForbidden, Code: "csrf_failed", Message: "cross-origin request refused"}
	}
	if !auth.CheckCSRFToken(s.cfg.SecretKey, p.Session.ID.String(), r.Header.Get("X-CSRF-Token")) {
		return &httpx.Error{Status: http.StatusForbidden, Code: "csrf_failed", Message: "missing or invalid X-CSRF-Token header"}
	}
	return nil
}

func (s *Server) allowedOrigin(origin string) bool {
	own := s.cfg.PublicURL.Scheme + "://" + s.cfg.PublicURL.Host
	if strings.EqualFold(origin, own) {
		return true
	}
	for _, o := range s.cfg.CORSOrigins {
		if strings.EqualFold(origin, strings.TrimRight(o, "/")) {
			return true
		}
	}
	return false
}

// userFunc is a handler for a fully authenticated user.
type userFunc func(w http.ResponseWriter, r *http.Request, p *principal) error

// user requires a session that has passed MFA, plus CSRF on unsafe methods.
func (s *Server) user(f userFunc) apiFunc {
	return func(w http.ResponseWriter, r *http.Request) error {
		p, err := s.loadSession(r)
		if err != nil {
			return err
		}
		if !p.Session.MFAPassed {
			return &httpx.Error{Status: http.StatusUnauthorized, Code: "mfa_required", Message: "two-factor authentication required"}
		}
		if err := s.checkCSRF(r, p); err != nil {
			return err
		}
		return f(w, r, p)
	}
}

// sysAdmin additionally requires the system admin role.
func (s *Server) sysAdmin(f userFunc) apiFunc {
	return s.user(func(w http.ResponseWriter, r *http.Request, p *principal) error {
		if p.User.SystemRole != store.SystemRoleAdmin {
			return httpx.Forbidden("system administrator role required")
		}
		return f(w, r, p)
	})
}

// netCtx is a principal acting within one network.
type netCtx struct {
	*principal
	Network *store.Network
	Role    string
}

func (n *netCtx) isAdmin() bool    { return store.IsNetworkAdmin(n.Role) }
func (n *netCtx) isOwner() bool    { return n.Role == store.RoleOwner }
func (n *netCtx) canViewAll() bool { return n.isAdmin() || n.Role == store.RoleAuditor }

type netFunc func(w http.ResponseWriter, r *http.Request, n *netCtx) error

// member resolves {nid} and requires network membership. Non-members get 404,
// not 403, so network IDs can't be probed.
func (s *Server) member(f netFunc) apiFunc {
	return s.user(func(w http.ResponseWriter, r *http.Request, p *principal) error {
		nid, err := pathUUID(r, "nid")
		if err != nil {
			return err
		}
		role, err := s.store.GetMemberRole(r.Context(), nid, p.User.ID)
		if errors.Is(err, store.ErrNotFound) {
			return httpx.NotFound("network not found")
		}
		if err != nil {
			return err
		}
		n, err := s.store.GetNetwork(r.Context(), nid)
		if err != nil {
			return err
		}
		return f(w, r, &netCtx{principal: p, Network: n, Role: role})
	})
}

// netAdmin requires owner or admin role.
func (s *Server) netAdmin(f netFunc) apiFunc {
	return s.member(func(w http.ResponseWriter, r *http.Request, n *netCtx) error {
		if !n.isAdmin() {
			return httpx.Forbidden("network admin role required")
		}
		return f(w, r, n)
	})
}

func pathUUID(r *http.Request, name string) (uuid.UUID, error) {
	id, err := uuid.Parse(r.PathValue(name))
	if err != nil {
		return uuid.Nil, httpx.NotFound("resource not found")
	}
	return id, nil
}

// audit records an event. Failures are logged but never fail the request:
// the action already happened.
func (s *Server) audit(r *http.Request, e store.NewAuditEntry) {
	if ip, ok := middleware.ClientIPFrom(r); ok {
		e.IP = &ip
	}
	e.UserAgent = r.UserAgent()
	if err := s.store.InsertAudit(r.Context(), e); err != nil {
		s.log.ErrorContext(r.Context(), "audit insert failed", "action", e.Action, "error", err)
	}
}

func ptr[T any](v T) *T { return &v }

func itoaCeil(f float64) string { return strconv.Itoa(int(math.Ceil(f))) }

// fieldErrors accumulates validation errors.
type fieldErrors map[string]string

func (f fieldErrors) add(field, format string, args ...any) {
	if _, exists := f[field]; !exists {
		f[field] = fmt.Sprintf(format, args...)
	}
}

func (f fieldErrors) err() error {
	if len(f) == 0 {
		return nil
	}
	return httpx.Validation(f)
}
