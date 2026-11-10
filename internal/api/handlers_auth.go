package api

import (
	"context"
	"errors"
	"net/http"
	"net/mail"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"

	"github.com/siv151992-lang/network-connector/internal/api/httpx"
	"github.com/siv151992-lang/network-connector/internal/api/middleware"
	"github.com/siv151992-lang/network-connector/internal/auth"
	"github.com/siv151992-lang/network-connector/internal/store"
)

const (
	verifyTokenTTL = 24 * time.Hour
	resetTokenTTL  = time.Hour
)

func (s *Server) authRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/v1/auth/register", s.handle(s.limited(s.handleRegister)))
	mux.HandleFunc("GET /api/v1/auth/setup", s.handle(s.handleSetupStatus))
	mux.HandleFunc("POST /api/v1/auth/verify-email", s.handle(s.limited(s.handleVerifyEmail)))
	mux.HandleFunc("POST /api/v1/auth/verify-email/resend", s.handle(s.limited(s.handleResendVerification)))
	mux.HandleFunc("POST /api/v1/auth/login", s.handle(s.limited(s.handleLogin)))
	mux.HandleFunc("POST /api/v1/auth/login/mfa", s.handle(s.limited(s.handleLoginMFA)))
	mux.HandleFunc("POST /api/v1/auth/password/forgot", s.handle(s.limited(s.handleForgotPassword)))
	mux.HandleFunc("POST /api/v1/auth/password/reset", s.handle(s.limited(s.handleResetPassword)))

	mux.HandleFunc("POST /api/v1/auth/logout", s.handle(s.user(s.handleLogout)))
	mux.HandleFunc("GET /api/v1/auth/me", s.handle(s.user(s.handleMe)))
	mux.HandleFunc("PATCH /api/v1/auth/me", s.handle(s.user(s.handleUpdateMe)))
	mux.HandleFunc("POST /api/v1/auth/password/change", s.handle(s.user(s.handleChangePassword)))
	mux.HandleFunc("GET /api/v1/auth/sessions", s.handle(s.user(s.handleListSessions)))
	mux.HandleFunc("DELETE /api/v1/auth/sessions/{id}", s.handle(s.user(s.handleRevokeSession)))
	mux.HandleFunc("POST /api/v1/auth/mfa/totp/setup", s.handle(s.user(s.handleTOTPSetup)))
	mux.HandleFunc("POST /api/v1/auth/mfa/totp/enable", s.handle(s.user(s.handleTOTPEnable)))
	mux.HandleFunc("POST /api/v1/auth/mfa/totp/disable", s.handle(s.user(s.handleTOTPDisable)))
}

// validEmail checks syntax only (deliverability is proven by verification).
func validEmail(e string) bool {
	if len(e) < 3 || len(e) > 254 {
		return false
	}
	a, err := mail.ParseAddress(e)
	return err == nil && a.Address == e && strings.Contains(e[strings.LastIndexByte(e, '@')+1:], ".")
}

func validateDisplayName(f fieldErrors, name string) {
	if utf8.RuneCountInString(name) > 100 || strings.ContainsAny(name, "\x00\r\n") {
		f.add("display_name", "must be at most 100 characters on one line")
	}
}

func (s *Server) sendMail(r *http.Request, m auth.Message) {
	if err := s.mailer.Send(r.Context(), m); err != nil {
		s.log.ErrorContext(r.Context(), "queueing email failed", "subject", m.Subject, "error", err)
	}
}

func (s *Server) issueUserToken(ctx context.Context, userID uuid.UUID, purpose string, ttl time.Duration) (string, error) {
	raw, hash, err := auth.NewToken(auth.PrefixEmail)
	if err != nil {
		return "", err
	}
	if err := s.store.CreateUserToken(ctx, userID, purpose, hash, ttl); err != nil {
		return "", err
	}
	return raw, nil
}

// ---------------------------------------------------------------------------
// Registration and email verification
// ---------------------------------------------------------------------------

type registerReq struct {
	Email       string `json:"email"`
	Password    string `json:"password"`
	DisplayName string `json:"display_name"`
}

// handleSetupStatus tells the dashboard whether to show first-run admin setup.
func (s *Server) handleSetupStatus(w http.ResponseWriter, r *http.Request) error {
	required := false
	if s.cfg.FirstUserSetup {
		n, err := s.store.CountUsers(r.Context())
		if err != nil {
			return err
		}
		required = n == 0
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]bool{"setup_required": required})
	return nil
}

func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) error {
	// First-run setup: while no users exist, the first sign-up becomes the
	// system admin (serialized so two simultaneous sign-ups can't both win).
	firstUser := false
	if s.cfg.FirstUserSetup {
		s.setupMu.Lock()
		defer s.setupMu.Unlock()
		n, err := s.store.CountUsers(r.Context())
		if err != nil {
			return err
		}
		firstUser = n == 0
	}
	if !s.cfg.AllowRegistration && !firstUser {
		return &httpx.Error{Status: http.StatusForbidden, Code: "registration_disabled",
			Message: "self-registration is disabled; ask an administrator for an account"}
	}
	var req registerReq
	if err := httpx.DecodeJSON(r, &req); err != nil {
		return err
	}
	req.Email = store.NormalizeEmail(req.Email)
	f := fieldErrors{}
	if !validEmail(req.Email) {
		f.add("email", "must be a valid email address")
	}
	if msg := auth.ValidatePassword(req.Password, req.Email); msg != "" {
		f.add("password", "%s", msg)
	}
	validateDisplayName(f, req.DisplayName)
	if err := f.err(); err != nil {
		return err
	}
	hash, err := s.hasher.Hash(r.Context(), req.Password)
	if err != nil {
		return err
	}
	nu := store.NewUser{
		Email: req.Email, PasswordHash: hash, DisplayName: req.DisplayName,
		Verified: !s.cfg.RequireEmailVerification,
	}
	if firstUser {
		nu.SystemRole, nu.Verified = store.SystemRoleAdmin, true
	}
	u, err := s.store.CreateUser(r.Context(), nu)
	accepted := map[string]string{"status": "verification_email_sent",
		"message": "check your inbox for a link to verify your email address"}
	if errors.Is(err, store.ErrConflict) {
		if s.cfg.RequireEmailVerification {
			// Same response as success, so the endpoint can't be used to find
			// registered addresses. The real owner is told by email instead.
			s.sendMail(r, auth.AccountExistsEmail(s.cfg.PublicURL, req.Email))
			httpx.WriteJSON(w, http.StatusAccepted, accepted)
			return nil
		}
		return httpx.Conflict("an account with this email already exists")
	}
	if err != nil {
		return err
	}
	s.audit(r, store.NewAuditEntry{ActorUserID: &u.ID, Action: "user.register", TargetType: "user", TargetID: u.ID.String()})

	if !s.cfg.RequireEmailVerification || firstUser {
		httpx.WriteJSON(w, http.StatusCreated, map[string]any{"user": u})
		return nil
	}
	tok, err := s.issueUserToken(r.Context(), u.ID, store.TokenVerifyEmail, verifyTokenTTL)
	if err != nil {
		return err
	}
	s.sendMail(r, auth.VerificationEmail(s.cfg.PublicURL, u.Email, tok))
	httpx.WriteJSON(w, http.StatusAccepted, accepted)
	return nil
}

type tokenReq struct {
	Token string `json:"token"`
}

var errBadToken = httpx.BadRequest("this link is invalid or has expired")

func (s *Server) handleVerifyEmail(w http.ResponseWriter, r *http.Request) error {
	var req tokenReq
	if err := httpx.DecodeJSON(r, &req); err != nil {
		return err
	}
	hash, ok := auth.ParseToken(req.Token, auth.PrefixEmail)
	if !ok {
		return errBadToken
	}
	uid, err := s.store.ConsumeUserToken(r.Context(), hash, store.TokenVerifyEmail)
	if errors.Is(err, store.ErrNotFound) {
		return errBadToken
	}
	if err != nil {
		return err
	}
	if err := s.store.MarkEmailVerified(r.Context(), uid); err != nil {
		return err
	}
	s.audit(r, store.NewAuditEntry{ActorUserID: &uid, Action: "user.verify_email", TargetType: "user", TargetID: uid.String()})
	httpx.WriteJSON(w, http.StatusOK, map[string]string{"status": "verified"})
	return nil
}

type emailReq struct {
	Email string `json:"email"`
}

// handleResendVerification always answers 202 (no account enumeration).
func (s *Server) handleResendVerification(w http.ResponseWriter, r *http.Request) error {
	var req emailReq
	if err := httpx.DecodeJSON(r, &req); err != nil {
		return err
	}
	u, err := s.store.GetUserByEmail(r.Context(), req.Email)
	if err == nil && u.EmailVerifiedAt == nil && u.DisabledAt == nil {
		tok, err := s.issueUserToken(r.Context(), u.ID, store.TokenVerifyEmail, verifyTokenTTL)
		if err != nil {
			return err
		}
		s.sendMail(r, auth.VerificationEmail(s.cfg.PublicURL, u.Email, tok))
	} else if err != nil && !errors.Is(err, store.ErrNotFound) {
		return err
	}
	httpx.WriteJSON(w, http.StatusAccepted, map[string]string{"status": "accepted"})
	return nil
}

// ---------------------------------------------------------------------------
// Login, MFA, logout
// ---------------------------------------------------------------------------

type loginReq struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type loginResp struct {
	User        *store.User `json:"user"`
	CSRFToken   string      `json:"csrf_token"`
	MFARequired bool        `json:"mfa_required"`
}

var errInvalidCredentials = &httpx.Error{Status: http.StatusUnauthorized, Code: "invalid_credentials", Message: "invalid email or password"}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) error {
	var req loginReq
	if err := httpx.DecodeJSON(r, &req); err != nil {
		return err
	}
	if len(req.Password) > 4*auth.MaxPasswordLen {
		return errInvalidCredentials
	}
	ctx := r.Context()
	now := s.now()
	u, err := s.store.GetUserByEmail(ctx, req.Email)
	if errors.Is(err, store.ErrNotFound) {
		s.hasher.VerifyDummy(ctx, req.Password) // equalize timing
		return errInvalidCredentials
	}
	if err != nil {
		return err
	}
	// While locked, refuse without checking the password, with the same
	// response as a wrong password (no oracle for guessing during lockout).
	if u.LockedUntil != nil && u.LockedUntil.After(now) {
		s.hasher.VerifyDummy(ctx, req.Password)
		s.audit(r, store.NewAuditEntry{ActorUserID: &u.ID, Action: "user.login_locked", TargetType: "user", TargetID: u.ID.String()})
		return errInvalidCredentials
	}
	ok, rehash, err := s.hasher.Verify(ctx, req.Password, u.PasswordHash)
	if err != nil && !errors.Is(err, auth.ErrInvalidHash) {
		return err
	}
	if !ok {
		n, err := s.store.RecordLoginFailure(ctx, u.ID, maxFailedLogins, lockoutDuration)
		if err != nil {
			return err
		}
		s.audit(r, store.NewAuditEntry{ActorUserID: &u.ID, Action: "user.login_failed", TargetType: "user",
			TargetID: u.ID.String(), Metadata: map[string]any{"failures": n}})
		return errInvalidCredentials
	}
	// Correct password: only now reveal account state.
	if u.DisabledAt != nil {
		return &httpx.Error{Status: http.StatusForbidden, Code: "account_disabled", Message: "this account has been disabled"}
	}
	if s.cfg.RequireEmailVerification && u.EmailVerifiedAt == nil {
		return &httpx.Error{Status: http.StatusForbidden, Code: "email_not_verified", Message: "verify your email address before signing in"}
	}
	if rehash {
		if h, err := s.hasher.Hash(ctx, req.Password); err == nil {
			_ = s.store.SetPasswordHash(ctx, u.ID, h)
		}
	}
	if err := s.store.RecordLoginSuccess(ctx, u.ID); err != nil {
		return err
	}

	mfaPassed := !u.TOTPEnabled
	exp := now.Add(s.cfg.SessionIdleTimeout)
	if !mfaPassed {
		exp = now.Add(mfaPendingTTL)
	}
	p, err := s.startSession(w, r, u, mfaPassed, exp)
	if err != nil {
		return err
	}
	action := "user.login"
	if !mfaPassed {
		action = "user.login_password_ok"
	}
	s.audit(r, store.NewAuditEntry{ActorUserID: &u.ID, Action: action, TargetType: "session", TargetID: p.Session.ID.String()})
	httpx.WriteJSON(w, http.StatusOK, loginResp{User: u, CSRFToken: p.csrf(s.cfg.SecretKey), MFARequired: !mfaPassed})
	return nil
}

func (s *Server) startSession(w http.ResponseWriter, r *http.Request, u *store.User, mfaPassed bool, exp time.Time) (*principal, error) {
	raw, hash, err := auth.NewToken(auth.PrefixSession)
	if err != nil {
		return nil, err
	}
	ns := store.NewSession{TokenHash: hash, UserID: u.ID, MFAPassed: mfaPassed, UserAgent: r.UserAgent(), ExpiresAt: exp}
	if ip, ok := middleware.ClientIPFrom(r); ok {
		ns.IP = &ip
	}
	sess, err := s.store.CreateSession(r.Context(), ns)
	if err != nil {
		return nil, err
	}
	s.setSessionCookie(w, raw, exp)
	return &principal{User: u, Session: sess}, nil
}

type codeReq struct {
	Code string `json:"code"`
}

// checkTOTP verifies a code against the user's stored secret and atomically
// marks its time step as used.
func (s *Server) checkTOTP(ctx context.Context, u *store.User, code string) (bool, error) {
	if u.TOTPSecretEnc == nil {
		return false, nil
	}
	secret, err := s.box.Open(u.TOTPSecretEnc, []byte("totp:"+u.ID.String()))
	if err != nil {
		return false, err
	}
	step, ok := auth.VerifyTOTP(string(secret), code, s.now(), u.TOTPLastStep)
	if !ok {
		return false, nil
	}
	return s.store.ClaimTOTPStep(ctx, u.ID, step)
}

func (s *Server) handleLoginMFA(w http.ResponseWriter, r *http.Request) error {
	p, err := s.loadSession(r)
	if err != nil {
		return err
	}
	if p.Session.MFAPassed {
		return httpx.Conflict("this session has already completed two-factor authentication")
	}
	if err := s.checkCSRF(r, p); err != nil {
		return err
	}
	var req codeReq
	if err := httpx.DecodeJSON(r, &req); err != nil {
		return err
	}
	ok, err := s.checkTOTP(r.Context(), p.User, req.Code)
	if err != nil {
		return err
	}
	if !ok {
		n, err := s.store.RecordLoginFailure(r.Context(), p.User.ID, maxFailedLogins, lockoutDuration)
		if err != nil {
			return err
		}
		if n >= maxFailedLogins {
			_ = s.store.RevokeSession(r.Context(), p.User.ID, p.Session.ID)
		}
		s.audit(r, store.NewAuditEntry{ActorUserID: &p.User.ID, Action: "user.mfa_failed", TargetType: "user", TargetID: p.User.ID.String()})
		return &httpx.Error{Status: http.StatusUnauthorized, Code: "invalid_code", Message: "invalid or already used code"}
	}
	// Replace the half-authenticated session with a fresh one (prevents
	// session fixation from carrying over to the fully authenticated state).
	if err := s.store.RevokeSession(r.Context(), p.User.ID, p.Session.ID); err != nil {
		return err
	}
	if err := s.store.RecordLoginSuccess(r.Context(), p.User.ID); err != nil {
		return err
	}
	np, err := s.startSession(w, r, p.User, true, s.now().Add(s.cfg.SessionIdleTimeout))
	if err != nil {
		return err
	}
	s.audit(r, store.NewAuditEntry{ActorUserID: &p.User.ID, Action: "user.login", TargetType: "session", TargetID: np.Session.ID.String(),
		Metadata: map[string]any{"mfa": "totp"}})
	httpx.WriteJSON(w, http.StatusOK, loginResp{User: p.User, CSRFToken: np.csrf(s.cfg.SecretKey)})
	return nil
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request, p *principal) error {
	if err := s.store.RevokeSession(r.Context(), p.User.ID, p.Session.ID); err != nil && !errors.Is(err, store.ErrNotFound) {
		return err
	}
	s.clearSessionCookie(w)
	s.audit(r, store.NewAuditEntry{ActorUserID: &p.User.ID, Action: "user.logout", TargetType: "session", TargetID: p.Session.ID.String()})
	w.WriteHeader(http.StatusNoContent)
	return nil
}

func (s *Server) handleMe(w http.ResponseWriter, r *http.Request, p *principal) error {
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"user": p.User, "csrf_token": p.csrf(s.cfg.SecretKey)})
	return nil
}

func (s *Server) handleUpdateMe(w http.ResponseWriter, r *http.Request, p *principal) error {
	var req struct {
		DisplayName string `json:"display_name"`
	}
	if err := httpx.DecodeJSON(r, &req); err != nil {
		return err
	}
	f := fieldErrors{}
	validateDisplayName(f, req.DisplayName)
	if err := f.err(); err != nil {
		return err
	}
	if err := s.store.UpdateDisplayName(r.Context(), p.User.ID, req.DisplayName); err != nil {
		return err
	}
	u, err := s.store.GetUser(r.Context(), p.User.ID)
	if err != nil {
		return err
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"user": u})
	return nil
}

// ---------------------------------------------------------------------------
// Passwords
// ---------------------------------------------------------------------------

func (s *Server) handleForgotPassword(w http.ResponseWriter, r *http.Request) error {
	var req emailReq
	if err := httpx.DecodeJSON(r, &req); err != nil {
		return err
	}
	u, err := s.store.GetUserByEmail(r.Context(), req.Email)
	switch {
	case err == nil && u.DisabledAt == nil:
		tok, err := s.issueUserToken(r.Context(), u.ID, store.TokenResetPassword, resetTokenTTL)
		if err != nil {
			return err
		}
		s.sendMail(r, auth.PasswordResetEmail(s.cfg.PublicURL, u.Email, tok))
		s.audit(r, store.NewAuditEntry{ActorUserID: &u.ID, Action: "user.password_reset_requested", TargetType: "user", TargetID: u.ID.String()})
	case err != nil && !errors.Is(err, store.ErrNotFound):
		return err
	}
	httpx.WriteJSON(w, http.StatusAccepted, map[string]string{"status": "accepted",
		"message": "if an account exists for that address, a reset link has been sent"})
	return nil
}

type resetReq struct {
	Token       string `json:"token"`
	NewPassword string `json:"new_password"`
}

func (s *Server) handleResetPassword(w http.ResponseWriter, r *http.Request) error {
	var req resetReq
	if err := httpx.DecodeJSON(r, &req); err != nil {
		return err
	}
	hash, ok := auth.ParseToken(req.Token, auth.PrefixEmail)
	if !ok {
		return errBadToken
	}
	// Validate before consuming so a rejected password doesn't burn the link.
	if msg := auth.ValidatePassword(req.NewPassword, ""); msg != "" {
		return httpx.Validation(map[string]string{"new_password": msg})
	}
	pwHash, err := s.hasher.Hash(r.Context(), req.NewPassword)
	if err != nil {
		return err
	}
	var uid uuid.UUID
	err = s.store.WithTx(r.Context(), func(tx *store.Store) error {
		id, err := tx.ConsumeUserToken(r.Context(), hash, store.TokenResetPassword)
		if errors.Is(err, store.ErrNotFound) {
			return errBadToken
		}
		if err != nil {
			return err
		}
		uid = id
		if err := tx.SetPasswordHash(r.Context(), id, pwHash); err != nil {
			return err
		}
		// Receiving the email proves ownership of the address.
		if err := tx.MarkEmailVerified(r.Context(), id); err != nil {
			return err
		}
		_, err = tx.RevokeUserSessions(r.Context(), id, uuid.Nil)
		return err
	})
	if err != nil {
		return err
	}
	s.audit(r, store.NewAuditEntry{ActorUserID: &uid, Action: "user.password_reset", TargetType: "user", TargetID: uid.String()})
	httpx.WriteJSON(w, http.StatusOK, map[string]string{"status": "password_reset"})
	return nil
}

type changePasswordReq struct {
	CurrentPassword string `json:"current_password"`
	NewPassword     string `json:"new_password"`
}

func (s *Server) verifyPassword(ctx context.Context, u *store.User, pw string) error {
	ok, _, err := s.hasher.Verify(ctx, pw, u.PasswordHash)
	if err != nil && !errors.Is(err, auth.ErrInvalidHash) {
		return err
	}
	if !ok {
		return &httpx.Error{Status: http.StatusForbidden, Code: "invalid_password", Message: "current password is incorrect"}
	}
	return nil
}

func (s *Server) handleChangePassword(w http.ResponseWriter, r *http.Request, p *principal) error {
	var req changePasswordReq
	if err := httpx.DecodeJSON(r, &req); err != nil {
		return err
	}
	if err := s.verifyPassword(r.Context(), p.User, req.CurrentPassword); err != nil {
		return err
	}
	if msg := auth.ValidatePassword(req.NewPassword, p.User.Email); msg != "" {
		return httpx.Validation(map[string]string{"new_password": msg})
	}
	h, err := s.hasher.Hash(r.Context(), req.NewPassword)
	if err != nil {
		return err
	}
	if err := s.store.SetPasswordHash(r.Context(), p.User.ID, h); err != nil {
		return err
	}
	n, err := s.store.RevokeUserSessions(r.Context(), p.User.ID, p.Session.ID)
	if err != nil {
		return err
	}
	s.audit(r, store.NewAuditEntry{ActorUserID: &p.User.ID, Action: "user.password_change", TargetType: "user",
		TargetID: p.User.ID.String(), Metadata: map[string]any{"other_sessions_revoked": n}})
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"status": "password_changed", "other_sessions_revoked": n})
	return nil
}

// ---------------------------------------------------------------------------
// Sessions
// ---------------------------------------------------------------------------

type sessionView struct {
	*store.Session
	Current bool `json:"current"`
}

func (s *Server) handleListSessions(w http.ResponseWriter, r *http.Request, p *principal) error {
	list, err := s.store.ListActiveSessions(r.Context(), p.User.ID)
	if err != nil {
		return err
	}
	out := make([]sessionView, 0, len(list))
	for _, sess := range list {
		out = append(out, sessionView{Session: sess, Current: sess.ID == p.Session.ID})
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"sessions": out})
	return nil
}

func (s *Server) handleRevokeSession(w http.ResponseWriter, r *http.Request, p *principal) error {
	id, err := pathUUID(r, "id")
	if err != nil {
		return err
	}
	if err := s.store.RevokeSession(r.Context(), p.User.ID, id); err != nil {
		return err
	}
	if id == p.Session.ID {
		s.clearSessionCookie(w)
	}
	s.audit(r, store.NewAuditEntry{ActorUserID: &p.User.ID, Action: "user.session_revoke", TargetType: "session", TargetID: id.String()})
	w.WriteHeader(http.StatusNoContent)
	return nil
}

// ---------------------------------------------------------------------------
// TOTP two-factor authentication
// ---------------------------------------------------------------------------

func (s *Server) handleTOTPSetup(w http.ResponseWriter, r *http.Request, p *principal) error {
	var req struct {
		Password string `json:"password"`
	}
	if err := httpx.DecodeJSON(r, &req); err != nil {
		return err
	}
	if p.User.TOTPEnabled {
		return httpx.Conflict("two-factor authentication is already enabled")
	}
	if err := s.verifyPassword(r.Context(), p.User, req.Password); err != nil {
		return err
	}
	secret, err := auth.GenerateTOTPSecret()
	if err != nil {
		return err
	}
	enc, err := s.box.Seal([]byte(secret), []byte("totp:"+p.User.ID.String()))
	if err != nil {
		return err
	}
	if err := s.store.SetTOTP(r.Context(), p.User.ID, enc, false); err != nil {
		return err
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]string{
		"secret":      secret,
		"otpauth_uri": auth.TOTPURI("WireMesh", p.User.Email, secret),
	})
	return nil
}

func (s *Server) handleTOTPEnable(w http.ResponseWriter, r *http.Request, p *principal) error {
	var req codeReq
	if err := httpx.DecodeJSON(r, &req); err != nil {
		return err
	}
	if p.User.TOTPEnabled {
		return httpx.Conflict("two-factor authentication is already enabled")
	}
	if p.User.TOTPSecretEnc == nil {
		return httpx.BadRequest("call /auth/mfa/totp/setup first")
	}
	ok, err := s.checkTOTP(r.Context(), p.User, req.Code)
	if err != nil {
		return err
	}
	if !ok {
		return &httpx.Error{Status: http.StatusUnprocessableEntity, Code: "invalid_code", Message: "invalid code; check your device clock"}
	}
	if err := s.store.SetTOTP(r.Context(), p.User.ID, p.User.TOTPSecretEnc, true); err != nil {
		return err
	}
	s.audit(r, store.NewAuditEntry{ActorUserID: &p.User.ID, Action: "user.mfa_enable", TargetType: "user", TargetID: p.User.ID.String()})
	httpx.WriteJSON(w, http.StatusOK, map[string]string{"status": "enabled"})
	return nil
}

func (s *Server) handleTOTPDisable(w http.ResponseWriter, r *http.Request, p *principal) error {
	var req struct {
		Password string `json:"password"`
		Code     string `json:"code"`
	}
	if err := httpx.DecodeJSON(r, &req); err != nil {
		return err
	}
	if !p.User.TOTPEnabled {
		return httpx.Conflict("two-factor authentication is not enabled")
	}
	if err := s.verifyPassword(r.Context(), p.User, req.Password); err != nil {
		return err
	}
	ok, err := s.checkTOTP(r.Context(), p.User, req.Code)
	if err != nil {
		return err
	}
	if !ok {
		return &httpx.Error{Status: http.StatusUnprocessableEntity, Code: "invalid_code", Message: "invalid or already used code"}
	}
	if err := s.store.SetTOTP(r.Context(), p.User.ID, nil, false); err != nil {
		return err
	}
	s.audit(r, store.NewAuditEntry{ActorUserID: &p.User.ID, Action: "user.mfa_disable", TargetType: "user", TargetID: p.User.ID.String()})
	httpx.WriteJSON(w, http.StatusOK, map[string]string{"status": "disabled"})
	return nil
}
