package api

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/siv151992-lang/network-connector/internal/auth"
)

const pw = "correct horse battery"

func TestE2ERegistrationAndLogin(t *testing.T) {
	t.Parallel()
	e := newEnv(t, nil)
	c := e.client()

	// Registration sends a verification email; login is refused until verified.
	c.must(202, "POST", "/api/v1/auth/register", map[string]string{"email": "Alice@Example.com", "password": pw, "display_name": "Alice"})
	c.errCode(422, "validation_failed", "POST", "/api/v1/auth/register", map[string]string{"email": "nope", "password": "short"})
	c.errCode(403, "email_not_verified", "POST", "/api/v1/auth/login", map[string]string{"email": "alice@example.com", "password": pw})

	tok := e.mailToken("alice@example.com")
	c.errCode(400, "bad_request", "POST", "/api/v1/auth/verify-email", map[string]string{"token": "wme_bogus"})
	c.must(200, "POST", "/api/v1/auth/verify-email", map[string]string{"token": tok})
	c.errCode(400, "bad_request", "POST", "/api/v1/auth/verify-email", map[string]string{"token": tok}) // single use

	// Registering an existing address looks identical to the caller, but the
	// owner gets a notice instead of a verification link.
	before := len(e.mail.Sent)
	c.must(202, "POST", "/api/v1/auth/register", map[string]string{"email": "alice@example.com", "password": pw})
	if m, _ := e.mail.Last("alice@example.com"); len(e.mail.Sent) != before+1 || !strings.Contains(m.Subject, "sign-up attempt") {
		t.Fatalf("expected account-exists email, got %+v", m)
	}

	// Wrong password and unknown user give the same error.
	c.errCode(401, "invalid_credentials", "POST", "/api/v1/auth/login", map[string]string{"email": "alice@example.com", "password": "wrong password!"})
	c.errCode(401, "invalid_credentials", "POST", "/api/v1/auth/login", map[string]string{"email": "nobody@example.com", "password": pw})

	r := c.login("alice@example.com", pw)
	if r.str(t, "user.email") != "alice@example.com" || get(r.json(t), "mfa_required") != false || c.csrf == "" {
		t.Fatalf("login response: %s", r.body)
	}
	if strings.Contains(string(r.body), "password_hash") || strings.Contains(string(r.body), "argon2") {
		t.Fatal("password hash leaked in response")
	}
	setCookie := r.hdr.Get("Set-Cookie")
	if !strings.Contains(setCookie, "HttpOnly") || !strings.Contains(setCookie, "SameSite=Strict") {
		t.Fatalf("session cookie attributes: %s", setCookie)
	}
	c.must(200, "GET", "/api/v1/auth/me", nil)

	// CSRF: mutations need the header and a same-origin Origin.
	saved := c.csrf
	c.csrf = ""
	c.errCode(403, "csrf_failed", "PATCH", "/api/v1/auth/me", map[string]string{"display_name": "A"})
	c.csrf = "forged"
	c.errCode(403, "csrf_failed", "PATCH", "/api/v1/auth/me", map[string]string{"display_name": "A"})
	c.csrf, c.origin = saved, "https://evil.example"
	c.errCode(403, "csrf_failed", "PATCH", "/api/v1/auth/me", map[string]string{"display_name": "A"})
	c.origin = "http://localhost"
	if c.must(200, "PATCH", "/api/v1/auth/me", map[string]string{"display_name": "Alice A."}).str(t, "user.display_name") != "Alice A." {
		t.Fatal("display name not updated")
	}

	sessions := c.must(200, "GET", "/api/v1/auth/sessions", nil).json(t)
	if get(sessions, "sessions.0.current") != true {
		t.Fatalf("sessions: %v", sessions)
	}

	c.must(204, "POST", "/api/v1/auth/logout", nil)
	c.errCode(401, "unauthorized", "GET", "/api/v1/auth/me", nil)
}

func TestE2ERegistrationDisabledAndAdmin(t *testing.T) {
	t.Parallel()
	e := newEnv(t, map[string]string{"WIREMESH_ALLOW_REGISTRATION": "false"})
	e.client().errCode(403, "registration_disabled", "POST", "/api/v1/auth/register",
		map[string]string{"email": "x@example.com", "password": pw})

	e.createUser("root@example.com", pw, true)
	admin := e.loggedIn("root@example.com", pw)
	r := admin.must(201, "POST", "/api/v1/admin/users", map[string]string{"email": "bob@example.com", "password": pw, "display_name": "Bob"})
	bobID := r.str(t, "user.id")
	admin.errCode(409, "conflict", "POST", "/api/v1/admin/users", map[string]string{"email": "bob@example.com", "password": pw})
	if total := get(admin.must(200, "GET", "/api/v1/admin/users", nil).json(t), "total"); total != 2.0 {
		t.Fatalf("total users = %v", total)
	}

	bob := e.loggedIn("bob@example.com", pw) // admin-created users are pre-verified
	bob.errCode(403, "forbidden", "GET", "/api/v1/admin/users", nil)

	// Disabling revokes existing sessions immediately and blocks login.
	admin.must(200, "PATCH", "/api/v1/admin/users/"+bobID, map[string]bool{"disabled": true})
	bob.errCode(401, "unauthorized", "GET", "/api/v1/auth/me", nil)
	e.client().errCode(403, "account_disabled", "POST", "/api/v1/auth/login", map[string]string{"email": "bob@example.com", "password": pw})
	admin.must(200, "PATCH", "/api/v1/admin/users/"+bobID, map[string]bool{"disabled": false})
	e.loggedIn("bob@example.com", pw)

	// Admins can't lock themselves out.
	me := admin.must(200, "GET", "/api/v1/auth/me", nil).str(t, "user.id")
	admin.errCode(403, "forbidden", "PATCH", "/api/v1/admin/users/"+me, map[string]bool{"disabled": true})
}

func TestE2ETOTP(t *testing.T) {
	t.Parallel()
	e := newEnv(t, nil)
	e.createUser("mfa@example.com", pw, false)
	c := e.loggedIn("mfa@example.com", pw)

	c.errCode(403, "invalid_password", "POST", "/api/v1/auth/mfa/totp/setup", map[string]string{"password": "wrong password!"})
	r := c.must(200, "POST", "/api/v1/auth/mfa/totp/setup", map[string]string{"password": pw})
	secret := r.str(t, "secret")
	if !strings.HasPrefix(r.str(t, "otpauth_uri"), "otpauth://totp/WireMesh:") {
		t.Fatalf("uri: %s", r.body)
	}
	code := func() string {
		s, err := auth.TOTPCodeAt(secret, e.clock())
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	wrong := "000000"
	if code() == wrong {
		wrong = "111111"
	}
	c.errCode(422, "invalid_code", "POST", "/api/v1/auth/mfa/totp/enable", map[string]string{"code": wrong})
	c.must(200, "POST", "/api/v1/auth/mfa/totp/enable", map[string]string{"code": code()})
	c.errCode(409, "conflict", "POST", "/api/v1/auth/mfa/totp/setup", map[string]string{"password": pw})

	// The secret is stored encrypted, never in plaintext.
	u, _ := e.store.GetUserByEmail(context.Background(), "mfa@example.com")
	if !u.TOTPEnabled || strings.Contains(string(u.TOTPSecretEnc), secret) {
		t.Fatal("TOTP secret not enabled or stored in plaintext")
	}

	// Login now needs a second step; the partial session can't do anything else.
	e.advance(30 * time.Second)
	c2 := e.client()
	if get(c2.login("mfa@example.com", pw).json(t), "mfa_required") != true {
		t.Fatal("mfa not required")
	}
	c2.errCode(401, "mfa_required", "GET", "/api/v1/auth/me", nil)
	c2.errCode(401, "invalid_code", "POST", "/api/v1/auth/login/mfa", map[string]string{"code": wrong})
	used := code()
	r = c2.must(200, "POST", "/api/v1/auth/login/mfa", map[string]string{"code": used})
	c2.csrf = r.str(t, "csrf_token")
	c2.must(200, "GET", "/api/v1/auth/me", nil)

	// The same code can't be used twice (replay).
	c3 := e.client()
	c3.login("mfa@example.com", pw)
	c3.errCode(401, "invalid_code", "POST", "/api/v1/auth/login/mfa", map[string]string{"code": used})

	// Disabling needs password + a fresh code.
	e.advance(30 * time.Second)
	c2.errCode(403, "invalid_password", "POST", "/api/v1/auth/mfa/totp/disable", map[string]string{"password": "nope nope nope", "code": code()})
	c2.must(200, "POST", "/api/v1/auth/mfa/totp/disable", map[string]string{"password": pw, "code": code()})
	if get(e.client().login("mfa@example.com", pw).json(t), "mfa_required") != false {
		t.Fatal("mfa still required after disable")
	}
}

func TestE2EPasswordResetAndChange(t *testing.T) {
	t.Parallel()
	e := newEnv(t, nil)
	e.createUser("pw@example.com", pw, false)
	old := e.loggedIn("pw@example.com", pw)
	anon := e.client()

	anon.must(202, "POST", "/api/v1/auth/password/forgot", map[string]string{"email": "ghost@example.com"})
	if len(e.mail.Sent) != 0 {
		t.Fatal("email sent for unknown account")
	}
	anon.must(202, "POST", "/api/v1/auth/password/forgot", map[string]string{"email": "pw@example.com"})
	tok := e.mailToken("pw@example.com")

	// A rejected password does not consume the token.
	anon.errCode(422, "validation_failed", "POST", "/api/v1/auth/password/reset", map[string]string{"token": tok, "new_password": "short"})
	newPW := "brand new passphrase"
	anon.must(200, "POST", "/api/v1/auth/password/reset", map[string]string{"token": tok, "new_password": newPW})
	anon.errCode(400, "bad_request", "POST", "/api/v1/auth/password/reset", map[string]string{"token": tok, "new_password": newPW})

	old.errCode(401, "unauthorized", "GET", "/api/v1/auth/me", nil) // all sessions revoked
	anon.errCode(401, "invalid_credentials", "POST", "/api/v1/auth/login", map[string]string{"email": "pw@example.com", "password": pw})

	a := e.loggedIn("pw@example.com", newPW)
	b := e.loggedIn("pw@example.com", newPW)
	a.errCode(403, "invalid_password", "POST", "/api/v1/auth/password/change", map[string]string{"current_password": pw, "new_password": "another passphrase"})
	r := a.must(200, "POST", "/api/v1/auth/password/change", map[string]string{"current_password": newPW, "new_password": "another passphrase"})
	if get(r.json(t), "other_sessions_revoked") != 1.0 {
		t.Fatalf("change response: %s", r.body)
	}
	a.must(200, "GET", "/api/v1/auth/me", nil)                    // current session kept
	b.errCode(401, "unauthorized", "GET", "/api/v1/auth/me", nil) // others revoked
}

func TestE2ELockout(t *testing.T) {
	t.Parallel()
	e := newEnv(t, nil)
	e.createUser("lock@example.com", pw, false)
	c := e.client()
	for i := 0; i < maxFailedLogins; i++ {
		c.errCode(401, "invalid_credentials", "POST", "/api/v1/auth/login", map[string]string{"email": "lock@example.com", "password": "wrong password!"})
	}
	// Even the right password is refused while locked.
	c.errCode(401, "invalid_credentials", "POST", "/api/v1/auth/login", map[string]string{"email": "lock@example.com", "password": pw})
	u, _ := e.store.GetUserByEmail(context.Background(), "lock@example.com")
	if u.LockedUntil == nil {
		t.Fatal("account not locked")
	}
}

func TestE2EAuthRateLimit(t *testing.T) {
	t.Parallel()
	e := newEnv(t, map[string]string{"WIREMESH_AUTH_RATE_LIMIT_PER_MIN": "3"})
	c := e.client()
	for i := 0; i < 3; i++ {
		c.must(401, "POST", "/api/v1/auth/login", map[string]string{"email": "x@example.com", "password": pw})
	}
	r := c.must(429, "POST", "/api/v1/auth/login", map[string]string{"email": "x@example.com", "password": pw})
	if r.hdr.Get("Retry-After") == "" {
		t.Fatal("missing Retry-After")
	}
	c.must(401, "GET", "/api/v1/auth/me", nil) // non-credential endpoints use the general limit
}
