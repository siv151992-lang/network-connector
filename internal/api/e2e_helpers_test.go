package api

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/siv151992-lang/network-connector/internal/api/middleware"
	"github.com/siv151992-lang/network-connector/internal/auth"
	"github.com/siv151992-lang/network-connector/internal/config"
	"github.com/siv151992-lang/network-connector/internal/secretbox"
	"github.com/siv151992-lang/network-connector/internal/store"
	"github.com/siv151992-lang/network-connector/internal/testutil"
)

// env is a running API server backed by an isolated PostgreSQL database.
type env struct {
	t      *testing.T
	srv    *httptest.Server
	store  *store.Store
	mail   *auth.CaptureMailer
	hasher *auth.Hasher

	mu  sync.Mutex
	now time.Time
}

func (e *env) clock() time.Time { e.mu.Lock(); defer e.mu.Unlock(); return e.now }

func (e *env) advance(d time.Duration) { e.mu.Lock(); e.now = e.now.Add(d); e.mu.Unlock() }

var testSecret = bytes.Repeat([]byte{42}, 32)

func newEnv(t *testing.T, overrides map[string]string) *env {
	t.Helper()
	vars := map[string]string{
		"WIREMESH_DATABASE_URL":            "postgres://unused",
		"WIREMESH_PUBLIC_URL":              "http://localhost",
		"WIREMESH_SECRET_KEY":              base64.StdEncoding.EncodeToString(testSecret),
		"WIREMESH_ALLOW_REGISTRATION":      "true",
		"WIREMESH_RATE_LIMIT_RPS":          "1000",
		"WIREMESH_RATE_LIMIT_BURST":        "1000",
		"WIREMESH_AUTH_RATE_LIMIT_PER_MIN": "6000",
	}
	for k, v := range overrides {
		vars[k] = v
	}
	cfg, err := config.LoadFrom(func(k string) (string, bool) { v, ok := vars[k]; return v, ok })
	if err != nil {
		t.Fatal(err)
	}
	e := &env{
		t: t, store: store.New(testutil.NewDB(t)), mail: &auth.CaptureMailer{},
		hasher: auth.NewHasher(auth.Argon2Params{Memory: 1024, Iterations: 1, Parallelism: 1, SaltLen: 16, KeyLen: 32}, 4),
		now:    time.Now(),
	}
	box, _ := secretbox.New(cfg.SecretKey)
	lim := middleware.NewLimiter(cfg.RateLimitRPS, cfg.RateLimitBurst)
	authLim := middleware.NewLimiter(cfg.AuthRateLimitPerMin/60, int(cfg.AuthRateLimitPerMin))
	t.Cleanup(lim.Stop)
	t.Cleanup(authLim.Stop)
	h := NewHandler(Deps{
		Config: cfg, Log: slog.New(slog.NewTextHandler(io.Discard, nil)), Store: e.store, DB: e.store.Pool(),
		Limiter: lim, AuthLimiter: authLim, Hasher: e.hasher, Mailer: e.mail, Box: box, Now: e.clock,
	})
	e.srv = httptest.NewServer(h)
	t.Cleanup(e.srv.Close)
	return e
}

// createUser inserts a verified user directly.
func (e *env) createUser(email, password string, admin bool) *store.User {
	e.t.Helper()
	h, err := e.hasher.Hash(context.Background(), password)
	if err != nil {
		e.t.Fatal(err)
	}
	role := store.SystemRoleUser
	if admin {
		role = store.SystemRoleAdmin
	}
	u, err := e.store.CreateUser(context.Background(), store.NewUser{Email: email, PasswordHash: h, SystemRole: role, Verified: true})
	if err != nil {
		e.t.Fatal(err)
	}
	return u
}

var tokenRe = regexp.MustCompile(`wme_[A-Za-z0-9_-]{43}`)

// mailToken extracts the one-time token from the last email sent to addr.
func (e *env) mailToken(addr string) string {
	e.t.Helper()
	m, ok := e.mail.Last(addr)
	if !ok {
		e.t.Fatalf("no email sent to %s", addr)
	}
	tok := tokenRe.FindString(m.Text)
	if tok == "" {
		e.t.Fatalf("no token in email: %s", m.Text)
	}
	return tok
}

// client is one browser (cookie jar) or one device (bearer credential).
type client struct {
	t      *testing.T
	e      *env
	hc     *http.Client
	csrf   string
	bearer string
	origin string
}

func (e *env) client() *client {
	jar, _ := cookiejar.New(nil)
	return &client{t: e.t, e: e, hc: &http.Client{Jar: jar}}
}

type resp struct {
	code int
	body []byte
	hdr  http.Header
}

func (r resp) json(t *testing.T) map[string]any {
	t.Helper()
	var m map[string]any
	if len(r.body) == 0 {
		return m
	}
	if err := json.Unmarshal(r.body, &m); err != nil {
		t.Fatalf("decode %q: %v", r.body, err)
	}
	return m
}

// get walks a dotted path ("user.email", "devices.0.name") through decoded JSON.
func get(m any, path string) any {
	cur := m
	for _, part := range strings.Split(path, ".") {
		switch v := cur.(type) {
		case map[string]any:
			cur = v[part]
		case []any:
			i := 0
			for _, c := range part {
				i = i*10 + int(c-'0')
			}
			if i >= len(v) {
				return nil
			}
			cur = v[i]
		default:
			return nil
		}
	}
	return cur
}

func (r resp) str(t *testing.T, path string) string {
	t.Helper()
	s, _ := get(r.json(t), path).(string)
	return s
}

func (c *client) do(method, path string, body any) resp {
	c.t.Helper()
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			c.t.Fatal(err)
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, c.e.srv.URL+path, rd)
	if err != nil {
		c.t.Fatal(err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.csrf != "" {
		req.Header.Set("X-CSRF-Token", c.csrf)
	}
	if c.bearer != "" {
		req.Header.Set("Authorization", "Bearer "+c.bearer)
	}
	if c.origin != "" {
		req.Header.Set("Origin", c.origin)
	}
	res, err := c.hc.Do(req)
	if err != nil {
		c.t.Fatal(err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return resp{code: res.StatusCode, body: b, hdr: res.Header}
}

// must asserts a status code and returns the response.
func (c *client) must(code int, method, path string, body any) resp {
	c.t.Helper()
	r := c.do(method, path, body)
	if r.code != code {
		c.t.Fatalf("%s %s: want %d, got %d: %s", method, path, code, r.code, r.body)
	}
	return r
}

// errCode asserts a status code and error code.
func (c *client) errCode(code int, errCode, method, path string, body any) {
	c.t.Helper()
	r := c.must(code, method, path, body)
	if got := r.str(c.t, "error.code"); got != errCode {
		c.t.Fatalf("%s %s: want error code %q, got %q (%s)", method, path, errCode, got, r.body)
	}
}

func (c *client) login(email, password string) resp {
	c.t.Helper()
	r := c.must(200, "POST", "/api/v1/auth/login", map[string]string{"email": email, "password": password})
	c.csrf = r.str(c.t, "csrf_token")
	return r
}

func (e *env) loggedIn(email, password string) *client {
	c := e.client()
	c.login(email, password)
	return c
}

func wgKey(t *testing.T) string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(b)
}
