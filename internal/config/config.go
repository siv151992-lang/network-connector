// Package config loads and validates server configuration from environment
// variables (12-factor style). Every variable is prefixed WIREMESH_.
package config

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

// Environment names.
const (
	EnvDevelopment = "development"
	EnvProduction  = "production"
)

// Config is the fully validated server configuration.
type Config struct {
	Env       string // development | production
	HTTPAddr  string // listen address, e.g. ":8080"
	PublicURL *url.URL

	DatabaseURL      string
	DBMaxConns       int32
	AutoMigrate      bool
	RedisURL         string // optional
	SecretKey        []byte // 32 bytes, AES-256-GCM key for column encryption
	LogLevel         string // debug | info | warn | error
	LogFormat        string // json | text
	TrustedProxies   []netip.Prefix
	CORSOrigins      []string
	RateLimitRPS     float64
	RateLimitBurst   int
	MaxBodyBytes     int64
	ShutdownTimeout  time.Duration
	DefaultIPv4Range netip.Prefix // address range assigned to new networks

	// Authentication (Phase 3)
	AllowRegistration        bool          // public self-sign-up; otherwise admins create users
	RequireEmailVerification bool          // users must verify email before logging in
	SessionIdleTimeout       time.Duration // sliding expiry
	SessionMaxLifetime       time.Duration // absolute expiry
	AuthRateLimitPerMin      float64       // per-IP limit on login/register/reset/device-register
	MaxConcurrentHashes      int           // bounds Argon2id memory use (64 MiB each)

	// Outbound email. If SMTPHost is empty, emails are logged (development) or dropped.
	SMTPHost     string
	SMTPPort     int
	SMTPUsername string
	SMTPPassword string
	SMTPFrom     string
	SMTPTLS      string // starttls | tls | none
}

// IsProduction reports whether the server runs in production mode.
func (c *Config) IsProduction() bool { return c.Env == EnvProduction }

// Load reads configuration from the process environment.
func Load() (*Config, error) { return LoadFrom(os.LookupEnv) }

// LoadFrom reads configuration using the supplied lookup function, which makes
// the loader testable without touching the real environment.
func LoadFrom(lookup func(string) (string, bool)) (*Config, error) {
	g := getter{lookup: lookup}
	c := &Config{
		Env:             g.str("WIREMESH_ENV", EnvDevelopment),
		HTTPAddr:        g.str("WIREMESH_HTTP_ADDR", ":8080"),
		DatabaseURL:     g.str("WIREMESH_DATABASE_URL", ""),
		DBMaxConns:      int32(g.int("WIREMESH_DB_MAX_CONNS", 20)),
		AutoMigrate:     g.bool("WIREMESH_AUTO_MIGRATE", true),
		RedisURL:        g.str("WIREMESH_REDIS_URL", ""),
		LogLevel:        strings.ToLower(g.str("WIREMESH_LOG_LEVEL", "info")),
		LogFormat:       strings.ToLower(g.str("WIREMESH_LOG_FORMAT", "json")),
		CORSOrigins:     g.list("WIREMESH_CORS_ORIGINS"),
		RateLimitRPS:    g.float("WIREMESH_RATE_LIMIT_RPS", 10),
		RateLimitBurst:  g.int("WIREMESH_RATE_LIMIT_BURST", 30),
		MaxBodyBytes:    int64(g.int("WIREMESH_MAX_BODY_BYTES", 1<<20)),
		ShutdownTimeout: g.duration("WIREMESH_SHUTDOWN_TIMEOUT", 20*time.Second),

		AllowRegistration:        g.bool("WIREMESH_ALLOW_REGISTRATION", false),
		RequireEmailVerification: g.bool("WIREMESH_REQUIRE_EMAIL_VERIFICATION", true),
		SessionIdleTimeout:       g.duration("WIREMESH_SESSION_IDLE_TIMEOUT", 7*24*time.Hour),
		SessionMaxLifetime:       g.duration("WIREMESH_SESSION_MAX_LIFETIME", 30*24*time.Hour),
		AuthRateLimitPerMin:      g.float("WIREMESH_AUTH_RATE_LIMIT_PER_MIN", 12),
		MaxConcurrentHashes:      g.int("WIREMESH_MAX_CONCURRENT_HASHES", 4),

		SMTPHost:     g.str("WIREMESH_SMTP_HOST", ""),
		SMTPPort:     g.int("WIREMESH_SMTP_PORT", 587),
		SMTPUsername: g.str("WIREMESH_SMTP_USERNAME", ""),
		SMTPPassword: g.str("WIREMESH_SMTP_PASSWORD", ""),
		SMTPFrom:     g.str("WIREMESH_SMTP_FROM", ""),
		SMTPTLS:      strings.ToLower(g.str("WIREMESH_SMTP_TLS", "starttls")),
	}

	var errs []error
	errs = append(errs, g.errs...)

	if c.Env != EnvDevelopment && c.Env != EnvProduction {
		errs = append(errs, fmt.Errorf("WIREMESH_ENV must be %q or %q, got %q", EnvDevelopment, EnvProduction, c.Env))
	}
	if c.DatabaseURL == "" {
		errs = append(errs, errors.New("WIREMESH_DATABASE_URL is required"))
	}
	if c.DBMaxConns < 2 || c.DBMaxConns > 1000 {
		errs = append(errs, errors.New("WIREMESH_DB_MAX_CONNS must be between 2 and 1000"))
	}
	switch c.LogLevel {
	case "debug", "info", "warn", "error":
	default:
		errs = append(errs, fmt.Errorf("WIREMESH_LOG_LEVEL must be debug|info|warn|error, got %q", c.LogLevel))
	}
	if c.LogFormat != "json" && c.LogFormat != "text" {
		errs = append(errs, fmt.Errorf("WIREMESH_LOG_FORMAT must be json|text, got %q", c.LogFormat))
	}
	if c.RateLimitRPS <= 0 || c.RateLimitBurst <= 0 {
		errs = append(errs, errors.New("WIREMESH_RATE_LIMIT_RPS and WIREMESH_RATE_LIMIT_BURST must be positive"))
	}
	if c.MaxBodyBytes < 1024 {
		errs = append(errs, errors.New("WIREMESH_MAX_BODY_BYTES must be at least 1024"))
	}
	if c.SessionIdleTimeout < time.Minute || c.SessionMaxLifetime < c.SessionIdleTimeout {
		errs = append(errs, errors.New("WIREMESH_SESSION_IDLE_TIMEOUT must be >= 1m and <= WIREMESH_SESSION_MAX_LIFETIME"))
	}
	if c.AuthRateLimitPerMin <= 0 {
		errs = append(errs, errors.New("WIREMESH_AUTH_RATE_LIMIT_PER_MIN must be positive"))
	}
	if c.MaxConcurrentHashes < 1 || c.MaxConcurrentHashes > 256 {
		errs = append(errs, errors.New("WIREMESH_MAX_CONCURRENT_HASHES must be between 1 and 256"))
	}
	switch c.SMTPTLS {
	case "starttls", "tls", "none":
	default:
		errs = append(errs, fmt.Errorf("WIREMESH_SMTP_TLS must be starttls|tls|none, got %q", c.SMTPTLS))
	}
	if c.SMTPPort < 1 || c.SMTPPort > 65535 {
		errs = append(errs, errors.New("WIREMESH_SMTP_PORT must be a valid port"))
	}
	if c.SMTPHost != "" && c.SMTPFrom == "" {
		errs = append(errs, errors.New("WIREMESH_SMTP_FROM is required when WIREMESH_SMTP_HOST is set"))
	}
	if c.IsProduction() && c.RequireEmailVerification && c.SMTPHost == "" {
		errs = append(errs, errors.New("WIREMESH_SMTP_HOST is required in production when WIREMESH_REQUIRE_EMAIL_VERIFICATION=true"))
	}
	if c.IsProduction() && c.SMTPHost != "" && c.SMTPTLS == "none" {
		errs = append(errs, errors.New("WIREMESH_SMTP_TLS=none is not allowed in production"))
	}

	// Public URL: used for email links, cookie security and CORS defaults.
	rawURL := g.str("WIREMESH_PUBLIC_URL", "http://localhost:8080")
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		errs = append(errs, fmt.Errorf("WIREMESH_PUBLIC_URL must be an absolute http(s) URL, got %q", rawURL))
	} else {
		u.Path = strings.TrimRight(u.Path, "/")
		c.PublicURL = u
		if c.IsProduction() && u.Scheme != "https" {
			errs = append(errs, errors.New("WIREMESH_PUBLIC_URL must use https in production"))
		}
	}

	// Secret key: 32 random bytes, base64. Dev mode gets an ephemeral key with a
	// loud warning in main; production must configure one.
	if raw := g.str("WIREMESH_SECRET_KEY", ""); raw != "" {
		key, err := base64.StdEncoding.DecodeString(raw)
		if err != nil || len(key) != 32 {
			errs = append(errs, errors.New("WIREMESH_SECRET_KEY must be 32 bytes, base64-encoded (openssl rand -base64 32)"))
		} else {
			c.SecretKey = key
		}
	} else if c.IsProduction() {
		errs = append(errs, errors.New("WIREMESH_SECRET_KEY is required in production"))
	}

	for _, s := range g.list("WIREMESH_TRUSTED_PROXIES") {
		p, err := parsePrefixOrAddr(s)
		if err != nil {
			errs = append(errs, fmt.Errorf("WIREMESH_TRUSTED_PROXIES: %w", err))
			continue
		}
		c.TrustedProxies = append(c.TrustedProxies, p)
	}

	rangeStr := g.str("WIREMESH_IPV4_RANGE", "100.64.0.0/10")
	pfx, err := netip.ParsePrefix(rangeStr)
	switch {
	case err != nil:
		errs = append(errs, fmt.Errorf("WIREMESH_IPV4_RANGE: %w", err))
	case !pfx.Addr().Is4() || pfx.Bits() > 24 || pfx.Masked() != pfx:
		errs = append(errs, fmt.Errorf("WIREMESH_IPV4_RANGE must be a canonical IPv4 prefix of /24 or larger, got %q", rangeStr))
	default:
		c.DefaultIPv4Range = pfx
	}

	for _, o := range c.CORSOrigins {
		ou, err := url.Parse(o)
		if err != nil || ou.Scheme == "" || ou.Host == "" || ou.Path != "" {
			errs = append(errs, fmt.Errorf("WIREMESH_CORS_ORIGINS entry %q must be an origin like https://admin.example.com", o))
		}
	}

	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	return c, nil
}

func parsePrefixOrAddr(s string) (netip.Prefix, error) {
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return netip.Prefix{}, err
		}
		return p.Masked(), nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, err
	}
	return netip.PrefixFrom(a, a.BitLen()), nil
}

// getter accumulates parse errors so that Load can report every problem at once.
type getter struct {
	lookup func(string) (string, bool)
	errs   []error
}

func (g *getter) str(key, def string) string {
	if v, ok := g.lookup(key); ok {
		return strings.TrimSpace(v)
	}
	return def
}

func (g *getter) int(key string, def int) int {
	v, ok := g.lookup(key)
	if !ok || strings.TrimSpace(v) == "" {
		return def
	}
	n, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil {
		g.errs = append(g.errs, fmt.Errorf("%s: invalid integer %q", key, v))
		return def
	}
	return n
}

func (g *getter) float(key string, def float64) float64 {
	v, ok := g.lookup(key)
	if !ok || strings.TrimSpace(v) == "" {
		return def
	}
	f, err := strconv.ParseFloat(strings.TrimSpace(v), 64)
	if err != nil {
		g.errs = append(g.errs, fmt.Errorf("%s: invalid number %q", key, v))
		return def
	}
	return f
}

func (g *getter) bool(key string, def bool) bool {
	v, ok := g.lookup(key)
	if !ok || strings.TrimSpace(v) == "" {
		return def
	}
	b, err := strconv.ParseBool(strings.TrimSpace(v))
	if err != nil {
		g.errs = append(g.errs, fmt.Errorf("%s: invalid boolean %q", key, v))
		return def
	}
	return b
}

func (g *getter) duration(key string, def time.Duration) time.Duration {
	v, ok := g.lookup(key)
	if !ok || strings.TrimSpace(v) == "" {
		return def
	}
	d, err := time.ParseDuration(strings.TrimSpace(v))
	if err != nil || d <= 0 {
		g.errs = append(g.errs, fmt.Errorf("%s: invalid duration %q", key, v))
		return def
	}
	return d
}

func (g *getter) list(key string) []string {
	v, ok := g.lookup(key)
	if !ok {
		return nil
	}
	var out []string
	for _, part := range strings.Split(v, ",") {
		if p := strings.TrimSpace(part); p != "" {
			out = append(out, p)
		}
	}
	return out
}
