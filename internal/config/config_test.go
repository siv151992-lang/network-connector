package config

import (
	"encoding/base64"
	"strings"
	"testing"
	"time"
)

func env(m map[string]string) func(string) (string, bool) {
	return func(k string) (string, bool) { v, ok := m[k]; return v, ok }
}

var validKey = base64.StdEncoding.EncodeToString(make([]byte, 32))

func TestLoadDefaults(t *testing.T) {
	c, err := LoadFrom(env(map[string]string{"WIREMESH_DATABASE_URL": "postgres://x"}))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c.Env != EnvDevelopment || c.HTTPAddr != ":8080" || !c.AutoMigrate {
		t.Fatalf("bad defaults: %+v", c)
	}
	if c.DefaultIPv4Range.String() != "100.64.0.0/10" {
		t.Fatalf("ipv4 range = %s", c.DefaultIPv4Range)
	}
	if c.ShutdownTimeout != 20*time.Second {
		t.Fatalf("shutdown timeout = %s", c.ShutdownTimeout)
	}
	if c.SecretKey != nil {
		t.Fatal("secret key should be nil when unset in development")
	}
}

func TestLoadProductionRequirements(t *testing.T) {
	_, err := LoadFrom(env(map[string]string{
		"WIREMESH_ENV":          "production",
		"WIREMESH_DATABASE_URL": "postgres://x",
		"WIREMESH_PUBLIC_URL":   "http://vpn.example.com",
	}))
	if err == nil {
		t.Fatal("expected error")
	}
	for _, want := range []string{"https in production", "WIREMESH_SECRET_KEY is required", "WIREMESH_SMTP_HOST is required"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q missing %q", err, want)
		}
	}

	c, err := LoadFrom(env(map[string]string{
		"WIREMESH_ENV":             "production",
		"WIREMESH_DATABASE_URL":    "postgres://x",
		"WIREMESH_PUBLIC_URL":      "https://vpn.example.com/",
		"WIREMESH_SECRET_KEY":      validKey,
		"WIREMESH_TRUSTED_PROXIES": "172.16.0.0/12, 10.0.0.5",
		"WIREMESH_CORS_ORIGINS":    "https://admin.example.com",
		"WIREMESH_SMTP_HOST":       "smtp.example.com",
		"WIREMESH_SMTP_FROM":       "WireMesh <noreply@example.com>",
	}))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !c.IsProduction() || len(c.SecretKey) != 32 || len(c.TrustedProxies) != 2 {
		t.Fatalf("bad config: %+v", c)
	}
	if c.TrustedProxies[1].String() != "10.0.0.5/32" {
		t.Fatalf("single address should become /32, got %s", c.TrustedProxies[1])
	}
	if c.PublicURL.String() != "https://vpn.example.com" {
		t.Fatalf("public url not normalized: %s", c.PublicURL)
	}
}

func TestLoadReportsAllErrors(t *testing.T) {
	_, err := LoadFrom(env(map[string]string{
		"WIREMESH_DB_MAX_CONNS":    "abc",
		"WIREMESH_LOG_LEVEL":       "loud",
		"WIREMESH_SECRET_KEY":      "short",
		"WIREMESH_IPV4_RANGE":      "100.64.0.0/28",
		"WIREMESH_CORS_ORIGINS":    "not-an-origin",
		"WIREMESH_TRUSTED_PROXIES": "bogus",
	}))
	if err == nil {
		t.Fatal("expected error")
	}
	for _, want := range []string{
		"WIREMESH_DATABASE_URL is required",
		"WIREMESH_DB_MAX_CONNS: invalid integer",
		"WIREMESH_LOG_LEVEL",
		"WIREMESH_SECRET_KEY must be 32 bytes",
		"WIREMESH_IPV4_RANGE must be",
		"WIREMESH_CORS_ORIGINS entry",
		"WIREMESH_TRUSTED_PROXIES",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error missing %q:\n%v", want, err)
		}
	}
}
