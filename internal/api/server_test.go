package api

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/siv151992-lang/network-connector/internal/api/middleware"
	"github.com/siv151992-lang/network-connector/internal/config"
)

type fakeDB struct{ err error }

func (f fakeDB) Ping(context.Context) error { return f.err }

func newTestServer(t *testing.T, db Pinger) *httptest.Server {
	t.Helper()
	cfg, err := config.LoadFrom(func(k string) (string, bool) {
		if k == "WIREMESH_DATABASE_URL" {
			return "postgres://unused", true
		}
		return "", false
	})
	if err != nil {
		t.Fatal(err)
	}
	lim := middleware.NewLimiter(100, 100)
	t.Cleanup(lim.Stop)
	h := NewHandler(Deps{Config: cfg, Log: slog.New(slog.NewTextHandler(io.Discard, nil)), DB: db, Limiter: lim})
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return srv
}

func getJSON(t *testing.T, url string) (int, map[string]any, http.Header) {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var body map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode %s: %v", url, err)
	}
	return resp.StatusCode, body, resp.Header
}

func TestSystemEndpoints(t *testing.T) {
	srv := newTestServer(t, fakeDB{})

	code, body, hdr := getJSON(t, srv.URL+"/healthz")
	if code != 200 || body["status"] != "ok" || hdr.Get("X-Request-ID") == "" {
		t.Fatalf("healthz: %d %v", code, body)
	}
	code, body, _ = getJSON(t, srv.URL+"/readyz")
	if code != 200 || body["status"] != "ready" {
		t.Fatalf("readyz: %d %v", code, body)
	}
	code, body, _ = getJSON(t, srv.URL+"/api/v1/version")
	if code != 200 || body["api"] != "v1" {
		t.Fatalf("version: %d %v", code, body)
	}
	code, body, hdr = getJSON(t, srv.URL+"/api/v1/nope")
	errObj, _ := body["error"].(map[string]any)
	if code != 404 || errObj["code"] != "not_found" || errObj["request_id"] != hdr.Get("X-Request-ID") {
		t.Fatalf("404: %d %v", code, body)
	}
	if hdr.Get("X-Content-Type-Options") != "nosniff" {
		t.Fatal("security headers missing")
	}
}

func TestReadyzReportsDatabaseDown(t *testing.T) {
	srv := newTestServer(t, fakeDB{err: errors.New("connection refused")})
	code, body, _ := getJSON(t, srv.URL+"/readyz")
	checks, _ := body["checks"].(map[string]any)
	if code != 503 || body["status"] != "not_ready" || checks["database"] != "unavailable" {
		t.Fatalf("readyz: %d %v", code, body)
	}
}
