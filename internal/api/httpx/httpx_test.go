package httpx

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/siv151992-lang/network-connector/internal/store"
)

func TestDecodeJSON(t *testing.T) {
	type req struct {
		Name string `json:"name"`
		N    int    `json:"n"`
	}
	cases := []struct {
		body, ct string
		status   int // 0 = success
	}{
		{`{"name":"a","n":1}`, "application/json", 0},
		{`{"name":"a"}`, "", 0},
		{``, "application/json", 400},
		{`{"name":`, "application/json", 400},
		{`{"name":"a","extra":1}`, "application/json", 400},
		{`{"n":"x"}`, "application/json", 400},
		{`{"name":"a"}{"name":"b"}`, "application/json", 400},
		{`{"name":"a"}`, "text/plain", 415},
		{`{"name":"` + strings.Repeat("a", 100) + `"}`, "application/json", 413},
	}
	for i, c := range cases {
		r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(c.body))
		if c.ct != "" {
			r.Header.Set("Content-Type", c.ct)
		}
		r.Body = http.MaxBytesReader(httptest.NewRecorder(), r.Body, 64)
		var v req
		err := DecodeJSON(r, &v)
		if c.status == 0 {
			if err != nil {
				t.Errorf("case %d: unexpected error %v", i, err)
			}
			continue
		}
		var e *Error
		if !errors.As(err, &e) || e.Status != c.status {
			t.Errorf("case %d: want status %d, got %v", i, c.status, err)
		}
	}
}

func TestFromErrorMapsStoreErrors(t *testing.T) {
	cases := []struct {
		err    error
		status int
		msg    string
	}{
		{fmt.Errorf("get: %w", store.ErrNotFound), 404, "resource not found"},
		{fmt.Errorf("x: %w", &store.ConflictError{Constraint: "users_email_key"}), 409, "resource already exists"},
		{&store.InvalidError{Reason: "a network must keep at least one owner"}, 422, "a network must keep at least one owner"},
		{&store.InvalidError{Reason: "constraint devices_name_format"}, 422, "invalid request"}, // schema details hidden
		{errors.New("boom: password=hunter2"), 500, "internal server error"},
	}
	for _, c := range cases {
		e := FromError(c.err)
		if e.Status != c.status || e.Message != c.msg {
			t.Errorf("%v: got %d %q", c.err, e.Status, e.Message)
		}
	}
}

func TestWriteErrorEnvelope(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/x", nil)
	r = r.WithContext(WithRequestID(r.Context(), "req-1"))
	w := httptest.NewRecorder()
	WriteError(w, r, nil, Validation(map[string]string{"email": "required"}))

	if w.Code != 422 || !strings.HasPrefix(w.Header().Get("Content-Type"), "application/json") {
		t.Fatalf("status %d ct %q", w.Code, w.Header().Get("Content-Type"))
	}
	var body struct {
		Error struct {
			Code, Message, RequestID string
			Fields                   map[string]string
		} `json:"error"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Error.Code != "validation_failed" || body.Error.Fields["email"] != "required" {
		t.Fatalf("body: %s", w.Body.String())
	}
	if !strings.Contains(w.Body.String(), `"request_id":"req-1"`) {
		t.Fatalf("missing request id: %s", w.Body.String())
	}
}
