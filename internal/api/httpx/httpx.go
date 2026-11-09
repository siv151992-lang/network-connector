// Package httpx contains JSON request/response helpers and the uniform error
// envelope used by every API endpoint:
//
//	{"error": {"code": "not_found", "message": "device not found", "request_id": "…"}}
package httpx

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"

	"github.com/siv151992-lang/network-connector/internal/store"
)

type ctxKey int

const requestIDKey ctxKey = iota

// WithRequestID stores the request ID in ctx.
func WithRequestID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, requestIDKey, id)
}

// RequestID returns the request ID stored in ctx, or "".
func RequestID(ctx context.Context) string {
	id, _ := ctx.Value(requestIDKey).(string)
	return id
}

// Error is an API error with an HTTP status and a stable machine-readable code.
// Message is shown to clients, so it must never contain internal details.
type Error struct {
	Status  int               `json:"-"`
	Code    string            `json:"code"`
	Message string            `json:"message"`
	Fields  map[string]string `json:"fields,omitempty"` // per-field validation errors
	Err     error             `json:"-"`                // internal cause, logged only
}

func (e *Error) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("%s: %s: %v", e.Code, e.Message, e.Err)
	}
	return e.Code + ": " + e.Message
}

func (e *Error) Unwrap() error { return e.Err }

// Constructors for common errors.
func BadRequest(msg string) *Error {
	return &Error{Status: http.StatusBadRequest, Code: "bad_request", Message: msg}
}
func Unauthorized(msg string) *Error {
	return &Error{Status: http.StatusUnauthorized, Code: "unauthorized", Message: msg}
}
func Forbidden(msg string) *Error {
	return &Error{Status: http.StatusForbidden, Code: "forbidden", Message: msg}
}
func NotFound(msg string) *Error {
	return &Error{Status: http.StatusNotFound, Code: "not_found", Message: msg}
}
func Conflict(msg string) *Error {
	return &Error{Status: http.StatusConflict, Code: "conflict", Message: msg}
}
func TooManyRequests() *Error {
	return &Error{Status: http.StatusTooManyRequests, Code: "rate_limited", Message: "too many requests, slow down"}
}

// Validation returns a 422 with per-field messages.
func Validation(fields map[string]string) *Error {
	return &Error{Status: http.StatusUnprocessableEntity, Code: "validation_failed", Message: "request validation failed", Fields: fields}
}

// Internal wraps an unexpected error. The cause is logged, never returned.
func Internal(err error) *Error {
	return &Error{Status: http.StatusInternalServerError, Code: "internal", Message: "internal server error", Err: err}
}

// FromError maps arbitrary errors (including store sentinels) to *Error.
func FromError(err error) *Error {
	var e *Error
	switch {
	case errors.As(err, &e):
		return e
	case errors.Is(err, store.ErrNotFound):
		return NotFound("resource not found")
	case errors.Is(err, store.ErrConflict):
		return &Error{Status: http.StatusConflict, Code: "conflict", Message: "resource already exists", Err: err}
	case errors.Is(err, store.ErrInvalid):
		var ie *store.InvalidError
		msg := "invalid request"
		if errors.As(err, &ie) && !strings.HasPrefix(ie.Reason, "constraint ") && !strings.HasPrefix(ie.Reason, "reference ") {
			msg = ie.Reason // business-rule messages are safe to show
		}
		return &Error{Status: http.StatusUnprocessableEntity, Code: "invalid", Message: msg, Err: err}
	case errors.Is(err, context.Canceled):
		return &Error{Status: 499, Code: "canceled", Message: "request canceled", Err: err}
	case errors.Is(err, context.DeadlineExceeded):
		return &Error{Status: http.StatusGatewayTimeout, Code: "timeout", Message: "request timed out", Err: err}
	default:
		return Internal(err)
	}
}

// WriteJSON writes v as JSON with the given status.
func WriteJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	if v == nil {
		return
	}
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(true)
	_ = enc.Encode(v)
}

// WriteError writes err using the error envelope and logs server-side failures.
func WriteError(w http.ResponseWriter, r *http.Request, log *slog.Logger, err error) {
	e := FromError(err)
	if e.Status >= 500 && log != nil {
		log.ErrorContext(r.Context(), "request failed",
			"request_id", RequestID(r.Context()), "method", r.Method, "path", r.URL.Path, "error", err)
	}
	type body struct {
		Code      string            `json:"code"`
		Message   string            `json:"message"`
		Fields    map[string]string `json:"fields,omitempty"`
		RequestID string            `json:"request_id,omitempty"`
	}
	WriteJSON(w, e.Status, map[string]body{"error": {e.Code, e.Message, e.Fields, RequestID(r.Context())}})
}

// DecodeJSON strictly decodes a JSON request body into dst: it requires a JSON
// content type, rejects unknown fields and trailing data, and maps size-limit
// errors (from http.MaxBytesReader) to 413.
func DecodeJSON(r *http.Request, dst any) error {
	ct := r.Header.Get("Content-Type")
	if ct != "" && !strings.HasPrefix(strings.ToLower(ct), "application/json") {
		return &Error{Status: http.StatusUnsupportedMediaType, Code: "unsupported_media_type", Message: "Content-Type must be application/json"}
	}
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		var maxErr *http.MaxBytesError
		var synErr *json.SyntaxError
		var typErr *json.UnmarshalTypeError
		switch {
		case errors.As(err, &maxErr):
			return &Error{Status: http.StatusRequestEntityTooLarge, Code: "body_too_large", Message: "request body too large"}
		case errors.Is(err, io.EOF):
			return BadRequest("request body is empty")
		case errors.As(err, &synErr), errors.Is(err, io.ErrUnexpectedEOF):
			return BadRequest("malformed JSON")
		case errors.As(err, &typErr):
			return BadRequest(fmt.Sprintf("field %q has the wrong type", typErr.Field))
		case strings.HasPrefix(err.Error(), "json: unknown field "):
			return BadRequest("unknown field " + strings.TrimPrefix(err.Error(), "json: unknown field "))
		default:
			return BadRequest("invalid JSON body")
		}
	}
	if dec.More() {
		return BadRequest("request body must contain a single JSON object")
	}
	return nil
}
