// Package auth contains authentication primitives: password hashing,
// random tokens, TOTP and outbound email. It holds no HTTP or SQL code.
package auth

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"
)

// Argon2Params are Argon2id cost parameters.
type Argon2Params struct {
	Memory      uint32 // KiB
	Iterations  uint32
	Parallelism uint8
	SaltLen     uint32
	KeyLen      uint32
}

// DefaultArgon2Params follow the OWASP recommendation band
// (m=64 MiB, t=3, p=2): roughly 50–100 ms on a small VPS core.
var DefaultArgon2Params = Argon2Params{Memory: 64 * 1024, Iterations: 3, Parallelism: 2, SaltLen: 16, KeyLen: 32}

// ErrInvalidHash is returned when a stored hash cannot be parsed.
var ErrInvalidHash = errors.New("auth: invalid password hash format")

// Hasher hashes and verifies passwords. A semaphore bounds the number of
// concurrent hashes, since each needs Memory KiB of RAM: without it, a burst
// of logins could exhaust memory on a small server.
type Hasher struct {
	p   Argon2Params
	sem chan struct{}
	// dummy is a valid hash used to equalize timing for unknown accounts.
	dummy string
}

// NewHasher creates a Hasher allowing maxConcurrent simultaneous hashes.
func NewHasher(p Argon2Params, maxConcurrent int) *Hasher {
	if maxConcurrent < 1 {
		maxConcurrent = 1
	}
	h := &Hasher{p: p, sem: make(chan struct{}, maxConcurrent)}
	h.dummy, _ = h.hash("dummy-password-for-timing")
	return h
}

func (h *Hasher) acquire(ctx context.Context) error {
	select {
	case h.sem <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (h *Hasher) release() { <-h.sem }

// Hash returns a PHC-format Argon2id hash:
// $argon2id$v=19$m=65536,t=3,p=2$<salt>$<key>
func (h *Hasher) Hash(ctx context.Context, password string) (string, error) {
	if err := h.acquire(ctx); err != nil {
		return "", err
	}
	defer h.release()
	return h.hash(password)
}

func (h *Hasher) hash(password string) (string, error) {
	salt := make([]byte, h.p.SaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key := argon2.IDKey([]byte(password), salt, h.p.Iterations, h.p.Memory, h.p.Parallelism, h.p.KeyLen)
	b64 := base64.RawStdEncoding
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, h.p.Memory, h.p.Iterations, h.p.Parallelism, b64.EncodeToString(salt), b64.EncodeToString(key)), nil
}

// Verify checks password against an encoded hash in constant time. needsRehash
// is true when the hash used weaker parameters than the current ones, so the
// caller can upgrade it after a successful login.
func (h *Hasher) Verify(ctx context.Context, password, encoded string) (ok, needsRehash bool, err error) {
	p, salt, key, err := decodeHash(encoded)
	if err != nil {
		return false, false, err
	}
	if err := h.acquire(ctx); err != nil {
		return false, false, err
	}
	defer h.release()
	got := argon2.IDKey([]byte(password), salt, p.Iterations, p.Memory, p.Parallelism, uint32(len(key)))
	if subtle.ConstantTimeCompare(got, key) != 1 {
		return false, false, nil
	}
	needsRehash = p.Memory < h.p.Memory || p.Iterations < h.p.Iterations || uint32(len(key)) < h.p.KeyLen
	return true, needsRehash, nil
}

// VerifyDummy burns the same CPU/memory as a real verification. Call it when
// the account does not exist so response timing does not reveal that.
func (h *Hasher) VerifyDummy(ctx context.Context, password string) {
	_, _, _ = h.Verify(ctx, password, h.dummy)
}

func decodeHash(encoded string) (Argon2Params, []byte, []byte, error) {
	var p Argon2Params
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return p, nil, nil, ErrInvalidHash
	}
	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil || version != argon2.Version {
		return p, nil, nil, ErrInvalidHash
	}
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &p.Memory, &p.Iterations, &p.Parallelism); err != nil {
		return p, nil, nil, ErrInvalidHash
	}
	// Reject absurd parameters from a tampered row (DoS protection).
	if p.Memory == 0 || p.Memory > 1<<20 || p.Iterations == 0 || p.Iterations > 20 || p.Parallelism == 0 {
		return p, nil, nil, ErrInvalidHash
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil || len(salt) < 8 {
		return p, nil, nil, ErrInvalidHash
	}
	key, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil || len(key) < 16 || len(key) > 64 {
		return p, nil, nil, ErrInvalidHash
	}
	return p, salt, key, nil
}

// Password policy. Following NIST SP 800-63B: length matters, composition
// rules don't; very long inputs are capped to bound hashing cost.
const (
	MinPasswordLen = 10
	MaxPasswordLen = 128 // characters
)

var commonPasswords = map[string]bool{
	"password1234": true, "passwordpassword": true, "1234567890": true, "12345678910": true,
	"qwertyuiop": true, "qwerty12345": true, "iloveyou123": true, "letmein1234": true,
	"administrator": true, "welcome1234": true, "0123456789": true, "1q2w3e4r5t": true,
}

// ValidatePassword returns a user-facing problem description, or "" if acceptable.
func ValidatePassword(password, email string) string {
	if !utf8.ValidString(password) {
		return "password must be valid UTF-8"
	}
	n := utf8.RuneCountInString(password)
	switch {
	case n < MinPasswordLen:
		return fmt.Sprintf("password must be at least %d characters", MinPasswordLen)
	case n > MaxPasswordLen:
		return fmt.Sprintf("password must be at most %d characters", MaxPasswordLen)
	}
	lower := strings.ToLower(password)
	if commonPasswords[lower] {
		return "password is too common"
	}
	if local, _, ok := strings.Cut(strings.ToLower(email), "@"); ok && len(local) >= 4 && strings.Contains(lower, local) {
		return "password must not contain your email address"
	}
	if strings.Count(password, string([]rune(password)[0])) == len(password) {
		return "password must not be a single repeated character"
	}
	return ""
}
