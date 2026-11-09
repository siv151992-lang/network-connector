package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"strings"
)

// Token prefixes make leaked secrets easy to identify (and to add to secret
// scanners), and stop one kind of token being used where another is expected.
const (
	PrefixSession = "wms_" // dashboard session cookie
	PrefixDevice  = "wmd_" // device bearer credential
	PrefixAuthKey = "wmk_" // pre-authentication key
	PrefixEmail   = "wme_" // email verification / password reset
)

const tokenBytes = 32

var tokenEncodedLen = base64.RawURLEncoding.EncodedLen(tokenBytes)

// NewToken returns a random prefixed token and its SHA-256 hash. Only the hash
// is persisted; the raw token is shown to its owner once.
func NewToken(prefix string) (raw string, hash []byte, err error) {
	b := make([]byte, tokenBytes)
	if _, err := rand.Read(b); err != nil {
		return "", nil, err
	}
	raw = prefix + base64.RawURLEncoding.EncodeToString(b)
	return raw, HashToken(raw), nil
}

// HashToken returns SHA-256(raw). A fast hash is appropriate here because the
// tokens carry 256 bits of entropy, so they cannot be brute-forced.
func HashToken(raw string) []byte {
	h := sha256.Sum256([]byte(raw))
	return h[:]
}

// ParseToken checks a raw token's prefix and shape and returns its hash.
func ParseToken(raw, prefix string) ([]byte, bool) {
	if !strings.HasPrefix(raw, prefix) || len(raw) != len(prefix)+tokenEncodedLen {
		return nil, false
	}
	if _, err := base64.RawURLEncoding.DecodeString(raw[len(prefix):]); err != nil {
		return nil, false
	}
	return HashToken(raw), true
}

// CSRFToken derives the CSRF token bound to a session. It is stateless: an
// HMAC under the server secret, so it can't be forged without the key and
// changes whenever the session does.
func CSRFToken(secret []byte, sessionID string) string {
	m := hmac.New(sha256.New, secret)
	m.Write([]byte("wiremesh-csrf-v1:"))
	m.Write([]byte(sessionID))
	return base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

// CheckCSRFToken compares in constant time.
func CheckCSRFToken(secret []byte, sessionID, token string) bool {
	return token != "" && hmac.Equal([]byte(CSRFToken(secret, sessionID)), []byte(token))
}
