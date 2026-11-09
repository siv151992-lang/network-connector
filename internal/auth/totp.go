package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // RFC 6238 TOTP uses HMAC-SHA1; authenticator apps expect it.
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// TOTP parameters (RFC 6238 defaults, understood by every authenticator app).
const (
	TOTPPeriod = 30
	TOTPDigits = 6
	totpSkew   = 1 // accept codes one step before/after to tolerate clock drift
)

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// GenerateTOTPSecret returns a new 160-bit secret, base32-encoded.
func GenerateTOTPSecret() (string, error) {
	b := make([]byte, 20)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return b32.EncodeToString(b), nil
}

// totpCode computes the HOTP value for a counter (RFC 4226 §5.3).
func totpCode(secret []byte, counter uint64, digits int) string {
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], counter)
	m := hmac.New(sha1.New, secret)
	m.Write(msg[:])
	sum := m.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	bin := binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff
	mod := uint32(1)
	for i := 0; i < digits; i++ {
		mod *= 10
	}
	return fmt.Sprintf("%0*d", digits, bin%mod)
}

// TOTPStep returns the time-step counter for t.
func TOTPStep(t time.Time) int64 { return t.Unix() / TOTPPeriod }

// TOTPCodeAt returns the current code for a base32 secret (used by tests and clients).
func TOTPCodeAt(secretB32 string, t time.Time) (string, error) {
	secret, err := b32.DecodeString(strings.ToUpper(secretB32))
	if err != nil {
		return "", err
	}
	return totpCode(secret, uint64(TOTPStep(t)), TOTPDigits), nil
}

// VerifyTOTP checks code against the secret at time now, accepting ±1 step.
// To block replay, a match is only accepted if its step is greater than
// lastStep (the step of the last code accepted for this user). It returns the
// matched step, which the caller must persist atomically.
func VerifyTOTP(secretB32, code string, now time.Time, lastStep int64) (int64, bool) {
	code = strings.ReplaceAll(strings.TrimSpace(code), " ", "")
	if len(code) != TOTPDigits {
		return 0, false
	}
	secret, err := b32.DecodeString(strings.ToUpper(secretB32))
	if err != nil {
		return 0, false
	}
	cur := TOTPStep(now)
	matched := int64(-1)
	for d := -totpSkew; d <= totpSkew; d++ {
		step := cur + int64(d)
		if step <= lastStep || step < 0 {
			continue
		}
		// Check every candidate (no early exit) to keep timing uniform.
		if hmac.Equal([]byte(totpCode(secret, uint64(step), TOTPDigits)), []byte(code)) {
			matched = step
		}
	}
	return matched, matched >= 0
}

// TOTPURI builds the otpauth:// URI that authenticator apps import via QR code.
func TOTPURI(issuer, account, secretB32 string) string {
	label := url.PathEscape(issuer) + ":" + url.PathEscape(account)
	q := url.Values{}
	q.Set("secret", secretB32)
	q.Set("issuer", issuer)
	q.Set("algorithm", "SHA1")
	q.Set("digits", fmt.Sprint(TOTPDigits))
	q.Set("period", fmt.Sprint(TOTPPeriod))
	return "otpauth://totp/" + label + "?" + q.Encode()
}
