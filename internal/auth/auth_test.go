package auth

import (
	"context"
	"net/url"
	"strings"
	"testing"
	"time"
)

// Cheap parameters keep the tests fast; production uses DefaultArgon2Params.
var testParams = Argon2Params{Memory: 1024, Iterations: 1, Parallelism: 1, SaltLen: 16, KeyLen: 32}

func TestPasswordHashVerify(t *testing.T) {
	ctx := context.Background()
	h := NewHasher(testParams, 2)
	enc, err := h.Hash(ctx, "correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(enc, "$argon2id$v=19$m=1024,t=1,p=1$") {
		t.Fatalf("unexpected encoding %q", enc)
	}
	enc2, _ := h.Hash(ctx, "correct horse battery")
	if enc == enc2 {
		t.Fatal("hashes must be salted")
	}
	if ok, rehash, err := h.Verify(ctx, "correct horse battery", enc); !ok || rehash || err != nil {
		t.Fatalf("verify: %v %v %v", ok, rehash, err)
	}
	if ok, _, _ := h.Verify(ctx, "wrong", enc); ok {
		t.Fatal("wrong password accepted")
	}
	stronger := NewHasher(Argon2Params{Memory: 2048, Iterations: 1, Parallelism: 1, SaltLen: 16, KeyLen: 32}, 1)
	if ok, rehash, _ := stronger.Verify(ctx, "correct horse battery", enc); !ok || !rehash {
		t.Fatal("weaker hash should verify and request rehash")
	}
	for _, bad := range []string{"", "$argon2i$v=19$m=1,t=1,p=1$aaaa$bbbb", "$argon2id$v=19$m=99999999,t=1,p=1$c2FsdHNhbHQ$" + strings.Repeat("A", 43)} {
		if _, _, err := h.Verify(ctx, "x", bad); err != ErrInvalidHash {
			t.Errorf("%q: want ErrInvalidHash, got %v", bad, err)
		}
	}
}

func TestHasherRespectsContext(t *testing.T) {
	h := NewHasher(testParams, 1)
	h.sem <- struct{}{} // occupy the only slot
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := h.Hash(ctx, "x"); err == nil {
		t.Fatal("expected context error while semaphore is full")
	}
}

func TestValidatePassword(t *testing.T) {
	cases := map[string]bool{
		"short":                    false,
		"aaaaaaaaaaaa":             false,
		"password1234":             false,
		"alice-secret-pass":        false, // contains email local part
		"correct horse battery":    true,
		strings.Repeat("x", 129):   false,
		"Ünïcödé pässwörd ok":      true,
	}
	for pw, ok := range cases {
		if got := ValidatePassword(pw, "alice@example.com") == ""; got != ok {
			t.Errorf("%q: got ok=%v want %v (%s)", pw, got, ok, ValidatePassword(pw, "alice@example.com"))
		}
	}
}

func TestTokens(t *testing.T) {
	raw, hash, err := NewToken(PrefixDevice)
	if err != nil || !strings.HasPrefix(raw, "wmd_") || len(hash) != 32 {
		t.Fatalf("%q %x %v", raw, hash, err)
	}
	if h, ok := ParseToken(raw, PrefixDevice); !ok || string(h) != string(hash) {
		t.Fatal("parse failed")
	}
	if _, ok := ParseToken(raw, PrefixSession); ok {
		t.Fatal("token accepted with wrong prefix")
	}
	if _, ok := ParseToken(raw[:len(raw)-1], PrefixDevice); ok {
		t.Fatal("truncated token accepted")
	}
	if _, ok := ParseToken("wmd_"+strings.Repeat("!", 43), PrefixDevice); ok {
		t.Fatal("non-base64 token accepted")
	}
}

func TestCSRF(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	tok := CSRFToken(secret, "session-a")
	if !CheckCSRFToken(secret, "session-a", tok) {
		t.Fatal("valid token rejected")
	}
	if CheckCSRFToken(secret, "session-b", tok) || CheckCSRFToken([]byte("other-secret-other-secret-123456"), "session-a", tok) || CheckCSRFToken(secret, "session-a", "") {
		t.Fatal("invalid token accepted")
	}
}

// RFC 6238 Appendix B test vectors (SHA1, 8 digits); we use the last 6 digits.
func TestTOTPVectors(t *testing.T) {
	secret := []byte("12345678901234567890")
	vectors := map[int64]string{59: "94287082", 1111111109: "07081804", 1234567890: "89005924", 2000000000: "69279037"}
	for ts, want := range vectors {
		if got := totpCode(secret, uint64(ts/30), 8); got != want {
			t.Errorf("t=%d: got %s want %s", ts, got, want)
		}
	}
}

func TestVerifyTOTP(t *testing.T) {
	secret, err := GenerateTOTPSecret()
	if err != nil || len(secret) != 32 {
		t.Fatalf("secret %q %v", secret, err)
	}
	now := time.Unix(1_700_000_000, 0)
	code, _ := TOTPCodeAt(secret, now)

	step, ok := VerifyTOTP(secret, code, now, 0)
	if !ok || step != TOTPStep(now) {
		t.Fatal("current code rejected")
	}
	if _, ok := VerifyTOTP(secret, code, now, step); ok {
		t.Fatal("replayed code accepted")
	}
	if _, ok := VerifyTOTP(secret, code, now.Add(30*time.Second), 0); !ok {
		t.Fatal("code from previous step should be accepted (clock skew)")
	}
	if _, ok := VerifyTOTP(secret, code, now.Add(90*time.Second), 0); ok {
		t.Fatal("code three steps old accepted")
	}
	if _, ok := VerifyTOTP(secret, "000000", now, 0); ok && code != "000000" {
		t.Fatal("wrong code accepted")
	}
	if _, ok := VerifyTOTP(secret, "12345", now, 0); ok {
		t.Fatal("short code accepted")
	}
	spaced := code[:3] + " " + code[3:]
	if _, ok := VerifyTOTP(secret, spaced, now, 0); !ok {
		t.Fatal("code with space rejected")
	}
}

func TestTOTPURI(t *testing.T) {
	u, err := url.Parse(TOTPURI("WireMesh", "a@example.com", "ABC"))
	if err != nil || u.Scheme != "otpauth" || u.Host != "totp" || u.Query().Get("secret") != "ABC" || u.Query().Get("issuer") != "WireMesh" {
		t.Fatalf("bad uri %v %v", u, err)
	}
}

func TestMailerRejectsHeaderInjection(t *testing.T) {
	var c CaptureMailer
	if err := c.Send(context.Background(), Message{To: "a@example.com\r\nBcc: x@evil", Subject: "s"}); err == nil {
		t.Fatal("injection accepted")
	}
	if err := c.Send(context.Background(), Message{To: "a@example.com", Subject: "s\nBcc: x"}); err == nil {
		t.Fatal("subject injection accepted")
	}
	pub, _ := url.Parse("https://vpn.example.com")
	m := VerificationEmail(pub, "a@example.com", "wme_tok")
	if !strings.Contains(m.Text, "https://vpn.example.com/verify-email?token=wme_tok") {
		t.Fatalf("link missing: %s", m.Text)
	}
}

func TestBuildMessage(t *testing.T) {
	b := string(buildMessage("WireMesh <noreply@example.com>", "noreply@example.com", Message{To: "a@example.com", Subject: "Grüße", Text: "line1\nline2"}))
	if !strings.Contains(b, "Subject: =?UTF-8?B?") || !strings.Contains(b, "line1\r\nline2") || !strings.Contains(b, "@example.com>\r\n") {
		t.Fatalf("bad message:\n%s", b)
	}
}
