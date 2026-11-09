package secretbox

import (
	"bytes"
	"testing"
)

func TestRoundTrip(t *testing.T) {
	b, err := New(bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	ad := []byte("totp:user-1")
	c1, err := b.Seal([]byte("JBSWY3DPEHPK3PXP"), ad)
	if err != nil {
		t.Fatal(err)
	}
	c2, _ := b.Seal([]byte("JBSWY3DPEHPK3PXP"), ad)
	if bytes.Equal(c1, c2) {
		t.Fatal("two seals of the same plaintext must differ (random nonce)")
	}
	pt, err := b.Open(c1, ad)
	if err != nil || string(pt) != "JBSWY3DPEHPK3PXP" {
		t.Fatalf("open: %q %v", pt, err)
	}
}

func TestOpenRejectsTampering(t *testing.T) {
	b, _ := New(bytes.Repeat([]byte{1}, 32))
	other, _ := New(bytes.Repeat([]byte{2}, 32))
	c, _ := b.Seal([]byte("secret"), []byte("a"))

	cases := map[string]func() ([]byte, error){
		"wrong ad":    func() ([]byte, error) { return b.Open(c, []byte("b")) },
		"wrong key":   func() ([]byte, error) { return other.Open(c, []byte("a")) },
		"flipped bit": func() ([]byte, error) { x := bytes.Clone(c); x[len(x)-1] ^= 1; return b.Open(x, []byte("a")) },
		"bad version": func() ([]byte, error) { x := bytes.Clone(c); x[0] = 9; return b.Open(x, []byte("a")) },
		"truncated":   func() ([]byte, error) { return b.Open(c[:5], []byte("a")) },
	}
	for name, f := range cases {
		if _, err := f(); err != ErrDecrypt {
			t.Errorf("%s: want ErrDecrypt, got %v", name, err)
		}
	}
}

func TestNewRejectsBadKey(t *testing.T) {
	if _, err := New(make([]byte, 16)); err == nil {
		t.Fatal("expected error for 16-byte key")
	}
}
