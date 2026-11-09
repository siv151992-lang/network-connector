// Package secretbox encrypts small secrets (e.g. TOTP seeds) before they are
// stored in PostgreSQL, so a database dump alone does not reveal them.
//
// Format: version(1) | nonce(12) | AES-256-GCM ciphertext+tag.
// The caller-supplied associated data (e.g. "totp:"+userID) binds a ciphertext
// to its row, so a ciphertext copied into another user's row fails to decrypt.
package secretbox

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
)

const formatV1 byte = 1

// ErrDecrypt is returned for any authentication or format failure. It is
// intentionally uninformative.
var ErrDecrypt = errors.New("secretbox: decryption failed")

// Box seals and opens values with a single 256-bit key.
type Box struct{ aead cipher.AEAD }

// New creates a Box. key must be exactly 32 bytes.
func New(key []byte) (*Box, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("secretbox: key must be 32 bytes, got %d", len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Box{aead: aead}, nil
}

// Seal encrypts plaintext with a fresh random nonce.
func (b *Box) Seal(plaintext, associatedData []byte) ([]byte, error) {
	ns := b.aead.NonceSize()
	out := make([]byte, 1+ns, 1+ns+len(plaintext)+b.aead.Overhead())
	out[0] = formatV1
	if _, err := rand.Read(out[1 : 1+ns]); err != nil {
		return nil, fmt.Errorf("secretbox: nonce: %w", err)
	}
	return b.aead.Seal(out, out[1:1+ns], plaintext, associatedData), nil
}

// Open decrypts a value produced by Seal with the same associated data.
func (b *Box) Open(sealed, associatedData []byte) ([]byte, error) {
	ns := b.aead.NonceSize()
	if len(sealed) < 1+ns+b.aead.Overhead() || sealed[0] != formatV1 {
		return nil, ErrDecrypt
	}
	pt, err := b.aead.Open(nil, sealed[1:1+ns], sealed[1+ns:], associatedData)
	if err != nil {
		return nil, ErrDecrypt
	}
	return pt, nil
}
