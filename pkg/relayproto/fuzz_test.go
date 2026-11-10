package relayproto

import (
	"bytes"
	"crypto/ed25519"
	"testing"
	"time"
)

func FuzzDecodeAndVerify(f *testing.F) {
	sk, _ := SigningKey(bytes.Repeat([]byte{1}, 32))
	pub := sk.Public().(ed25519.PublicKey)
	tok, _ := Sign(sk, Claims{NodeKey: [32]byte{1}, NetworkID: "n", Expires: 4102444800})
	f.Add([]byte(tok))
	f.Add(Encode(FrameSend, [32]byte{2}, []byte("payload")))
	f.Fuzz(func(t *testing.T, b []byte) {
		_, _, _, _ = Decode(b)
		if c, err := Verify(pub, string(b), time.Unix(1700000000, 0)); err == nil && string(b) != tok {
			t.Fatalf("forged token accepted: %+v", c)
		}
	})
}
