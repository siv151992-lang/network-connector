package disco

import (
	"bytes"
	"net/netip"
	"testing"

	"github.com/siv151992-lang/network-connector/pkg/protocol"
)

func keys(t *testing.T) (protocol.PrivateKey, protocol.Key) {
	k, err := protocol.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	return k, k.Public()
}

func TestSealOpen(t *testing.T) {
	aPriv, aPub := keys(t)
	bPriv, bPub := keys(t)
	ab, ba := Shared(aPriv, bPub), Shared(bPriv, aPub)
	if ab != ba {
		t.Fatal("shared keys differ")
	}
	var nk protocol.Key
	nk[0] = 9
	for _, m := range []Message{
		{Type: TypePing, TxID: NewTxID(), NodeKey: nk},
		{Type: TypePong, TxID: NewTxID(), Src: netip.MustParseAddrPort("203.0.113.5:41641")},
		{Type: TypePong, TxID: NewTxID(), Src: netip.MustParseAddrPort("[2001:db8::7]:1")},
	} {
		pkt, err := Seal(m, aPub, ab)
		if err != nil {
			t.Fatal(err)
		}
		if !Is(pkt) {
			t.Fatal("Is() false for disco packet")
		}
		if s, _ := Sender(pkt); s != aPub {
			t.Fatal("sender key not in header")
		}
		got, err := Open(pkt, ba)
		if err != nil || got != m {
			t.Fatalf("open: %+v %v (want %+v)", got, err, m)
		}
	}
}

func TestOpenRejects(t *testing.T) {
	aPriv, aPub := keys(t)
	_, bPub := keys(t)
	cPriv, _ := keys(t)
	ab := Shared(aPriv, bPub)
	pkt, _ := Seal(Message{Type: TypePing, TxID: NewTxID()}, aPub, ab)

	// A third party (wrong shared key) can't open it.
	if _, err := Open(pkt, Shared(cPriv, aPub)); err == nil {
		t.Fatal("opened with wrong key")
	}
	// Any bit flip in the ciphertext is detected.
	bad := bytes.Clone(pkt)
	bad[len(bad)-1] ^= 1
	if _, err := Open(bad, ab); err == nil {
		t.Fatal("tampered packet accepted")
	}
	if _, err := Open(pkt[:20], ab); err == nil {
		t.Fatal("truncated accepted")
	}
	if Is([]byte{1, 0, 0, 0}) {
		t.Fatal("WireGuard packet looks like disco")
	}
	if _, err := Seal(Message{Type: 99}, aPub, ab); err == nil {
		t.Fatal("unknown type sealed")
	}
}

func FuzzOpen(f *testing.F) {
	aPriv, _ := protocol.NewPrivateKey()
	bPriv, _ := protocol.NewPrivateKey()
	ab := Shared(aPriv, bPriv.Public())
	pkt, _ := Seal(Message{Type: TypePing, TxID: NewTxID()}, aPriv.Public(), ab)
	f.Add(pkt)
	f.Fuzz(func(t *testing.T, b []byte) {
		_, _ = Open(b, ab)
		_, _ = unmarshal(b)
	})
}
