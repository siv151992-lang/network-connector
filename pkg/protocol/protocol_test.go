package protocol

import (
	"encoding/hex"
	"encoding/json"
	"testing"
	"time"
)

// RFC 7748 §6.1 X25519 test vector (Alice): WireGuard's `wg pubkey` is the same function.
func TestKeyDerivationRFC7748(t *testing.T) {
	var priv PrivateKey
	b, _ := hex.DecodeString("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
	copy(priv[:], b)
	if got := priv.Public().Hex(); got != "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a" {
		t.Fatalf("public key = %s", got)
	}
	k, _ := NewPrivateKey()
	if k[0]&7 != 0 || k[31]&128 != 0 || k[31]&64 == 0 {
		t.Fatal("private key not clamped")
	}
}

func TestJSONRoundTrip(t *testing.T) {
	k, _ := NewPrivateKey()
	nm := NetworkMap{Version: "v1", Self: Node{NodeKey: k.Public()}, PollInterval: Duration(15 * time.Second),
		PacketFilter: []FilterRule{{Ports: []PortRange{{First: 22, Last: 22}}}}}
	b, err := json.Marshal(nm)
	if err != nil {
		t.Fatal(err)
	}
	var back NetworkMap
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatal(err)
	}
	if back.Self.NodeKey != k.Public() || time.Duration(back.PollInterval) != 15*time.Second || back.PacketFilter[0].Ports[0].Last != 22 {
		t.Fatalf("round trip: %s", b)
	}
	var bad Key
	if err := json.Unmarshal([]byte(`"short"`), &bad); err == nil {
		t.Fatal("bad key accepted")
	}
}

func TestPortRange(t *testing.T) {
	if AllPorts.String() != "*" || (PortRange{First: 80, Last: 80}).String() != "80" || (PortRange{First: 1, Last: 5}).String() != "1-5" {
		t.Fatal("String")
	}
	if !(PortRange{First: 10, Last: 20}).Contains(15) || (PortRange{First: 10, Last: 20}).Contains(21) {
		t.Fatal("Contains")
	}
}
