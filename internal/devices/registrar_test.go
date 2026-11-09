package devices

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/siv151992-lang/network-connector/internal/auth"
	"github.com/siv151992-lang/network-connector/internal/store"
	"github.com/siv151992-lang/network-connector/internal/testutil"
)

func TestSanitizeName(t *testing.T) {
	cases := map[string]string{
		"Alice's MacBook Pro.local": "alice-s-macbook-pro",
		"  DESKTOP-ABC123  ":        "desktop-abc123",
		"---":                       "device",
		"":                          "device",
		"pixel_8":                   "pixel-8",
		strings.Repeat("a", 70):     strings.Repeat("a", 63),
		"日本語":                       "device",
	}
	for in, want := range cases {
		if got := SanitizeName(in); got != want {
			t.Errorf("%q: got %q want %q", in, got, want)
		}
	}
	if !ValidName("laptop-2") || ValidName("Laptop") || ValidName("-x") {
		t.Fatal("ValidName wrong")
	}
}

func TestUniqueName(t *testing.T) {
	taken := map[string]bool{"laptop": true, "laptop-2": true}
	if got := uniqueName("laptop", taken); got != "laptop-3" {
		t.Fatalf("got %s", got)
	}
	long := strings.Repeat("a", 63)
	if got := uniqueName(long, map[string]bool{long: true}); len(got) > 63 || !strings.HasSuffix(got, "-2") {
		t.Fatalf("got %s", got)
	}
}

func TestParseKeyAndTags(t *testing.T) {
	k := make([]byte, 32)
	k[0] = 1
	if _, err := ParseKey(base64.StdEncoding.EncodeToString(k)); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"", "abc", base64.StdEncoding.EncodeToString(make([]byte, 32)), base64.StdEncoding.EncodeToString(make([]byte, 31))} {
		if _, err := ParseKey(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	if !ValidTag("tag:servers") || ValidTag("servers") || ValidTag("tag:Bad") || ValidTag("tag:") {
		t.Fatal("ValidTag wrong")
	}
}

// --- integration ---

func key(t *testing.T) []byte {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return b
}

func setup(t *testing.T) (*store.Store, *Registrar, *store.User, *store.Network) {
	t.Helper()
	s := store.New(testutil.NewDB(t))
	u, err := s.CreateUser(context.Background(), store.NewUser{Email: "o@example.com", PasswordHash: "x"})
	if err != nil {
		t.Fatal(err)
	}
	n, err := s.CreateNetwork(context.Background(), store.NewNetwork{
		Name: "Home", Slug: "home", IPv4CIDR: netip.MustParsePrefix("100.64.0.0/10"),
		IPv6CIDR: netip.MustParsePrefix("fd7a:1:2::/48"), DeviceApprovalRequired: true, KeyExpiryDays: 180, OwnerID: u.ID,
	})
	if err != nil {
		t.Fatal(err)
	}
	return s, New(s), u, n
}

func TestRegisterWithSession(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s, r, u, n := setup(t)

	res, err := r.Register(ctx, Request{UserID: u.ID, NetworkID: n.ID, NodeKey: key(t), DiscoKey: key(t), Hostname: "Laptop.local", OS: "linux"})
	if err != nil {
		t.Fatal(err)
	}
	d := res.Device
	if d.Name != "laptop" || d.Status != store.DeviceStatusPending || d.IPv4.String() != "100.64.0.1" ||
		d.IPv6.String() != "fd7a:1:2::6440:1" || d.KeyExpiresAt == nil || !strings.HasPrefix(res.Credential, "wmd_") {
		t.Fatalf("unexpected result: %+v cred=%s", d, res.Credential)
	}
	// The stored hash matches the issued credential.
	if got, err := s.GetDeviceByCredentialHash(ctx, auth.HashToken(res.Credential)); err != nil || got.ID != d.ID {
		t.Fatalf("credential lookup: %v", err)
	}

	res2, err := r.Register(ctx, Request{UserID: u.ID, NetworkID: n.ID, NodeKey: key(t), DiscoKey: key(t), Hostname: "laptop"})
	if err != nil || res2.Device.Name != "laptop-2" || res2.Device.IPv4.String() != "100.64.0.2" {
		t.Fatalf("second device: %+v %v", res2, err)
	}

	if _, err := r.Register(ctx, Request{UserID: u.ID, NetworkID: n.ID, NodeKey: d.NodeKey, DiscoKey: key(t)}); !errors.Is(err, ErrNodeKeyInUse) {
		t.Fatalf("duplicate node key: %v", err)
	}
}

func TestRegisterWithAuthKey(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s, r, u, n := setup(t)

	raw, hash, _ := auth.NewToken(auth.PrefixAuthKey)
	_, err := s.CreateAuthKey(ctx, store.NewAuthKey{NetworkID: n.ID, CreatedBy: u.ID, KeyHash: hash, Prefix: raw[:8],
		Preauthorized: true, Tags: []string{"tag:server"}, ExpiresAt: time.Now().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	res, err := r.Register(ctx, Request{AuthKey: raw, NodeKey: key(t), DiscoKey: key(t), Hostname: "srv"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Device.Status != store.DeviceStatusApproved || res.Device.UserID != u.ID || res.Device.Tags[0] != "tag:server" || res.AuthKeyID == nil {
		t.Fatalf("auth key device: %+v", res.Device)
	}
	// Single-use: second use fails.
	if _, err := r.Register(ctx, Request{AuthKey: raw, NodeKey: key(t), DiscoKey: key(t)}); !errors.Is(err, store.ErrAuthKeyUnusable) {
		t.Fatalf("reused single-use key: %v", err)
	}
	if _, err := r.Register(ctx, Request{AuthKey: "wmk_garbage", NodeKey: key(t), DiscoKey: key(t)}); !errors.Is(err, store.ErrAuthKeyUnusable) {
		t.Fatalf("garbage key: %v", err)
	}

	// A failed registration (duplicate node key) must not consume a single-use key.
	raw2, hash2, _ := auth.NewToken(auth.PrefixAuthKey)
	if _, err := s.CreateAuthKey(ctx, store.NewAuthKey{NetworkID: n.ID, CreatedBy: u.ID, KeyHash: hash2, Prefix: raw2[:8], ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Register(ctx, Request{AuthKey: raw2, NodeKey: res.Device.NodeKey, DiscoKey: key(t)}); !errors.Is(err, ErrNodeKeyInUse) {
		t.Fatalf("expected node key conflict: %v", err)
	}
	if _, err := r.Register(ctx, Request{AuthKey: raw2, NodeKey: key(t), DiscoKey: key(t)}); err != nil {
		t.Fatalf("key was consumed by a failed registration: %v", err)
	}

	// Expired keys are rejected.
	raw3, hash3, _ := auth.NewToken(auth.PrefixAuthKey)
	_, _ = s.CreateAuthKey(ctx, store.NewAuthKey{NetworkID: n.ID, CreatedBy: u.ID, KeyHash: hash3, Prefix: raw3[:8], Reusable: true, ExpiresAt: time.Now().Add(-time.Minute)})
	if _, err := r.Register(ctx, Request{AuthKey: raw3, NodeKey: key(t), DiscoKey: key(t)}); !errors.Is(err, store.ErrAuthKeyUnusable) {
		t.Fatalf("expired key: %v", err)
	}
}

// Concurrent registrations in one network get distinct addresses and names.
func TestRegisterConcurrent(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	_, r, u, n := setup(t)
	const N = 20
	var wg sync.WaitGroup
	results := make(chan *Result, N)
	errs := make(chan error, N)
	for i := 0; i < N; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			res, err := r.Register(ctx, Request{UserID: u.ID, NetworkID: n.ID, NodeKey: key(t), DiscoKey: key(t), Hostname: "node"})
			if err != nil {
				errs <- err
				return
			}
			results <- res
		}()
	}
	wg.Wait()
	close(results)
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	ips, names := map[netip.Addr]bool{}, map[string]bool{}
	for res := range results {
		if ips[res.Device.IPv4] || names[res.Device.Name] {
			t.Fatalf("duplicate allocation: %s %s", res.Device.IPv4, res.Device.Name)
		}
		ips[res.Device.IPv4], names[res.Device.Name] = true, true
	}
	if len(ips) != N {
		t.Fatalf("got %d devices", len(ips))
	}
}
