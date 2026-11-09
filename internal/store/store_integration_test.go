package store_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/siv151992-lang/network-connector/internal/store"
	"github.com/siv151992-lang/network-connector/internal/testutil"
)

func newStore(t *testing.T) *store.Store {
	t.Helper()
	return store.New(testutil.NewDB(t))
}

func randKey(t *testing.T) []byte {
	t.Helper()
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		t.Fatal(err)
	}
	return k
}

func mustUser(t *testing.T, s *store.Store, email string) *store.User {
	t.Helper()
	u, err := s.CreateUser(context.Background(), store.NewUser{Email: email, PasswordHash: "$argon2id$x", DisplayName: "T"})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	return u
}

func mustNetwork(t *testing.T, s *store.Store, owner uuid.UUID, slug string) *store.Network {
	t.Helper()
	n, err := s.CreateNetwork(context.Background(), store.NewNetwork{
		Name: "Home", Slug: slug,
		IPv4CIDR:               netip.MustParsePrefix("100.64.0.0/16"),
		IPv6CIDR:               netip.MustParsePrefix("fd7a:1234:5678::/48"),
		DeviceApprovalRequired: true, KeyExpiryDays: 180, OwnerID: owner,
	})
	if err != nil {
		t.Fatalf("create network: %v", err)
	}
	return n
}

func newDevice(t *testing.T, n *store.Network, u *store.User, name, v4, v6 string) store.NewDevice {
	return store.NewDevice{
		NetworkID: n.ID, UserID: u.ID, Name: name, Hostname: name, OS: "linux",
		NodeKey: randKey(t), DiscoKey: randKey(t), CredentialHash: randKey(t),
		IPv4: netip.MustParseAddr(v4), IPv6: netip.MustParseAddr(v6),
	}
}

func TestUsers(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := newStore(t)

	u := mustUser(t, s, "  Alice@Example.COM ")
	if u.Email != "alice@example.com" || u.SystemRole != store.SystemRoleUser {
		t.Fatalf("unexpected user: %+v", u)
	}
	if _, err := s.CreateUser(ctx, store.NewUser{Email: "ALICE@example.com", PasswordHash: "x"}); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("duplicate email: want ErrConflict, got %v", err)
	}
	got, err := s.GetUserByEmail(ctx, "alice@EXAMPLE.com")
	if err != nil || got.ID != u.ID {
		t.Fatalf("get by email: %v %v", got, err)
	}
	if _, err := s.GetUser(ctx, uuid.New()); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("missing user: want ErrNotFound, got %v", err)
	}

	// Lockout after 3 failures.
	for i := 1; i <= 3; i++ {
		n, err := s.RecordLoginFailure(ctx, u.ID, 3, time.Minute)
		if err != nil || n != i {
			t.Fatalf("failure %d: n=%d err=%v", i, n, err)
		}
	}
	got, _ = s.GetUser(ctx, u.ID)
	if got.LockedUntil == nil || !got.LockedUntil.After(time.Now()) {
		t.Fatalf("expected account to be locked, got %v", got.LockedUntil)
	}
	if err := s.RecordLoginSuccess(ctx, u.ID); err != nil {
		t.Fatal(err)
	}
	got, _ = s.GetUser(ctx, u.ID)
	if got.FailedLogins != 0 || got.LockedUntil != nil || got.LastLoginAt == nil {
		t.Fatalf("login success did not reset: %+v", got)
	}

	// TOTP consistency constraint: cannot enable without a secret.
	if err := s.SetTOTP(ctx, u.ID, nil, true); !errors.Is(err, store.ErrInvalid) {
		t.Fatalf("totp without secret: want ErrInvalid, got %v", err)
	}
	if err := s.SetTOTP(ctx, u.ID, []byte{1, 2, 3}, true); err != nil {
		t.Fatal(err)
	}

	mustUser(t, s, "bob@example.com")
	list, total, err := s.ListUsers(ctx, 10, 0)
	if err != nil || total != 2 || len(list) != 2 {
		t.Fatalf("list users: %d %d %v", len(list), total, err)
	}
}

func TestSessions(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := newStore(t)
	u := mustUser(t, s, "s@example.com")
	ip := netip.MustParseAddr("203.0.113.9")

	hash := randKey(t)
	sess, err := s.CreateSession(ctx, store.NewSession{
		TokenHash: hash, UserID: u.ID, IP: &ip, UserAgent: "test", ExpiresAt: time.Now().Add(time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	got, err := s.GetSessionByTokenHash(ctx, hash)
	if err != nil || got.ID != sess.ID || got.IP == nil || *got.IP != ip || !got.Active(time.Now()) {
		t.Fatalf("get session: %+v %v", got, err)
	}
	other, _ := s.CreateSession(ctx, store.NewSession{TokenHash: randKey(t), UserID: u.ID, ExpiresAt: time.Now().Add(time.Hour)})

	n, err := s.RevokeUserSessions(ctx, u.ID, sess.ID)
	if err != nil || n != 1 {
		t.Fatalf("revoke others: n=%d err=%v", n, err)
	}
	active, _ := s.ListActiveSessions(ctx, u.ID)
	if len(active) != 1 || active[0].ID != sess.ID {
		t.Fatalf("active sessions: %+v", active)
	}
	if err := s.RevokeSession(ctx, u.ID, other.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("revoking already-revoked session: want ErrNotFound, got %v", err)
	}
	// Another user cannot revoke this session.
	stranger := mustUser(t, s, "x@example.com")
	if err := s.RevokeSession(ctx, stranger.ID, sess.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("cross-user revoke: want ErrNotFound, got %v", err)
	}
}

func TestNetworkMembership(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := newStore(t)
	owner := mustUser(t, s, "owner@example.com")
	member := mustUser(t, s, "member@example.com")
	n := mustNetwork(t, s, owner.ID, "home")

	if n.IPv4CIDR.String() != "100.64.0.0/16" || n.IPv6CIDR.String() != "fd7a:1234:5678::/48" {
		t.Fatalf("cidrs: %s %s", n.IPv4CIDR, n.IPv6CIDR)
	}
	if role, err := s.GetMemberRole(ctx, n.ID, owner.ID); err != nil || role != store.RoleOwner {
		t.Fatalf("owner role: %q %v", role, err)
	}
	if _, err := s.CreateNetwork(ctx, store.NewNetwork{Name: "x", Slug: "home",
		IPv4CIDR: netip.MustParsePrefix("100.65.0.0/16"), IPv6CIDR: netip.MustParsePrefix("fd00::/48"), OwnerID: owner.ID}); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("duplicate slug: want ErrConflict, got %v", err)
	}
	if _, err := s.CreateNetwork(ctx, store.NewNetwork{Name: "x", Slug: "Bad Slug!",
		IPv4CIDR: netip.MustParsePrefix("100.65.0.0/16"), IPv6CIDR: netip.MustParsePrefix("fd00::/48"), OwnerID: owner.ID}); !errors.Is(err, store.ErrInvalid) {
		t.Fatalf("bad slug: want ErrInvalid, got %v", err)
	}

	if err := s.AddMember(ctx, n.ID, member.ID, store.RoleMember); err != nil {
		t.Fatal(err)
	}
	if err := s.AddMember(ctx, n.ID, member.ID, store.RoleMember); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("duplicate member: %v", err)
	}
	if err := s.AddMember(ctx, n.ID, member.ID, "superuser"); !errors.Is(err, store.ErrInvalid) {
		t.Fatalf("bad role: %v", err)
	}

	// The last owner cannot be demoted or removed.
	if err := s.SetMemberRole(ctx, n.ID, owner.ID, store.RoleAdmin); !errors.Is(err, store.ErrInvalid) {
		t.Fatalf("demote last owner: want ErrInvalid, got %v", err)
	}
	if err := s.RemoveMember(ctx, n.ID, owner.ID); !errors.Is(err, store.ErrInvalid) {
		t.Fatalf("remove last owner: want ErrInvalid, got %v", err)
	}
	// After promoting another owner it works.
	if err := s.SetMemberRole(ctx, n.ID, member.ID, store.RoleOwner); err != nil {
		t.Fatal(err)
	}
	if err := s.SetMemberRole(ctx, n.ID, owner.ID, store.RoleAdmin); err != nil {
		t.Fatalf("demote with another owner present: %v", err)
	}

	nets, err := s.ListNetworksForUser(ctx, member.ID)
	if err != nil || len(nets) != 1 || nets[0].Role != store.RoleOwner {
		t.Fatalf("list networks: %+v %v", nets, err)
	}
	members, _ := s.ListMembers(ctx, n.ID)
	if len(members) != 2 {
		t.Fatalf("members: %+v", members)
	}
}

// Two concurrent demotions of the only two owners must not both succeed.
func TestLastOwnerRace(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := newStore(t)
	a := mustUser(t, s, "a@example.com")
	b := mustUser(t, s, "b@example.com")
	n := mustNetwork(t, s, a.ID, "race")
	if err := s.AddMember(ctx, n.ID, b.ID, store.RoleOwner); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	errs := make([]error, 2)
	for i, u := range []uuid.UUID{a.ID, b.ID} {
		wg.Add(1)
		go func(i int, u uuid.UUID) {
			defer wg.Done()
			errs[i] = s.SetMemberRole(ctx, n.ID, u, store.RoleMember)
		}(i, u)
	}
	wg.Wait()
	ok := 0
	for _, err := range errs {
		if err == nil {
			ok++
		}
	}
	if ok != 1 {
		t.Fatalf("exactly one demotion should succeed, got errors %v", errs)
	}
}

func TestDevices(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := newStore(t)
	u := mustUser(t, s, "d@example.com")
	n := mustNetwork(t, s, u.ID, "devs")

	nd := newDevice(t, n, u, "laptop", "100.64.0.1", "fd7a:1234:5678::1")
	d, err := s.CreateDevice(ctx, nd)
	if err != nil {
		t.Fatal(err)
	}
	if d.Status != store.DeviceStatusPending || d.IPv4.String() != "100.64.0.1" || d.IPv6.String() != "fd7a:1234:5678::1" {
		t.Fatalf("device: %+v", d)
	}
	if !bytes.Equal(d.NodeKey, nd.NodeKey) || len(d.Tags) != 0 || len(d.Endpoints) != 0 {
		t.Fatalf("device keys/defaults: %+v", d)
	}

	// Address, name and node-key uniqueness are enforced by the database.
	dup := newDevice(t, n, u, "phone", "100.64.0.1", "fd7a:1234:5678::2")
	if _, err := s.CreateDevice(ctx, dup); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("duplicate ipv4: want ErrConflict, got %v", err)
	}
	dup = newDevice(t, n, u, "laptop", "100.64.0.2", "fd7a:1234:5678::2")
	if _, err := s.CreateDevice(ctx, dup); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("duplicate name: want ErrConflict, got %v", err)
	}
	dup = newDevice(t, n, u, "phone", "100.64.0.2", "fd7a:1234:5678::2")
	dup.NodeKey = nd.NodeKey
	if _, err := s.CreateDevice(ctx, dup); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("duplicate node key: want ErrConflict, got %v", err)
	}
	bad := newDevice(t, n, u, "Not_DNS", "100.64.0.3", "fd7a:1234:5678::3")
	if _, err := s.CreateDevice(ctx, bad); !errors.Is(err, store.ErrInvalid) {
		t.Fatalf("bad name: want ErrInvalid, got %v", err)
	}

	phone, err := s.CreateDevice(ctx, newDevice(t, n, u, "phone", "100.64.0.2", "fd7a:1234:5678::2"))
	if err != nil {
		t.Fatal(err)
	}

	// Lookups.
	if got, err := s.GetDeviceByNodeKey(ctx, nd.NodeKey); err != nil || got.ID != d.ID {
		t.Fatalf("by node key: %v", err)
	}
	if got, err := s.GetDeviceByCredentialHash(ctx, nd.CredentialHash); err != nil || got.ID != d.ID {
		t.Fatalf("by credential: %v", err)
	}
	other := mustNetwork(t, s, u.ID, "other")
	if _, err := s.GetDevice(ctx, other.ID, d.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("cross-network get: want ErrNotFound, got %v", err)
	}

	// Status lifecycle.
	approved, err := s.SetDeviceStatus(ctx, n.ID, d.ID, store.DeviceStatusApproved, &u.ID)
	if err != nil || approved.ApprovedAt == nil || approved.ApprovedBy == nil || *approved.ApprovedBy != u.ID {
		t.Fatalf("approve: %+v %v", approved, err)
	}
	if _, err := s.SetDeviceStatus(ctx, n.ID, d.ID, store.DeviceStatusPending, nil); !errors.Is(err, store.ErrInvalid) {
		t.Fatalf("approved->pending: want ErrInvalid, got %v", err)
	}
	revoked, err := s.SetDeviceStatus(ctx, n.ID, d.ID, store.DeviceStatusRevoked, &u.ID)
	if err != nil || revoked.RevokedAt == nil || revoked.CredentialHash != nil {
		t.Fatalf("revoke must clear credential: %+v %v", revoked, err)
	}
	if _, err := s.GetDeviceByCredentialHash(ctx, nd.CredentialHash); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("revoked credential still authenticates: %v", err)
	}

	// Endpoints round-trip through JSONB.
	eps := []netip.AddrPort{netip.MustParseAddrPort("198.51.100.7:41641"), netip.MustParseAddrPort("[2001:db8::1]:41641")}
	region := 1
	if err := s.UpdateDeviceEndpoints(ctx, phone.ID, eps, &region); err != nil {
		t.Fatal(err)
	}
	got, _ := s.GetDevice(ctx, n.ID, phone.ID)
	if len(got.Endpoints) != 2 || got.Endpoints[1] != eps[1] || got.HomeRelayRegion == nil || *got.HomeRelayRegion != 1 || got.LastSeenAt == nil {
		t.Fatalf("endpoints: %+v", got)
	}

	if _, err := s.SetDeviceTags(ctx, n.ID, phone.ID, []string{"tag:mobile"}); err != nil {
		t.Fatal(err)
	}

	list, err := s.ListDevices(ctx, n.ID, store.DeviceFilter{Status: store.DeviceStatusPending})
	if err != nil || len(list) != 1 || list[0].Name != "phone" || list[0].Tags[0] != "tag:mobile" {
		t.Fatalf("list pending: %+v %v", list, err)
	}
	addrs, err := s.UsedAddresses(ctx, n.ID)
	if err != nil || len(addrs) != 4 {
		t.Fatalf("used addresses: %v %v", addrs, err)
	}

	if err := s.DeleteDevice(ctx, n.ID, phone.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteDevice(ctx, n.ID, phone.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("double delete: %v", err)
	}
}

func TestAudit(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := newStore(t)
	u := mustUser(t, s, "audit@example.com")
	n := mustNetwork(t, s, u.ID, "aud")
	ip := netip.MustParseAddr("2001:db8::5")

	for i := 0; i < 5; i++ {
		action := "device.approve"
		if i%2 == 0 {
			action = "user.login"
		}
		if err := s.InsertAudit(ctx, store.NewAuditEntry{
			NetworkID: &n.ID, ActorUserID: &u.ID, Action: action, TargetType: "device",
			TargetID: "x", IP: &ip, Metadata: map[string]any{"i": i},
		}); err != nil {
			t.Fatal(err)
		}
	}
	page1, err := s.ListAudit(ctx, store.AuditQuery{NetworkID: &n.ID, Limit: 2})
	if err != nil || len(page1) != 2 || page1[0].ID <= page1[1].ID {
		t.Fatalf("page1: %+v %v", page1, err)
	}
	page2, _ := s.ListAudit(ctx, store.AuditQuery{NetworkID: &n.ID, Limit: 10, BeforeID: page1[1].ID})
	if len(page2) != 3 {
		t.Fatalf("page2 len %d", len(page2))
	}
	logins, _ := s.ListAudit(ctx, store.AuditQuery{NetworkID: &n.ID, Action: "user.login"})
	if len(logins) != 3 || logins[0].IP == nil || *logins[0].IP != ip {
		t.Fatalf("filter by action: %+v", logins)
	}
}
