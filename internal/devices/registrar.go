// Package devices implements device enrollment: validating the request,
// consuming an auth key, allocating addresses, choosing a unique DNS name and
// issuing the device's control-plane credential, all in one transaction.
package devices

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/siv151992-lang/network-connector/internal/auth"
	"github.com/siv151992-lang/network-connector/internal/ipam"
	"github.com/siv151992-lang/network-connector/internal/store"
)

// Errors returned by Register.
var (
	ErrNodeKeyInUse = errors.New("this node key is already registered")
	ErrNoOwner      = errors.New("auth key has no owning user")
)

// Request describes a device asking to join.
type Request struct {
	// Exactly one of AuthKey or (UserID + NetworkID) identifies who enrolls the device.
	AuthKey   string
	UserID    uuid.UUID
	NetworkID uuid.UUID

	NodeKey       []byte // WireGuard public key
	DiscoKey      []byte
	Name          string // requested name; defaults to hostname
	Hostname      string
	OS            string
	OSVersion     string
	ClientVersion string
}

// Result is the outcome of a successful registration.
type Result struct {
	Device     *store.Device
	Network    *store.Network
	Credential string // raw device credential; returned to the device once, never stored
	AuthKeyID  *uuid.UUID
}

// Registrar enrolls devices.
type Registrar struct {
	Store *store.Store
	Now   func() time.Time
}

// New returns a Registrar using the real clock.
func New(s *store.Store) *Registrar { return &Registrar{Store: s, Now: time.Now} }

// ParseKey decodes a standard-base64 Curve25519 public key (WireGuard's format).
func ParseKey(s string) ([]byte, error) {
	b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(s))
	if err != nil || len(b) != 32 {
		return nil, errors.New("must be a base64-encoded 32-byte key")
	}
	zero := true
	for _, x := range b {
		if x != 0 {
			zero = false
			break
		}
	}
	if zero {
		return nil, errors.New("must not be the all-zero key")
	}
	return b, nil
}

var (
	invalidLabelChars = regexp.MustCompile(`[^a-z0-9-]+`)
	multiDash         = regexp.MustCompile(`-{2,}`)
	tagPattern        = regexp.MustCompile(`^tag:[a-z0-9][a-z0-9-]{0,62}$`)
)

// SanitizeName turns a hostname into a DNS label (RFC 1123), e.g.
// "Alice's MacBook Pro.local" -> "alice-s-macbook-pro".
func SanitizeName(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if i := strings.IndexByte(s, '.'); i > 0 {
		s = s[:i] // drop domain suffix
	}
	s = invalidLabelChars.ReplaceAllString(s, "-")
	s = multiDash.ReplaceAllString(s, "-")
	s = strings.Trim(s, "-")
	if len(s) > 63 {
		s = strings.TrimRight(s[:63], "-")
	}
	if s == "" {
		return "device"
	}
	return s
}

// ValidName reports whether s is an acceptable device name.
func ValidName(s string) bool { return s != "" && SanitizeName(s) == s }

// ValidTag reports whether t is a well-formed ACL tag ("tag:servers").
func ValidTag(t string) bool { return tagPattern.MatchString(t) }

// uniqueName appends -2, -3, … until the name is free.
func uniqueName(base string, taken map[string]bool) string {
	if !taken[base] {
		return base
	}
	for i := 2; ; i++ {
		suffix := fmt.Sprintf("-%d", i)
		cand := base
		if len(cand)+len(suffix) > 63 {
			cand = strings.TrimRight(cand[:63-len(suffix)], "-")
		}
		cand += suffix
		if !taken[cand] {
			return cand
		}
	}
}

// Register enrolls a device. Authorization of a session-based request (is the
// user a member who may add devices?) is the caller's job; auth-key requests
// are authorized by the key itself.
func (r *Registrar) Register(ctx context.Context, req Request) (*Result, error) {
	if len(req.NodeKey) != 32 || len(req.DiscoKey) != 32 {
		return nil, &store.InvalidError{Reason: "node_key and disco_key must be 32 bytes"}
	}
	now := r.Now()
	cred, credHash, err := auth.NewToken(auth.PrefixDevice)
	if err != nil {
		return nil, err
	}

	var res *Result
	err = r.Store.WithTx(ctx, func(tx *store.Store) error {
		var (
			networkID     = req.NetworkID
			userID        = req.UserID
			tags          []string
			preauthorized bool
			ephemeral     bool
			authKeyID     *uuid.UUID
		)
		if req.AuthKey != "" {
			hash, ok := auth.ParseToken(req.AuthKey, auth.PrefixAuthKey)
			if !ok {
				return store.ErrAuthKeyUnusable
			}
			key, err := tx.ConsumeAuthKey(ctx, hash, now)
			if err != nil {
				return err
			}
			if key.CreatedBy == nil {
				return ErrNoOwner
			}
			networkID, userID = key.NetworkID, *key.CreatedBy
			tags, preauthorized, ephemeral = key.Tags, key.Preauthorized, key.Ephemeral
			authKeyID = &key.ID
		}

		n, err := tx.LockNetwork(ctx, networkID)
		if err != nil {
			return err
		}

		used, err := tx.UsedAddresses(ctx, n.ID)
		if err != nil {
			return err
		}
		usedSet := make(map[netip.Addr]bool, len(used))
		for _, a := range used {
			usedSet[a] = true
		}
		v4, err := ipam.AllocateIPv4(n.IPv4CIDR, usedSet)
		if err != nil {
			return err
		}
		v6, err := ipam.IPv6For(n.IPv6CIDR, v4)
		if err != nil {
			return err
		}

		taken, err := tx.DeviceNames(ctx, n.ID)
		if err != nil {
			return err
		}
		requested := req.Name
		if requested == "" {
			requested = req.Hostname
		}
		name := uniqueName(SanitizeName(requested), taken)

		status := store.DeviceStatusPending
		if preauthorized || !n.DeviceApprovalRequired {
			status = store.DeviceStatusApproved
		}
		var keyExpiry *time.Time
		if n.KeyExpiryDays > 0 {
			t := now.Add(time.Duration(n.KeyExpiryDays) * 24 * time.Hour)
			keyExpiry = &t
		}

		d, err := tx.CreateDevice(ctx, store.NewDevice{
			NetworkID: n.ID, UserID: userID, AuthKeyID: authKeyID, Name: name,
			Hostname: req.Hostname, OS: req.OS, OSVersion: req.OSVersion, ClientVersion: req.ClientVersion,
			NodeKey: req.NodeKey, DiscoKey: req.DiscoKey, CredentialHash: credHash,
			IPv4: v4, IPv6: v6, Status: status, Ephemeral: ephemeral, Tags: tags, KeyExpiresAt: keyExpiry,
		})
		if err != nil {
			var ce *store.ConflictError
			if errors.As(err, &ce) && ce.Constraint == "devices_node_key_key" {
				return ErrNodeKeyInUse
			}
			return err
		}
		res = &Result{Device: d, Network: n, Credential: cred, AuthKeyID: authKeyID}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return res, nil
}
