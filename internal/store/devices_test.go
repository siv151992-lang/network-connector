package store

import "testing"

func TestValidDeviceTransition(t *testing.T) {
	cases := []struct {
		from, to string
		ok       bool
	}{
		{DeviceStatusPending, DeviceStatusApproved, true},
		{DeviceStatusPending, DeviceStatusRejected, true},
		{DeviceStatusPending, DeviceStatusRevoked, true},
		{DeviceStatusRejected, DeviceStatusApproved, true},
		{DeviceStatusApproved, DeviceStatusRevoked, true},
		{DeviceStatusApproved, DeviceStatusPending, false},
		{DeviceStatusApproved, DeviceStatusRejected, false},
		{DeviceStatusRevoked, DeviceStatusApproved, false},
		{DeviceStatusRevoked, DeviceStatusPending, false},
		{"bogus", DeviceStatusApproved, false},
	}
	for _, c := range cases {
		if got := ValidDeviceTransition(c.from, c.to); got != c.ok {
			t.Errorf("%s -> %s: got %v want %v", c.from, c.to, got, c.ok)
		}
	}
}

func TestTruncateKeepsUTF8Valid(t *testing.T) {
	s := "héllo" // 'é' is 2 bytes at index 1..2
	if got := truncate(s, 2); got != "h" {
		t.Fatalf("truncate cut a rune: %q", got)
	}
	if got := truncate(s, 100); got != s {
		t.Fatalf("got %q", got)
	}
}
