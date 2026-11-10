// Package client is the WireMesh device engine shared by every platform:
// control-plane client, WireGuard (wireguard-go) tunnel, inbound packet
// filter and the run loop that keeps them in sync with the network map.
package client

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/siv151992-lang/network-connector/pkg/protocol"
)

// State is persisted on the device. It holds the private keys and the
// control-plane credential, so it is written with mode 0600 and must live on
// a root-only path (default /var/lib/wiremesh/state.json).
type State struct {
	ServerURL    string              `json:"server_url"`
	NodePrivate  protocol.PrivateKey `json:"node_private_key"`
	DiscoPrivate protocol.PrivateKey `json:"disco_private_key"`
	Credential   string              `json:"credential,omitempty"`
	DeviceID     string              `json:"device_id,omitempty"`
	NetworkID    string              `json:"network_id,omitempty"`
	// Down records `wiremesh down`: the daemon won't auto-start the tunnel.
	Down bool `json:"down,omitempty"`
}

// LoadOrCreateState reads the state file, or generates fresh keys if it
// does not exist yet.
func LoadOrCreateState(path, serverURL string) (*State, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		node, err := protocol.NewPrivateKey()
		if err != nil {
			return nil, err
		}
		disco, err := protocol.NewPrivateKey()
		if err != nil {
			return nil, err
		}
		st := &State{ServerURL: serverURL, NodePrivate: node, DiscoPrivate: disco}
		return st, st.Save(path)
	}
	if err != nil {
		return nil, err
	}
	if fi, err := os.Stat(path); err == nil && fi.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("%s is readable by other users (mode %o); it contains private keys: chmod 600 it", path, fi.Mode().Perm())
	}
	var st State
	if err := json.Unmarshal(b, &st); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if protocol.Key(st.NodePrivate).IsZero() || protocol.Key(st.DiscoPrivate).IsZero() {
		return nil, fmt.Errorf("%s has no keys; delete it to re-enroll", path)
	}
	if serverURL != "" && st.ServerURL != serverURL {
		return nil, fmt.Errorf("%s belongs to server %s, not %s; use another state file to join a different server", path, st.ServerURL, serverURL)
	}
	return &st, nil
}

// Save writes the state atomically (temp file + rename) with mode 0600.
func (s *State) Save(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".state-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// LoadState loads an existing state file without creating one.
func LoadState(path string) (*State, error) {
	if _, err := os.Stat(path); err != nil {
		return nil, fmt.Errorf("%s: %w (enroll first with `wiremesh up --server … --auth-key …`)", path, err)
	}
	st, err := LoadOrCreateState(path, "")
	if err != nil {
		return nil, err
	}
	if st.Credential == "" {
		return nil, fmt.Errorf("%s has no credential: this device is not enrolled", path)
	}
	return st, nil
}
