package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"runtime"
	"strings"
	"time"

	"github.com/siv151992-lang/network-connector/pkg/protocol"
)

// Errors with special meaning for the run loop.
var (
	ErrUnauthorized = errors.New("control: device credential rejected (revoked, logged out or deleted)")
	ErrNotApproved  = errors.New("control: device is waiting for admin approval")
)

// APIError is a non-2xx response from the control server.
type APIError struct {
	Status  int
	Code    string
	Message string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("control: %d %s: %s", e.Status, e.Code, e.Message)
}

// Control talks to the control server's device API.
type Control struct {
	base       *url.URL
	credential string
	hc         *http.Client
	userAgent  string
}

// NewControl creates a client. serverURL is the public URL, e.g. https://vpn.example.com.
func NewControl(serverURL, credential, version string) (*Control, error) {
	u, err := url.Parse(strings.TrimRight(serverURL, "/"))
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return nil, fmt.Errorf("invalid server URL %q", serverURL)
	}
	return &Control{
		base: u, credential: credential,
		hc:        &http.Client{Timeout: 30 * time.Second},
		userAgent: fmt.Sprintf("wiremesh/%s (%s/%s)", version, runtime.GOOS, runtime.GOARCH),
	}, nil
}

// SetCredential replaces the bearer credential (after registration).
func (c *Control) SetCredential(cred string) { c.credential = cred }

func (c *Control) do(ctx context.Context, method, path string, in, out any, hdr map[string]string) (*http.Response, error) {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return nil, err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base.String()+path, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", c.userAgent)
	req.Header.Set("Accept", "application/json")
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.credential != "" {
		req.Header.Set("Authorization", "Bearer "+c.credential)
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return resp, err
	}
	if resp.StatusCode == http.StatusNotModified {
		return resp, nil
	}
	if resp.StatusCode >= 300 {
		var env struct {
			Error struct{ Code, Message string } `json:"error"`
		}
		_ = json.Unmarshal(data, &env)
		apiErr := &APIError{Status: resp.StatusCode, Code: env.Error.Code, Message: env.Error.Message}
		switch {
		// On /register a 401 means a bad auth key (reported as APIError);
		// anywhere else it means our credential is no longer valid.
		case resp.StatusCode == http.StatusUnauthorized && path != "/api/v1/device/register":
			return resp, fmt.Errorf("%w: %v", ErrUnauthorized, apiErr)
		case env.Error.Code == "device_not_approved":
			return resp, ErrNotApproved
		}
		return resp, apiErr
	}
	if out != nil && len(data) > 0 {
		if err := json.Unmarshal(data, out); err != nil {
			return resp, fmt.Errorf("control: decode %s: %w", path, err)
		}
	}
	return resp, nil
}

// RegisterRequest is the enrollment payload.
type RegisterRequest struct {
	AuthKey       string `json:"auth_key"`
	NodeKey       string `json:"node_key"`
	DiscoKey      string `json:"disco_key"`
	Hostname      string `json:"hostname"`
	OS            string `json:"os"`
	OSVersion     string `json:"os_version,omitempty"`
	ClientVersion string `json:"client_version"`
}

// RegisterResponse is what enrollment returns.
type RegisterResponse struct {
	Device struct {
		ID        string `json:"id"`
		NetworkID string `json:"network_id"`
		Name      string `json:"name"`
		Status    string `json:"status"`
		IPv4      string `json:"ipv4"`
		IPv6      string `json:"ipv6"`
	} `json:"device"`
	Credential string `json:"credential"`
}

// Register enrolls this device with an auth key.
func (c *Control) Register(ctx context.Context, req RegisterRequest) (*RegisterResponse, error) {
	var out RegisterResponse
	if _, err := c.do(ctx, http.MethodPost, "/api/v1/device/register", req, &out, nil); err != nil {
		return nil, err
	}
	if out.Credential == "" {
		return nil, errors.New("control: registration returned no credential")
	}
	return &out, nil
}

// SelfInfo is the subset of GET /device/self the client uses.
type SelfInfo struct {
	Device struct {
		ID     string `json:"id"`
		Name   string `json:"name"`
		Status string `json:"status"`
		IPv4   string `json:"ipv4"`
	} `json:"device"`
}

// Self returns the device's own record.
func (c *Control) Self(ctx context.Context) (*SelfInfo, error) {
	var out SelfInfo
	_, err := c.do(ctx, http.MethodGet, "/api/v1/device/self", nil, &out, nil)
	return &out, err
}

// Netmap fetches the network map. If version matches the server's, it
// returns (nil, nil): nothing changed.
func (c *Control) Netmap(ctx context.Context, version string) (*protocol.NetworkMap, error) {
	hdr := map[string]string{}
	if version != "" {
		hdr["If-None-Match"] = `"` + version + `"`
	}
	var nm protocol.NetworkMap
	resp, err := c.do(ctx, http.MethodGet, "/api/v1/device/netmap", nil, &nm, hdr)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == http.StatusNotModified {
		return nil, nil
	}
	return &nm, nil
}

// ReportEndpoints tells the server where this device can be reached.
func (c *Control) ReportEndpoints(ctx context.Context, u protocol.EndpointsUpdate) error {
	_, err := c.do(ctx, http.MethodPost, "/api/v1/device/endpoints", u, nil, nil)
	return err
}

// Logout invalidates the credential on the server.
func (c *Control) Logout(ctx context.Context) error {
	_, err := c.do(ctx, http.MethodPost, "/api/v1/device/logout", nil, nil, nil)
	return err
}
