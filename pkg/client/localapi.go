package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"
)

// LocalClient talks to the daemon's local API over its Unix socket.
type LocalClient struct{ hc *http.Client }

// NewLocalClient returns a client for the socket at path.
func NewLocalClient(path string) *LocalClient {
	return &LocalClient{hc: &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", path)
		}},
	}}
}

// ErrDaemonUnreachable means the daemon socket could not be reached.
var ErrDaemonUnreachable = errors.New("cannot reach the WireMesh service")

// Call performs one request and decodes the returned status.
func (c *LocalClient) Call(method, path string, body any) (*DaemonStatus, error) {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, "http://wiremeshd"+path, rd)
	if err != nil {
		return nil, err
	}
	res, err := c.hc.Do(req)
	if err != nil {
		var opErr *net.OpError
		if errors.As(err, &opErr) {
			return nil, fmt.Errorf("%w: %v", ErrDaemonUnreachable, err)
		}
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		var e struct{ Error string }
		_ = json.NewDecoder(res.Body).Decode(&e)
		return nil, errors.New(e.Error)
	}
	var st DaemonStatus
	return &st, json.NewDecoder(res.Body).Decode(&st)
}
