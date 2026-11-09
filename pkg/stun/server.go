package stun

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"sync/atomic"
)

// Server answers STUN Binding requests on a UDP socket. It keeps no state per
// client, so it is safe to expose to the internet; responses are never larger
// than requests plus 24 bytes, which limits reflection amplification.
type Server struct {
	Log *slog.Logger

	conn     *net.UDPConn
	Requests atomic.Uint64
	Invalid  atomic.Uint64
}

// Listen binds addr (e.g. ":3478").
func (s *Server) Listen(addr string) error {
	ua, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return err
	}
	s.conn, err = net.ListenUDP("udp", ua)
	return err
}

// Addr returns the bound address.
func (s *Server) Addr() net.Addr { return s.conn.LocalAddr() }

// Serve handles requests until ctx is cancelled.
func (s *Server) Serve(ctx context.Context) error {
	go func() {
		<-ctx.Done()
		s.conn.Close()
	}()
	buf := make([]byte, 1500)
	for {
		n, src, err := s.conn.ReadFromUDPAddrPort(buf)
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		tx, err := ParseRequest(buf[:n])
		if err != nil {
			s.Invalid.Add(1)
			continue
		}
		s.Requests.Add(1)
		src = netip.AddrPortFrom(src.Addr().Unmap(), src.Port())
		if _, err := s.conn.WriteToUDPAddrPort(Response(tx, src), src); err != nil && s.Log != nil {
			s.Log.Debug("stun: write failed", "to", src, "error", err)
		}
	}
}
