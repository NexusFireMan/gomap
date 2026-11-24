package scanner

import (
	"context"
	"crypto/tls"
	"net"
	"time"
)

// Only the opt-in embeddable engine sets probeContext. Legacy CLI probes keep
// their existing transport and timing behavior.
func (s *Scanner) dialTCPContext(address string, timeout time.Duration, paced bool) (net.Conn, error) {
	ctx := s.probeContext
	if paced {
		if err := s.AttemptLimiter.WaitContext(ctx); err != nil {
			return nil, err
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	dial := s.probeDial
	if dial == nil {
		dial = s.recoveryDial
	}
	conn, err := dial(ctx, address, timeout)
	if err != nil {
		return nil, err
	}
	return bindProbeConnection(ctx, conn)
}

func bindProbeConnection(ctx context.Context, conn net.Conn) (net.Conn, error) {
	if err := ctx.Err(); err != nil {
		_ = conn.Close()
		return nil, err
	}
	guard := &contextProbeConn{Conn: conn, ctx: ctx}
	guard.stop = context.AfterFunc(ctx, func() { _ = conn.Close() })
	return guard, nil
}

func (s *Scanner) dialTLSContext(address string, timeout time.Duration, cfg *tls.Config) (*tls.Conn, error) {
	raw, err := s.dialTCPContext(address, timeout, true)
	if err != nil {
		return nil, err
	}
	conn := tls.Client(raw, cfg)
	ctx, cancel := context.WithTimeout(s.probeContext, timeout)
	defer cancel()
	if err := conn.HandshakeContext(ctx); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return conn, nil
}

type contextProbeConn struct {
	net.Conn
	ctx  context.Context
	stop func() bool
}

func (c *contextProbeConn) Close() error { c.stop(); return c.Conn.Close() }
func (c *contextProbeConn) bound(t time.Time) time.Time {
	if deadline, ok := c.ctx.Deadline(); ok && (t.IsZero() || deadline.Before(t)) {
		return deadline
	}
	return t
}
func (c *contextProbeConn) SetDeadline(t time.Time) error { return c.Conn.SetDeadline(c.bound(t)) }
func (c *contextProbeConn) SetReadDeadline(t time.Time) error {
	return c.Conn.SetReadDeadline(c.bound(t))
}
func (c *contextProbeConn) SetWriteDeadline(t time.Time) error {
	return c.Conn.SetWriteDeadline(c.bound(t))
}
