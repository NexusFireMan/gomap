package scanner

import (
	"io"
	"net"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type finalBannerConn struct {
	net.Conn
	data string
	err  error
}

func (c *finalBannerConn) Read(p []byte) (int, error)    { return copy(p, c.data), c.err }
func (*finalBannerConn) Write(p []byte) (int, error)     { return len(p), nil }
func (*finalBannerConn) SetDeadline(time.Time) error     { return nil }
func (*finalBannerConn) SetReadDeadline(time.Time) error { return nil }

func TestBannerReadPreservesDataAlongsideError(t *testing.T) {
	s := NewScanner("fixture.invalid", false)
	for _, tc := range []struct {
		name string
		err  error
	}{
		{"success", nil}, {"eof", io.EOF}, {"timeout", os.ErrDeadlineExceeded},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, banner := range []string{"", "SSH-2.0-OpenSSH_9.0\r\n", "220 mail.local ESMTP Postfix\r\n"} {
				c := &finalBannerConn{data: banner, err: tc.err}
				if got := s.tryPassiveBanner(c); got != banner {
					t.Fatalf("passive: got %q, want %q", got, banner)
				}
				if got := s.probeTextServiceOnConn(c, "EHLO scanner.invalid\r\n"); got != banner {
					t.Fatalf("active: got %q, want %q", got, banner)
				}
			}
		})
	}
}

func TestGrabBannerPreservesFinalSSHRead(t *testing.T) {
	s := NewScanner("fixture.invalid", true)
	r := ScanResult{Port: 22}
	s.grabBanner(&finalBannerConn{data: "SSH-2.0-OpenSSH_9.0\r\n", err: io.EOF}, 22, &r)
	if r.ServiceName != "ssh" || r.Version == "" || r.Confidence != "high" {
		t.Fatalf("lost final banner: %+v", r)
	}
}

func TestUnparsedBannerDoesNotRepeatProtocolFingerprint(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			calls.Add(1)
			_ = conn.Close()
		}
	}()
	defer func() { _ = listener.Close(); <-done }()
	port := listener.Addr().(*net.TCPAddr).Port
	s := NewScanner("127.0.0.1", false)
	s.PortManager.serviceMap[port] = "fixture"
	r := ScanResult{Port: port}
	s.grabBanner(&finalBannerConn{data: "unrecognized fixture\r\n", err: io.EOF}, port, &r)
	if got := calls.Load(); got != 1 {
		t.Fatalf("expected one unsuccessful protocol probe, got %d", got)
	}
	if r.ServiceName != "fixture" || r.Confidence != "low" {
		t.Fatalf("unexpected fallback: %+v", r)
	}
}

func TestEnrichedFTPVersionRetainsSupportingEvidence(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			_ = conn.SetDeadline(time.Now().Add(time.Second))
			_, _ = io.WriteString(conn, "220 ProFTPD 1.3.5 Server (fixture.local)\r\n")
			_ = conn.Close()
		}
	}()
	defer func() { _ = listener.Close(); <-done }()
	port := listener.Addr().(*net.TCPAddr).Port
	s := NewScanner("127.0.0.1", false)
	s.DeepVersion = true
	r := ScanResult{Port: port}
	s.grabBanner(&finalBannerConn{data: "220\r\n", err: io.EOF}, port, &r)
	if r.Version != "ProFTPD 1.3.5" || !strings.Contains(r.Evidence, "ProFTPD 1.3.5") {
		t.Fatalf("enriched version lost its evidence: %+v", r)
	}
}

func TestOpenUnknownPortReportsExplicitEvidence(t *testing.T) {
	s := NewScanner("fixture.invalid", true)
	r := ScanResult{Port: 65000, IsOpen: true}
	s.grabBanner(&finalBannerConn{err: io.EOF}, 65000, &r)
	if r.ServiceName != "" || r.Confidence != "low" {
		t.Fatalf("unexpected unknown-port classification: %+v", r)
	}
	if r.Evidence != "tcp/65000 open; no recognizable protocol response" || r.DetectionPath != "open-port-fallback" {
		t.Fatalf("missing unknown-port evidence: %+v", r)
	}
}
