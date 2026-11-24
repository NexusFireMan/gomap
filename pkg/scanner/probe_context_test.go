package scanner

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type contextBannerFixture struct {
	net.Conn
	*bytes.Reader
	closed *atomic.Int32
}

func (c *contextBannerFixture) Read(p []byte) (int, error)     { return c.Reader.Read(p) }
func (*contextBannerFixture) Write(p []byte) (int, error)      { return len(p), nil }
func (*contextBannerFixture) SetDeadline(time.Time) error      { return nil }
func (*contextBannerFixture) SetReadDeadline(time.Time) error  { return nil }
func (*contextBannerFixture) SetWriteDeadline(time.Time) error { return nil }
func (c *contextBannerFixture) Close() error                   { c.closed.Add(1); return nil }

func TestContextNativeServiceParsers(t *testing.T) {
	for _, tc := range []struct {
		name                     string
		port                     int
		banner, service, version string
	}{
		{"SSH", 22, "SSH-2.0-OpenSSH_9.9\r\n", "ssh", "OpenSSH"},
		{"SSH alternate", 22222, "SSH-2.0-OpenSSH_9.9\r\n", "ssh", "OpenSSH"},
		{"SSH dynamic", 55000, "SSH-2.0-OpenSSH_9.9\r\n", "ssh", "OpenSSH"},
		{"HTTP", 80, "HTTP/1.1 200 OK\r\nServer: nginx/1.26.0\r\nContent-Length: 0\r\n\r\n", "http", "nginx"},
		{"FTP", 21, "220 ProFTPD 1.3.8 Server\r\n", "ftp", "ProFTPD"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var opens, closes atomic.Int32
			var result ScanResult
			summary, err := scanConnectContext(context.Background(), "127.0.0.1", []int{tc.port}, ConnectOptions{DetectServices: true, Rate: 1000}, func(r ScanResult) error { result = r; return nil }, func(context.Context, string, time.Duration) (net.Conn, error) {
				opens.Add(1)
				return &contextBannerFixture{Reader: bytes.NewReader([]byte(tc.banner)), closed: &closes}, nil
			})
			if err != nil || summary.Open != 1 || result.ServiceName != tc.service || !strings.Contains(strings.ToLower(result.Version), strings.ToLower(tc.version)) || !strings.Contains(strings.ToLower(result.Evidence), strings.ToLower(tc.version)) || result.Confidence == "low" || opens.Load() != closes.Load() {
				t.Fatalf("native identification/cleanup: %+v %+v err=%v sockets=%d/%d", result, summary, err, opens.Load(), closes.Load())
			}
		})
	}
}

func TestContextFailedServiceReadsRetainOpenState(t *testing.T) {
	var opens, closes atomic.Int32
	var result ScanResult
	summary, err := scanConnectContext(context.Background(), "127.0.0.1", []int{22}, ConnectOptions{DetectServices: true, Rate: 1000}, func(r ScanResult) error { result = r; return nil }, func(context.Context, string, time.Duration) (net.Conn, error) {
		opens.Add(1)
		return &contextBannerFixture{Reader: bytes.NewReader(nil), closed: &closes}, nil
	})
	if err != nil || summary.Open != 1 || summary.Closed != 0 || result.State != "open" || !result.IsOpen || result.Confidence != "low" || opens.Load() != closes.Load() {
		t.Fatalf("failed fingerprint erased CONNECT evidence: %+v %+v %v", result, summary, err)
	}
}

type readingContextConn struct {
	net.Conn
	entered chan struct{}
}

func (c *readingContextConn) Read(p []byte) (int, error) {
	select {
	case c.entered <- struct{}{}:
	default:
	}
	return c.Conn.Read(p)
}

func TestContextServiceCancellationClosesBlockedRead(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	client, server := net.Pipe()
	defer func() { _ = server.Close() }()
	entered := make(chan struct{}, 1)
	done := make(chan error, 1)
	go func() {
		_, err := scanConnectContext(ctx, "127.0.0.1", []int{22}, ConnectOptions{DetectServices: true}, func(ScanResult) error { t.Error("cancelled observation delivered"); return nil }, func(context.Context, string, time.Duration) (net.Conn, error) {
			return &readingContextConn{Conn: client, entered: entered}, nil
		})
		done <- err
	}()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("banner read did not start")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("cancellation retained a banner reader")
	}
	if _, err := server.Write([]byte("x")); err == nil || (!errors.Is(err, io.ErrClosedPipe) && !errors.Is(err, net.ErrClosed)) {
		t.Fatal("native socket retained", err)
	}
}

func TestContextTLSCancellationJoinsHandshake(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	client, server := net.Pipe()
	defer func() { cancel(); _ = server.Close() }()
	s := NewScanner("127.0.0.1", false)
	s.probeContext = ctx
	entered := make(chan struct{})
	s.probeDial = func(context.Context, string, time.Duration) (net.Conn, error) { close(entered); return client, nil }
	done := make(chan struct{})
	go func() { _, _ = s.detectTLSFingerprint(443); close(done) }()
	<-entered
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("TLS handshake ignored cancellation")
	}
}

func TestContextHTTPSNativeLoopback(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Server", "nginx/1.26.0")
		w.Header().Set("Connection", "close")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	s := NewScanner("127.0.0.1", false)
	s.probeContext = ctx
	banner, fp := s.grabHTTPBannerTransport(server.Listener.Addr().(*net.TCPAddr).Port, true)
	service, version := parseObservedBanner(banner)
	if fp == nil || !strings.HasPrefix(fp.Version, "TLS") || service != "http" || !strings.Contains(strings.ToLower(version), "nginx") {
		t.Fatalf("context-aware TLS lost native HTTP parsing: fp=%+v %q %q", fp, service, version)
	}
}

func TestContextServiceBudgetStartsAfterConnect(t *testing.T) {
	var closes atomic.Int32
	summary, err := scanConnectContext(context.Background(), "127.0.0.1", []int{22}, ConnectOptions{DetectServices: true}, func(ScanResult) error { return nil }, func(ctx context.Context, _ string, _ time.Duration) (net.Conn, error) {
		if _, ok := ctx.Deadline(); ok {
			t.Error("service deadline consumed primary CONNECT/pacing budget")
		}
		return &contextBannerFixture{Reader: bytes.NewReader([]byte("SSH-2.0-OpenSSH_9.9\r\n")), closed: &closes}, nil
	})
	if err != nil || summary.Open != 1 || closes.Load() != 1 {
		t.Fatal(summary, err)
	}
}
