package scanner

import (
	"net"
	"testing"
	"time"
)

func TestRandomCompatibleSourceIPMatchesTargetFamily(t *testing.T) {
	ips := []net.IP{net.ParseIP("192.0.2.10"), net.ParseIP("2001:db8::10")}

	v4 := randomCompatibleSourceIP(ips, "198.51.100.20:443")
	if v4 == nil || v4.To4() == nil {
		t.Fatalf("expected IPv4 source, got %v", v4)
	}

	v6 := randomCompatibleSourceIP(ips, "[2001:db8::20]:443")
	if v6 == nil || v6.To4() != nil {
		t.Fatalf("expected IPv6 source, got %v", v6)
	}
}

func TestRandomCompatibleSourceIPReturnsNilWithoutMatchingFamily(t *testing.T) {
	ips := []net.IP{net.ParseIP("192.0.2.10")}
	if got := randomCompatibleSourceIP(ips, "[2001:db8::20]:443"); got != nil {
		t.Fatalf("expected no compatible source, got %v", got)
	}
}

func TestValidateSourceIPsForTargetsRejectsMissingFamily(t *testing.T) {
	ips := []net.IP{net.ParseIP("192.0.2.10")}
	if err := ValidateSourceIPsForTargets(ips, []string{"2001:db8::20"}); err == nil {
		t.Fatal("expected missing IPv6 source address error")
	}
}

func TestValidateSourceIPsForTargetsAcceptsMatchingFamilies(t *testing.T) {
	ips := []net.IP{net.ParseIP("192.0.2.10"), net.ParseIP("2001:db8::10")}
	if err := ValidateSourceIPsForTargets(ips, []string{"198.51.100.20", "2001:db8::20"}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDialTCPBindsConfiguredSourceIP(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = listener.Close() }()

	remoteAddr := make(chan net.Addr, 1)
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr == nil {
			remoteAddr <- conn.RemoteAddr()
			_ = conn.Close()
		}
	}()

	s := NewScanner("127.0.0.1", false)
	s.SourceIPs = []net.IP{net.ParseIP("127.0.0.1")}
	conn, err := s.dialTCP(listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	_ = conn.Close()

	select {
	case addr := <-remoteAddr:
		host, _, splitErr := net.SplitHostPort(addr.String())
		if splitErr != nil {
			t.Fatalf("split remote address: %v", splitErr)
		}
		if host != "127.0.0.1" {
			t.Fatalf("expected bound source 127.0.0.1, got %s", host)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for local test connection")
	}
}
