package scanner

import (
	"net"
	"testing"
	"time"
)

func TestScanUDPDetectsResponsivePort(t *testing.T) {
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	defer func() { _ = conn.Close() }()

	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, 512)
		n, addr, err := conn.ReadFrom(buf)
		if err != nil || n == 0 {
			return
		}
		_, _ = conn.WriteTo([]byte("udp-test-response"), addr)
	}()

	port := conn.LocalAddr().(*net.UDPAddr).Port
	s := NewScanner("127.0.0.1", false)
	s.Configure(ScanConfig{Timeout: 200 * time.Millisecond, NumWorkers: 1})

	results := s.ScanUDP([]int{port}, true)
	if len(results) != 1 {
		t.Fatalf("expected one udp result, got %d (%v)", len(results), results)
	}
	if !results[0].IsOpen || results[0].Port != port {
		t.Fatalf("unexpected udp result: %+v", results[0])
	}
	if results[0].DetectionPath != "udp-probe" {
		t.Fatalf("unexpected detection path: %q", results[0].DetectionPath)
	}

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("udp test server did not finish")
	}
}

func TestGetTopUDPPorts(t *testing.T) {
	ports := GetTopUDPPorts()
	if len(ports) == 0 {
		t.Fatal("expected udp top ports")
	}
	if ports[0] != 53 {
		t.Fatalf("expected DNS first in udp top ports, got %d", ports[0])
	}
}
