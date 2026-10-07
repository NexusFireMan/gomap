package scanner

import (
	"fmt"
	"net"
	"os"
	"syscall"
	"testing"
	"time"
)

func TestUDPErrorStates(t *testing.T) {
	for _, tt := range []struct {
		err   error
		state string
	}{
		{fmt.Errorf("read: %w", syscall.ECONNREFUSED), "closed"},
		{os.ErrDeadlineExceeded, "open|filtered"},
		{syscall.EACCES, "unknown"},
		{syscall.ENETUNREACH, "unknown"},
	} {
		state, evidence := udpErrorState(tt.err)
		if state != tt.state || evidence == "" {
			t.Fatalf("%v: got %q/%q", tt.err, state, evidence)
		}
	}
}

func TestScanUDPRetainsSilentPortOnce(t *testing.T) {
	listener, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	port := listener.LocalAddr().(*net.UDPAddr).Port
	s := NewScanner("127.0.0.1", false)
	s.Configure(ScanConfig{Timeout: 20 * time.Millisecond, NumWorkers: 1})
	results := s.ScanUDP([]int{port, port}, false)
	if len(results) != 1 || results[0].State != "open|filtered" || results[0].IsOpen {
		t.Fatalf("silent UDP result lost or confirmed open: %+v", results)
	}
}

func TestCountOpenExcludesUncertainAndClosedResults(t *testing.T) {
	results := []ScanResult{{IsOpen: true}, {IsOpen: true, State: "open"},
		{State: "closed"}, {State: "open|filtered"}, {State: "unknown"}}
	if got := CountOpen(results); got != 2 {
		t.Fatalf("expected 2 confirmed open ports, got %d", got)
	}
}
