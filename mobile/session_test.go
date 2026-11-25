package mobile

import (
	"context"
	"encoding/json"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/NexusFireMan/gomap/v2/pkg/scanner"
)

func decodeEvent(t *testing.T, text string) event {
	t.Helper()
	var got event
	if err := json.Unmarshal([]byte(text), &got); err != nil || got.SchemaVersion != 1 {
		t.Fatalf("invalid event %q: %v", text, err)
	}
	return got
}

func TestSessionNativeLoopback(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()
	s, err := StartConnect("127.0.0.1", strconv.Itoa(l.Addr().(*net.TCPAddr).Port))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Cancel()
	got := decodeEvent(t, s.NextEvent())
	if got.Type != "result" || got.Host != "127.0.0.1" || got.Result == nil || got.Result.State != "open" {
		t.Fatalf("invalid result: %+v", got)
	}
	if s.NextEvent() != "" {
		t.Fatal("unexpected extra result")
	}
	summaryText := s.AwaitSummary()
	summary := decodeEvent(t, summaryText)
	if summary.Type != "summary" || summary.Error != "" || summary.Summary == nil || summary.Summary.Open != 1 || summary.Summary.Completed != 1 || summary.Summary.Unreported != 0 {
		t.Fatalf("invalid summary: %+v", summary)
	}
	if s.AwaitSummary() != summaryText {
		t.Fatal("summary changed")
	}
}

func TestSessionBackpressureCancelAndConcurrentWait(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	blocked := make(chan struct{})
	runner := func(_ context.Context, _ string, _ []int, _ scanner.ConnectOptions, emit func(scanner.ScanResult) error) (scanner.ConnectSummary, error) {
		summary := scanner.ConnectSummary{Requested: 40}
		for port := 1; port <= 40; port++ {
			if port == 33 {
				close(blocked)
			}
			if err := emit(scanner.ScanResult{Port: port, State: "open", IsOpen: true}); err != nil {
				summary.Unreported = 40 - summary.Completed
				summary.Cancelled = true
				return summary, err
			}
			summary.Completed++
			summary.Open++
		}
		return summary, nil
	}
	s := startSession(ctx, cancel, "127.0.0.1", nil, runner)
	defer s.Cancel()
	select {
	case <-blocked:
	case <-time.After(3 * time.Second):
		t.Fatal("queue did not fill")
	}
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(s.Cancel)
	}
	wg.Wait()
	finished := make(chan string, 2)
	for range 2 {
		go func() { finished <- s.AwaitSummary() }()
	}
	for range 2 {
		select {
		case text := <-finished:
			got := decodeEvent(t, text)
			if got.Error != "cancelled" || got.Summary == nil || got.Summary.Completed != 32 || got.Summary.Unreported != 8 || !got.Summary.Cancelled {
				t.Fatalf("incorrect cancellation: %+v", got)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("queue retained scan goroutine")
		}
	}
	count := 0
	for text := s.NextEvent(); text != ""; text = s.NextEvent() {
		decodeEvent(t, text)
		count++
	}
	if count != 32 {
		t.Fatalf("lost queued observations: %d", count)
	}
}

func TestSessionValidation(t *testing.T) {
	for _, tc := range []struct{ host, ports string }{
		{"example.invalid", "80"}, {"0.0.0.0", "80"}, {"255.255.255.255", "80"}, {"224.0.0.1", "80"}, {"::", "80"}, {"fe80::1%wlan0", "80"},
		{"127.0.0.1", ""}, {"127.0.0.1", "-"}, {"127.0.0.1", "0"}, {"127.0.0.1", "65536"}, {"127.0.0.1", "1-4097"},
		{"127.0.0.1", strings.Repeat("1,", 257) + "1"}, {"127.0.0.1", strings.Repeat("1", 8193)},
	} {
		if s, err := StartConnect(tc.host, tc.ports); err == nil {
			s.Cancel()
			t.Fatalf("accepted invalid scope %q %q", tc.host, tc.ports)
		}
	}
	ports, err := parseSessionPorts("80,80,81-82,81")
	if err != nil || len(ports) != 3 || ports[0] != 80 || ports[2] != 82 {
		t.Fatal(ports, err)
	}
	for _, s := range []*Session{nil, {}} {
		s.Cancel()
		if s.NextEvent() != "" || decodeEvent(t, s.AwaitSummary()).Error != "invalid_session" {
			t.Fatal("unsafe zero session")
		}
	}
}
