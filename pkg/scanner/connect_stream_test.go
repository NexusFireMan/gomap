package scanner

import (
	"net"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

func TestConnectStreamsBeforeOtherPortsFinish(t *testing.T) {
	s := NewScanner("fixture.invalid", false)
	s.NumWorkers = 2
	blocked := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	defer unblock()
	events := make(chan ScanResult, 2)
	s.OnResult = func(r ScanResult) { events <- r }
	done := make(chan []ScanResult, 1)
	var closes atomic.Int32
	go func() {
		results, _ := s.scanPortsReportWithDial([]int{1, 2, 1}, false, func(address string, _ time.Duration) (net.Conn, error) {
			_, port, _ := net.SplitHostPort(address)
			if port == "2" {
				close(blocked)
				<-release
			}
			return countedScanConn{closes: &closes}, nil
		})
		done <- results
	}()
	defer func() {
		unblock()
		select {
		case results := <-done:
			if len(results) != 2 || results[0].Port != 1 || results[1].Port != 2 || closes.Load() != 2 {
				t.Errorf("results=%v closed=%d", results, closes.Load())
			}
		case <-time.After(5 * time.Second):
			t.Error("scan did not stop")
		}
	}()
	select {
	case <-blocked:
	case <-time.After(5 * time.Second):
		t.Fatal("second dial did not start")
	}
	select {
	case event := <-events:
		if event.Port != 1 || !event.IsOpen {
			t.Fatalf("event=%+v", event)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("first open port was buffered behind the blocked dial")
	}
	unblock()
	select {
	case event := <-events:
		if event.Port != 2 {
			t.Fatalf("event=%+v", event)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("missing second result")
	}
	// Completion is drained by cleanup; each unique open port has one event.
	select {
	case event := <-events:
		t.Fatalf("duplicate event: %+v", event)
	default:
	}
}

func TestConnectStreamDrainsBoundedQueue(t *testing.T) {
	s := NewScanner("fixture.invalid", false)
	s.NumWorkers = 4
	ports := make([]int, 96)
	for i := range ports {
		ports[i] = len(ports) - i
	}
	var closes atomic.Int32
	seen := make(map[int]int)
	s.OnResult = func(r ScanResult) { seen[r.Port]++ }
	results, diag := s.scanPortsReportWithDial(ports, false, func(_ string, _ time.Duration) (net.Conn, error) {
		return countedScanConn{closes: &closes}, nil
	})
	if len(results) != len(ports) || len(seen) != len(ports) || int(closes.Load()) != len(ports) || diag.UnresolvedPorts != 0 {
		t.Fatalf("results=%d seen=%d closes=%d diag=%+v", len(results), len(seen), closes.Load(), diag)
	}
	for i, result := range results {
		if result.Port != i+1 || seen[result.Port] != 1 {
			t.Fatalf("result=%+v count=%d", result, seen[result.Port])
		}
	}
}

func TestConnectRecordsAdaptiveAttemptBudget(t *testing.T) {
	s := NewScanner("fixture.invalid", false)
	s.failureStreak = 2
	_, diag := s.scanPortsReportWithDial([]int{1}, false, func(_ string, budget time.Duration) (net.Conn, error) {
		if budget != 600*time.Millisecond {
			t.Errorf("adaptive attempt budget=%s", budget)
		}
		return nil, os.ErrDeadlineExceeded
	})
	if diag.TimeoutMS != 500 || len(diag.Issues) != 1 || diag.Issues[0].TimeoutMS != 600 || diag.FilteredPorts != 1 {
		t.Fatalf("lost adaptive budget: %+v", diag)
	}
}

func TestConnectIssueStatesAndActualTimeout(t *testing.T) {
	s := NewScanner("fixture.invalid", false)
	s.Timeout = 750 * time.Millisecond
	s.MinAdaptiveTimeout = s.Timeout
	s.AdaptiveTimeout = false
	s.Retries = 1
	s.BackoffBase = time.Nanosecond
	s.NumWorkers = 1
	var closes atomic.Int32
	calls := make(map[int]int)
	var events []ScanResult
	s.OnResult = func(r ScanResult) { events = append(events, r) }
	results, diag := s.scanPortsReportWithDial([]int{1, 2, 3, 4, 5, 6}, false, func(address string, budget time.Duration) (net.Conn, error) {
		_, p, _ := net.SplitHostPort(address)
		port, _ := strconv.Atoi(p)
		calls[port]++
		if budget != 750*time.Millisecond {
			t.Errorf("budget=%s", budget)
		}
		switch port {
		case 1:
			return nil, os.ErrDeadlineExceeded
		case 2:
			return nil, syscall.ECONNREFUSED
		case 3:
			return nil, syscall.EMFILE
		case 4:
			return nil, syscall.EHOSTUNREACH
		case 5:
			if calls[port] == 1 {
				return nil, os.ErrDeadlineExceeded
			}
		}
		return countedScanConn{closes: &closes}, nil
	})
	if len(results) != 2 || len(events) != 2 || diag.FilteredPorts != 1 || diag.UnresolvedPorts != 3 || diag.RefusedPorts != 1 || diag.RecoveredPorts != 1 || diag.TimeoutMS != 750 {
		t.Fatalf("results=%v events=%v diagnostics=%+v", results, events, diag)
	}
	want := map[int]string{1: "filtered", 3: "unknown", 4: "unknown", 5: "open"}
	for _, issue := range diag.Issues {
		if issue.State != want[issue.Port] || issue.TimeoutMS != 750 {
			t.Fatalf("issue=%+v", issue)
		}
	}
}
