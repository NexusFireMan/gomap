package scanner

import (
	"errors"
	"net"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

func TestConnectDiagnosticsDistinguishRecoveryAndUnresolved(t *testing.T) {
	s := NewScanner("fixture.invalid", false)
	s.Retries = 1
	s.BackoffBase = time.Nanosecond
	var mu sync.Mutex
	calls := make(map[int]int)
	var closes atomic.Int32
	results, diag := s.scanPortsReportWithDial([]int{6, 5, 4, 3, 2, 1, 3}, false, func(address string, _ time.Duration) (net.Conn, error) {
		_, p, _ := net.SplitHostPort(address)
		port, _ := strconv.Atoi(p)
		mu.Lock()
		calls[port]++
		attempt := calls[port]
		mu.Unlock()
		var err error
		switch port {
		case 1:
			err = syscall.ECONNREFUSED
		case 2:
			err = os.ErrDeadlineExceeded
		case 3:
			if attempt == 1 {
				err = syscall.EHOSTUNREACH
			}
		case 4:
			err = syscall.EACCES
		case 5:
			err = errors.New("fixture failure")
		}
		if err != nil {
			return nil, &net.OpError{Op: "dial", Net: "tcp", Err: err}
		}
		return countedScanConn{closes: &closes}, nil
	})
	if len(results) != 2 || results[0].Port != 3 || results[1].Port != 6 || closes.Load() != 2 {
		t.Fatalf("results=%+v closes=%d", results, closes.Load())
	}
	if diag.AttemptedPorts != 6 || diag.RefusedPorts != 1 || diag.UnresolvedPorts != 3 || diag.RecoveredPorts != 1 || len(diag.Issues) != 4 {
		t.Fatalf("diagnostics=%+v", diag)
	}
	for i, kind := range []string{"timeout", "unreachable", "permission", "other"} {
		issue := diag.Issues[i]
		if issue.Port != i+2 || issue.Kind != kind || issue.Error == "" || issue.Recovered != (issue.Port == 3) {
			t.Fatalf("issue=%+v", issue)
		}
		wantAttempts := 1
		if i < 2 {
			wantAttempts = 2
		}
		if issue.Attempts != wantAttempts {
			t.Fatalf("attempts=%d want=%d", issue.Attempts, wantAttempts)
		}
	}
}

func TestConnectRetryConcurrencyIsBounded(t *testing.T) {
	s := NewScanner("fixture.invalid", false)
	s.NumWorkers = 32
	s.Retries = 1
	s.BackoffBase = time.Nanosecond
	var mu sync.Mutex
	calls := make(map[string]int)
	var active, maximum, closes atomic.Int32
	entered := make(chan struct{}, 16)
	release := make(chan struct{})
	done := make(chan ConnectDiagnostics, 1)
	ports := make([]int, 17)
	for i := range ports {
		ports[i] = i + 1
	}
	go func() {
		_, diag := s.scanPortsReportWithDial(ports, false, func(address string, _ time.Duration) (net.Conn, error) {
			mu.Lock()
			calls[address]++
			attempt := calls[address]
			mu.Unlock()
			_, port, _ := net.SplitHostPort(address)
			if port == "1" {
				return nil, syscall.ECONNREFUSED
			}
			if attempt == 1 {
				return nil, os.ErrDeadlineExceeded
			}
			n := active.Add(1)
			defer active.Add(-1)
			for old := maximum.Load(); n > old; old = maximum.Load() {
				if maximum.CompareAndSwap(old, n) {
					break
				}
			}
			entered <- struct{}{}
			<-release
			return countedScanConn{closes: &closes}, nil
		})
		done <- diag
	}()
	for i := 0; i < 8; i++ {
		select {
		case <-entered:
		case <-time.After(time.Second):
			close(release)
			<-done
			t.Fatal("retry workers stalled")
		}
	}
	select {
	case <-entered:
		close(release)
		<-done
		t.Fatal("more than eight simultaneous retries")
	case <-time.After(20 * time.Millisecond):
	}
	close(release)
	select {
	case diag := <-done:
		if maximum.Load() > 8 || diag.RecoveredPorts != 16 || closes.Load() != 16 {
			t.Fatalf("max=%d diag=%+v closes=%d", maximum.Load(), diag, closes.Load())
		}
	case <-time.After(time.Second):
		t.Fatal("retries did not finish")
	}
}

func TestRecoveredConnectionReadsBannerOnce(t *testing.T) {
	s := NewScanner("fixture.invalid", false)
	s.Retries = 1
	s.BackoffBase = time.Nanosecond
	client, server := net.Pipe()
	defer func() { _ = client.Close() }()
	defer func() { _ = server.Close() }()
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = server.SetWriteDeadline(time.Now().Add(time.Second))
		_, _ = server.Write([]byte("SSH-2.0-OpenSSH_9.6\r\n"))
	}()
	var calls int
	results, diag := s.scanPortsReportWithDial([]int{2222}, true, func(_ string, _ time.Duration) (net.Conn, error) {
		calls++
		if calls == 1 {
			return nil, syscall.ECONNRESET
		}
		return client, nil
	})
	<-done
	if calls != 2 || len(results) != 1 || results[0].ServiceName != "ssh" || diag.RecoveredPorts != 1 || diag.UnresolvedPorts != 0 {
		t.Fatalf("calls=%d results=%+v diag=%+v", calls, results, diag)
	}
}
