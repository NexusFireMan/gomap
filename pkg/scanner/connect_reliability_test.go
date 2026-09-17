package scanner

import (
	"errors"
	"net"
	"os"
	"strconv"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

type countedScanConn struct {
	net.Conn
	closes *atomic.Int32
}

func (c countedScanConn) Close() error {
	c.closes.Add(1)
	return nil
}

func TestConnectStartupWaitsForFirstDial(t *testing.T) {
	for _, firstErr := range []error{nil, syscall.ECONNREFUSED, os.ErrDeadlineExceeded} {
		t.Run(strconv.FormatBool(firstErr == nil)+"-"+errorText(firstErr), func(t *testing.T) {
			s := NewScanner("fixture.invalid", false)
			s.NumWorkers = 8
			var calls, closes atomic.Int32
			entered := make(chan struct{})
			release := make(chan struct{})
			premature := make(chan struct{}, 8)
			var ready atomic.Bool
			done := make(chan []ScanResult, 1)
			go func() {
				done <- s.scanPortsWithDial([]int{1, 2, 3, 4, 5, 6, 7, 8}, false, func(_ string, _ time.Duration) (net.Conn, error) {
					if calls.Add(1) == 1 {
						close(entered)
						<-release
						ready.Store(true)
						if firstErr != nil {
							return nil, firstErr
						}
					} else if !ready.Load() {
						premature <- struct{}{}
						return nil, syscall.EHOSTUNREACH
					}
					return countedScanConn{closes: &closes}, nil
				})
			}()
			<-entered
			select {
			case <-premature:
				close(release)
				<-done
				t.Fatal("concurrent dial started before the first outcome")
			case <-time.After(20 * time.Millisecond):
			}
			close(release)
			select {
			case results := <-done:
				want := 8
				if firstErr != nil {
					want--
				}
				if len(results) != want || int(closes.Load()) != want || calls.Load() != 8 {
					t.Fatalf("results=%d closes=%d calls=%d", len(results), closes.Load(), calls.Load())
				}
			case <-time.After(time.Second):
				t.Fatal("first dial failure stalled other workers")
			}
		})
	}
}

func TestConnectTimeoutDoesNotFollowFilteredPortBackoff(t *testing.T) {
	s := NewScanner("fixture.invalid", false)
	s.Timeout = 500 * time.Millisecond
	s.MinAdaptiveTimeout = s.Timeout
	s.MaxAdaptiveTimeout = 4 * time.Second
	s.failureStreak = 20
	if got, want := s.connectTimeout(), 600*time.Millisecond; got != want {
		t.Fatalf("connect timeout = %s, want %s", got, want)
	}
}

func errorText(err error) string {
	if err == nil {
		return "success"
	}
	return err.Error()
}

func TestConnectRetriesOnlyTransientFailures(t *testing.T) {
	for _, tt := range []struct {
		name  string
		err   error
		retry bool
	}{
		{"timeout", os.ErrDeadlineExceeded, true},
		{"unreachable", syscall.EHOSTUNREACH, true},
		{"reset", syscall.ECONNRESET, true},
		{"local exhaustion", syscall.EMFILE, true},
		{"refused", syscall.ECONNREFUSED, false},
		{"permission", syscall.EACCES, false},
		{"invalid", syscall.EINVAL, false},
		{"unknown", errors.New("unknown failure"), false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			s := NewScanner("fixture.invalid", false)
			s.Retries = 1
			s.BackoffBase = time.Nanosecond
			var calls, closes atomic.Int32
			result := s.scanPortWithDial(2222, false, func(_ string, _ time.Duration) (net.Conn, error) {
				if calls.Add(1) == 1 {
					return nil, &net.OpError{Op: "dial", Net: "tcp", Err: &os.SyscallError{Syscall: "connect", Err: tt.err}}
				}
				return countedScanConn{closes: &closes}, nil
			})
			want := int32(1)
			if tt.retry {
				want++
			}
			if calls.Load() != want || result.IsOpen != tt.retry || closes.Load() != want-1 {
				t.Fatalf("result=%+v calls=%d closes=%d", result, calls.Load(), closes.Load())
			}
		})
	}
}

func TestConnectRetryLimitAndEmptyScan(t *testing.T) {
	s := NewScanner("fixture.invalid", false)
	for _, retries := range []int{0, 2} {
		s.Retries = retries
		s.BackoffBase = time.Nanosecond
		calls := 0
		dial := func(_ string, _ time.Duration) (net.Conn, error) {
			calls++
			return nil, os.ErrDeadlineExceeded
		}
		if result := s.scanPortWithDial(80, false, dial); result.IsOpen || calls != retries+1 {
			t.Fatalf("retries=%d calls=%d result=%+v", retries, calls, result)
		}
		calls = 0
		if result := s.scanPortsWithDial(nil, false, dial); len(result) != 0 || calls != 0 {
			t.Fatal("empty scan dialed a target")
		}
	}
}

func TestConnectStartupDoesNotWaitForBanner(t *testing.T) {
	s := NewScanner("fixture.invalid", false)
	s.NumWorkers = 2
	client, server := net.Pipe()
	defer func() { _ = server.Close() }()
	defer func() { _ = client.Close() }()
	otherDial := make(chan struct{})
	done := make(chan []ScanResult, 1)
	go func() {
		done <- s.scanPortsWithDial([]int{2222, 2223}, true, func(address string, _ time.Duration) (net.Conn, error) {
			_, port, _ := net.SplitHostPort(address)
			if port == "2222" {
				return client, nil
			}
			close(otherDial)
			return nil, syscall.ECONNREFUSED
		})
	}()
	select {
	case <-otherDial:
	case <-time.After(time.Second):
		t.Fatal("banner blocked remaining dials")
	}
	_ = server.SetWriteDeadline(time.Now().Add(time.Second))
	if _, err := server.Write([]byte("SSH-2.0-OpenSSH_9.6\r\n")); err != nil {
		t.Fatal(err)
	}
	select {
	case results := <-done:
		if len(results) != 1 || results[0].ServiceName != "ssh" {
			t.Fatalf("lost first connection: %+v", results)
		}
	case <-time.After(time.Second):
		t.Fatal("scan did not finish")
	}
}
