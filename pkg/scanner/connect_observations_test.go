package scanner

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

func TestConnectClosedRequiresObservedRefusal(t *testing.T) {
	for _, tc := range []struct {
		name             string
		failures         []error
		closed, timeouts int
	}{
		{"silent ports", []error{nil, os.ErrDeadlineExceeded, os.ErrDeadlineExceeded, os.ErrDeadlineExceeded}, 0, 3},
		{"mixed observations", []error{nil,
			&net.OpError{Op: "dial", Net: "tcp", Err: syscall.ECONNREFUSED},
			fmt.Errorf("wrapped: %w", &os.SyscallError{Syscall: "connect", Err: syscall.ECONNREFUSED}),
			&net.OpError{Op: "dial", Net: "tcp", Err: os.ErrDeadlineExceeded},
			syscall.EHOSTUNREACH, syscall.ECONNRESET}, 2, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ports := make([]int, len(tc.failures))
			for i := range ports {
				ports[i] = i + 1
			}
			s := NewScanner("fixture.invalid", false)
			s.NumWorkers = 4
			var closes atomic.Int32
			results, diag := s.scanPortsReportWithDial(ports, false, func(address string, _ time.Duration) (net.Conn, error) {
				_, text, err := net.SplitHostPort(address)
				if err != nil {
					return nil, err
				}
				port, err := strconv.Atoi(text)
				if err != nil {
					return nil, err
				}
				if err := tc.failures[port-1]; err != nil {
					return nil, err
				}
				return countedScanConn{closes: &closes}, nil
			})
			if len(results) != 1 || closes.Load() != 1 || diag.RefusedPorts != tc.closed || diag.FilteredPorts != tc.timeouts || diag.UnresolvedPorts != len(ports)-1-tc.closed || diag.RecoveredPorts != 0 {
				t.Fatalf("observation counters changed: results=%+v diag=%+v", results, diag)
			}
			if len(results)+diag.RefusedPorts+diag.UnresolvedPorts != diag.AttemptedPorts {
				t.Fatal("CONNECT observations do not reconcile")
			}
		})
	}
}

func TestConnectRetryRefusalIsClosedNotFiltered(t *testing.T) {
	s := NewScanner("fixture.invalid", false)
	s.Retries, s.BackoffBase = 1, time.Nanosecond
	var calls atomic.Int32
	results, diag := s.scanPortsReportWithDial([]int{81}, false, func(string, time.Duration) (net.Conn, error) {
		if calls.Add(1) == 1 {
			return nil, os.ErrDeadlineExceeded
		}
		return nil, &net.OpError{Op: "dial", Net: "tcp", Err: syscall.ECONNREFUSED}
	})
	if calls.Load() != 2 || len(results) != 0 || diag.RefusedPorts != 1 || diag.FilteredPorts != 0 || diag.UnresolvedPorts != 0 {
		t.Fatalf("confirmed retry refusal lost: %+v", diag)
	}
}
