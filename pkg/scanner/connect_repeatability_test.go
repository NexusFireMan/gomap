package scanner

import (
	"net"
	"os"
	"runtime"
	"strconv"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

func TestConnectRepeatabilityUnderMixedFailures(t *testing.T) {
	for _, size := range []int{1024, 65535} {
		for _, workers := range []int{1, 32, 128} {
			for _, retries := range []int{0, 1} {
				t.Run(strconv.Itoa(size)+"/workers="+strconv.Itoa(workers)+"/retries="+strconv.Itoa(retries), func(t *testing.T) {
					s := NewScanner("fixture.invalid", false)
					s.NumWorkers, s.Retries = workers, retries
					s.AdaptiveTimeout, s.BackoffBase = false, time.Nanosecond
					ports := make([]int, size)
					attempts := make([]int, size+1)
					wantOpen, wantClosed, wantTimeout, wantRecovered, wantCalls := 0, 0, 0, 0, 0
					for i := range ports {
						port := size - i
						ports[i] = port
						wantCalls++
						switch port % 5 {
						case 0:
							wantOpen++
						case 1:
							wantClosed++
						case 2, 3:
							if retries == 0 {
								wantTimeout++
							} else {
								wantCalls++
								if port%5 == 2 {
									wantOpen++
									wantRecovered++
								} else {
									wantClosed++
								}
							}
						case 4:
							wantTimeout++
							wantCalls += retries
						}
					}
					ports = append(ports, ports[0], ports[len(ports)-1])
					streamed := make(map[int]bool)
					s.OnResult = func(r ScanResult) {
						if streamed[r.Port] {
							t.Errorf("duplicate streamed port %d", r.Port)
						}
						streamed[r.Port] = true
					}
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
						// Each unique port belongs to one worker; yielding varies completion order without wall-clock expectations.
						attempts[port]++
						runtime.Gosched()
						switch port % 5 {
						case 1:
							return nil, syscall.ECONNREFUSED
						case 2, 3:
							if attempts[port] == 1 {
								return nil, os.ErrDeadlineExceeded
							}
							if port%5 == 3 {
								return nil, syscall.ECONNREFUSED
							}
						case 4:
							return nil, os.ErrDeadlineExceeded
						}
						return countedScanConn{closes: &closes}, nil
					})
					calls := 0
					for _, n := range attempts {
						calls += n
					}
					if len(results) != wantOpen || len(streamed) != wantOpen || int(closes.Load()) != wantOpen || calls != wantCalls || diag.AttemptedPorts != size || diag.RefusedPorts != wantClosed || diag.FilteredPorts != wantTimeout || diag.UnresolvedPorts != wantTimeout || diag.RecoveredPorts != wantRecovered {
						t.Fatalf("lost outcomes: open=%d streamed=%d closes=%d calls=%d diag=%+v", len(results), len(streamed), closes.Load(), calls, diag)
					}
					previous := 0
					for _, r := range results {
						expected := r.Port%5 == 0 || (retries > 0 && r.Port%5 == 2)
						if r.Port <= previous || !streamed[r.Port] || !expected {
							t.Fatalf("unexpected/duplicate/missing streamed result: %+v", r)
						}
						previous = r.Port
					}
				})
			}
		}
	}
}
