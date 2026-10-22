package scanner

import (
	"net"
	"os"
	"reflect"
	"slices"
	"strconv"
	"syscall"
	"testing"
	"time"
)

// This policy is an experiment, not part of Scan or the CLI. Only positive TCP
// evidence promotes an earlier timeout; a second failure retains uncertainty.
type recoveryExperiment struct {
	Attempts        int
	Opened, Refused []int
	Elapsed         time.Duration
	Stop            string
}

func evaluateSelectiveRecovery(host string, results []ScanResult, diag ConnectDiagnostics, dial tcpDialFunc, now func() time.Time, sleep func(time.Duration)) recoveryExperiment {
	const maxCandidates, maxAttempts = 32, 8
	const budget, timeout, interval = 3 * time.Second, 1500 * time.Millisecond, 100 * time.Millisecond
	start := now()
	out := recoveryExperiment{}
	finish := func(reason string) recoveryExperiment {
		out.Stop, out.Elapsed = reason, now().Sub(start)
		return out
	}
	if diag.FilteredPorts > maxCandidates {
		return finish("broad silence")
	}
	opened := make(map[int]bool)
	for _, r := range results {
		if r.IsOpen {
			opened[r.Port] = true
		}
	}
	seen := make(map[int]bool)
	var candidates []int
	for _, issue := range diag.Issues {
		if issue.Kind != "timeout" || issue.Recovered {
			continue
		}
		if issue.Port < 1 || issue.Port > 65535 || seen[issue.Port] || opened[issue.Port] {
			return finish("invalid diagnostics")
		}
		seen[issue.Port] = true
		candidates = append(candidates, issue.Port)
		if len(candidates) > maxCandidates {
			return finish("broad silence")
		}
	}
	if diag.FilteredPorts != len(candidates) || diag.UnresolvedPorts < diag.FilteredPorts {
		return finish("invalid diagnostics")
	}
	slices.Sort(candidates)
	deadline, next := start.Add(budget), start
	for _, port := range candidates {
		if out.Attempts == maxAttempts {
			return finish("attempt budget")
		}
		if delay := next.Sub(now()); delay > 0 {
			remaining := deadline.Sub(now())
			if remaining <= delay {
				return finish("time budget")
			}
			sleep(delay)
		}
		remaining := deadline.Sub(now())
		if remaining <= 0 {
			return finish("time budget")
		}
		next = now().Add(interval)
		out.Attempts++
		conn, err := dial(net.JoinHostPort(host, strconv.Itoa(port)), min(timeout, remaining))
		if conn != nil {
			_ = conn.Close()
		}
		if err == nil && conn != nil {
			out.Opened = append(out.Opened, port)
		} else if dialErrorKind(err) == "refused" {
			out.Refused = append(out.Refused, port)
		}
	}
	return finish("candidates exhausted")
}

func recoveryTimeoutFixture(ports ...int) ConnectDiagnostics {
	d := ConnectDiagnostics{AttemptedPorts: len(ports), FilteredPorts: len(ports), UnresolvedPorts: len(ports)}
	for _, port := range ports {
		d.Issues = append(d.Issues, ConnectionIssue{Port: port, Kind: "timeout", State: "filtered", Attempts: 1})
	}
	return d
}

func TestSelectiveRecoveryBudgetsAndEvidence(t *testing.T) {
	boundary := make([]int, 32)
	for i := range boundary {
		boundary[i] = i + 1
	}
	for _, tc := range []struct {
		name, stop                string
		ports                     []int
		failures                  []error
		durations                 []time.Duration
		attempts, opened, refused int
		elapsed                   time.Duration
	}{
		{name: "recovered open and refused", stop: "candidates exhausted", ports: []int{3, 2, 1}, failures: []error{nil, syscall.ECONNREFUSED, syscall.EHOSTUNREACH}, durations: []time.Duration{time.Millisecond, time.Millisecond, time.Millisecond}, attempts: 3, opened: 1, refused: 1, elapsed: 201 * time.Millisecond},
		{name: "persistent silence", stop: "time budget", ports: []int{1, 2, 3}, failures: []error{os.ErrDeadlineExceeded, os.ErrDeadlineExceeded}, durations: []time.Duration{1500 * time.Millisecond, 1500 * time.Millisecond}, attempts: 2, elapsed: 3 * time.Second},
		{name: "late but within budget", stop: "candidates exhausted", ports: []int{1, 2}, failures: []error{nil, syscall.ECONNREFUSED}, durations: []time.Duration{1400 * time.Millisecond, 1400 * time.Millisecond}, attempts: 2, opened: 1, refused: 1, elapsed: 2800 * time.Millisecond},
		{name: "last dial clipped", stop: "candidates exhausted", ports: []int{1, 2, 3}, failures: []error{nil, syscall.ECONNREFUSED, os.ErrDeadlineExceeded}, durations: []time.Duration{1400 * time.Millisecond, 1400 * time.Millisecond, 500 * time.Millisecond}, attempts: 3, opened: 1, refused: 1, elapsed: 3 * time.Second},
		{name: "next paced start outside window", stop: "time budget", ports: []int{1, 2, 3, 4}, failures: []error{nil, nil, nil}, durations: []time.Duration{1450 * time.Millisecond, 1450 * time.Millisecond, time.Millisecond}, attempts: 3, opened: 3, elapsed: 2901 * time.Millisecond},
		{name: "attempt cap", stop: "attempt budget", ports: []int{1, 2, 3, 4, 5, 6, 7, 8, 9}, failures: make([]error, 8), durations: make([]time.Duration, 8), attempts: 8, opened: 8, elapsed: 700 * time.Millisecond},
		{name: "eligible at candidate boundary", stop: "attempt budget", ports: boundary, failures: make([]error, 8), durations: make([]time.Duration, 8), attempts: 8, opened: 8, elapsed: 700 * time.Millisecond},
		{name: "no candidates", stop: "candidates exhausted"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			clock := time.Unix(0, 0)
			diag := recoveryTimeoutFixture(tc.ports...)
			beforeIssues := slices.Clone(diag.Issues)
			results := []ScanResult{{Port: 65535, IsOpen: true, ServiceName: "ssh", Version: "fixture"}}
			beforeResults := slices.Clone(results)
			calls, closes := 0, 0
			order := slices.Clone(tc.ports)
			slices.Sort(order)
			got := evaluateSelectiveRecovery("fixture.invalid", results, diag, func(address string, limit time.Duration) (net.Conn, error) {
				if calls >= len(tc.failures) {
					t.Fatal("unexpected extra dial")
				}
				if address != net.JoinHostPort("fixture.invalid", strconv.Itoa(order[calls])) {
					t.Fatalf("unexpected candidate order: %s", address)
				}
				remaining := 3*time.Second - clock.Sub(time.Unix(0, 0))
				if limit != min(1500*time.Millisecond, remaining) || limit <= 0 {
					t.Fatalf("unbounded dial timeout: %s", limit)
				}
				duration := tc.durations[calls]
				clock = clock.Add(min(duration, limit))
				failure := tc.failures[calls]
				calls++
				if failure != nil {
					return nil, failure
				}
				return recoveryCloseConn{close: func() { closes++ }}, nil
			}, func() time.Time { return clock }, func(d time.Duration) { clock = clock.Add(d) })
			if got.Attempts != tc.attempts || got.Stop != tc.stop || len(got.Opened) != tc.opened || len(got.Refused) != tc.refused || got.Elapsed != tc.elapsed || closes != tc.opened || calls != tc.attempts {
				t.Fatalf("unexpected evaluation: %+v closes=%d calls=%d", got, closes, calls)
			}
			if !reflect.DeepEqual(beforeIssues, diag.Issues) || !reflect.DeepEqual(beforeResults, results) {
				t.Fatal("experiment mutated original evidence/results")
			}
		})
	}
}

type recoveryCloseConn struct {
	net.Conn
	close func()
}

func (c recoveryCloseConn) Close() error { c.close(); return nil }

func TestSelectiveRecoveryExclusions(t *testing.T) {
	for _, tc := range []struct {
		name string
		diag ConnectDiagnostics
	}{
		{"broad Linux silence", ConnectDiagnostics{FilteredPorts: 65524, UnresolvedPorts: 65524}},
		{"just above candidate boundary", ConnectDiagnostics{FilteredPorts: 33, UnresolvedPorts: 33}},
		{"duplicate", recoveryTimeoutFixture(1, 1)},
		{"invalid port", recoveryTimeoutFixture(0)},
		{"already open", recoveryTimeoutFixture(22)},
		{"counter mismatch", ConnectDiagnostics{FilteredPorts: 1, UnresolvedPorts: 1}},
		{"non-timeout and recovered", ConnectDiagnostics{Issues: []ConnectionIssue{{Port: 80, Kind: "timeout", Recovered: true}, {Port: 81, Kind: "reset"}, {Port: 82, Kind: "permission"}}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := evaluateSelectiveRecovery("fixture.invalid", []ScanResult{{Port: 22, IsOpen: true}}, tc.diag, func(string, time.Duration) (net.Conn, error) {
				t.Fatal("excluded evidence generated a dial")
				return nil, nil
			}, func() time.Time { return time.Unix(0, 0) }, func(time.Duration) { t.Fatal("excluded evidence slept") })
			if got.Attempts != 0 || got.Elapsed != 0 {
				t.Fatalf("unexpected exclusion: %+v", got)
			}
		})
	}
}

func TestSelectiveRecoveryDoesNotDialAfterOversleep(t *testing.T) {
	clock := time.Unix(0, 0)
	calls, closes := 0, 0
	got := evaluateSelectiveRecovery("fixture.invalid", nil, recoveryTimeoutFixture(1, 2), func(string, time.Duration) (net.Conn, error) {
		calls++
		return recoveryCloseConn{close: func() { closes++ }}, nil
	}, func() time.Time { return clock }, func(time.Duration) { clock = clock.Add(4 * time.Second) })
	if calls != 1 || closes != 1 || len(got.Opened) != 1 || got.Stop != "time budget" {
		t.Fatalf("expired scheduling window allowed another dial: %+v", got)
	}
}
