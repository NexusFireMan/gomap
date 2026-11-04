package scanner

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"reflect"
	"slices"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

func TestTimeoutRecoveryMergesEvidenceAndStreamsOnce(t *testing.T) {
	s := NewScanner("fixture.invalid", false)
	s.RecoveryBudget = NewTimeoutRecoveryBudget()
	before := recoveryTimeoutFixture(22, 81, 82, 83)
	before.RefusedPorts, before.AttemptedPorts = 2, 7
	before.Issues[0].Error, before.Issues[0].TimeoutMS = "original timeout", 200
	originalIssues := slices.Clone(before.Issues)
	original := []ScanResult{{Port: 80, IsOpen: true, ServiceName: "http", Version: "preserve", Confidence: "high", Evidence: "fixture header"}}
	streamed := []int{80} // The primary phase has already emitted this result.
	s.OnResult = func(r ScanResult) { streamed = append(streamed, r.Port) }
	var closes atomic.Int32
	results, diag := s.recoverTimeouts(context.Background(), original, before, true, func(_ context.Context, address string, timeout time.Duration) (net.Conn, error) {
		if timeout <= 0 || timeout > 1500*time.Millisecond {
			t.Fatalf("invalid timeout %s", timeout)
		}
		_, port, _ := net.SplitHostPort(address)
		switch port {
		case "22":
			return countedScanConn{closes: &closes}, nil
		case "81":
			return nil, syscall.ECONNREFUSED
		case "82":
			return nil, os.ErrDeadlineExceeded
		default:
			return nil, syscall.EHOSTUNREACH
		}
	})
	r := diag.Recovery
	if r == nil || r.Attempts != 4 || r.Opened != 1 || r.Refused != 1 || r.Stop != "completed" || closes.Load() != 1 {
		t.Fatalf("unexpected recovery: %+v", r)
	}
	if len(results) != 2 || results[0].Port != 22 || !reflect.DeepEqual(results[1], original[0]) || !reflect.DeepEqual(streamed, []int{80, 22}) {
		t.Fatalf("lost/duplicated results: %+v streamed=%v", results, streamed)
	}
	if results[0].Confidence != "low" || results[0].DetectionPath != "timeout-recovery" || results[0].Version != "TCP service (recovered; not fingerprinted)" {
		t.Fatalf("recovered TCP was overclaimed: %+v", results[0])
	}
	if diag.RefusedPorts != 3 || diag.UnresolvedPorts != 2 || diag.FilteredPorts != 1 || diag.RecoveredPorts != 1 || len(results)+diag.RefusedPorts+diag.UnresolvedPorts != diag.AttemptedPorts {
		t.Fatalf("coverage mismatch: %+v", diag)
	}
	if len(diag.Issues) != 3 || !diag.Issues[0].Recovered || diag.Issues[0].State != "open" || diag.Issues[2].State != "unknown" || diag.Issues[2].Kind != "unreachable" {
		t.Fatalf("final issues mismatch: %+v", diag.Issues)
	}
	if !reflect.DeepEqual(before.Issues, originalIssues) || r.Observations[0].Before.Error != "original timeout" || r.Observations[0].Before.TimeoutMS != 200 || r.InitialFiltered != 4 || r.InitialUnresolved != 4 {
		t.Fatal("original evidence was not preserved")
	}
	data, err := json.Marshal(diag)
	var roundTrip ConnectDiagnostics
	if err != nil || json.Unmarshal(data, &roundTrip) != nil || !reflect.DeepEqual(diag, roundTrip) {
		t.Fatalf("JSON lost recovery provenance: %s %v", data, err)
	}
	_, repeated := s.recoverTimeouts(context.Background(), results, diag, true, func(context.Context, string, time.Duration) (net.Conn, error) {
		t.Fatal("same diagnostics were verified twice")
		return nil, nil
	})
	if repeated.Recovery != r || len(streamed) != 2 {
		t.Fatal("repeated recovery changed delivery")
	}
}

func TestTimeoutRecoveryRunWideAttemptBudget(t *testing.T) {
	b := NewTimeoutRecoveryBudget()
	var closes atomic.Int32
	for host := range 2 {
		s := NewScanner("fixture.invalid", false)
		s.RecoveryBudget = b
		ports := []int{1, 2, 3, 4, 5}
		results, diag := s.recoverTimeouts(context.Background(), nil, recoveryTimeoutFixture(ports...), false, func(context.Context, string, time.Duration) (net.Conn, error) {
			return countedScanConn{closes: &closes}, nil
		})
		want := 5
		if host == 1 {
			want = 3
		}
		if len(results) != want || diag.Recovery.Attempts != want || diag.UnresolvedPorts != 5-want {
			t.Fatalf("host %d bypassed shared budget: %+v", host, diag)
		}
	}
	if closes.Load() != 8 || b.attempts != 0 || b.remaining >= 3*time.Second {
		t.Fatalf("run budget was replenished: %+v closes=%d", b, closes.Load())
	}
}

func TestTimeoutRecoveryGuardsAndCancellation(t *testing.T) {
	for _, tc := range []struct {
		name, stop string
		filtered   int
		remaining  time.Duration
		attempts   int
		ghost      bool
		cancel     bool
	}{
		{"broad silence", "broad_silence", 65524, time.Second, 8, false, false},
		{"empty", "no_timeouts", 0, time.Second, 8, false, false},
		{"run attempts", "attempt_budget", 1, time.Second, 0, false, false},
		{"run time", "time_budget", 1, 0, 8, false, false},
		{"controlled", "controlled_profile", 1, time.Second, 8, true, false},
		{"parent canceled", "canceled", 1, time.Second, 8, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := NewScanner("fixture.invalid", tc.ghost)
			s.RecoveryBudget = &TimeoutRecoveryBudget{attempts: tc.attempts, remaining: tc.remaining}
			diag := recoveryTimeoutFixture(81)
			if tc.filtered == 0 {
				diag = ConnectDiagnostics{}
			} else if tc.filtered > 32 {
				diag.FilteredPorts, diag.UnresolvedPorts = tc.filtered, tc.filtered
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if tc.cancel {
				cancel()
			}
			_, got := s.recoverTimeouts(ctx, nil, diag, false, func(context.Context, string, time.Duration) (net.Conn, error) {
				t.Fatal("excluded recovery dialed")
				return nil, nil
			})
			if got.Recovery.Stop != tc.stop || got.Recovery.Attempts != 0 {
				t.Fatalf("unexpected guard: %+v", got.Recovery)
			}
		})
	}
}

func TestTimeoutRecoveryWaitsAndDialsAreCanceled(t *testing.T) {
	for _, stage := range []string{"global lock", "per-host pace"} {
		t.Run(stage, func(t *testing.T) {
			s := NewScanner("fixture.invalid", false)
			s.RecoveryBudget = NewTimeoutRecoveryBudget()
			s.RecoveryBudget.remaining = 25 * time.Millisecond
			switch stage {
			case "global lock":
				s.AttemptLimiter = NewAttemptLimiter(1)
				s.AttemptLimiter.mu.Lock()
				defer s.AttemptLimiter.mu.Unlock()
			case "per-host pace":
				s.Rate, s.lastConnectStart = 1, time.Now().Add(time.Hour)
			}
			calls := 0
			_, diag := s.recoverTimeouts(context.Background(), nil, recoveryTimeoutFixture(81, 82), false, func(ctx context.Context, _ string, limit time.Duration) (net.Conn, error) {
				calls++
				if limit > 25*time.Millisecond {
					t.Fatal("dial ignored remaining run budget")
				}
				<-ctx.Done()
				return nil, ctx.Err()
			})
			if calls != 0 {
				t.Fatal("waiting for a permit consumed a dial")
			}
			if s.RecoveryBudget.remaining != 0 || diag.Recovery.Stop != "time_budget" {
				t.Fatalf("deadline did not stop recovery: %+v", diag.Recovery)
			}
		})
	}
}

func TestTimeoutRecoveryDialCancellationAndTimeoutClip(t *testing.T) {
	s := NewScanner("fixture.invalid", false)
	s.RecoveryBudget = NewTimeoutRecoveryBudget()
	s.RecoveryBudget.remaining = time.Second
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	calls := 0
	_, diag := s.recoverTimeouts(ctx, nil, recoveryTimeoutFixture(81, 82), false, func(dialContext context.Context, _ string, limit time.Duration) (net.Conn, error) {
		calls++
		if limit <= 0 || limit > time.Second {
			t.Fatalf("dial ignored remaining run budget: %s", limit)
		}
		cancel()
		<-dialContext.Done()
		return nil, dialContext.Err()
	})
	if calls != 1 || diag.UnresolvedPorts != 2 || diag.FilteredPorts != 1 || diag.RefusedPorts != 0 || diag.Recovery.Opened != 0 || diag.Recovery.Stop != "canceled" {
		t.Fatalf("canceled dial was promoted or retried: %+v", diag)
	}
}

func TestTimeoutRecoveryNativeDialUsesSourceBinding(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	s := NewScanner("127.0.0.1", false)
	s.SourceIPs = []net.IP{net.ParseIP("127.0.0.1")}
	s.RecoveryBudget = NewTimeoutRecoveryBudget()
	port := listener.Addr().(*net.TCPAddr).Port
	results, diag := s.recoverTimeouts(context.Background(), nil, recoveryTimeoutFixture(port), true, s.recoveryDial)
	if len(results) != 1 || diag.Recovery.Opened != 1 {
		t.Fatalf("native recovery failed: %+v", diag)
	}
	conn, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	if conn.RemoteAddr().(*net.TCPAddr).IP.String() != "127.0.0.1" {
		t.Fatal("source address contract changed")
	}
	if err := conn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatalf("recovered socket left open: %v", err)
	}
}

func TestTimeoutRecoveryPacesFromActualGlobalGrant(t *testing.T) {
	s := NewScanner("fixture.invalid", false)
	s.RecoveryBudget = NewTimeoutRecoveryBudget()
	s.Rate = 10
	s.AttemptLimiter = NewAttemptLimiter(100)
	s.AttemptLimiter.next = time.Now().Add(20 * time.Millisecond)
	var starts []time.Time
	_, diag := s.recoverTimeouts(context.Background(), nil, recoveryTimeoutFixture(81, 82), false, func(context.Context, string, time.Duration) (net.Conn, error) {
		s.adaptiveMu.Lock()
		starts = append(starts, s.lastConnectStart)
		s.adaptiveMu.Unlock()
		return nil, syscall.ECONNREFUSED
	})
	if diag.Recovery.Attempts != 2 || len(starts) != 2 || starts[1].Sub(starts[0]) < 100*time.Millisecond {
		t.Fatalf("global wait caused a per-host burst: %v %+v", starts, diag.Recovery)
	}
}

func TestTimeoutRecoveryRejectsInvalidCandidates(t *testing.T) {
	for _, diag := range []ConnectDiagnostics{
		recoveryTimeoutFixture(0), recoveryTimeoutFixture(81, 81), recoveryTimeoutFixture(22),
		{FilteredPorts: 1, UnresolvedPorts: 1},
	} {
		s := NewScanner("fixture.invalid", false)
		s.RecoveryBudget = NewTimeoutRecoveryBudget()
		_, got := s.recoverTimeouts(context.Background(), []ScanResult{{Port: 22, IsOpen: true}}, diag, false, func(context.Context, string, time.Duration) (net.Conn, error) {
			t.Fatal("invalid candidates dialed")
			return nil, nil
		})
		if got.Recovery.Stop != "invalid_diagnostics" || got.Recovery.Attempts != 0 {
			t.Fatalf("invalid input accepted: %+v", got.Recovery)
		}
	}
}

func TestTimeoutRecoveryAccepts32ButNever33Candidates(t *testing.T) {
	for _, size := range []int{32, 33} {
		s := NewScanner("fixture.invalid", false)
		s.RecoveryBudget = NewTimeoutRecoveryBudget()
		ports := make([]int, size)
		for i := range ports {
			ports[i] = i + 1
		}
		calls := 0
		_, diag := s.recoverTimeouts(context.Background(), nil, recoveryTimeoutFixture(ports...), false, func(context.Context, string, time.Duration) (net.Conn, error) {
			calls++
			return nil, syscall.ECONNREFUSED
		})
		if size == 32 && (calls != 8 || diag.RefusedPorts != 8 || diag.UnresolvedPorts != 24) {
			t.Fatalf("eligible boundary failed: %+v", diag.Recovery)
		}
		if size == 33 && (calls != 0 || diag.Recovery.Stop != "broad_silence") {
			t.Fatalf("broad guard failed: %+v", diag.Recovery)
		}
	}
}
