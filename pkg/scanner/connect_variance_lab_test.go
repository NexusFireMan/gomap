package scanner

import (
	"os"
	"reflect"
	"testing"
	"time"
)

func TestConnectVarianceLab(t *testing.T) {
	if os.Getenv("GOMAP_RUN_CONNECT_VARIANCE_TESTS") != "1" {
		t.Skip("set GOMAP_RUN_CONNECT_VARIANCE_TESTS=1 for authorized lab hosts")
	}
	ports, err := NewPortManager().GetPortsToScan(os.Getenv("GOMAP_LAB_PORTS"))
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("revision=%s requested=%d timeout_ms=150 retries=0 adaptive=false service_detection=false rate_per_host=500 global_rate=500", os.Getenv("GOMAP_LAB_REVISION"), len(ports))
	for _, fixture := range []struct {
		env, fallback string
		anchors       []int
	}{
		{"GOMAP_LAB_WINDOWS_IP", "10.0.11.6", []int{21, 80, 135, 445}},
		{"GOMAP_LAB_LINUX_IP", "10.0.11.9", []int{21, 22, 80, 445}},
	} {
		host := os.Getenv(fixture.env)
		if host == "" {
			host = fixture.fallback
		}
		var baseline []int
		for _, workers := range []int{32, 128} {
			var durations []time.Duration
			for run := 1; run <= 3; run++ {
				s := NewScanner(host, false)
				s.Configure(ScanConfig{NumWorkers: workers, Rate: 500, AttemptLimiter: NewAttemptLimiter(500), Timeout: 150 * time.Millisecond})
				start := time.Now()
				results, diag := s.ScanWithDiagnostics(ports, false)
				duration := time.Since(start)
				durations = append(durations, duration)
				observed := make([]int, 0, len(results))
				seen := make(map[int]bool)
				for _, r := range results {
					if !r.IsOpen || seen[r.Port] {
						t.Fatalf("host=%s invalid/duplicate open result", host)
					}
					seen[r.Port] = true
					observed = append(observed, r.Port)
				}
				for _, anchor := range fixture.anchors {
					if !seen[anchor] {
						t.Errorf("host=%s workers=%d run=%d missing baseline port %d; check VM readiness", host, workers, run, anchor)
					}
				}
				if diag.AttemptedPorts != len(ports) || len(results)+diag.RefusedPorts+diag.UnresolvedPorts != len(ports) || diag.FilteredPorts > diag.UnresolvedPorts {
					t.Fatal("coverage accounting mismatch")
				}
				if baseline == nil {
					baseline = observed
				} else if !reflect.DeepEqual(baseline, observed) {
					t.Errorf("host=%s workers=%d run=%d open set changed: baseline=%v observed=%v; do not discard this run", host, workers, run, baseline, observed)
				}
				t.Logf("host=%s workers=%d run=%d requested=%d open=%d closed=%d timeout_inferred=%d other_unresolved=%d duration_ms=%d scope_ports_s=%.2f confirmed_ports_s=%.2f", host, workers, run, len(ports), len(results), diag.RefusedPorts, diag.FilteredPorts, diag.UnresolvedPorts-diag.FilteredPorts, duration.Milliseconds(), float64(len(ports))/duration.Seconds(), float64(len(results)+diag.RefusedPorts)/duration.Seconds())
			}
			minDuration, maxDuration, sum := durations[0], durations[0], time.Duration(0)
			for _, duration := range durations {
				minDuration, maxDuration = min(minDuration, duration), max(maxDuration, duration)
				sum += duration
			}
			t.Logf("host=%s workers=%d samples=%d min_ms=%d max_ms=%d mean_ms=%d spread_ms=%d", host, workers, len(durations), minDuration.Milliseconds(), maxDuration.Milliseconds(), (sum / time.Duration(len(durations))).Milliseconds(), (maxDuration - minDuration).Milliseconds())
		}
	}
}
