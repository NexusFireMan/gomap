package scanner

import (
	"encoding/json"
	"net"
	"os"
	"testing"
	"time"
)

func TestSelectiveRecoveryCurrentLab(t *testing.T) {
	if os.Getenv("GOMAP_RUN_RECOVERY_LAB_TESTS") != "1" {
		t.Skip("set GOMAP_RUN_RECOVERY_LAB_TESTS=1 with an explicitly authorized host")
	}
	host := os.Getenv("GOMAP_RECOVERY_HOST")
	if net.ParseIP(host) == nil {
		t.Fatal("GOMAP_RECOVERY_HOST must be an authorized literal IP")
	}
	s := NewScanner(host, false)
	s.Configure(ScanConfig{NumWorkers: 4, Rate: 10, AttemptLimiter: NewAttemptLimiter(10), Timeout: 200 * time.Millisecond})
	ports := []int{21, 22, 80, 81, 135, 443, 445, 631, 3000, 3306, 3389, 3820, 3920, 8080, 8181}
	start := time.Now()
	results, diag := s.ScanWithDiagnostics(ports, false)
	baselineDuration := time.Since(start)
	if len(results) == 0 || len(results)+diag.RefusedPorts+diag.UnresolvedPorts != len(ports) {
		t.Fatal("host must expose baseline TCP ports and have consistent accounting; do not skip unavailable fixtures")
	}
	got := evaluateSelectiveRecovery(host, results, diag, recoveryLabDial, time.Now, time.Sleep)
	t.Logf("scope=%d baseline_open=%d baseline_refused=%d baseline_unresolved=%d baseline_ms=%d", len(ports), len(results), diag.RefusedPorts, diag.UnresolvedPorts, baselineDuration.Milliseconds())
	t.Logf("extra_attempts=%d newly_observed_open=%d newly_observed_refused=%d remaining_uncertainty=%d recovery_ms=%d total_ms=%d stop=%s", got.Attempts, len(got.Opened), len(got.Refused), diag.UnresolvedPorts-len(got.Opened)-len(got.Refused), got.Elapsed.Milliseconds(), time.Since(start).Milliseconds(), got.Stop)
	if got.Attempts > 8 || len(got.Opened)+len(got.Refused) > got.Attempts || got.Stop == "invalid diagnostics" {
		t.Fatalf("invalid current-scope evaluation: %+v", got)
	}
}

func TestSelectiveRecoveryHistoricalLab(t *testing.T) {
	if os.Getenv("GOMAP_RUN_RECOVERY_LAB_TESTS") != "1" {
		t.Skip("set GOMAP_RUN_RECOVERY_LAB_TESTS=1 with a private historical report and explicitly authorized host")
	}
	host, input := os.Getenv("GOMAP_RECOVERY_HOST"), os.Getenv("GOMAP_RECOVERY_INPUT")
	if net.ParseIP(host) == nil || input == "" {
		t.Fatal("GOMAP_RECOVERY_HOST must be an authorized literal IP; GOMAP_RECOVERY_INPUT is required")
	}
	data, err := os.ReadFile(input)
	if err != nil {
		t.Fatal(err)
	}
	var report struct {
		Generated string `json:"generated_at"`
		Hosts     []struct {
			Host    string             `json:"host"`
			Results []ScanResult       `json:"results"`
			Diag    ConnectDiagnostics `json:"connect_diagnostics"`
		} `json:"hosts"`
	}
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatal(err)
	}
	if len(report.Hosts) != 1 || report.Hosts[0].Host != host || report.Generated == "" {
		t.Fatal("private report must contain exactly the explicitly authorized host and its original timestamp")
	}
	h := report.Hosts[0]
	if len(h.Results)+h.Diag.RefusedPorts+h.Diag.UnresolvedPorts != h.Diag.AttemptedPorts {
		t.Fatal("historical report accounting mismatch")
	}
	got := evaluateSelectiveRecovery(host, h.Results, h.Diag, recoveryLabDial, time.Now, time.Sleep)
	t.Logf("historical_generated=%s baseline_open=%d baseline_refused=%d baseline_unresolved=%d baseline_timeouts=%d", report.Generated, len(h.Results), h.Diag.RefusedPorts, h.Diag.UnresolvedPorts, h.Diag.FilteredPorts)
	t.Logf("extra_attempts=%d newly_observed_open=%d newly_observed_refused=%d remaining_historical_uncertainty=%d elapsed_ms=%d stop=%s", got.Attempts, len(got.Opened), len(got.Refused), h.Diag.UnresolvedPorts-len(got.Opened)-len(got.Refused), got.Elapsed.Milliseconds(), got.Stop)
	t.Log("Historical replay, not a simultaneous A/B comparison or a refreshed full-host inventory; original evidence is unchanged. No service probes, retries, CLI integration or shared production-limiter integration.")
	if got.Attempts > 8 || len(got.Opened)+len(got.Refused) > got.Attempts || (h.Diag.FilteredPorts > 32 && got.Attempts != 0) || got.Stop == "invalid diagnostics" {
		t.Fatalf("invalid recovery evaluation: %+v", got)
	}
}

func recoveryLabDial(address string, timeout time.Duration) (net.Conn, error) {
	return net.DialTimeout("tcp", address, timeout)
}
