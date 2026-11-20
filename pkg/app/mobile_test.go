package app

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/NexusFireMan/gomap/v2/pkg/output"
	"github.com/NexusFireMan/gomap/v2/pkg/scanner"
)

func TestMobileDefaultsPreserveScopeAndOverrides(t *testing.T) {
	base := ScanRequest{Target: "127.0.0.1", PortsFlag: "-", AdaptiveTimeout: true}
	if applyMobileDefaults(base) != base {
		t.Fatal("desktop defaults changed")
	}
	base.Mobile = true
	got := applyMobileDefaults(base)
	if got.Workers != 32 || got.GlobalRate != 100 || got.TimeoutMS != 750 || got.PortsFlag != "-" || got.MaxHosts != 0 || got.ServiceDetect || !got.AdaptiveTimeout {
		t.Fatalf("unexpected defaults/scope: %+v", got)
	}
	if applyMobileDefaults(got) != got {
		t.Fatal("profile application is not idempotent")
	}
	custom := ScanRequest{Mobile: true, Workers: 80, GlobalRate: 7, Rate: 3, TimeoutMS: 1800, Retries: 2, DeepVersion: true, Exhaustive: true}
	if applyMobileDefaults(custom) != custom {
		t.Fatal("explicit settings or detection depth changed")
	}
	unlimited := applyMobileDefaults(ScanRequest{Mobile: true, GlobalRateSet: true})
	if unlimited.GlobalRate != 0 {
		t.Fatal("explicit unlimited global rate was ignored")
	}
	ghost := applyMobileDefaults(ScanRequest{Mobile: true, GhostMode: true})
	s := scanner.NewScanner("127.0.0.1", true)
	s.Configure(scanner.ScanConfig{NumWorkers: ghost.Workers, Rate: ghost.Rate, Timeout: time.Duration(ghost.TimeoutMS) * time.Millisecond})
	if ghost.TimeoutMS != 0 || s.Timeout != 2*time.Second || s.NumWorkers != 4 || s.Rate != 8 {
		t.Fatal("mobile weakened existing controlled-profile defaults")
	}
	for _, timeout := range []time.Duration{500 * time.Millisecond, 900 * time.Millisecond} {
		opts := mobileDiscoveryOptions(scanner.DiscoveryOptions{NumWorkers: 50, Timeout: timeout, Ports: []int{80, 443}})
		if opts.NumWorkers != 8 || opts.Timeout != max(timeout, 750*time.Millisecond) || len(opts.Ports) != 2 {
			t.Fatalf("discovery defaults changed scope or shortened timeouts: %+v", opts)
		}
	}
}

func TestMobileProfileReachesNativeScanAndJSON(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	file := filepath.Join(t.TempDir(), "mobile.json")
	if err := ExecuteScan(ScanRequest{Mobile: true, Target: "127.0.0.1", PortsFlag: strconv.Itoa(listener.Addr().(*net.TCPAddr).Port), Format: "json", OutputPath: file}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	var report struct {
		TotalOpen int                `json:"total_open_ports"`
		Metrics   output.ScanMetrics `json:"metrics"`
	}
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatal(err)
	}
	opts := report.Metrics.Options
	if report.TotalOpen != 1 || !opts.Mobile || opts.Workers != 32 || opts.GlobalRate != 100 || opts.TimeoutMS != 750 || len(report.Metrics.Hosts) != 1 || report.Metrics.Hosts[0].Settings.TimeoutMS != 750 {
		t.Fatalf("missing mobile runtime settings or invalid coverage: %s", data)
	}
	if strings.Contains(string(data), "global_rate_set") {
		t.Fatal("parser bookkeeping leaked into JSON")
	}
}

func TestMobileFieldOmittedForDesktop(t *testing.T) {
	data, err := json.Marshal(newScanMetrics(ScanRequest{}, 0))
	if err != nil || strings.Contains(string(data), `"mobile"`) {
		t.Fatalf("default JSON metadata changed: %s %v", data, err)
	}
}
