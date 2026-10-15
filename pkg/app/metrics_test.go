package app

import (
	"encoding/csv"
	"encoding/json"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/NexusFireMan/gomap/v2/pkg/output"
)

func TestMetricsOptionsWhitelist(t *testing.T) {
	req := ScanRequest{
		Build:    output.BuildInfo{Version: "fixture-version", Commit: "fixture-commit"},
		ScanType: "connect", TimeoutMS: 300, Retries: 2, GlobalRate: 10,
		SourceIPs: "must-not-log-pool", SourceInterface: "must-not-log-interface", OutputPath: "must-not-log-path",
	}
	metrics := newScanMetrics(req, 12)
	if metrics.Build != req.Build || metrics.ExpandedHosts != 12 || metrics.Options.TimeoutMS != 300 || metrics.Options.Retries != 2 || metrics.Options.GlobalRate != 10 {
		t.Fatalf("lost reproducibility context: %+v", metrics)
	}
	data, err := json.Marshal(metrics)
	if err != nil || strings.Contains(string(data), "must-not-log") {
		t.Fatalf("unsafe metadata: %s, %v", data, err)
	}
	if metrics := newScanMetrics(ScanRequest{}, 0); metrics.Build.Version != "unknown" || metrics.Hosts == nil {
		t.Fatalf("missing build/empty scope semantics: %+v", metrics)
	}
}

func TestExecuteScanJSONIncludesMetrics(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	port := listener.Addr().(*net.TCPAddr).Port
	path := filepath.Join(t.TempDir(), "report.json")
	req := ScanRequest{
		Target: "127.0.0.1", PortsFlag: strconv.Itoa(port), Format: "json", OutputPath: path,
		Build: output.BuildInfo{Version: "fixture"}, TimeoutMS: 300, Workers: 1,
		HostConfig: hostConfigFixture(t, `{"127.0.0.1":{"timeout_ms":200,"max_timeout_ms":800,"retries":1,"adaptive_timeout":false}}`),
	}
	if err := ExecuteScan(req); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var report struct {
		TotalOpenPorts int                `json:"total_open_ports"`
		Metrics        output.ScanMetrics `json:"metrics"`
	}
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatal(err)
	}
	m := report.Metrics
	if report.TotalOpenPorts != 1 || m.Build.Version != "fixture" || m.Coverage.Requested != 1 || m.Coverage.Open != 1 || m.Coverage.OpenClosedPercent != 100 || m.Coverage.Inconclusive() != 0 {
		t.Fatalf("bad integrated counters: %+v", report)
	}
	if len(m.Hosts) != 1 || m.Hosts[0].Engine != "connect" || m.Options.Ports != req.PortsFlag || m.Options.TimeoutMS != 300 || m.ExpandedHosts != 1 {
		t.Fatalf("missing host/config context: %+v", m)
	}
	settings := m.Hosts[0].Settings
	if settings == nil || settings.TimeoutMS != 200 || settings.MaxTimeoutMS != 800 || settings.Retries != 1 || settings.AdaptiveTimeout {
		t.Fatalf("per-host settings not applied/reported: %+v", settings)
	}
}

func TestMachineRowsKeepMetricsOnStderr(t *testing.T) {
	for _, format := range []string{"jsonl", "csv"} {
		t.Run(format, func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = listener.Close() })
			reader, writer, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			oldStderr := os.Stderr
			os.Stderr = writer
			t.Cleanup(func() {
				os.Stderr = oldStderr
				_ = writer.Close()
				_ = reader.Close()
			})
			path := filepath.Join(t.TempDir(), "report."+format)
			port := listener.Addr().(*net.TCPAddr).Port
			err = ExecuteScan(ScanRequest{Target: "127.0.0.1", PortsFlag: strconv.Itoa(port), Format: format, OutputPath: path, Workers: 1})
			if closeErr := writer.Close(); err != nil || closeErr != nil {
				t.Fatalf("scan/write failed: %v, %v", err, closeErr)
			}
			os.Stderr = oldStderr
			stderr, err := io.ReadAll(reader)
			if err != nil || !strings.Contains(string(stderr), "Performance") || !strings.Contains(string(stderr), "Coverage") {
				t.Fatalf("missing stderr summary: %s, %v", stderr, err)
			}
			data, err := os.ReadFile(path)
			if err != nil || strings.Contains(string(data), "Performance") || strings.Contains(string(data), "Coverage") {
				t.Fatalf("metrics contaminated result rows: %s, %v", data, err)
			}
			if format == "jsonl" {
				var record map[string]any
				if err := json.Unmarshal(data, &record); err != nil || record["state"] != "open" {
					t.Fatalf("expected exactly one JSONL result: %s, %v", data, err)
				}
			} else {
				rows, err := csv.NewReader(strings.NewReader(string(data))).ReadAll()
				if err != nil || len(rows) != 2 || len(rows[0]) != 16 || rows[1][2] != "open" {
					t.Fatalf("CSV shape changed: %s, %v", data, err)
				}
			}
		})
	}
}
