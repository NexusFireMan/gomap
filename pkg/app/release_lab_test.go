package app

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/NexusFireMan/gomap/v2/pkg/output"
	"github.com/NexusFireMan/gomap/v2/pkg/scanner"
)

type releaseLabReport struct {
	SchemaVersion  string              `json:"schema_version"`
	PortsRequested int                 `json:"ports_requested"`
	TotalOpenPorts int                 `json:"total_open_ports"`
	DurationMS     int64               `json:"duration_ms"`
	Metrics        *output.ScanMetrics `json:"metrics"`
	Hosts          []struct {
		Host        string                     `json:"host"`
		OpenPorts   int                        `json:"open_ports"`
		Results     []scanner.ScanResult       `json:"results"`
		Diagnostics scanner.ConnectDiagnostics `json:"connect_diagnostics"`
	} `json:"hosts"`
}

func TestReleaseLabRegression(t *testing.T) {
	if os.Getenv("GOMAP_RUN_RELEASE_LAB_TESTS") != "1" {
		t.Skip("set GOMAP_RUN_RELEASE_LAB_TESTS=1 for authorized Metasploitable fixtures")
	}
	t.Logf("source_revision=%s validation_started_utc=%s", os.Getenv("GOMAP_LAB_REVISION"), time.Now().UTC().Format(time.RFC3339))
	windows, linux := os.Getenv("GOMAP_LAB_WINDOWS_IP"), os.Getenv("GOMAP_LAB_LINUX_IP")
	if windows == "" {
		windows = "10.0.11.6"
	}
	if linux == "" {
		linux = "10.0.11.9"
	}
	if windows == linux || !hostReachable(windows, "80", time.Second) || !hostReachable(linux, "22", time.Second) {
		t.Fatal("both distinct authorized lab VMs must be reachable; this gate cannot pass by skipping hosts")
	}
	targets := []string{windows, linux}
	for _, profile := range []struct {
		name, ports string
		deep        bool
	}{
		{"quick-1", "", false}, {"quick-2", "", false},
		{"deep", "21,22,80,111,135,139,445,631,1433,3306,3389,4848,5985,7676,8080,8181,8383,8686,9200,47001", true},
		{"full", "-", false},
	} {
		t.Run(profile.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "scan.json")
			req := ScanRequest{Target: strings.Join(targets, ","), PortsFlag: profile.ports, ScanType: "connect", NoDiscovery: true,
				Build:         output.BuildInfo{Version: "unreleased-validation", Commit: os.Getenv("GOMAP_LAB_REVISION")},
				ServiceDetect: true, DeepVersion: profile.deep, Format: "json", OutputPath: path,
				Workers: 32, Rate: 500, GlobalRate: 1000, TimeoutMS: 750, AdaptiveTimeout: false}
			if profile.ports == "-" {
				req.Workers, req.TimeoutMS = 128, 150
			}
			t.Logf("profile=%s workers=%d rate_per_host=%d global_rate=%d timeout_ms=%d retries=%d adaptive=%t", profile.name, req.Workers, req.Rate, req.GlobalRate, req.TimeoutMS, req.Retries, req.AdaptiveTimeout)
			if err := ExecuteScan(req); err != nil {
				t.Fatal(err)
			}
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			var report releaseLabReport
			if err := json.Unmarshal(data, &report); err != nil {
				t.Fatal(err)
			}
			if report.SchemaVersion == "" || report.Metrics == nil || len(report.Hosts) != 2 || report.PortsRequested == 0 {
				t.Fatal("missing report schema, metrics or hosts")
			}
			if profile.ports == "-" && report.PortsRequested != 65535 {
				t.Fatal("full range was not scanned")
			}
			all := make(map[string][]scanner.ScanResult)
			total := 0
			for _, host := range report.Hosts {
				if host.Host != windows && host.Host != linux {
					t.Fatal("unexpected host in lab output")
				}
				if _, duplicate := all[host.Host]; duplicate {
					t.Fatal("duplicate host")
				}
				all[host.Host] = host.Results
				seen := make(map[int]bool)
				for _, result := range host.Results {
					if seen[result.Port] || result.Port < 1 || result.Port > 65535 || !result.IsOpen || result.ServiceName == "" || result.Evidence == "" {
						t.Fatal("invalid, duplicate or unidentified-without-label result")
					}
					seen[result.Port] = true
					if result.Confidence != "low" && result.Confidence != "medium" && result.Confidence != "high" {
						t.Fatal("invalid confidence")
					}
					if result.Version == "MySQL (connection rejected)" && result.Confidence != "medium" {
						t.Fatal("generic MySQL rejection overclaimed")
					}
					if strings.HasPrefix(result.Version, "IIS ") && strings.Contains(result.Version, "Windows") {
						t.Fatal("IIS version was promoted to an OS release")
					}
				}
				anchors := []int{21, 80, 445}
				if host.Host == windows {
					anchors = append(anchors, 135)
				} else {
					anchors = append(anchors, 22)
				}
				for _, port := range anchors {
					if !seen[port] {
						t.Errorf("lab baseline anchor missing on host %s port %d; check service availability and scan coverage", host.Host, port)
					}
				}
				diag := host.Diagnostics
				if host.OpenPorts != len(host.Results) || diag.AttemptedPorts != report.PortsRequested || host.OpenPorts+diag.RefusedPorts+diag.UnresolvedPorts != report.PortsRequested || diag.FilteredPorts > diag.UnresolvedPorts {
					t.Fatal("coverage counts do not reconcile")
				}
				total += host.OpenPorts
				t.Logf("host=%s requested=%d open=%d closed=%d unresolved=%d filtered=%d duration_ms=%d", host.Host, report.PortsRequested, host.OpenPorts, diag.RefusedPorts, diag.UnresolvedPorts, diag.FilteredPorts, report.DurationMS)
				if diag.UnresolvedPorts > 0 {
					t.Log("INCOMPLETE COVERAGE: a passing regression does not establish that unresolved ports are closed")
				}
			}
			if total != report.TotalOpenPorts {
				t.Fatal("global open count mismatch")
			}
			validateLabFormats(t, req.Target, targets, all)
		})
	}
}

func validateLabFormats(t *testing.T, target string, targets []string, all map[string][]scanner.ScanResult) {
	t.Helper()
	want := make(map[string][]string)
	for host, results := range all {
		for _, r := range results {
			key := fmt.Sprintf("%s:%d", host, r.Port)
			want[key] = []string{r.EffectiveState(), r.ServiceName, r.Version, r.Confidence, r.Evidence}
		}
	}
	var wire bytes.Buffer
	if err := output.PrintJSONLReport(&wire, target, targets, all); err != nil {
		t.Fatal(err)
	}
	seen := make(map[string][]string)
	decoder := json.NewDecoder(&wire)
	for {
		var row struct {
			Host string `json:"host"`
			scanner.ScanResult
		}
		if err := decoder.Decode(&row); err == io.EOF {
			break
		} else if err != nil {
			t.Fatal(err)
		}
		key := fmt.Sprintf("%s:%d", row.Host, row.Port)
		if _, duplicate := seen[key]; duplicate {
			t.Fatal("duplicate JSONL row")
		}
		seen[key] = []string{row.State, row.ServiceName, row.Version, row.Confidence, row.Evidence}
	}
	if !reflect.DeepEqual(seen, want) {
		t.Fatal("JSONL lost or changed observed metadata")
	}
	if err := output.PrintCSVReport(&wire, all, targets); err != nil {
		t.Fatal(err)
	}
	rows, err := csv.NewReader(&wire).ReadAll()
	if err != nil || len(rows) != len(want)+1 || strings.Join(rows[0], ",") != "host,port,state,service,version,hostname,tls,tls_version,tls_cipher,tls_alpn,tls_server_name,tls_issuer,latency_ms,confidence,evidence,detection_path" {
		t.Fatal("CSV header/row-count regression", err)
	}
	seen = make(map[string][]string)
	for _, row := range rows[1:] {
		port, err := strconv.Atoi(row[1])
		if err != nil {
			t.Fatal(err)
		}
		key := fmt.Sprintf("%s:%d", row[0], port)
		if _, duplicate := seen[key]; duplicate {
			t.Fatal("duplicate CSV row")
		}
		seen[key] = []string{row[2], row[3], row[4], row[13], row[14]}
	}
	if !reflect.DeepEqual(seen, want) {
		t.Fatal("CSV lost or changed observed metadata")
	}
}
