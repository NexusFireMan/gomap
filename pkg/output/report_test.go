package output

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"io"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/NexusFireMan/gomap/v2/pkg/scanner"
)

func sampleResults() ([]string, map[string][]scanner.ScanResult) {
	targets := []string{"10.0.11.6"}
	results := map[string][]scanner.ScanResult{
		"10.0.11.6": {
			{
				Port:          80,
				IsOpen:        true,
				ServiceName:   "http",
				Version:       "IIS 7.5",
				TLS:           true,
				TLSVersion:    "TLS1.2",
				TLSCipher:     "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
				TLSALPN:       "http/1.1",
				TLSServerName: "10.0.11.6",
				TLSIssuer:     "Test CA",
				LatencyMs:     2,
				Confidence:    "high",
				Evidence:      "protocol banner",
				DetectionPath: "banner-parser",
			},
			{
				Port:          445,
				IsOpen:        true,
				ServiceName:   "microsoft-ds",
				Version:       "Windows Server 2008 R2",
				LatencyMs:     3,
				Confidence:    "high",
				Evidence:      "raw smb negotiate",
				DetectionPath: "smb-specialized",
			},
		},
	}
	return targets, results
}

func TestPrintJSONReport(t *testing.T) {
	targets, results := sampleResults()
	var buf bytes.Buffer
	if err := PrintJSONReport(&buf, "10.0.11.6", []int{80, 445}, targets, results, true, 150*time.Millisecond); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var report scanReport
	if err := json.Unmarshal(buf.Bytes(), &report); err != nil {
		t.Fatalf("invalid json report: %v\n%s", err, buf.String())
	}
	if report.SchemaVersion != "1.0.0" {
		t.Fatalf("unexpected schema version: %q", report.SchemaVersion)
	}
	if _, err := time.Parse(time.RFC3339, report.GeneratedAt); err != nil {
		t.Fatalf("generated_at is not RFC3339: %q", report.GeneratedAt)
	}
	if report.Target != "10.0.11.6" {
		t.Fatalf("unexpected target: %q", report.Target)
	}
	if !report.ServiceScan {
		t.Fatal("expected service_scan to be true")
	}
	if report.HostsScanned != 1 || report.PortsRequested != 2 || report.TotalOpenPorts != 2 || report.DurationMs != 150 {
		t.Fatalf("unexpected report counters: %+v", report)
	}
	if len(report.Hosts) != 1 {
		t.Fatalf("expected one host, got %d", len(report.Hosts))
	}
	host := report.Hosts[0]
	if host.Host != "10.0.11.6" || host.OpenPorts != 2 || len(host.Results) != 2 {
		t.Fatalf("unexpected host report: %+v", host)
	}
	first := host.Results[0]
	if first.Port != 80 || first.ServiceName != "http" || first.Version != "IIS 7.5" {
		t.Fatalf("unexpected first result: %+v", first)
	}
	if !first.TLS || first.TLSVersion != "TLS1.2" || first.TLSALPN != "http/1.1" {
		t.Fatalf("missing tls metadata in first result: %+v", first)
	}
	second := host.Results[1]
	if second.Port != 445 || second.ServiceName != "microsoft-ds" || second.Evidence != "raw smb negotiate" {
		t.Fatalf("unexpected second result: %+v", second)
	}
}

func TestPrintJSONReportEmptyResults(t *testing.T) {
	targets := []string{"10.0.11.6", "10.0.11.7"}
	results := map[string][]scanner.ScanResult{}
	var buf bytes.Buffer
	if err := PrintJSONReport(&buf, "10.0.11.0/24", []int{80, 443}, targets, results, false, 42*time.Millisecond); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var report scanReport
	if err := json.Unmarshal(buf.Bytes(), &report); err != nil {
		t.Fatalf("invalid json report: %v\n%s", err, buf.String())
	}
	if report.ServiceScan {
		t.Fatal("expected service_scan to be false")
	}
	if report.HostsScanned != 2 || report.TotalOpenPorts != 0 || report.PortsRequested != 2 || report.DurationMs != 42 {
		t.Fatalf("unexpected empty report counters: %+v", report)
	}
	if len(report.Hosts) != 2 {
		t.Fatalf("expected two host entries, got %d", len(report.Hosts))
	}
	for _, host := range report.Hosts {
		if host.OpenPorts != 0 {
			t.Fatalf("expected no open ports for host: %+v", host)
		}
		if len(host.Results) != 0 {
			t.Fatalf("expected empty results, got %d", len(host.Results))
		}
	}
}

func TestPrintCSVReport(t *testing.T) {
	targets, results := sampleResults()
	var buf bytes.Buffer
	if err := PrintCSVReport(&buf, results, targets); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	rows, err := csv.NewReader(strings.NewReader(buf.String())).ReadAll()
	if err != nil {
		t.Fatalf("invalid csv output: %v\n%s", err, buf.String())
	}
	if len(rows) != 3 {
		t.Fatalf("expected header plus 2 rows, got %d", len(rows))
	}
	wantHeader := []string{"host", "port", "state", "service", "version", "tls", "tls_version", "tls_cipher", "tls_alpn", "tls_server_name", "tls_issuer", "latency_ms", "confidence", "evidence", "detection_path"}
	if !reflect.DeepEqual(rows[0], wantHeader) {
		t.Fatalf("unexpected csv header:\n got: %#v\nwant: %#v", rows[0], wantHeader)
	}
	wantFirstRow := []string{"10.0.11.6", "80", "open", "http", "IIS 7.5", "true", "TLS1.2", "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "http/1.1", "10.0.11.6", "Test CA", "2", "high", "protocol banner", "banner-parser"}
	if !reflect.DeepEqual(rows[1], wantFirstRow) {
		t.Fatalf("unexpected first csv row:\n got: %#v\nwant: %#v", rows[1], wantFirstRow)
	}
	wantSecondRow := []string{"10.0.11.6", "445", "open", "microsoft-ds", "Windows Server 2008 R2", "false", "", "", "", "", "", "3", "high", "raw smb negotiate", "smb-specialized"}
	if !reflect.DeepEqual(rows[2], wantSecondRow) {
		t.Fatalf("unexpected second csv row:\n got: %#v\nwant: %#v", rows[2], wantSecondRow)
	}
}

func TestPrintCSVReportEmptyResults(t *testing.T) {
	targets := []string{"10.0.11.6"}
	results := map[string][]scanner.ScanResult{}
	var buf bytes.Buffer
	if err := PrintCSVReport(&buf, results, targets); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	rows, err := csv.NewReader(strings.NewReader(buf.String())).ReadAll()
	if err != nil {
		t.Fatalf("invalid csv output: %v\n%s", err, buf.String())
	}
	if len(rows) != 1 {
		t.Fatalf("expected only csv header for empty results, got %d rows", len(rows))
	}
	wantHeader := []string{"host", "port", "state", "service", "version", "tls", "tls_version", "tls_cipher", "tls_alpn", "tls_server_name", "tls_issuer", "latency_ms", "confidence", "evidence", "detection_path"}
	if !reflect.DeepEqual(rows[0], wantHeader) {
		t.Fatalf("unexpected csv header:\n got: %#v\nwant: %#v", rows[0], wantHeader)
	}
}

func TestPrintJSONLReport(t *testing.T) {
	targets, results := sampleResults()
	var buf bytes.Buffer
	if err := PrintJSONLReport(&buf, "10.0.11.6", targets, results); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 jsonl lines, got %d", len(lines))
	}
	for i, line := range lines {
		var rec jsonlRecord
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("invalid jsonl record %d: %v\n%s", i, err, line)
		}
		if rec.SchemaVersion != "1.0.0" {
			t.Fatalf("unexpected jsonl schema version on line %d: %q", i, rec.SchemaVersion)
		}
		if _, err := time.Parse(time.RFC3339, rec.GeneratedAt); err != nil {
			t.Fatalf("jsonl generated_at on line %d is not RFC3339: %q", i, rec.GeneratedAt)
		}
		if rec.Target != "10.0.11.6" || rec.Host != "10.0.11.6" || rec.State != "open" {
			t.Fatalf("unexpected jsonl routing fields on line %d: %+v", i, rec)
		}
	}

	var first jsonlRecord
	if err := json.Unmarshal([]byte(lines[0]), &first); err != nil {
		t.Fatalf("invalid first jsonl record: %v", err)
	}
	if first.Port != 80 || first.Service != "http" || first.Version != "IIS 7.5" || !first.TLS {
		t.Fatalf("unexpected first jsonl record: %+v", first)
	}
	if first.TLSVersion != "TLS1.2" || first.TLSCipher != "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256" || first.TLSALPN != "http/1.1" || first.TLSServerName != "10.0.11.6" || first.TLSIssuer != "Test CA" {
		t.Fatalf("missing tls jsonl metadata: %+v", first)
	}

	var second jsonlRecord
	if err := json.Unmarshal([]byte(lines[1]), &second); err != nil {
		t.Fatalf("invalid second jsonl record: %v", err)
	}
	if second.Port != 445 || second.Service != "microsoft-ds" || second.Version != "Windows Server 2008 R2" || second.Evidence != "raw smb negotiate" {
		t.Fatalf("unexpected second jsonl record: %+v", second)
	}
}

func TestPrintJSONLReportEmptyResults(t *testing.T) {
	targets := []string{"10.0.11.6"}
	results := map[string][]scanner.ScanResult{}
	var buf bytes.Buffer
	if err := PrintJSONLReport(&buf, "10.0.11.6", targets, results); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := buf.String(); got != "" {
		t.Fatalf("expected no jsonl records for empty results, got %q", got)
	}
	if err := json.NewDecoder(&buf).Decode(&jsonlRecord{}); err != io.EOF {
		t.Fatalf("expected empty jsonl stream to decode as EOF, got %v", err)
	}
}
