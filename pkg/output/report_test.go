package output

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/NexusFireMan/gomap/pkg/scanner"
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
				Evidence:      "nmap smb-os-discovery",
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

	out := buf.String()
	if !strings.Contains(out, `"schema_version": "1.0.0"`) {
		t.Fatalf("missing schema version: %s", out)
	}
	if !strings.Contains(out, `"total_open_ports": 2`) {
		t.Fatalf("missing open ports summary: %s", out)
	}
}

func TestPrintCSVReport(t *testing.T) {
	targets, results := sampleResults()
	var buf bytes.Buffer
	if err := PrintCSVReport(&buf, results, targets); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 3 {
		t.Fatalf("expected 3 csv lines, got %d", len(lines))
	}
	if !strings.Contains(lines[0], "detection_path") {
		t.Fatalf("missing csv header fields: %s", lines[0])
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
	if !strings.Contains(lines[0], `"state":"open"`) {
		t.Fatalf("invalid jsonl state field: %s", lines[0])
	}
}
