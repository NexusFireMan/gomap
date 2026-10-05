package output

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"strings"
	"testing"

	"github.com/NexusFireMan/gomap/v2/pkg/scanner"
)

func TestReportsPreserveUDPStatesAndOpenCounts(t *testing.T) {
	targets := []string{"fixture"}
	results := []scanner.ScanResult{{Port: 53, IsOpen: true, State: "open"},
		{Port: 54, State: "open|filtered"}, {Port: 55, State: "closed"}, {Port: 56, State: "unknown"}}
	all := map[string][]scanner.ScanResult{"fixture": results}
	var buf bytes.Buffer
	if err := PrintJSONReport(&buf, "fixture", []int{53, 54, 55, 56}, targets, all, false, 0); err != nil {
		t.Fatal(err)
	}
	var report scanReport
	if err := json.Unmarshal(buf.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	if report.TotalOpenPorts != 1 || report.Hosts[0].OpenPorts != 1 || len(report.Hosts[0].Results) != 4 {
		t.Fatalf("incorrect totals: %+v", report)
	}
	for i, result := range report.Hosts[0].Results {
		if result.State != results[i].State || result.IsOpen != results[i].IsOpen {
			t.Fatalf("JSON state or compatibility boolean lost: %+v", result)
		}
	}
	buf.Reset()
	if err := PrintJSONLReport(&buf, "fixture", targets, all); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 4 {
		t.Fatalf("got %d JSONL lines", len(lines))
	}
	for i, line := range lines {
		var record jsonlRecord
		if err := json.Unmarshal([]byte(line), &record); err != nil || record.State != results[i].State {
			t.Fatalf("line %d: %+v, %v", i, record, err)
		}
	}
	buf.Reset()
	if err := PrintCSVReport(&buf, all, targets); err != nil {
		t.Fatal(err)
	}
	rows, err := csv.NewReader(&buf).ReadAll()
	if err != nil || len(rows) != 5 {
		t.Fatalf("CSV rows: %v, %v", rows, err)
	}
	for i, result := range results {
		if rows[i+1][2] != result.State {
			t.Fatalf("CSV state lost: %v", rows[i+1])
		}
	}
	for _, formatter := range []*OutputFormatter{NewOutputFormatter(false, false), NewOutputFormatter(true, false), NewOutputFormatter(true, true), NewEvidenceOutputFormatter()} {
		buf.Reset()
		if err := formatter.WriteResults(&buf, results); err != nil {
			t.Fatal(err)
		}
		for _, result := range results {
			if !strings.Contains(buf.String(), result.State) {
				t.Fatalf("text state missing: %s", buf.String())
			}
		}
	}
}
