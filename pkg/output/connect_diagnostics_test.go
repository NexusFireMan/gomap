package output

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/NexusFireMan/gomap/v2/pkg/scanner"
)

func TestJSONConnectDiagnostics(t *testing.T) {
	diag := map[string]scanner.ConnectDiagnostics{"fixture": {
		AttemptedPorts: 2, RefusedPorts: 1, UnresolvedPorts: 1,
		Issues: []scanner.ConnectionIssue{{Port: 80, Attempts: 2, Kind: "timeout", Error: "dial timeout"}},
	}}
	var b bytes.Buffer
	if err := PrintJSONReport(&b, "fixture", []int{1, 80}, []string{"fixture"}, nil, false, 0, diag); err != nil {
		t.Fatal(err)
	}
	var report scanReport
	if err := json.Unmarshal(b.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	if report.TotalOpenPorts != 0 || len(report.Hosts) != 1 {
		t.Fatalf("report=%+v", report)
	}
	got := report.Hosts[0].ConnectDiagnostics
	if got == nil || got.UnresolvedPorts != 1 || got.RefusedPorts != 1 || got.Issues[0].Attempts != 2 {
		t.Fatalf("diag=%+v", got)
	}
	b.Reset()
	if err := PrintJSONReport(&b, "fixture", nil, []string{"fixture"}, nil, false, 0); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(b.Bytes(), []byte("connect_diagnostics")) {
		t.Fatal("invented diagnostics for legacy caller")
	}
}
