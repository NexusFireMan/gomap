package app

import (
	"strings"
	"testing"

	"github.com/NexusFireMan/gomap/v2/pkg/scanner"
)

func TestInconclusiveConnectSummary(t *testing.T) {
	diag := map[string]scanner.ConnectDiagnostics{"fixture": {
		UnresolvedPorts: 2,
		Issues: []scanner.ConnectionIssue{
			{Port: 21, Kind: "timeout", Error: "must not be printed"},
			{Port: 80, Kind: "local_resource"},
			{Port: 22, Kind: "timeout", Recovered: true},
		},
	}}
	warning := connectWarnings([]string{"fixture"}, diag)
	if !strings.Contains(warning, "2 unresolved ports (local_resource=1, timeout=1)") || strings.Contains(warning, "must not") {
		t.Fatalf("warning=%q", warning)
	}
	summary := hostSummaries([]string{"fixture"}, nil, diag)
	if !strings.Contains(summary, "exposure: indeterminate") {
		t.Fatalf("summary=%q", summary)
	}
	if warning := connectWarnings([]string{"fixture"}, nil); warning != "" {
		t.Fatal(warning)
	}
}
