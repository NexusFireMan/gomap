package app

import (
	"strings"
	"testing"

	"github.com/NexusFireMan/gomap/v2/pkg/scanner"
)

func TestInconclusiveConnectSummary(t *testing.T) {
	diag := map[string]scanner.ConnectDiagnostics{"fixture": {
		UnresolvedPorts: 2,
		FilteredPorts:   1,
		TimeoutMS:       750,
		Issues: []scanner.ConnectionIssue{
			{Port: 21, Kind: "timeout", Error: "must not be printed", TimeoutMS: 1250},
			{Port: 80, Kind: "local_resource"},
			{Port: 22, Kind: "timeout", Recovered: true},
		},
	}}
	warning := connectWarnings([]string{"fixture"}, diag)
	if !strings.Contains(warning, "2 unresolved ports (local_resource_ports=1, timeout_ports=1)") || strings.Contains(warning, "must not") || strings.Contains(warning, "timeout=1") {
		t.Fatalf("warning=%q", warning)
	}
	for _, field := range []string{"filtered=1", "unknown=1", "configured_timeout_ms=750", "last_attempt_timeout_ms=1250..1250"} {
		if !strings.Contains(warning, field) {
			t.Fatalf("missing %q in %q", field, warning)
		}
	}
	summary := hostSummaries([]string{"fixture"}, nil, diag)
	if !strings.Contains(summary, "exposure: indeterminate") {
		t.Fatalf("summary=%q", summary)
	}
	if warning := connectWarnings([]string{"fixture"}, nil); warning != "" {
		t.Fatal(warning)
	}
}
