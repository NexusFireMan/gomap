package app

import (
	"strings"
	"testing"

	"github.com/NexusFireMan/gomap/v2/pkg/scanner"
)

func TestHostSummaryDoesNotTreatUncertainUDPAsExposure(t *testing.T) {
	results := map[string][]scanner.ScanResult{"fixture": {
		{Port: 53, IsOpen: true, State: "open"},
		{Port: 3306, State: "open|filtered", ServiceName: "mysql"},
		{Port: 22, State: "closed", ServiceName: "ssh"},
	}}
	summary := hostSummaries([]string{"fixture"}, results)
	for _, want := range []string{"open ports: 1", "critical: none", "exposure: indeterminate"} {
		if !strings.Contains(summary, want) {
			t.Fatalf("missing %q in %s", want, summary)
		}
	}
}
