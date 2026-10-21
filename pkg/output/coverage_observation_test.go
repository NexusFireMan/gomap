package output

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/NexusFireMan/gomap/v2/pkg/scanner"
)

func TestFullRangeCoverageLabelsObservedStates(t *testing.T) {
	ports := make([]int, 65535)
	for i := range ports {
		ports[i] = i + 1
	}
	coverage := SummarizeCoverage(ports, []scanner.ScanResult{{Port: 22, IsOpen: true}}, &scanner.ConnectDiagnostics{
		AttemptedPorts: 65535, UnresolvedPorts: 65534, FilteredPorts: 65533,
	})
	if coverage.Closed != 0 || coverage.Filtered != 65533 || coverage.Unresolved != 1 || coverage.Inconclusive() != 65534 || coverage.OpenClosedPercent <= 0 {
		t.Fatalf("observations reinterpreted as invented closed ports: %+v", coverage)
	}
	metrics := ScanMetrics{Coverage: coverage, Hosts: []HostMetrics{{Host: "fixture.invalid", Engine: "connect", Coverage: coverage}}}
	var buf bytes.Buffer
	if err := WriteScanMetrics(&buf, metrics); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"closed (refused): 0", "filtered (timeout-inferred): 65533", "unresolved (other failures): 1",
		"inconclusive subtotal: 65534", "open/closed evidence: <0.1% (1/65535)", "no refusal was observed", "not a confirmed firewall drop",
	} {
		if !strings.Contains(buf.String(), want) {
			t.Fatalf("missing %q: %s", want, buf.String())
		}
	}
	if strings.Contains(buf.String(), "evidence: 0.0%") || strings.Count(buf.String(), "CONNECT observations:") != 1 {
		t.Fatal("positive coverage rounded to zero or explanatory note duplicated")
	}
	data, err := json.Marshal(coverage)
	if err != nil {
		t.Fatal(err)
	}
	var unchanged Coverage
	if err := json.Unmarshal(data, &unchanged); err != nil || unchanged != coverage {
		t.Fatal("text explanation changed structured numeric coverage", err)
	}
}

func TestCoveragePercentageKeepsTinyPositiveEvidence(t *testing.T) {
	for _, tc := range []struct {
		requested, confirmed int
		want                 string
	}{
		{65535, 0, "0.0% (0/65535)"}, {65535, 1, "<0.1% (1/65535)"},
		{2000000000, 1, "<0.1% (1/2000000000)"}, {1000, 1, "0.1% (1/1000)"},
		{2, 1, "50.0% (1/2)"}, {1, 1, "100.0% (1/1)"}, {0, 0, "0.0% (0/0)"},
		{65535, 65534, ">99.9% (65534/65535)"}, {1000, 999, "99.9% (999/1000)"},
	} {
		c := Coverage{Requested: tc.requested, Open: tc.confirmed}
		c.updatePercent()
		var buf bytes.Buffer
		if err := WriteScanMetrics(&buf, ScanMetrics{Coverage: c}); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(buf.String(), "open/closed evidence: "+tc.want) {
			t.Fatalf("got %s, want %s", buf.String(), tc.want)
		}
	}
}

func TestCoverageEngineSpecificLabelsAndNoteFailures(t *testing.T) {
	for _, engine := range []string{"connect", "connect (syn fallback)", "syn", "udp"} {
		var buf bytes.Buffer
		coverage := Coverage{Requested: 1, Filtered: 1}
		metrics := ScanMetrics{Coverage: coverage, Hosts: []HostMetrics{{Host: "fixture", Engine: engine, Coverage: coverage}}}
		if err := WriteScanMetrics(&buf, metrics); err != nil {
			t.Fatal(err)
		}
		isConnect := strings.HasPrefix(engine, "connect")
		if strings.Contains(buf.String(), "timeout-inferred") != isConnect || strings.Contains(buf.String(), "CONNECT observations:") != isConnect {
			t.Fatalf("borrowed error semantics across engines: %s", buf.String())
		}
	}
	coverage := Coverage{Requested: 1, Filtered: 1}
	metrics := ScanMetrics{Coverage: coverage, Hosts: []HostMetrics{{Host: "fixture", Engine: "connect", Coverage: coverage}, {Host: "fixture2", Engine: "udp"}}}
	var buf bytes.Buffer
	if err := WriteScanMetrics(&buf, metrics); err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(buf.String(), "\n") {
		if strings.HasPrefix(line, "- total") && strings.Contains(line, "timeout-inferred") {
			t.Fatal("mixed-engine total asserted CONNECT-only semantics")
		}
	}
	if err := WriteScanMetrics(coverageNoteFailureWriter{}, metrics); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatal("coverage note write failure discarded", err)
	}
}

func TestConfirmedConnectCoverageNeedsNoUncertaintyNote(t *testing.T) {
	coverage := Coverage{Requested: 3, Open: 2, Closed: 1, OpenClosedPercent: 100}
	metrics := ScanMetrics{Coverage: coverage, Hosts: []HostMetrics{{Host: "fixture", Engine: "connect", Coverage: coverage}}}
	var buf bytes.Buffer
	if err := WriteScanMetrics(&buf, metrics); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(buf.String(), "CONNECT observations:") || !strings.Contains(buf.String(), "closed (refused): 1") || !strings.Contains(buf.String(), "100.0% (3/3)") {
		t.Fatal("complete CONNECT coverage gained uncertainty or lost a confirmed refusal")
	}
}

type coverageNoteFailureWriter struct{}

func (coverageNoteFailureWriter) Write(p []byte) (int, error) {
	if bytes.HasPrefix(p, []byte("CONNECT observations:")) {
		return 0, io.ErrClosedPipe
	}
	return len(p), nil
}
