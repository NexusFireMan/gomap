package output

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
)

func mobileMetricsFixture() ScanMetrics {
	c := Coverage{Requested: 65535, Open: 1, Closed: 2, Filtered: 65529, OpenFiltered: 1, Unresolved: 1, Unreported: 1}
	c.updatePercent()
	return ScanMetrics{Build: BuildInfo{Version: "fixture"}, Options: ScanOptions{Mobile: true}, ExpandedHosts: 2,
		Timings: PhaseTimings{PreparationMS: 1, HostDiscoveryMS: 2, ScanAndServicesMS: 300, TotalMS: 303}, ScopeHostPortsPerSecond: 218450, OpenClosedHostPortsPerSecond: 10,
		Coverage: c, Hosts: []HostMetrics{{Host: "127.0.0.1", Engine: "connect", ScanAndServicesMS: 300, Coverage: c}}}
}

func TestMobileMetricsPreserveCountersAndSemantics(t *testing.T) {
	var b bytes.Buffer
	if err := WriteScanMetrics(&b, mobileMetricsFixture()); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"scope host-ports/s: 218450.00", "open/closed host-ports/s: 10.00", "preparation ms: 1", "host discovery ms: 2", "scan+services ms: 300", "before report/cleanup ms: 303", "expanded hosts: 2", "scanned hosts: 1", "requested: 65535", "open: 1", "closed (refused): 2", "filtered (timeout-inferred): 65529", "open|filtered: 1", "unresolved (other failures): 1", "unreported: 1", "inconclusive subtotal: 65532", "open/closed evidence: <0.1%", "evidence host-ports: 3/65535", "scope: scanned hosts only", "inferred from timeout", "loss or insufficient wait", "do not add subtotal again"} {
		if !strings.Contains(b.String(), want) {
			t.Fatalf("missing %q in %s", want, b.String())
		}
	}
	for _, line := range strings.Split(b.String(), "\n") {
		if len(line) > 40 {
			t.Fatalf("numeric fixture exceeds 40 columns: %q", line)
		}
	}
}

func TestMobileMetricsFallbackMixedEnginesAndPercentages(t *testing.T) {
	for _, engine := range []string{"udp", "syn", "connect (syn fallback)"} {
		m := mobileMetricsFixture()
		m.Build.Version = ""
		m.Hosts[0].Engine = engine
		var b bytes.Buffer
		if err := WriteScanMetrics(&b, m); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(b.String(), "GoMap: unknown") || !strings.Contains(b.String(), "engine: "+engine) {
			t.Fatal(b.String())
		}
		if strings.Contains(b.String(), "closed (refused)") != (engine == "connect (syn fallback)") {
			t.Fatal("engine-specific labels changed")
		}
	}
	for _, tc := range []struct {
		percent float64
		want    string
	}{{0, "0.0%"}, {0.01, "<0.1%"}, {99.99, ">99.9%"}, {100, "100.0%"}} {
		if got := coveragePercent(Coverage{OpenClosedPercent: tc.percent}); got != tc.want {
			t.Fatal(got, tc.want)
		}
	}
}

type mobileFailWriter struct{ remaining, writes int }

func (w *mobileFailWriter) Write(p []byte) (int, error) {
	w.writes++
	if w.remaining == 0 {
		return 0, io.ErrClosedPipe
	}
	w.remaining--
	return len(p), nil
}

func TestMobileMetricWriteErrorsAtEveryStage(t *testing.T) {
	m := mobileMetricsFixture()
	counter := &mobileFailWriter{remaining: 10000}
	if err := WriteScanMetrics(counter, m); err != nil {
		t.Fatal(err)
	}
	for n := 0; n < counter.writes; n++ {
		if err := WriteScanMetrics(&mobileFailWriter{remaining: n}, m); !errors.Is(err, io.ErrClosedPipe) {
			t.Fatalf("write %d lost error: %v", n, err)
		}
	}
}

func TestMobileBlockSanitizesAndPreservesLongValues(t *testing.T) {
	var b bytes.Buffer
	long := strings.Repeat("version", 100)
	if err := WriteMobileBlock(&b, "host\r\n\x1b[2J\u202e", [2]string{"evidence\x00", long}); err != nil {
		t.Fatal(err)
	}
	if strings.ContainsAny(b.String(), "\r\x1b\u202e\x00") || !strings.Contains(b.String(), long) {
		t.Fatalf("unsafe/truncated block: %q", b.String())
	}
}
