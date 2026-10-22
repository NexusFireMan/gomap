package output

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/NexusFireMan/gomap/v2/pkg/scanner"
)

func TestCoveragePreservesUncertainty(t *testing.T) {
	for _, tc := range []struct {
		name    string
		ports   []int
		results []scanner.ScanResult
		diag    *scanner.ConnectDiagnostics
		want    Coverage
	}{
		{"CONNECT", []int{1, 2, 3, 4, 5}, []scanner.ScanResult{{Port: 1, IsOpen: true}},
			&scanner.ConnectDiagnostics{AttemptedPorts: 5, RefusedPorts: 2, UnresolvedPorts: 1, RecoveredPorts: 1},
			Coverage{Requested: 5, Open: 1, Closed: 2, Unresolved: 1, Unreported: 1, OpenClosedPercent: 60}},
		{"UDP", []int{1, 2, 3, 4, 5, 6}, []scanner.ScanResult{
			{Port: 1, State: "open"}, {Port: 2, State: "closed"}, {Port: 3, State: "filtered"},
			{Port: 4, State: "open|filtered"}, {Port: 5, State: "unknown"}}, nil,
			Coverage{Requested: 6, Open: 1, Closed: 1, Filtered: 1, OpenFiltered: 1, Unresolved: 1, Unreported: 1, OpenClosedPercent: 100.0 / 3}},
		{"CONNECT filtered subset", []int{1, 2, 3, 4, 5}, []scanner.ScanResult{{Port: 1, IsOpen: true}},
			&scanner.ConnectDiagnostics{RefusedPorts: 1, UnresolvedPorts: 3, FilteredPorts: 2},
			Coverage{Requested: 5, Open: 1, Closed: 1, Filtered: 2, Unresolved: 1, OpenClosedPercent: 40}},
		{"bounded filtered subset", []int{1, 2}, nil,
			&scanner.ConnectDiagnostics{UnresolvedPorts: 1, FilteredPorts: 100},
			Coverage{Requested: 2, Filtered: 1, Unreported: 1}},
		{"SYN missing states", []int{1, 2}, []scanner.ScanResult{{Port: 1, IsOpen: true}}, nil,
			Coverage{Requested: 2, Open: 1, Unreported: 1, OpenClosedPercent: 50}},
		{"empty", nil, nil, nil, Coverage{}},
		{"no observations", []int{1, 2}, nil, nil, Coverage{Requested: 2, Unreported: 2}},
		{"deduplication and scope", []int{1, 1, 2}, []scanner.ScanResult{
			{Port: 1, IsOpen: true}, {Port: 1, State: "closed"}, {Port: 99, IsOpen: true}}, nil,
			Coverage{Requested: 2, Open: 1, Unreported: 1, OpenClosedPercent: 50}},
		{"bounded inconsistent diagnostics", []int{1, 2}, []scanner.ScanResult{{Port: 1, IsOpen: true}},
			&scanner.ConnectDiagnostics{RefusedPorts: 100, UnresolvedPorts: 100},
			Coverage{Requested: 2, Open: 1, Closed: 1, OpenClosedPercent: 100}},
		{"negative diagnostics", []int{1}, nil, &scanner.ConnectDiagnostics{RefusedPorts: -1, UnresolvedPorts: -2},
			Coverage{Requested: 1, Unreported: 1}},
		{"invalid port numbers", []int{-1, 0, 65536, 65535}, []scanner.ScanResult{{Port: -1, IsOpen: true}, {Port: 65536, IsOpen: true}, {Port: 65535, IsOpen: true}}, nil,
			Coverage{Requested: 1, Open: 1, OpenClosedPercent: 100}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := SummarizeCoverage(tc.ports, tc.results, tc.diag)
			if got != tc.want {
				t.Fatalf("got %+v, want %+v", got, tc.want)
			}
			if sum := got.Open + got.Closed + got.Filtered + got.OpenFiltered + got.Unresolved + got.Unreported; sum != got.Requested {
				t.Fatalf("outcomes do not partition requested scope: %+v", got)
			}
			if got.Inconclusive() != got.Filtered+got.OpenFiltered+got.Unresolved+got.Unreported {
				t.Fatal("lost inconclusive states")
			}
		})
	}
}

func TestMetricsRatesAndWeightedCoverage(t *testing.T) {
	metrics := ScanMetrics{}
	metrics.Coverage.Add(Coverage{Requested: 1, Open: 1})
	metrics.Coverage.Add(Coverage{Requested: 9, Unresolved: 9})
	metrics.SetTimings(4*time.Second, time.Second, 2*time.Second)
	if metrics.Coverage.OpenClosedPercent != 10 || metrics.ScopeHostPortsPerSecond != 5 || metrics.OpenClosedHostPortsPerSecond != 0.5 {
		t.Fatalf("misleading aggregate coverage or throughput: %+v", metrics)
	}
	if metrics.Timings != (PhaseTimings{TotalMS: 4000, PreparationMS: 1000, HostDiscoveryMS: 1000, ScanAndServicesMS: 2000}) {
		t.Fatalf("incorrect phase accounting: %+v", metrics.Timings)
	}
	for _, duration := range []time.Duration{0, -time.Second} {
		metrics.SetTimings(duration, duration, duration)
		if metrics.ScopeHostPortsPerSecond != 0 || metrics.OpenClosedHostPortsPerSecond != 0 || metrics.Timings != (PhaseTimings{}) {
			t.Fatalf("non-finite/stale metrics for zero duration: %+v", metrics)
		}
		if _, err := json.Marshal(metrics); err != nil {
			t.Fatal(err)
		}
	}
	metrics.SetTimings(time.Nanosecond, 0, time.Nanosecond)
	if math.IsInf(metrics.ScopeHostPortsPerSecond, 0) || math.IsNaN(metrics.ScopeHostPortsPerSecond) {
		t.Fatal("non-finite short-duration throughput")
	}
}

func TestJSONMetricsAreAdditive(t *testing.T) {
	metrics := ScanMetrics{Build: BuildInfo{Version: "fixture", Commit: "abc123"}, Hosts: []HostMetrics{}}
	metrics.SetTimings(time.Second, 300*time.Millisecond, 500*time.Millisecond)
	var buf bytes.Buffer
	if err := PrintJSONReportWithMetrics(&buf, "fixture.invalid", []int{80}, nil, nil, false, 500*time.Millisecond, nil, metrics); err != nil {
		t.Fatal(err)
	}
	var report scanReport
	if err := json.Unmarshal(buf.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	if report.DurationMs != 500 || report.Metrics == nil || report.Metrics.Timings.TotalMS != 1000 || report.Metrics.Build.Version != "fixture" {
		t.Fatalf("legacy duration or metadata changed: %+v", report)
	}
	if err := PrintJSONReportWithMetrics(failingWriter{}, "fixture.invalid", nil, nil, nil, false, 0, nil, metrics); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("write error lost: %v", err)
	}
}

func TestTextMetricsExposeCoverageAndSanitizeLabels(t *testing.T) {
	metrics := ScanMetrics{Hosts: []HostMetrics{{Host: "fixture\x1b[2J", Engine: "syn", Coverage: Coverage{Requested: 2, Open: 1, Unreported: 1, OpenClosedPercent: 50}}}}
	metrics.Coverage.Add(metrics.Hosts[0].Coverage)
	var buf bytes.Buffer
	if err := WriteScanMetrics(&buf, metrics); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Performance", "Coverage", "confirmed open/closed", "unreported: 1", "open/closed evidence: 50.0%", "report/cleanup"} {
		if !strings.Contains(buf.String(), want) {
			t.Fatalf("missing %q: %s", want, buf.String())
		}
	}
	if strings.Contains(buf.String(), "\x1b") {
		t.Fatal("unsafe terminal control in coverage label")
	}
	if err := WriteScanMetrics(failingWriter{}, metrics); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("write error lost: %v", err)
	}
}

func BenchmarkFullRangeCoverage(b *testing.B) {
	ports := make([]int, 65535)
	for i := range ports {
		ports[i] = i + 1
	}
	results := []scanner.ScanResult{{Port: 22, IsOpen: true}, {Port: 80, IsOpen: true}}
	diag := &scanner.ConnectDiagnostics{AttemptedPorts: len(ports), RefusedPorts: len(ports) - 3, UnresolvedPorts: 1}
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		if c := SummarizeCoverage(ports, results, diag); c.Unresolved != 1 || c.Unreported != 0 {
			b.Fatal(c)
		}
	}
}

func FuzzCoveragePartitionsRequestedScope(f *testing.F) {
	f.Add([]byte{0, 22, 1, 0, 80, 2, 0, 22, 0})
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1024 {
			return
		}
		var ports []int
		var results []scanner.ScanResult
		states := []string{"open", "closed", "filtered", "open|filtered", "unknown", "unexpected"}
		for i := 0; i+2 < len(data); i += 3 {
			port := int(binary.BigEndian.Uint16(data[i : i+2]))
			ports = append(ports, port)
			results = append(results, scanner.ScanResult{Port: port, State: states[int(data[i+2])%len(states)]})
		}
		c := SummarizeCoverage(ports, results, &scanner.ConnectDiagnostics{RefusedPorts: 20, UnresolvedPorts: 30})
		if c.Requested != c.Open+c.Closed+c.Filtered+c.OpenFiltered+c.Unresolved+c.Unreported || c.OpenClosedPercent < 0 || c.OpenClosedPercent > 100 {
			t.Fatalf("invalid coverage partition: %+v", c)
		}
	})
}
