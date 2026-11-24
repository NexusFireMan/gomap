package app

import (
	"bytes"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/NexusFireMan/gomap/v2/pkg/output"
	"github.com/NexusFireMan/gomap/v2/pkg/scanner"
)

func mobileReportFixture() (map[string][]scanner.ScanResult, map[string]scanner.ConnectDiagnostics, output.ScanMetrics) {
	results := map[string][]scanner.ScanResult{"fixture": {{Port: 22, IsOpen: true, ServiceName: "ssh", Version: strings.Repeat("v", 200), Evidence: "banner", Confidence: "high"}}}
	diags := map[string]scanner.ConnectDiagnostics{"fixture": {RefusedPorts: 2, UnresolvedPorts: 2, FilteredPorts: 1, TimeoutMS: 750,
		Issues:   []scanner.ConnectionIssue{{Kind: "timeout", TimeoutMS: 750}, {Kind: "local_resource", Error: "private error must not print"}, {Kind: "timeout", TimeoutMS: 2000, Recovered: true}},
		Recovery: &scanner.TimeoutRecoveryDiagnostics{Attempts: 2, Opened: 1, Refused: 1, ElapsedMS: 321, Stop: "attempt_budget"}}}
	coverage := output.SummarizeCoverage([]int{22, 23, 24, 25, 26}, results["fixture"], func() *scanner.ConnectDiagnostics { d := diags["fixture"]; return &d }())
	metrics := output.ScanMetrics{Options: output.ScanOptions{Mobile: true}, Coverage: coverage, Hosts: []output.HostMetrics{{Host: "fixture", Engine: "connect", Coverage: coverage}}}
	return results, diags, metrics
}

func TestMobileFullReportKeepsEvidenceAndInconclusiveCounts(t *testing.T) {
	results, diags, metrics := mobileReportFixture()
	f := output.NewOutputFormatter(true, true)
	f.Compact = true
	var b bytes.Buffer
	if err := writeMobileTextReport(&b, f, false, []string{"fixture"}, results, diags, metrics, 2*time.Second); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"22 open ssh", "version: " + strings.Repeat("v", 200), "Host Exposure Summary", "critical: ssh", "exposure: indeterminate", "closed (refused): 2", "filtered (timeout-inferred): 1", "unknown: 1", "configured timeout ms: 750", "last attempt timeout ms: 750..750", "local_resource_ports: 1", "timeout_ports: 1", "recovery attempts: 2", "recovery open: 1", "recovery refused: 1", "recovery elapsed ms: 321", "recovery stop: attempt_budget", "shared recovery budget: 8 attempts / 3000 ms", "Scan finished (inconclusive)", "inconclusive host-ports: 2"} {
		if !strings.Contains(b.String(), want) {
			t.Fatalf("missing %q in %s", want, b.String())
		}
	}
	if strings.Contains(b.String(), "private error") || strings.Contains(b.String(), "2000") || strings.Contains(b.String(), " | ") {
		t.Fatalf("private/obsolete/wide output: %s", b.String())
	}
	b.Reset()
	if err := writeMobileTextReport(&b, f, true, []string{"fixture"}, results, diags, metrics, 0); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(b.String(), "22 open ssh") || !strings.Contains(b.String(), "open ports: 1") {
		t.Fatal("stream duplicated results or lost summary")
	}
}

type reportFailureWriter struct{ remaining, writes int }

func (w *reportFailureWriter) Write(p []byte) (int, error) {
	w.writes++
	if w.remaining == 0 {
		return 0, io.ErrClosedPipe
	}
	w.remaining--
	return len(p), nil
}

func TestMobileReportPropagatesWriteFailures(t *testing.T) {
	results, diags, metrics := mobileReportFixture()
	f := output.NewOutputFormatter(true, true)
	f.Compact = true
	writer := &reportFailureWriter{remaining: 10000}
	if err := writeMobileTextReport(writer, f, false, []string{"fixture", "empty"}, results, diags, metrics, 0); err != nil {
		t.Fatal(err)
	}
	for n := 0; n < writer.writes; n++ {
		if err := writeMobileTextReport(&reportFailureWriter{remaining: n}, f, false, []string{"fixture", "empty"}, results, diags, metrics, 0); !errors.Is(err, io.ErrClosedPipe) {
			t.Fatalf("write %d lost error: %v", n, err)
		}
	}
}

func TestMobileUDPSummaryDoesNotInventCriticalServices(t *testing.T) {
	results := map[string][]scanner.ScanResult{"fixture": {{Port: 53, IsOpen: true, State: "open"}, {Port: 3306, State: "open|filtered", ServiceName: "mysql"}, {Port: 22, State: "closed", ServiceName: "ssh"}}}
	metrics := output.ScanMetrics{Options: output.ScanOptions{Mobile: true}, Coverage: output.Coverage{Requested: 3, Open: 1, Closed: 1, OpenFiltered: 1}}
	f := output.NewOutputFormatter(true, false)
	f.Compact = true
	var b bytes.Buffer
	if err := writeMobileTextReport(&b, f, false, []string{"fixture"}, results, nil, metrics, 0); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"critical: none", "exposure: indeterminate", "open|filtered: 1"} {
		if !strings.Contains(b.String(), want) {
			t.Fatalf("missing %q in %s", want, b.String())
		}
	}
}

func TestMobileNativeTextOutputAndStreaming(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()
	port := strconv.Itoa(l.Addr().(*net.TCPAddr).Port)
	for _, stream := range []bool{false, true} {
		path := filepath.Join(t.TempDir(), "report.txt")
		if err := ExecuteScan(ScanRequest{Mobile: true, Target: "127.0.0.1", PortsFlag: port, Format: "text", Stream: stream, OutputPath: path}); err != nil {
			t.Fatal(err)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Count(string(data), port+" open") != 1 || !strings.Contains(string(data), "Coverage: total") || !strings.Contains(string(data), "Completed scan") || strings.Contains(string(data), " | ") {
			t.Fatalf("unexpected mobile text: %s", data)
		}
	}
}

func BenchmarkMobileReportRendering(b *testing.B) {
	results := map[string][]scanner.ScanResult{"fixture": make([]scanner.ScanResult, 4096)}
	for i := range results["fixture"] {
		results["fixture"][i] = scanner.ScanResult{Port: i + 1, IsOpen: true, Version: strings.Repeat("v", 128)}
	}
	f := output.NewOutputFormatter(true, false)
	f.Compact = true
	metrics := output.ScanMetrics{Options: output.ScanOptions{Mobile: true}, Coverage: output.Coverage{Requested: 4096, Open: 4096}}
	for _, buffered := range []bool{false, true} {
		name := "bounded"
		if buffered {
			name = "report_buffer"
		}
		b.Run(name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				var buffer bytes.Buffer
				w := io.Discard
				if buffered {
					w = &buffer
				}
				if err := writeMobileTextReport(w, f, false, []string{"fixture"}, results, nil, metrics, 0); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
