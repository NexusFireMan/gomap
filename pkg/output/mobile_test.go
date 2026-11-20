package output

import (
	"bytes"
	"errors"
	"io"
	"reflect"
	"strings"
	"testing"

	"github.com/NexusFireMan/gomap/v2/pkg/scanner"
)

func TestMobileBlocksPreserveFieldsWithoutTablePadding(t *testing.T) {
	result := scanner.ScanResult{Port: 443, IsOpen: true, ServiceName: "https", Version: strings.Repeat("v", 200), Hostname: "fixture", Evidence: "complete evidence", Confidence: "high", LatencyMs: 12}
	want := result
	f := NewOutputFormatter(true, true)
	f.Compact = true
	var buf bytes.Buffer
	if err := f.WriteResults(&buf, []scanner.ScanResult{result}); err != nil {
		t.Fatal(err)
	}
	for _, text := range []string{"443 open https\n", "  version: " + result.Version, "  hostname: fixture", "  evidence: complete evidence", "  latency_ms: 12", "  confidence: high"} {
		if !strings.Contains(buf.String(), text) {
			t.Fatalf("missing %q: %s", text, buf.String())
		}
	}
	if strings.Contains(buf.String(), "PORT") || !reflect.DeepEqual(result, want) {
		t.Fatal("table was emitted or structured observation changed")
	}
	if err := f.WriteResults(failingWriter{}, []scanner.ScanResult{result}); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("write failure lost: %v", err)
	}
}

func TestMobileEvidenceAndUncertainStatesStayExplicit(t *testing.T) {
	f := NewEvidenceOutputFormatter()
	f.Compact = true
	var buf bytes.Buffer
	if err := f.WriteResults(&buf, []scanner.ScanResult{{Port: 161, State: "open|filtered", Evidence: "no response\r\n\x1b[2J\u202e", Confidence: "low"}}); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(buf.String(), "161 open|filtered\n") || !strings.Contains(buf.String(), "  evidence: no response") || strings.ContainsAny(buf.String(), "\r\x1b\u202e") || strings.Contains(buf.String(), "confidence:") {
		t.Fatalf("unsafe or misleading evidence block: %q", buf.String())
	}
	buf.Reset()
	f = NewOutputFormatter(false, false)
	f.Compact = true
	if err := f.WriteResults(&buf, []scanner.ScanResult{{Port: 53, State: "unknown", Version: "not requested"}}); err != nil {
		t.Fatal(err)
	}
	if buf.String() != "53 unknown\n\n" {
		t.Fatalf("unexpected basic block: %q", buf.String())
	}
}

func TestMobileStreamingHasHostAndWriterErrors(t *testing.T) {
	f := NewOutputFormatter(true, false)
	f.Compact = true
	var buf bytes.Buffer
	if err := f.WriteStreamResult(&buf, "::1", scanner.ScanResult{Port: 22, IsOpen: true, ServiceName: "ssh", Version: "fixture"}); err != nil {
		t.Fatal(err)
	}
	if buf.String() != "[::1]:22 open ssh\n  version: fixture\n\n" {
		t.Fatal(buf.String())
	}
	if err := f.WriteStreamResult(failingWriter{}, "fixture", scanner.ScanResult{}); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatal(err)
	}
}
