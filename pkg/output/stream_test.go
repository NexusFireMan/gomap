package output

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/NexusFireMan/gomap/v2/pkg/scanner"
)

func TestStreamResultSingleLineAndWriteErrors(t *testing.T) {
	result := scanner.ScanResult{Port: 22, IsOpen: true, ServiceName: "ssh", Version: "fixture\n\x1b[2J", Hostname: "host\rname", Evidence: "banner\nline", LatencyMs: 12, Confidence: "high"}
	for _, formatter := range []*OutputFormatter{NewOutputFormatter(false, false), NewOutputFormatter(true, true), NewEvidenceOutputFormatter()} {
		var b bytes.Buffer
		if err := formatter.WriteStreamResult(&b, "::1", result); err != nil {
			t.Fatal(err)
		}
		if strings.Count(b.String(), "\n") != 1 || !strings.HasPrefix(b.String(), "[::1]:22 open") || strings.ContainsAny(b.String(), "\r\x1b") {
			t.Fatalf("unsafe stream line: %q", b.String())
		}
		if formatter.IncludeServices && (!strings.Contains(b.String(), "service=\"ssh\"") || !strings.Contains(b.String(), "hostname=")) {
			t.Fatalf("missing service fields: %q", b.String())
		}
		if formatter.IncludeDetails && !strings.Contains(b.String(), "latency_ms=12 confidence=\"high\"") {
			t.Fatalf("missing details: %q", b.String())
		}
		if err := formatter.WriteStreamResult(failingWriter{}, "fixture", result); !errors.Is(err, io.ErrClosedPipe) {
			t.Fatalf("write error lost: %v", err)
		}
	}
}
