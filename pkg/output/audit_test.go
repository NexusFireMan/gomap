package output

import (
	"bytes"
	"strings"
	"testing"

	"github.com/NexusFireMan/gomap/v2/pkg/scanner"
)

func TestRemoteFieldsCannotInjectTerminalControls(t *testing.T) {
	raw := "fixture\x1b]52;c;payload\a\r\nforged\u202e"
	results := []scanner.ScanResult{{Port: 80, IsOpen: true, ServiceName: raw, Version: raw, Hostname: raw, Evidence: raw}}
	var buf bytes.Buffer
	if err := NewEvidenceOutputFormatter().WriteResults(&buf, results); err != nil {
		t.Fatal(err)
	}
	clean := ansiStripRE.ReplaceAllString(buf.String(), "")
	if strings.ContainsAny(clean, "\x1b\a\r\u202e") || strings.Count(clean, "\n") != 3 {
		t.Fatalf("unsafe text output: %q", clean)
	}
	if results[0].Evidence != raw {
		t.Fatal("renderer modified structured evidence")
	}
}

func TestDetailsColumnsAlignWithColorsAndLongVersions(t *testing.T) {
	results := []scanner.ScanResult{
		{Port: 22, IsOpen: true, Version: strings.Repeat("v", 50), LatencyMs: 123},
		{Port: 80, IsOpen: true, Version: "short", LatencyMs: 456},
	}
	var buf bytes.Buffer
	if err := NewOutputFormatter(true, true).WriteResults(&buf, results); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(ansiStripRE.ReplaceAllString(buf.String(), ""), "\n")
	column := strings.Index(lines[0], "LAT(ms)")
	if strings.Index(lines[1], "123") != column || strings.Index(lines[2], "456") != column {
		t.Fatalf("misaligned columns:\n%s", buf.String())
	}
}
