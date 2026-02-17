package output

import (
	"bytes"
	"os"
	"path/filepath"
	"regexp"
	"testing"

	"github.com/NexusFireMan/gomap/pkg/scanner"
)

var ansiStripRE = regexp.MustCompile(`\x1b\[[0-9;]*m`)

func TestOutputFormatterGolden(t *testing.T) {
	results := []scanner.ScanResult{
		{
			Port:        80,
			IsOpen:      true,
			ServiceName: "http",
			Version:     "Apache 2.4.7 (Ubuntu)",
			LatencyMs:   2,
			Confidence:  "high",
			Evidence:    "protocol banner",
		},
		{
			Port:        445,
			IsOpen:      true,
			ServiceName: "microsoft-ds",
			Version:     "Windows Server 2008 R2",
			LatencyMs:   4,
			Confidence:  "high",
			Evidence:    "nmap smb-os-discovery",
		},
	}

	cases := []struct {
		name      string
		formatter *OutputFormatter
		golden    string
	}{
		{name: "basic", formatter: NewOutputFormatter(false, false), golden: "basic.golden"},
		{name: "services", formatter: NewOutputFormatter(true, false), golden: "services.golden"},
		{name: "details", formatter: NewOutputFormatter(true, true), golden: "details.golden"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := captureStdout(t, func() {
				tc.formatter.PrintResults(results)
			})
			got = ansiStripRE.ReplaceAllString(got, "")

			goldenPath := filepath.Join("testdata", tc.golden)
			update := os.Getenv("UPDATE_GOLDEN") == "1"
			if update {
				if err := os.WriteFile(goldenPath, []byte(got), 0644); err != nil {
					t.Fatalf("failed to update golden file: %v", err)
				}
			}

			wantBytes, err := os.ReadFile(goldenPath)
			if err != nil {
				t.Fatalf("failed to read golden file %s: %v", goldenPath, err)
			}
			want := string(wantBytes)
			if got != want {
				t.Fatalf("golden mismatch for %s\n--- got ---\n%s\n--- want ---\n%s", tc.name, got, want)
			}
		})
	}
}

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()

	orig := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe creation failed: %v", err)
	}
	os.Stdout = w

	fn()

	_ = w.Close()
	os.Stdout = orig

	var buf bytes.Buffer
	if _, err := buf.ReadFrom(r); err != nil {
		t.Fatalf("failed to read captured stdout: %v", err)
	}
	_ = r.Close()
	return buf.String()
}
