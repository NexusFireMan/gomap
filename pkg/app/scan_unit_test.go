package app

import (
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/NexusFireMan/gomap/v2/pkg/scanner"
)

func TestTextReportWrittenToOutputFile(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()
	port := l.Addr().(*net.TCPAddr).Port
	path := filepath.Join(t.TempDir(), "report.txt")
	err = ExecuteScan(ScanRequest{Target: "127.0.0.1", PortsFlag: strconv.Itoa(port), Format: "text", OutputPath: path})
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil || !strings.Contains(string(data), "Host Exposure Summary") || !strings.Contains(string(data), strconv.Itoa(port)) {
		t.Fatalf("missing text report: %q, %v", data, err)
	}
}

func TestInvalidPortsPreserveOutputFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "report.txt")
	if err := os.WriteFile(path, []byte("previous report"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := ExecuteScan(ScanRequest{Target: "127.0.0.1", PortsFlag: "invalid", Format: "text", OutputPath: path}); err == nil {
		t.Fatal("expected invalid port error")
	}
	data, err := os.ReadFile(path)
	if err != nil || string(data) != "previous report" {
		t.Fatalf("existing output was modified: %q, %v", data, err)
	}
}

func TestFilterExcludedPorts(t *testing.T) {
	pm := scanner.NewPortManager()
	in := []int{21, 22, 80, 443, 445}
	out, err := filterExcludedPorts(pm, in, "22,445")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(out) != 3 {
		t.Fatalf("expected 3 ports, got %d (%v)", len(out), out)
	}
	if out[0] != 21 || out[1] != 80 || out[2] != 443 {
		t.Fatalf("unexpected filtered ports: %v", out)
	}
}

func TestExposureLevel(t *testing.T) {
	if got := exposureLevel(1, 0); got != "low" {
		t.Fatalf("expected low, got %s", got)
	}
	if got := exposureLevel(5, 0); got != "medium" {
		t.Fatalf("expected medium, got %s", got)
	}
	if got := exposureLevel(2, 3); got != "high" {
		t.Fatalf("expected high, got %s", got)
	}
}

func TestCriticalServices(t *testing.T) {
	results := []scanner.ScanResult{
		{ServiceName: "http"},
		{ServiceName: "ssh"},
		{ServiceName: "mysql"},
		{ServiceName: "ssh"},
	}
	critical := criticalServices(results)
	if len(critical) != 2 {
		t.Fatalf("expected 2 critical services, got %d (%v)", len(critical), critical)
	}
	if critical[0] != "mysql" || critical[1] != "ssh" {
		t.Fatalf("unexpected critical services: %v", critical)
	}
}
