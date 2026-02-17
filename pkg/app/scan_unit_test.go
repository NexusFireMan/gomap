package app

import (
	"testing"

	"github.com/NexusFireMan/gomap/v2/pkg/scanner"
)

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
