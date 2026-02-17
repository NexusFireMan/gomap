package app

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type labJSONReport struct {
	Hosts []struct {
		Host    string `json:"host"`
		Results []struct {
			Port    int    `json:"port"`
			Service string `json:"service"`
			Version string `json:"version"`
		} `json:"results"`
	} `json:"hosts"`
}

func TestLabIntegrationWindows(t *testing.T) {
	if os.Getenv("GOMAP_RUN_LAB_TESTS") != "1" {
		t.Skip("set GOMAP_RUN_LAB_TESTS=1 to execute lab integration tests")
	}

	ip := os.Getenv("GOMAP_LAB_WINDOWS_IP")
	if ip == "" {
		ip = "10.0.11.6"
	}
	if !hostReachable(ip, "80", 1200*time.Millisecond) {
		t.Skipf("windows lab host not reachable at %s", ip)
	}

	outPath := filepath.Join(t.TempDir(), "windows_scan.json")
	req := ScanRequest{
		Target:          ip,
		PortsFlag:       "21,80,135,139,445,3306,5985",
		ServiceDetect:   true,
		Format:          "json",
		OutputPath:      outPath,
		Retries:         2,
		AdaptiveTimeout: true,
		BackoffMS:       40,
	}
	if err := ExecuteScan(req); err != nil {
		t.Fatalf("execute scan failed: %v", err)
	}

	report := readLabReport(t, outPath)
	services := collectServices(report)
	requireService(t, services, "http")
	requireService(t, services, "microsoft-ds")
	requireService(t, services, "msrpc")
}

func TestLabIntegrationLinux(t *testing.T) {
	if os.Getenv("GOMAP_RUN_LAB_TESTS") != "1" {
		t.Skip("set GOMAP_RUN_LAB_TESTS=1 to execute lab integration tests")
	}

	ip := os.Getenv("GOMAP_LAB_LINUX_IP")
	if ip == "" {
		ip = "10.0.11.9"
	}
	if !hostReachable(ip, "22", 1200*time.Millisecond) {
		t.Skipf("linux lab host not reachable at %s", ip)
	}

	outPath := filepath.Join(t.TempDir(), "linux_scan.json")
	req := ScanRequest{
		Target:          ip,
		PortsFlag:       "21,22,80,445,631,3306",
		ServiceDetect:   true,
		Format:          "json",
		OutputPath:      outPath,
		Retries:         2,
		AdaptiveTimeout: true,
		BackoffMS:       40,
	}
	if err := ExecuteScan(req); err != nil {
		t.Fatalf("execute scan failed: %v", err)
	}

	report := readLabReport(t, outPath)
	services := collectServices(report)
	requireService(t, services, "ftp")
	requireService(t, services, "ssh")
	requireService(t, services, "http")
	requireService(t, services, "microsoft-ds")
}

func hostReachable(host, port string, timeout time.Duration) bool {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, port), timeout)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

func readLabReport(t *testing.T, path string) labJSONReport {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read report file: %v", err)
	}
	var report labJSONReport
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatalf("failed to parse json report: %v", err)
	}
	return report
}

func collectServices(report labJSONReport) map[string]bool {
	services := make(map[string]bool)
	for _, host := range report.Hosts {
		for _, result := range host.Results {
			if result.Service != "" {
				services[result.Service] = true
			}
		}
	}
	return services
}

func requireService(t *testing.T, services map[string]bool, service string) {
	t.Helper()
	if !services[service] {
		t.Fatalf("expected service %q not found; got services: %#v", service, services)
	}
}
