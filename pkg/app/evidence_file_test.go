package app

import (
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"testing"
)

func TestCaptureReportsRestrictUnixPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix mode bits do not enforce Windows ACL privacy")
	}
	path := filepath.Join(t.TempDir(), "report.json")
	if err := os.WriteFile(path, []byte("previous"), 0644); err != nil {
		t.Fatal(err)
	}
	// An idle UDP endpoint remains uncertain; no additional service probes are needed.
	udp, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = udp.Close() })
	port := udp.LocalAddr().(*net.UDPAddr).Port
	if err := ExecuteScan(ScanRequest{Target: "127.0.0.1", PortsFlag: strconv.Itoa(port), UDP: true, Format: "json", OutputPath: path, TimeoutMS: 20, CaptureUnknown: true, EvidenceBytes: 16}); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("capture report not private: %v, %v", info, err)
	}
}

func TestCaptureOutputRefusesDeviceDestinations(t *testing.T) {
	if err := ExecuteScan(ScanRequest{Target: "192.0.2.1", PortsFlag: "80", Format: "json", OutputPath: os.DevNull, CaptureUnknown: true}); err == nil {
		t.Fatal("device output accepted for private evidence capture")
	}
}
