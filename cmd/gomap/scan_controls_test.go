package gomap

import "testing"

func TestNewScanControls(t *testing.T) {
	opts, err := ParseCLIOptions([]string{"127.0.0.1", "--host-config", "fixture.json", "--capture-unknown", "--evidence-bytes", "64"})
	if err != nil || opts.HostConfig != "fixture.json" || !opts.CaptureUnknown || !opts.ServiceFlag || opts.EvidenceBytes != 64 {
		t.Fatalf("unexpected options: %+v, %v", opts, err)
	}
	for _, args := range [][]string{
		{"--capture-unknown", "--evidence-bytes", "0", "127.0.0.1"},
		{"--evidence-bytes", "1025", "127.0.0.1"},
		{"--host-config", "fixture.json", "--scan-type", "SYN", "127.0.0.1"},
	} {
		if _, err := ParseCLIOptions(args); err == nil {
			t.Fatalf("invalid controls accepted: %v", args)
		}
	}
	defaults, err := ParseCLIOptions([]string{"127.0.0.1"})
	if err != nil || defaults.CaptureUnknown || defaults.ServiceFlag || defaults.HostConfig != "" || defaults.EvidenceBytes != 256 {
		t.Fatalf("defaults changed: %+v, %v", defaults, err)
	}
}
