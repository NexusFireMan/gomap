package gomap

import (
	"errors"
	"testing"
)

func TestParseCLIOptionsTopPortsAlias(t *testing.T) {
	opts, err := ParseCLIOptions([]string{"--top-ports", "200", "10.0.11.6"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if opts.TopPorts != 200 {
		t.Fatalf("expected TopPorts=200, got %d", opts.TopPorts)
	}
}

func TestParseCLIOptionsExcludePortsAndRate(t *testing.T) {
	opts, err := ParseCLIOptions([]string{"-p", "1-1024", "--exclude-ports", "22,80", "--rate", "300", "--max-hosts", "10", "10.0.11.0/24"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if opts.ExcludePorts != "22,80" {
		t.Fatalf("unexpected exclude ports: %s", opts.ExcludePorts)
	}
	if opts.Rate != 300 {
		t.Fatalf("expected rate 300, got %d", opts.Rate)
	}
	if opts.MaxHosts != 10 {
		t.Fatalf("expected max hosts 10, got %d", opts.MaxHosts)
	}
}

func TestParseCLIOptionsTopPortsConflict(t *testing.T) {
	_, err := ParseCLIOptions([]string{"--top", "100", "--top-ports", "200", "10.0.11.6"})
	if err == nil {
		t.Fatal("expected conflict error for --top and --top-ports")
	}
}

func TestParseCLIOptionsRandomAgentAliases(t *testing.T) {
	opts, err := ParseCLIOptions([]string{"-s", "--ramdom-agent", "--ip-random", "10.0.11.0/24"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !opts.RandomAgent {
		t.Fatal("expected random-agent enabled via alias")
	}
	if !opts.RandomIP {
		t.Fatal("expected random-ip enabled via alias")
	}
}

func TestParseCLIOptionsRandomIPRequiresServiceDetection(t *testing.T) {
	_, err := ParseCLIOptions([]string{"--random-ip", "10.0.11.0/24"})
	if err == nil {
		t.Fatal("expected error because --random-ip requires -s")
	}
}

func TestParseCLIOptionsHelpFlag(t *testing.T) {
	_, err := ParseCLIOptions([]string{"-h"})
	if !errors.Is(err, errHelp) {
		t.Fatalf("expected errHelp, got: %v", err)
	}
}

func TestParseCLIOptionsDoctorFlag(t *testing.T) {
	opts, err := ParseCLIOptions([]string{"--doctor"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !opts.DoctorFlag {
		t.Fatal("expected doctor flag enabled")
	}
}

func TestParseCLIOptionsScanType(t *testing.T) {
	opts, err := ParseCLIOptions([]string{"--scan-type", "syn", "10.0.11.6"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if opts.ScanType != "syn" {
		t.Fatalf("expected scan type syn, got %q", opts.ScanType)
	}
}

func TestParseCLIOptionsUDPFlag(t *testing.T) {
	opts, err := ParseCLIOptions([]string{"-u", "10.0.11.6"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !opts.UDPFlag {
		t.Fatal("expected udp flag enabled")
	}
}

func TestParseCLIOptionsUDPRejectsSYN(t *testing.T) {
	_, err := ParseCLIOptions([]string{"-u", "--scan-type", "syn", "10.0.11.6"})
	if err == nil {
		t.Fatal("expected error for udp with syn scan type")
	}
}

func TestParseCLIOptionsScanTypeInvalid(t *testing.T) {
	_, err := ParseCLIOptions([]string{"--scan-type", "udp", "10.0.11.6"})
	if err == nil {
		t.Fatal("expected error for invalid scan type")
	}
}

func TestParseCLIOptionsJSONFormatAlias(t *testing.T) {
	opts, err := ParseCLIOptions([]string{"--json", "10.0.11.6"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if opts.FormatFlag != "json" {
		t.Fatalf("expected format=json, got %q", opts.FormatFlag)
	}
	if !opts.JSONFlag {
		t.Fatal("expected JSONFlag enabled")
	}
}

func TestParseCLIOptionsCSVFormatAlias(t *testing.T) {
	opts, err := ParseCLIOptions([]string{"--csv", "10.0.11.6"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if opts.FormatFlag != "csv" {
		t.Fatalf("expected format=csv, got %q", opts.FormatFlag)
	}
}

func TestParseCLIOptionsJSONAndCSVConflict(t *testing.T) {
	_, err := ParseCLIOptions([]string{"--json", "--csv", "10.0.11.6"})
	if err == nil {
		t.Fatal("expected error when --json and --csv combined")
	}
}

func TestParseCLIOptionsJSONWithIncompatibleFormat(t *testing.T) {
	_, err := ParseCLIOptions([]string{"--json", "--format", "csv", "10.0.11.6"})
	if err == nil {
		t.Fatal("expected error when --json combined with non-text/json --format")
	}
}

func TestParseCLIOptionsCSVWithIncompatibleFormat(t *testing.T) {
	_, err := ParseCLIOptions([]string{"--csv", "--format", "json", "10.0.11.6"})
	if err == nil {
		t.Fatal("expected error when --csv combined with non-text/csv --format")
	}
}

func TestParseCLIOptionsInvalidFormat(t *testing.T) {
	_, err := ParseCLIOptions([]string{"--format", "xml", "10.0.11.6"})
	if err == nil {
		t.Fatal("expected error for invalid --format value")
	}
}

func TestParseCLIOptionsFormatJSONLValid(t *testing.T) {
	opts, err := ParseCLIOptions([]string{"--format", "jsonl", "10.0.11.6"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if opts.FormatFlag != "jsonl" {
		t.Fatalf("expected format=jsonl, got %q", opts.FormatFlag)
	}
}

func TestParseCLIOptionsVersionFlag(t *testing.T) {
	opts, err := ParseCLIOptions([]string{"-v"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !opts.VersionFlag {
		t.Fatal("expected VersionFlag enabled")
	}
}

func TestParseCLIOptionsUpdateFlag(t *testing.T) {
	opts, err := ParseCLIOptions([]string{"-up"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !opts.UpdateFlag {
		t.Fatal("expected UpdateFlag enabled via -up")
	}
}

func TestParseCLIOptionsRemoveFlag(t *testing.T) {
	opts, err := ParseCLIOptions([]string{"--remove"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !opts.RemoveFlag {
		t.Fatal("expected RemoveFlag enabled")
	}
}

func TestParseCLIOptionsDetailsRequiresTextFormat(t *testing.T) {
	_, err := ParseCLIOptions([]string{"--details", "--json", "10.0.11.6"})
	if err == nil {
		t.Fatal("expected error: --details only valid with text output")
	}
}

func TestParseCLIOptionsNegativeRateRejected(t *testing.T) {
	_, err := ParseCLIOptions([]string{"--rate", "-1", "10.0.11.6"})
	if err == nil {
		t.Fatal("expected error for negative --rate")
	}
}

func TestParseCLIOptionsNegativeMaxHostsRejected(t *testing.T) {
	_, err := ParseCLIOptions([]string{"--max-hosts", "-1", "10.0.11.6"})
	if err == nil {
		t.Fatal("expected error for negative --max-hosts")
	}
}

func TestParseCLIOptionsScanTypeCaseInsensitive(t *testing.T) {
	opts, err := ParseCLIOptions([]string{"--scan-type", "SYN", "10.0.11.6"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if opts.ScanType != "syn" {
		t.Fatalf("expected scan type lowercased to syn, got %q", opts.ScanType)
	}
}
