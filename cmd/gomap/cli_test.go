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
