package gomap

import (
	"errors"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestCLIParserDefaults(t *testing.T) {
	got, err := ParseCLIOptions([]string{"127.0.0.1"})
	want := CLIOptions{
		Host: "127.0.0.1", ScanType: "connect", FormatFlag: "text",
		BackoffMS: 25, AdaptiveTimeout: true,
	}
	if err != nil || got != want {
		t.Fatalf("defaults: got %+v, %v; want %+v", got, err, want)
	}
}

func TestCLIParserValidationRegressions(t *testing.T) {
	for _, tt := range []struct {
		name string
		args []string
		want string
	}{
		{"negative retries", []string{"--retries=-1"}, "--retries"},
		{"negative timeout", []string{"--timeout=-1"}, "--timeout"},
		{"negative workers", []string{"--workers=-1"}, "--workers"},
		{"negative backoff", []string{"--backoff-ms=-1"}, "--backoff-ms"},
		{"negative maximum timeout", []string{"--max-timeout=-1"}, "--max-timeout"},
		{"blank output path", []string{"--out", " \t "}, "--out"},
		{"explicit ports and top", []string{"-p=80", "--top=5"}, "either -p"},
		{"details and jsonl", []string{"--details", "--format=jsonl"}, "--details"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			args := append(slices.Clone(tt.args), "127.0.0.1")
			_, err := ParseCLIOptions(args)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("%v: expected error mentioning %q, got %v", args, tt.want, err)
			}
		})
	}
}

func TestCLIParserUsageErrors(t *testing.T) {
	for _, tt := range []struct {
		name string
		args []string
	}{
		{"missing target", nil},
		{"multiple targets", []string{"127.0.0.1", "127.0.0.2"}},
		{"unknown flag", []string{"--not-a-gomap-option", "127.0.0.1"}},
		{"missing value", []string{"127.0.0.1", "--timeout"}},
		{"invalid integer", []string{"--workers=fast", "127.0.0.1"}},
		{"invalid boolean", []string{"--adaptive-timeout=maybe", "127.0.0.1"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseCLIOptions(tt.args)
			if !errors.Is(err, errUsage) {
				t.Fatalf("%v: expected usage error, got %v", tt.args, err)
			}
		})
	}
}

func TestCLIParserCanonicalFormsAndInputPreservation(t *testing.T) {
	args := []string{
		"127.0.0.1", "--format", " JSONL ", "--scan-type", " CONNECT ",
		"--adaptive-timeout=false", "--top-ports=25", "--out", "report with spaces.jsonl",
	}
	original := slices.Clone(args)
	got, err := ParseCLIOptions(args)
	want := CLIOptions{
		Host: "127.0.0.1", ScanType: "connect", FormatFlag: "jsonl",
		TopPorts: 25, TopPortsAlias: 25, BackoffMS: 25, OutPath: "report with spaces.jsonl",
	}
	if err != nil || got != want {
		t.Fatalf("got %+v, %v; want %+v", got, err, want)
	}
	if !slices.Equal(args, original) {
		t.Fatalf("parser mutated caller arguments: %q", args)
	}
}

func TestCLIParserLegacyBooleanAliasValues(t *testing.T) {
	for _, alias := range []string{"--ramdom-agent", "--ip-ram", "--ip-random"} {
		for _, suffix := range []string{"", "=false", "=true"} {
			t.Run(alias+suffix, func(t *testing.T) {
				value := suffix != "=false"
				args := []string{"-s", alias + suffix, "127.0.0.1"}
				original := slices.Clone(args)
				got, err := ParseCLIOptions(args)
				enabled := got.RandomIP
				if alias == "--ramdom-agent" {
					enabled = got.RandomAgent
				}
				if err != nil || enabled != value || !slices.Equal(args, original) {
					t.Fatalf("got %+v, %v; expected alias value %v and unchanged input", got, err, value)
				}
			})
		}
	}
}

func TestCLIParserDurationBoundary(t *testing.T) {
	if strconv.IntSize < 64 {
		t.Skip("duration boundary exceeds 32-bit int")
	}
	const maxMilliseconds = int64((1<<63 - 1) / time.Millisecond)
	for _, name := range []string{"--timeout", "--max-timeout", "--backoff-ms"} {
		t.Run(name, func(t *testing.T) {
			got, err := ParseCLIOptions([]string{name, strconv.FormatInt(maxMilliseconds, 10), "127.0.0.1"})
			if err != nil {
				t.Fatalf("largest representable duration rejected: %v", err)
			}
			values := map[string]int{"--timeout": got.TimeoutMS, "--max-timeout": got.MaxTimeoutMS, "--backoff-ms": got.BackoffMS}
			if int64(values[name]) != maxMilliseconds {
				t.Fatalf("duration changed: %+v", got)
			}
			_, err = ParseCLIOptions([]string{name, strconv.FormatInt(maxMilliseconds+1, 10), "127.0.0.1"})
			if err == nil || !strings.Contains(err.Error(), name) {
				t.Fatalf("first overflowing duration: expected %s error, got %v", name, err)
			}
		})
	}
}

func TestCLIParserMaintenanceStillValidatesOptions(t *testing.T) {
	for _, name := range []string{"--version", "--doctor", "--remove", "-up"} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseCLIOptions([]string{name}); err != nil {
				t.Fatalf("maintenance flag required a target: %v", err)
			}
			if _, err := ParseCLIOptions([]string{name, "--retries=-1"}); err == nil {
				t.Fatal("maintenance flag bypassed option validation")
			}
		})
	}
}
