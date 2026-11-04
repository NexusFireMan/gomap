package app

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func hostConfigFixture(t *testing.T, data string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "hosts.json")
	if err := os.WriteFile(path, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestHostConfigStrictValidation(t *testing.T) {
	for _, data := range []string{
		``, `null`, `[]`, `{`, `{} {}`, `{} trailing`,
		`{"example.invalid":{"timeout_ms":100}}`, `{"fe80::1%lo":{}}`,
		`{"192.0.2.1":null}`, `{"192.0.2.1":{"unknown":1}}`,
		`{"192.0.2.1":{"timeout_ms":null}}`, `{"192.0.2.1":{"timeout_ms":-1}}`,
		`{"192.0.2.1":{"timeout_ms":1.5}}`, `{"192.0.2.1":{"timeout_ms":9223372036854775807}}`,
		`{"192.0.2.1":{"retries":11}}`, `{"192.0.2.1":{"adaptive_timeout":null}}`,
		`{"192.0.2.1":{"adaptive_timeout":1}}`, `{"192.0.2.1":{"retries":1,"retries":2}}`,
		`{"192.0.2.1":{},"192.0.2.1":{}}`, `{"192.0.2.1":{},"::ffff:192.0.2.1":{}}`,
		`{"192.0.2.1":{"timeout_ms":100}`, strings.Repeat(" ", maxHostConfigBytes+1),
	} {
		if _, err := parseHostConfig([]byte(data)); err == nil {
			t.Fatalf("accepted invalid config: %.120s", data)
		}
	}
}

func TestHostOverridesAreScopedAndPreserveExplicitZero(t *testing.T) {
	config, err := parseHostConfig([]byte(`{"192.0.2.1":{"timeout_ms":200,"max_timeout_ms":800,"retries":0,"adaptive_timeout":false},"2001:db8::1":{"retries":2}}`))
	if err != nil {
		t.Fatal(err)
	}
	base := ScanRequest{TimeoutMS: 300, MaxTimeoutMS: 1000, Retries: 3, AdaptiveTimeout: true}
	if err := validateHostConfigScope(config, []string{"192.0.2.1", "2001:db8::1"}, base); err != nil {
		t.Fatal(err)
	}
	first := applyHostOverride(base, config["192.0.2.1"])
	if first.TimeoutMS != 200 || first.MaxTimeoutMS != 800 || first.Retries != 0 || first.AdaptiveTimeout {
		t.Fatalf("explicit overrides lost: %+v", first)
	}
	second := applyHostOverride(base, config["2001:db8::1"])
	if second.TimeoutMS != 300 || second.MaxTimeoutMS != 1000 || second.Retries != 2 || !second.AdaptiveTimeout || base.Retries != 3 {
		t.Fatalf("settings leaked between hosts: %+v / %+v", second, base)
	}
	if err := validateHostConfigScope(config, []string{"192.0.2.1"}, base); err == nil {
		t.Fatal("out-of-scope override accepted")
	}
	bad, err := parseHostConfig([]byte(`{"192.0.2.1":{"max_timeout_ms":100}}`))
	if err != nil {
		t.Fatal(err)
	}
	if err := validateHostConfigScope(bad, []string{"192.0.2.1"}, base); err == nil {
		t.Fatal("contradictory inherited timeout bounds accepted")
	}
}

func TestInvalidHostConfigPreservesOutputBeforeScanning(t *testing.T) {
	for _, data := range []string{`not json`, `{"192.0.2.99":{"retries":1}}`} {
		path := hostConfigFixture(t, "previous report")
		err := ExecuteScan(ScanRequest{Target: "192.0.2.1", PortsFlag: "80", Format: "json", HostConfig: hostConfigFixture(t, data), OutputPath: path})
		if err == nil {
			t.Fatal("invalid config accepted")
		}
		got, err := os.ReadFile(path)
		if err != nil || string(got) != "previous report" {
			t.Fatalf("existing report modified: %q, %v", got, err)
		}
	}
	path := hostConfigFixture(t, `{"192.0.2.1":{}}`)
	if err := ExecuteScan(ScanRequest{Target: "192.0.2.1", PortsFlag: "80", Format: "json", HostConfig: path, OutputPath: path}); err == nil {
		t.Fatal("configuration overwrite accepted")
	}
	if err := ExecuteScan(ScanRequest{ScanType: "syn", HostConfig: "unused"}); err == nil {
		t.Fatal("unsupported SYN override accepted")
	}
	if _, err := loadHostConfig(filepath.Join(t.TempDir(), "missing.json")); err == nil {
		t.Fatal("missing config accepted")
	}
}

func FuzzHostConfigParser(f *testing.F) {
	f.Add([]byte(`{"192.0.2.1":{"timeout_ms":200,"retries":0}}`))
	f.Add([]byte(`{}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > maxHostConfigBytes+1 {
			return
		}
		config, err := parseHostConfig(data)
		if err != nil {
			return
		}
		for _, override := range config {
			got := applyHostOverride(ScanRequest{}, override)
			if got.TimeoutMS < 0 || got.MaxTimeoutMS < 0 || got.Retries < 0 || got.Retries > 10 {
				t.Fatal("invalid settings escaped parser")
			}
		}
	})
}
