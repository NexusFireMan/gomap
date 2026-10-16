package app

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

const syntheticSNMPConfig = `{"127.0.0.1":{"username":"fixture-user","auth_protocol":"sha256","auth_password":"test-only-auth-pass","privacy_protocol":"aes128","privacy_password":"test-only-privacy-pass"}}`

func TestSNMPConfigStrictParsing(t *testing.T) {
	config, err := parseSNMPConfig([]byte(syntheticSNMPConfig))
	if err != nil || len(config) != 1 || config["127.0.0.1"] == nil {
		t.Fatal("valid synthetic config rejected")
	}
	if err := validateSNMPScope(config, []string{"127.0.0.1"}); err != nil {
		t.Fatal(err)
	}
	if err := validateSNMPScope(config, []string{"127.0.0.2"}); err == nil {
		t.Fatal("out-of-scope credential target accepted")
	}
	for _, data := range []string{
		"", "null", "[]", "{}", syntheticSNMPConfig + "{}",
		strings.Replace(syntheticSNMPConfig, `"username":"fixture-user"`, `"username":null`, 1),
		strings.Replace(syntheticSNMPConfig, `"username":"fixture-user"`, `"username":"first","username":"second"`, 1),
		strings.Replace(syntheticSNMPConfig, `"username"`, `"unexpected-field"`, 1),
		strings.Replace(syntheticSNMPConfig, `"sha256"`, `"md5"`, 1),
		strings.Replace(syntheticSNMPConfig, `"127.0.0.1"`, `"fixture.invalid"`, 1),
		strings.Replace(syntheticSNMPConfig, `"127.0.0.1"`, `"fe80::1%eth0"`, 1),
		syntheticSNMPConfig[:len(syntheticSNMPConfig)-1] + `,"127.0.0.1":{}}`,
		syntheticSNMPConfig[:len(syntheticSNMPConfig)-1] + `,"::ffff:127.0.0.1":{}}`,
		strings.Repeat("x", maxSNMPConfigBytes+1),
	} {
		_, err := parseSNMPConfig([]byte(data))
		if !errors.Is(err, errSNMPConfig) || strings.Contains(err.Error(), "test-only") {
			t.Fatal("unsafe config validation")
		}
	}
}

func TestSNMPConfigFileSafety(t *testing.T) {
	path := filepath.Join(t.TempDir(), "snmp-private.json")
	if err := os.WriteFile(path, []byte(syntheticSNMPConfig), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadSNMPConfig(path, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := loadSNMPConfig(path, path); err == nil {
		t.Fatal("credential/output collision accepted")
	}
	alias := filepath.Join(t.TempDir(), "hardlink.json")
	if err := os.Link(path, alias); err == nil {
		if _, err := loadSNMPConfig(path, alias); err == nil {
			t.Fatal("hardlink output collision accepted")
		}
	}
	if runtime.GOOS != "windows" {
		if err := os.Chmod(path, 0644); err != nil {
			t.Fatal(err)
		}
		if _, err := loadSNMPConfig(path, ""); err == nil {
			t.Fatal("public credential file accepted")
		}
		if err := os.Chmod(path, 0600); err != nil {
			t.Fatal(err)
		}
		symlink := filepath.Join(t.TempDir(), "symlink.json")
		if err := os.Symlink(path, symlink); err != nil {
			t.Fatal(err)
		}
		if _, err := loadSNMPConfig(symlink, ""); err == nil {
			t.Fatal("credential symlink accepted")
		}
	}
}

func TestSNMPConfigPreflightPreservesOutput(t *testing.T) {
	directory := t.TempDir()
	configPath, output := filepath.Join(directory, "snmp-private.json"), filepath.Join(directory, "output.json")
	if err := os.WriteFile(configPath, []byte(syntheticSNMPConfig), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(output, []byte("preserve-fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, req := range []ScanRequest{
		{Target: "127.0.0.2", UDP: true, SNMPConfig: configPath},
		{Target: "127.0.0.1", SNMPConfig: configPath},
		{Target: "127.0.0.1", UDP: true, GhostMode: true, SNMPConfig: configPath},
	} {
		req.OutputPath = output
		if err := ExecuteScan(req); err == nil {
			t.Fatal("invalid preflight accepted")
		}
		data, err := os.ReadFile(output)
		if err != nil || string(data) != "preserve-fixture" {
			t.Fatal("preflight truncated output")
		}
	}
}

func FuzzSNMPConfig(f *testing.F) {
	f.Add([]byte(syntheticSNMPConfig))
	f.Add([]byte(`{"127.0.0.1":null}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		result, err := parseSNMPConfig(data)
		if err != nil && err.Error() != errSNMPConfig.Error() {
			t.Fatal("parser disclosed input")
		}
		if len(data) > maxSNMPConfigBytes && (err == nil || result != nil) {
			t.Fatal("unbounded config accepted")
		}
	})
}
