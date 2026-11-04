package app

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/NexusFireMan/gomap/v2/pkg/scanner"
)

// This is independent-agent interoperability, never part of normal offline CI.
func TestSNMPAgentInterop(t *testing.T) {
	if os.Getenv("GOMAP_RUN_SNMP_AGENT_TESTS") != "1" {
		t.Skip("opt-in disconnected Net-SNMP container test")
	}
	if runtime.GOOS != "linux" {
		t.Skip("Linux container fixture required")
	}
	image := os.Getenv("GOMAP_SNMP_AGENT_IMAGE")
	if image == "" || strings.HasPrefix(image, "-") {
		t.Fatal("set GOMAP_SNMP_AGENT_IMAGE to a locally built fixture image")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	private := t.TempDir()
	write := func(name string, data []byte, mode os.FileMode) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(private, name), data, mode); err != nil {
			t.Fatal("cannot prepare private fixture")
		}
	}
	secret := func() string {
		var entropy [24]byte
		if _, err := rand.Read(entropy[:]); err != nil {
			t.Fatal("cannot generate fixture secret")
		}
		return hex.EncodeToString(entropy[:])
	}
	authPassword, privacyPassword := secret(), secret()
	var usm, agent strings.Builder
	agent.WriteString("agentaddress udp:127.0.0.1:161\nsysDescr synthetic-gomap-agent\n")
	for _, auth := range []string{"256", "512"} {
		for _, privacy := range []string{"none", "aes128"} {
			name := "fixture" + auth + privacy
			fmt.Fprintf(&usm, "createUser %s SHA-%s %s", name, auth, authPassword)
			if privacy != "none" {
				fmt.Fprintf(&usm, " AES %s", privacyPassword)
			}
			usm.WriteByte('\n')
			level := "auth"
			if privacy != "none" {
				level = "priv"
			}
			fmt.Fprintf(&agent, "rouser %s %s .1.3.6.1.2.1.1\n", name, level)
		}
	}
	write("usm.conf", []byte(usm.String()), 0600)
	write("snmpd.conf", []byte(agent.String()), 0600)
	working, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	build := exec.CommandContext(ctx, "go", "build", "-o", filepath.Join(private, "gomap"), ".")
	build.Dir = filepath.Clean(filepath.Join(working, "..", ".."))
	build.Env = append(os.Environ(), "CGO_ENABLED=0")
	if err := build.Run(); err != nil {
		t.Fatal("cannot build fixture binary")
	}
	command := exec.CommandContext(ctx, "docker", "run", "--rm", "--detach", "--network", "none", "--read-only",
		"--cap-drop", "ALL", "--cap-add", "NET_BIND_SERVICE", "--cap-add", "DAC_OVERRIDE",
		"--tmpfs", "/run:rw,mode=0700", "--tmpfs", "/var/lib/snmp:rw,mode=0700",
		"--volume", private+":/fixtures:ro", "--volume", filepath.Join(private, "snmpd.conf")+":/etc/snmp/snmpd.conf:ro", image)
	idBytes, err := command.Output()
	if err != nil {
		t.Fatal("cannot start disconnected fixture container")
	}
	id := strings.TrimSpace(string(idBytes))
	if decoded, err := hex.DecodeString(id); err != nil || len(decoded) != 32 {
		t.Fatal("unexpected fixture container ID")
	}
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 10*time.Second)
		defer stop()
		if err := exec.CommandContext(cleanup, "docker", "rm", "--force", id).Run(); err != nil {
			t.Error("cannot remove fixture container")
		}
	})
	ready := false
	for range 50 {
		if exec.CommandContext(ctx, "docker", "exec", id, "test", "-s", "/run/snmpd.pid").Run() == nil {
			ready = true
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !ready {
		t.Fatal("Net-SNMP fixture did not become ready; inspect privately without publishing credentials")
	}
	for _, auth := range []string{"256", "512"} {
		for _, privacy := range []string{"none", "aes128"} {
			for _, wrong := range []bool{false, true} {
				t.Run(auth+"/"+privacy+fmt.Sprint("/wrong=", wrong), func(t *testing.T) {
					entry := map[string]string{"username": "fixture" + auth + privacy, "auth_protocol": "sha" + auth,
						"auth_password": authPassword, "privacy_protocol": privacy}
					if privacy != "none" {
						entry["privacy_password"] = privacyPassword
					}
					if wrong {
						entry["auth_password"] = secret()
					}
					config, err := json.Marshal(map[string]any{"127.0.0.1": entry})
					if err != nil {
						t.Fatal("cannot encode private fixture")
					}
					write("snmp-private.json", config, 0600)
					var stdout, stderr bytes.Buffer
					timeout := "1000"
					if auth == "256" && privacy == "aes128" && !wrong {
						timeout = "400"
					}
					run := exec.CommandContext(ctx, "docker", "exec", id, "/fixtures/gomap", "-u", "-p", "161", "--timeout", timeout, "--adaptive-timeout=false",
						"--snmp-config", "/fixtures/snmp-private.json", "--format", "json", "127.0.0.1")
					if timeout == "400" {
						run.Args = append(run.Args, "--global-rate", "1")
					}
					run.Stdout, run.Stderr = &stdout, &stderr
					if err := run.Run(); err != nil {
						t.Fatal("fixture CLI failed; output withheld to protect ephemeral credentials")
					}
					for _, sensitive := range []string{authPassword, privacyPassword, entry["auth_password"], entry["username"], "synthetic-gomap-agent"} {
						if strings.Contains(stdout.String()+stderr.String(), sensitive) {
							t.Fatal("sensitive fixture data disclosed")
						}
					}
					var report struct {
						Hosts []struct {
							Results []scanner.ScanResult `json:"results"`
						} `json:"hosts"`
					}
					if json.Unmarshal(stdout.Bytes(), &report) != nil || len(report.Hosts) != 1 || len(report.Hosts[0].Results) != 1 {
						t.Fatal("invalid fixture report")
					}
					result := report.Hosts[0].Results[0]
					if !result.IsOpen || (result.Confidence == "high") == wrong {
						t.Fatalf("unexpected confirmation: %+v", result)
					}
				})
			}
		}
	}
}
