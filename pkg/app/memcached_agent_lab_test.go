package app

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/NexusFireMan/gomap/v2/pkg/scanner"
)

func TestMemcachedAgentInterop(t *testing.T) {
	if os.Getenv("GOMAP_RUN_MEMCACHED_AGENT_TESTS") != "1" {
		t.Skip("opt-in disconnected Memcached container test")
	}
	if runtime.GOOS != "linux" {
		t.Skip("Linux container fixture required")
	}
	image := os.Getenv("GOMAP_MEMCACHED_AGENT_IMAGE")
	if image == "" || strings.HasPrefix(image, "-") {
		t.Fatal("set GOMAP_MEMCACHED_AGENT_IMAGE to a locally available fixture image")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	binary := filepath.Join(t.TempDir(), "gomap")
	working, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	build := exec.CommandContext(ctx, "go", "build", "-o", binary, ".")
	build.Dir, build.Env = filepath.Clean(filepath.Join(working, "..", "..")), append(os.Environ(), "CGO_ENABLED=0")
	if err := build.Run(); err != nil {
		t.Fatal("cannot build fixture binary")
	}
	idBytes, err := exec.CommandContext(ctx, "docker", "run", "--rm", "--detach", "--network", "none", "--read-only", "--cap-drop", "ALL",
		"--volume", binary+":/gomap:ro", image, "-U", "11211", "-p", "11211", "-l", "127.0.0.1").Output()
	if err != nil {
		t.Fatal("cannot start disconnected Memcached container")
	}
	id := strings.TrimSpace(string(idBytes))
	if decoded, err := hex.DecodeString(id); err != nil || len(decoded) != 32 {
		t.Fatal("unexpected fixture container ID")
	}
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 10*time.Second)
		defer stop()
		if err := exec.CommandContext(cleanup, "docker", "rm", "--force", id).Run(); err != nil {
			t.Error("cannot remove Memcached fixture")
		}
	})
	run := func(args ...string) ([]byte, error) {
		return exec.CommandContext(ctx, "docker", append([]string{"exec", id, "/gomap"}, args...)...).Output()
	}
	ready := false
	for range 30 {
		data, err := run("-p", "11211", "--timeout", "200", "--format", "json", "127.0.0.1")
		var report struct {
			Open int `json:"total_open_ports"`
		}
		if err == nil && json.Unmarshal(data, &report) == nil && report.Open == 1 {
			ready = true
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !ready {
		t.Fatal("Memcached fixture did not become ready")
	}
	for _, deep := range []bool{false, true} {
		mode := "-s"
		if deep {
			mode = "-Dv"
		}
		data, err := run("-u", mode, "-p", "11211", "--timeout", "1000", "--adaptive-timeout=false", "--format", "json", "127.0.0.1")
		if err != nil {
			t.Fatal("fixture CLI failed")
		}
		var report struct {
			Hosts []struct {
				Results []scanner.ScanResult `json:"results"`
			} `json:"hosts"`
		}
		if json.Unmarshal(data, &report) != nil || len(report.Hosts) != 1 || len(report.Hosts[0].Results) != 1 {
			t.Fatal("invalid fixture report")
		}
		result := report.Hosts[0].Results[0]
		if !deep {
			if result.Version != "" || result.Confidence != "low" {
				t.Fatal("default query unexpectedly changed")
			}
			continue
		}
		if !result.IsOpen || result.ServiceName != "memcached" || result.Confidence != "medium" || !strings.HasPrefix(result.Version, "Memcached 1.6.") {
			t.Fatalf("bad fixture identification: %+v", result)
		}
		counts := regexp.MustCompile(`fragments=([0-9]+); bytes=([0-9]+);`).FindStringSubmatch(result.Evidence)
		if len(counts) != 3 {
			t.Fatal("fragment evidence absent")
		}
		fragments, err := strconv.Atoi(counts[1])
		if err != nil || fragments < 2 || fragments > 16 {
			t.Fatal("fixture did not exercise bounded multi-datagram reassembly")
		}
		if strings.Contains(string(data), "STAT ") {
			t.Fatal("raw statistics disclosed")
		}
		t.Logf("%s; %s", result.Version, result.Evidence)
	}
}
