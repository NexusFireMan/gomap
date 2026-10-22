package app

import (
	"encoding/json"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/NexusFireMan/gomap/v2/pkg/scanner"
)

func TestRecoveryFlagReachesNativeScanAndJSON(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	file := filepath.Join(t.TempDir(), "scan.json")
	if err := ExecuteScan(ScanRequest{Target: "127.0.0.1", PortsFlag: strconv.Itoa(listener.Addr().(*net.TCPAddr).Port), Format: "json", OutputPath: file, RecoverTimeouts: true, Workers: 1, TimeoutMS: 100}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	var report struct {
		Hosts []struct {
			Diag scanner.ConnectDiagnostics `json:"connect_diagnostics"`
		} `json:"hosts"`
	}
	if err := json.Unmarshal(data, &report); err != nil || len(report.Hosts) != 1 {
		t.Fatalf("invalid JSON: %s %v", data, err)
	}
	r := report.Hosts[0].Diag.Recovery
	if r == nil || r.Stop != "no_timeouts" || r.InitialOpen != 1 || r.Attempts != 0 || !strings.Contains(string(data), `"recover_timeouts": true`) {
		t.Fatalf("recovery option was not wired through: %s", data)
	}
}

func TestRecoveryRequestValidation(t *testing.T) {
	for _, req := range []ScanRequest{
		{RecoverTimeouts: true, UDP: true},
		{RecoverTimeouts: true, ScanType: "syn"},
		{RecoverTimeouts: true, GhostMode: true},
	} {
		if err := ExecuteScan(req); err == nil || !strings.Contains(err.Error(), "--recover-timeouts") {
			t.Fatalf("unsupported engine accepted: %+v %v", req, err)
		}
	}
	if !newScanMetrics(ScanRequest{RecoverTimeouts: true}, 1).Options.RecoverTimeouts {
		t.Fatal("reproducibility context lost recovery setting")
	}
}

func TestRecoverySummaryWithNoRemainingUncertainty(t *testing.T) {
	text := connectWarnings([]string{"fixture"}, map[string]scanner.ConnectDiagnostics{
		"fixture": {Recovery: &scanner.TimeoutRecoveryDiagnostics{Attempts: 1, Refused: 1, Stop: "completed"}},
	})
	if !strings.Contains(text, "attempts=1, open=0, refused=1") || strings.Contains(text, "discovery inconclusive") {
		t.Fatalf("incorrect recovery summary: %s", text)
	}
}

func TestRecoveryStreamingKeepsOneJSONLRecord(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	file := filepath.Join(t.TempDir(), "scan.jsonl")
	if err := ExecuteScan(ScanRequest{Target: "127.0.0.1", PortsFlag: strconv.Itoa(listener.Addr().(*net.TCPAddr).Port), Format: "jsonl", OutputPath: file, RecoverTimeouts: true, Stream: true, Workers: 1, TimeoutMS: 100}); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(file)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	d := json.NewDecoder(f)
	var row map[string]any
	if err := d.Decode(&row); err != nil || row["state"] != "open" {
		t.Fatalf("invalid JSONL row: %+v %v", row, err)
	}
	if err := d.Decode(&row); err != io.EOF {
		t.Fatalf("duplicate row or diagnostics in JSONL output: %v", err)
	}
}
