package app

import (
	"bytes"
	"encoding/json"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestStreamOutputDoesNotRepeatFinalResults(t *testing.T) {
	for _, format := range []string{"text", "jsonl"} {
		t.Run(format, func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = listener.Close() }()
			port := listener.Addr().(*net.TCPAddr).Port
			path := filepath.Join(t.TempDir(), "stream")
			err = ExecuteScan(ScanRequest{Target: "127.0.0.1", PortsFlag: strconv.Itoa(port), Format: format, Stream: true, OutputPath: path})
			if err != nil {
				t.Fatal(err)
			}
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if format == "text" {
				if strings.Count(string(data), listener.Addr().String()+" open") != 1 || !bytes.Contains(data, []byte("Host Exposure Summary")) || bytes.Contains(data, []byte("PORT    STATE")) {
					t.Fatalf("incorrect streaming text: %q", data)
				}
				return
			}
			decoder := json.NewDecoder(bytes.NewReader(data))
			var record map[string]any
			if err := decoder.Decode(&record); err != nil {
				t.Fatal(err)
			}
			if record["port"] != float64(port) || record["state"] != "open" || record["host"] != "127.0.0.1" || record["schema_version"] == nil {
				t.Fatalf("record=%+v", record)
			}
			if err := decoder.Decode(&record); err != io.EOF {
				t.Fatalf("duplicate record or contaminated JSONL: %v", err)
			}
		})
	}
}

func TestStreamRejectsUnsupportedModesBeforeCreatingOutput(t *testing.T) {
	for _, req := range []ScanRequest{
		{Format: "json"}, {Format: "csv"}, {Format: "text", UDP: true}, {Format: "text", ScanType: "syn"},
	} {
		req.Stream = true
		req.Target = "127.0.0.1"
		req.OutputPath = filepath.Join(t.TempDir(), "must-not-exist")
		if err := ExecuteScan(req); err == nil || !strings.Contains(err.Error(), "--stream") {
			t.Fatalf("req=%+v err=%v", req, err)
		}
		if _, err := os.Stat(req.OutputPath); !os.IsNotExist(err) {
			t.Fatalf("output created for invalid mode: %v", err)
		}
	}
}
