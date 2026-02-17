package output

import (
	"encoding/csv"
	"encoding/json"
	"io"
	"os"
	"strconv"
	"time"

	"github.com/NexusFireMan/gomap/pkg/scanner"
)

type hostReport struct {
	Host      string               `json:"host"`
	OpenPorts int                  `json:"open_ports"`
	Results   []scanner.ScanResult `json:"results"`
}

type scanReport struct {
	SchemaVersion  string       `json:"schema_version"`
	GeneratedAt    string       `json:"generated_at"`
	Target         string       `json:"target"`
	ServiceScan    bool         `json:"service_scan"`
	HostsScanned   int          `json:"hosts_scanned"`
	PortsRequested int          `json:"ports_requested"`
	TotalOpenPorts int          `json:"total_open_ports"`
	DurationMs     int64        `json:"duration_ms"`
	Hosts          []hostReport `json:"hosts"`
}

type jsonlRecord struct {
	SchemaVersion string `json:"schema_version"`
	GeneratedAt   string `json:"generated_at"`
	Target        string `json:"target"`
	Host          string `json:"host"`
	Port          int    `json:"port"`
	State         string `json:"state"`
	Service       string `json:"service,omitempty"`
	Version       string `json:"version,omitempty"`
	LatencyMs     int64  `json:"latency_ms,omitempty"`
	Confidence    string `json:"confidence,omitempty"`
	Evidence      string `json:"evidence,omitempty"`
	DetectionPath string `json:"detection_path,omitempty"`
}

const reportSchemaVersion = "1.0.0"

// PrintJSONReport prints the scan results in a machine-friendly JSON document.
func PrintJSONReport(w io.Writer, target string, ports []int, targets []string, allResults map[string][]scanner.ScanResult, serviceScan bool, duration time.Duration) error {
	report := scanReport{
		SchemaVersion:  reportSchemaVersion,
		GeneratedAt:    time.Now().UTC().Format(time.RFC3339),
		Target:         target,
		ServiceScan:    serviceScan,
		HostsScanned:   len(targets),
		PortsRequested: len(ports),
		DurationMs:     duration.Milliseconds(),
		Hosts:          make([]hostReport, 0, len(targets)),
	}

	for _, host := range targets {
		results := allResults[host]
		report.TotalOpenPorts += len(results)
		report.Hosts = append(report.Hosts, hostReport{
			Host:      host,
			OpenPorts: len(results),
			Results:   results,
		})
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(report)
}

// PrintCSVReport prints one row per open port.
func PrintCSVReport(writer io.Writer, allResults map[string][]scanner.ScanResult, targets []string) error {
	w := csv.NewWriter(writer)
	defer w.Flush()

	header := []string{"host", "port", "state", "service", "version", "latency_ms", "confidence", "evidence", "detection_path"}
	if err := w.Write(header); err != nil {
		return err
	}

	for _, host := range targets {
		results := allResults[host]
		for _, r := range results {
			row := []string{
				host,
				strconv.Itoa(r.Port),
				"open",
				r.ServiceName,
				r.Version,
				strconv.FormatInt(r.LatencyMs, 10),
				r.Confidence,
				r.Evidence,
				r.DetectionPath,
			}
			if err := w.Write(row); err != nil {
				return err
			}
		}
	}

	return w.Error()
}

// PrintJSONLReport prints one JSON object per open port.
func PrintJSONLReport(w io.Writer, target string, targets []string, allResults map[string][]scanner.ScanResult) error {
	enc := json.NewEncoder(w)
	for _, host := range targets {
		results := allResults[host]
		for _, r := range results {
			rec := jsonlRecord{
				SchemaVersion: reportSchemaVersion,
				GeneratedAt:   time.Now().UTC().Format(time.RFC3339),
				Target:        target,
				Host:          host,
				Port:          r.Port,
				State:         "open",
				Service:       r.ServiceName,
				Version:       r.Version,
				LatencyMs:     r.LatencyMs,
				Confidence:    r.Confidence,
				Evidence:      r.Evidence,
				DetectionPath: r.DetectionPath,
			}
			if err := enc.Encode(rec); err != nil {
				return err
			}
		}
	}
	return nil
}

// DefaultWriter returns stdout for output rendering.
func DefaultWriter() io.Writer {
	return os.Stdout
}
