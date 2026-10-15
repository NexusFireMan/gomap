package output

import (
	"fmt"
	"io"
	"time"

	"github.com/NexusFireMan/gomap/v2/pkg/scanner"
)

// Coverage counts host-port outcomes, not probes, retries or identified services.
type Coverage struct {
	Requested         int     `json:"requested"`
	Open              int     `json:"open"`
	Closed            int     `json:"closed"`
	Filtered          int     `json:"filtered"`
	OpenFiltered      int     `json:"open_filtered"`
	Unresolved        int     `json:"unresolved"`
	Unreported        int     `json:"unreported"`
	OpenClosedPercent float64 `json:"open_closed_percent"`
}

// SummarizeCoverage never infers closed/filtered states from missing results.
func SummarizeCoverage(ports []int, results []scanner.ScanResult, diag *scanner.ConnectDiagnostics) Coverage {
	// Port numbers are bounded; a stack-local table avoids full-range map allocation.
	var wanted [1 << 16]uint8
	c := Coverage{}
	for _, port := range ports {
		if port > 0 && port < len(wanted) && wanted[port] == 0 {
			wanted[port] = 1
			c.Requested++
		}
	}
	for _, result := range results {
		if result.Port <= 0 || result.Port >= len(wanted) || wanted[result.Port] != 1 {
			continue
		}
		wanted[result.Port] = 2
		switch result.EffectiveState() {
		case "open":
			c.Open++
		case "closed":
			c.Closed++
		case "filtered":
			c.Filtered++
		case "open|filtered":
			c.OpenFiltered++
		default:
			c.Unresolved++
		}
	}
	remaining := c.Requested - c.Open - c.Closed - c.Filtered - c.OpenFiltered - c.Unresolved
	if diag != nil {
		// CONNECT returns only open results; refusals and failures live in diagnostics.
		closed := min(remaining, max(0, diag.RefusedPorts))
		c.Closed += closed
		remaining -= closed
		unresolved := min(remaining, max(0, diag.UnresolvedPorts))
		c.Unresolved += unresolved
		remaining -= unresolved
	}
	c.Unreported = remaining
	c.updatePercent()
	return c
}

func (c *Coverage) updatePercent() {
	if c.Requested > 0 {
		c.OpenClosedPercent = 100 * float64(c.Open+c.Closed) / float64(c.Requested)
	}
}

func (c *Coverage) Add(other Coverage) {
	c.Requested += other.Requested
	c.Open += other.Open
	c.Closed += other.Closed
	c.Filtered += other.Filtered
	c.OpenFiltered += other.OpenFiltered
	c.Unresolved += other.Unresolved
	c.Unreported += other.Unreported
	c.updatePercent()
}

func (c Coverage) Inconclusive() int {
	return c.OpenFiltered + c.Unresolved + c.Unreported
}

type BuildInfo struct {
	Version string `json:"version"`
	Commit  string `json:"commit,omitempty"`
	Date    string `json:"date,omitempty"`
}

// ScanOptions is a whitelist: never serialize arbitrary argv, source pools or banners.
type ScanOptions struct {
	ScanType        string `json:"scan_type"`
	UDP             bool   `json:"udp"`
	Ports           string `json:"ports"`
	TopPorts        int    `json:"top_ports"`
	ExcludePorts    string `json:"exclude_ports"`
	NoDiscovery     bool   `json:"no_discovery"`
	MaxHosts        int    `json:"max_hosts"`
	ServiceDetect   bool   `json:"service_detection"`
	DeepVersion     bool   `json:"deep_version"`
	Exhaustive      bool   `json:"exhaustive"`
	GhostMode       bool   `json:"low_noise"`
	Workers         int    `json:"workers"`
	TimeoutMS       int    `json:"timeout_ms"`
	Retries         int    `json:"retries"`
	AdaptiveTimeout bool   `json:"adaptive_timeout"`
	MaxTimeoutMS    int    `json:"max_timeout_ms"`
	BackoffMS       int    `json:"backoff_ms"`
	Rate            int    `json:"rate"`
	GlobalRate      int    `json:"global_rate"`
}

type PhaseTimings struct {
	TotalMS           int64 `json:"total_ms"`
	PreparationMS     int64 `json:"preparation_ms"`
	HostDiscoveryMS   int64 `json:"host_discovery_ms"`
	ScanAndServicesMS int64 `json:"scan_and_services_ms"`
}

type HostMetrics struct {
	Host              string   `json:"host"`
	Engine            string   `json:"engine_used"`
	ScanAndServicesMS int64    `json:"scan_and_services_ms"`
	Coverage          Coverage `json:"coverage"`
}

type ScanMetrics struct {
	Build                        BuildInfo     `json:"build"`
	Options                      ScanOptions   `json:"options"`
	ExpandedHosts                int           `json:"expanded_hosts"`
	Timings                      PhaseTimings  `json:"timings"`
	ScopeHostPortsPerSecond      float64       `json:"scope_host_ports_per_second"`
	OpenClosedHostPortsPerSecond float64       `json:"open_closed_host_ports_per_second"`
	Coverage                     Coverage      `json:"coverage"`
	Hosts                        []HostMetrics `json:"hosts"`
}

// SetTimings excludes rendering/cleanup; scan time includes inline service detection.
func (m *ScanMetrics) SetTimings(total, discovery, scan time.Duration) {
	total, discovery, scan = max(0, total), max(0, discovery), max(0, scan)
	m.Timings = PhaseTimings{
		TotalMS: total.Milliseconds(), PreparationMS: max(0, total-discovery-scan).Milliseconds(),
		HostDiscoveryMS: discovery.Milliseconds(), ScanAndServicesMS: scan.Milliseconds(),
	}
	m.ScopeHostPortsPerSecond, m.OpenClosedHostPortsPerSecond = 0, 0
	if scan > 0 {
		m.ScopeHostPortsPerSecond = float64(m.Coverage.Requested) / scan.Seconds()
		m.OpenClosedHostPortsPerSecond = float64(m.Coverage.Open+m.Coverage.Closed) / scan.Seconds()
	}
}

func WriteScanMetrics(w io.Writer, metrics ScanMetrics) error {
	version := metrics.Build.Version
	if version == "" {
		version = "unknown"
	}
	if _, err := fmt.Fprintf(w, "\nPerformance (GoMap %s)\n- host-ports/s: scope %.2f | confirmed open/closed %.2f\n- time (ms): preparation %d | host discovery %d | scan+services %d | total before report/cleanup %d\n- hosts: expanded %d | scanned %d; coverage applies to scanned hosts only\n\nCoverage\n",
		terminalText(version),
		metrics.ScopeHostPortsPerSecond, metrics.OpenClosedHostPortsPerSecond,
		metrics.Timings.PreparationMS, metrics.Timings.HostDiscoveryMS, metrics.Timings.ScanAndServicesMS, metrics.Timings.TotalMS,
		metrics.ExpandedHosts, len(metrics.Hosts)); err != nil {
		return err
	}
	writeCoverage := func(label string, c Coverage) error {
		_, err := fmt.Fprintf(w, "- %s | requested: %d | open: %d | closed: %d | filtered: %d | open|filtered: %d | unresolved: %d | unreported: %d | open/closed evidence: %.1f%%\n",
			terminalText(label), c.Requested, c.Open, c.Closed, c.Filtered, c.OpenFiltered, c.Unresolved, c.Unreported, c.OpenClosedPercent)
		return err
	}
	for _, host := range metrics.Hosts {
		if err := writeCoverage(fmt.Sprintf("%s (%s, scan+services %d ms)", host.Host, host.Engine, host.ScanAndServicesMS), host.Coverage); err != nil {
			return err
		}
	}
	return writeCoverage("total", metrics.Coverage)
}
