package output

import (
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"

	"github.com/NexusFireMan/gomap/v2/pkg/scanner"
)

// Compact blocks rely on terminal soft wrapping, not guessed Unicode cell widths.
// Never truncate evidence or introduce width-dependent fields into machine output.
func (of *OutputFormatter) compactResult(host string, result scanner.ScanResult) string {
	var block strings.Builder
	port := strconv.Itoa(result.Port)
	if host != "" {
		port = net.JoinHostPort(terminalText(host), port)
	}
	fmt.Fprintf(&block, "%s %s", port, terminalText(result.EffectiveState()))
	if of.IncludeServices && result.ServiceName != "" {
		fmt.Fprintf(&block, " %s", terminalText(result.ServiceName))
	}
	block.WriteByte('\n')
	field := func(name, value string) {
		if value != "" {
			fmt.Fprintf(&block, "  %s: %s\n", name, terminalText(value))
		}
	}
	if of.IncludeServices {
		field("version", result.Version)
		field("hostname", result.Hostname)
	}
	if of.IncludeDetails {
		field("latency_ms", strconv.FormatInt(result.LatencyMs, 10))
		field("confidence", result.Confidence)
	}
	if of.IncludeDetails || of.IncludeEvidence {
		field("evidence", result.Evidence)
	}
	block.WriteByte('\n')
	return block.String()
}

// PrintMobileBanner avoids wide ASCII artwork in scan output.
func PrintMobileBanner(version string) {
	fmt.Printf("GoMap %s | mobile\n\n", terminalText(version))
}

// WriteMobileBlock writes sanitized fields without padding, truncation or a
// report-sized buffer. Long values use the terminal's normal soft wrapping.
func WriteMobileBlock(w io.Writer, title string, fields ...[2]string) error {
	f := OutputFormatter{writer: w}
	f.printf("\n%s\n", terminalText(title))
	for _, field := range fields {
		f.printf("  %s: %s\n", terminalText(field[0]), terminalText(field[1]))
	}
	return f.writeErr
}

// WriteMobileScanMetrics preserves all counters and timing distinctions from the
// standard report; only presentation changes. Structured reports are untouched.
func WriteMobileScanMetrics(w io.Writer, m ScanMetrics) error {
	version := m.Build.Version
	if version == "" {
		version = "unknown"
	}
	if err := WriteMobileBlock(w, "Performance", [2]string{"GoMap", version},
		[2]string{"scope host-ports/s", fmt.Sprintf("%.2f", m.ScopeHostPortsPerSecond)},
		[2]string{"open/closed host-ports/s", fmt.Sprintf("%.2f", m.OpenClosedHostPortsPerSecond)},
		[2]string{"preparation ms", strconv.FormatInt(m.Timings.PreparationMS, 10)},
		[2]string{"host discovery ms", strconv.FormatInt(m.Timings.HostDiscoveryMS, 10)},
		[2]string{"scan+services ms", strconv.FormatInt(m.Timings.ScanAndServicesMS, 10)},
		[2]string{"before report/cleanup ms", strconv.FormatInt(m.Timings.TotalMS, 10)},
		[2]string{"expanded hosts", strconv.Itoa(m.ExpandedHosts)},
		[2]string{"scanned hosts", strconv.Itoa(len(m.Hosts))}); err != nil {
		return err
	}
	explainConnect, allConnect := false, len(m.Hosts) > 0
	for _, host := range m.Hosts {
		connect := host.Engine == "connect" || host.Engine == "connect (syn fallback)"
		explainConnect = explainConnect || connect && host.Coverage.Inconclusive() > 0
		allConnect = allConnect && connect
		if err := WriteMobileBlock(w, "Coverage: "+host.Host,
			[2]string{"engine", host.Engine}, [2]string{"scan+services ms", strconv.FormatInt(host.ScanAndServicesMS, 10)}); err != nil {
			return err
		}
		if err := writeMobileCoverage(w, host.Coverage, connect); err != nil {
			return err
		}
	}
	if err := WriteMobileBlock(w, "Coverage: total", [2]string{"scope", "scanned hosts only"}); err != nil {
		return err
	}
	if err := writeMobileCoverage(w, m.Coverage, allConnect); err != nil {
		return err
	}
	if explainConnect {
		return WriteMobileBlock(w, "CONNECT observations",
			[2]string{"closed", "connection refusals only"},
			[2]string{"filtered", "inferred from timeout"},
			[2]string{"or", "loss or insufficient wait"},
			[2]string{"inconclusive", "uncertain-state subtotal"},
			[2]string{"counts", "do not add subtotal again"})
	}
	return nil
}

func writeMobileCoverage(w io.Writer, c Coverage, connect bool) error {
	closed, filtered, unresolved := "closed", "filtered", "unresolved"
	if connect {
		closed, filtered, unresolved = "closed (refused)", "filtered (timeout-inferred)", "unresolved (other failures)"
	}
	f := OutputFormatter{writer: w}
	for _, field := range []struct {
		name  string
		value int
	}{
		{"requested", c.Requested}, {"open", c.Open}, {closed, c.Closed}, {filtered, c.Filtered}, {"open|filtered", c.OpenFiltered}, {unresolved, c.Unresolved}, {"unreported", c.Unreported}, {"inconclusive subtotal", c.Inconclusive()},
	} {
		f.printf("  %s: %d\n", field.name, field.value)
	}
	f.printf("  open/closed evidence: %s\n  evidence host-ports: %d/%d\n", coveragePercent(c), c.Open+c.Closed, c.Requested)
	return f.writeErr
}
