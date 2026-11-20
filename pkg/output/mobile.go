package output

import (
	"fmt"
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
