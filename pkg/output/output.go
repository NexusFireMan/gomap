package output

import (
	"fmt"
	"io"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/NexusFireMan/gomap/v2/pkg/scanner"
)

// OutputFormatter handles the formatting and display of scan results
type OutputFormatter struct {
	IncludeServices bool
	IncludeDetails  bool
	IncludeEvidence bool
	writer          io.Writer
	writeErr        error
}

// WriteResults renders a report to a writer and propagates write failures.
func (of *OutputFormatter) WriteResults(w io.Writer, results []scanner.ScanResult) error {
	copy := *of
	copy.writer, copy.writeErr = w, nil
	copy.PrintResults(results)
	return copy.writeErr
}

func (of *OutputFormatter) printf(format string, args ...any) {
	if of.writeErr != nil {
		return
	}
	w := of.writer
	if w == nil {
		w = DefaultWriter()
	}
	_, of.writeErr = fmt.Fprintf(w, format, args...)
}

var ansiPattern = regexp.MustCompile(`\x1b\[[0-9;]*m`)

const (
	portColWidth    = 7
	stateColWidth   = 6
	serviceColWidth = 15
)

// NewOutputFormatter creates a new OutputFormatter instance
func NewOutputFormatter(includeServices bool, includeDetails bool) *OutputFormatter {
	return &OutputFormatter{
		IncludeServices: includeServices,
		IncludeDetails:  includeDetails,
	}
}

// NewEvidenceOutputFormatter creates the compact deep-version output view.
func NewEvidenceOutputFormatter() *OutputFormatter {
	return &OutputFormatter{
		IncludeServices: true,
		IncludeEvidence: true,
	}
}

// visibleWidth calculates printable width without ANSI escape codes
func visibleWidth(text string) int {
	clean := ansiPattern.ReplaceAllString(text, "")
	return utf8.RuneCountInString(clean)
}

// padANSI right-pads colored text based on visible width
func padANSI(text string, width int) string {
	padding := width - visibleWidth(text)
	if padding <= 0 {
		return text
	}
	return text + strings.Repeat(" ", padding)
}

// PrintResults displays the scan results in a formatted table
func (of *OutputFormatter) PrintResults(results []scanner.ScanResult) {
	if of.IncludeServices {
		of.printWithServices(results)
	} else {
		of.printBasic(results)
	}
}

// printBasic prints results without service information
func (of *OutputFormatter) printBasic(results []scanner.ScanResult) {
	of.printf("%s%s%s\n", ColorBold, fmt.Sprintf("%-*s %-*s", portColWidth, "PORT", stateColWidth, "STATE"), ColorReset)
	for _, result := range results {
		of.printf("%s %s\n", padANSI(Port(result.Port), portColWidth), padANSI(State("open"), stateColWidth))
	}
}

// printWithServices prints results with service and version information
func (of *OutputFormatter) printWithServices(results []scanner.ScanResult) {
	if hostnames := detectedHostnames(results); len(hostnames) > 0 {
		of.printf("%s%s%s\n", ColorBold, "Detected Hostname: "+strings.Join(hostnames, ", "), ColorReset)
	}

	if of.IncludeEvidence {
		of.printf("%s%s%s\n", ColorBold, fmt.Sprintf("%-*s %-*s %-*s %-36s %s", portColWidth, "PORT", stateColWidth, "STATE", serviceColWidth, "SERVICE", "VERSION", "EVIDENCE"), ColorReset)
		for _, result := range results {
			of.printf("%s %s %s %-36s %s\n",
				padANSI(Port(result.Port), portColWidth),
				padANSI(State("open"), stateColWidth),
				padANSI(Service(result.ServiceName), serviceColWidth),
				padANSI(Version(result.Version), 36),
				result.Evidence,
			)
		}
		return
	}

	if of.IncludeDetails {
		of.printf("%s%s%s\n", ColorBold, fmt.Sprintf("%-*s %-*s %-*s %-36s %-7s %-8s %s", portColWidth, "PORT", stateColWidth, "STATE", serviceColWidth, "SERVICE", "VERSION", "LAT(ms)", "CONF", "EVIDENCE"), ColorReset)
		for _, result := range results {
			of.printf("%s %s %s %-36s %-7d %-8s %s\n",
				padANSI(Port(result.Port), portColWidth),
				padANSI(State("open"), stateColWidth),
				padANSI(Service(result.ServiceName), serviceColWidth),
				Version(result.Version),
				result.LatencyMs,
				result.Confidence,
				result.Evidence,
			)
		}
		return
	}

	of.printf("%s%s%s\n", ColorBold, fmt.Sprintf("%-*s %-*s %-*s %s", portColWidth, "PORT", stateColWidth, "STATE", serviceColWidth, "SERVICE", "VERSION"), ColorReset)
	for _, result := range results {
		of.printf("%s %s %s %s\n",
			padANSI(Port(result.Port), portColWidth),
			padANSI(State("open"), stateColWidth),
			padANSI(Service(result.ServiceName), serviceColWidth),
			Version(result.Version),
		)
	}
}

func detectedHostnames(results []scanner.ScanResult) []string {
	seen := make(map[string]struct{})
	hostnames := make([]string, 0, 2)
	for _, result := range results {
		name := strings.TrimSpace(result.Hostname)
		if name == "" {
			continue
		}
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		hostnames = append(hostnames, name)
	}
	return hostnames
}

// PrintBanner displays the application banner
func PrintBanner() {
	banner := `
  ██████╗  ██████╗ ███╗   ███╗ █████╗ ██████╗ 
 ██╔════╝ ██╔═══██╗████╗ ████║██╔══██╗██╔══██╗
 ██║  ███╗██║   ██║██╔████╔██║███████║██████╔╝
 ██║   ██║██║   ██║██║╚██╔╝██║██╔══██║██╔═══╝ 
 ╚██████╔╝╚██████╔╝██║ ╚═╝ ██║██║  ██║██║     
  ╚═════╝  ╚═════╝ ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝
`
	fmt.Printf("%s%s%s\n", ColorBrightCyan, banner, ColorReset)
}

// PrintScanStart displays the initial scan information
func PrintScanStart(host string, numPorts int) {
	fmt.Printf("Scanning %s (%s ports)\n\n", Host(host), Count(numPorts))
}
