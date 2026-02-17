package output

import (
	"fmt"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/NexusFireMan/gomap/v2/pkg/scanner"
)

// OutputFormatter handles the formatting and display of scan results
type OutputFormatter struct {
	IncludeServices bool
	IncludeDetails  bool
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
	fmt.Printf("%s%s%s\n", ColorBold, fmt.Sprintf("%-*s %-*s", portColWidth, "PORT", stateColWidth, "STATE"), ColorReset)
	for _, result := range results {
		fmt.Printf("%s %s\n", padANSI(Port(result.Port), portColWidth), padANSI(State("open"), stateColWidth))
	}
}

// printWithServices prints results with service and version information
func (of *OutputFormatter) printWithServices(results []scanner.ScanResult) {
	if of.IncludeDetails {
		fmt.Printf("%s%s%s\n", ColorBold, fmt.Sprintf("%-*s %-*s %-*s %-36s %-7s %-8s %s", portColWidth, "PORT", stateColWidth, "STATE", serviceColWidth, "SERVICE", "VERSION", "LAT(ms)", "CONF", "EVIDENCE"), ColorReset)
		for _, result := range results {
			fmt.Printf("%s %s %s %-36s %-7d %-8s %s\n",
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

	fmt.Printf("%s%s%s\n", ColorBold, fmt.Sprintf("%-*s %-*s %-*s %s", portColWidth, "PORT", stateColWidth, "STATE", serviceColWidth, "SERVICE", "VERSION"), ColorReset)
	for _, result := range results {
		fmt.Printf("%s %s %s %s\n",
			padANSI(Port(result.Port), portColWidth),
			padANSI(State("open"), stateColWidth),
			padANSI(Service(result.ServiceName), serviceColWidth),
			Version(result.Version),
		)
	}
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
