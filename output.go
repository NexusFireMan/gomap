package main

import (
	"fmt"
)

// OutputFormatter handles the formatting and display of scan results
type OutputFormatter struct {
	IncludeServices bool
}

// NewOutputFormatter creates a new OutputFormatter instance
func NewOutputFormatter(includeServices bool) *OutputFormatter {
	return &OutputFormatter{
		IncludeServices: includeServices,
	}
}

// PrintResults displays the scan results in a formatted table
func (of *OutputFormatter) PrintResults(results []ScanResult) {
	if of.IncludeServices {
		of.printWithServices(results)
	} else {
		of.printBasic(results)
	}
}

// printBasic prints results without service information
func (of *OutputFormatter) printBasic(results []ScanResult) {
	fmt.Printf("%s % -7s %s%s\n", ColorBold, "PORT", "STATE", ColorReset)
	for _, result := range results {
		fmt.Printf("% -7s %s\n", Port(result.Port), State("open"))
	}
}

// printWithServices prints results with service and version information
func (of *OutputFormatter) printWithServices(results []ScanResult) {
	fmt.Printf("%s % -7s % -6s % -12s %s%s\n", ColorBold, "PORT", "STATE", "SERVICE", "VERSION", ColorReset)
	for _, result := range results {
		fmt.Printf("% -7s % -6s % -12s %s\n", Port(result.Port), State("open"), Service(result.ServiceName), Version(result.Version))
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
