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
	fmt.Printf("% -7s %s\n", "PORT", "STATE")
	for _, result := range results {
		fmt.Printf("% -7d %s\n", result.Port, "open")
	}
}

// printWithServices prints results with service and version information
func (of *OutputFormatter) printWithServices(results []ScanResult) {
	fmt.Printf("% -7s % -6s % -12s %s\n", "PORT", "STATE", "SERVICE", "VERSION")
	for _, result := range results {
		fmt.Printf("% -7d % -6s % -12s %s\n", result.Port, "open", result.ServiceName, result.Version)
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
	fmt.Println(banner)
}

// PrintScanStart displays the initial scan information
func PrintScanStart(host string, numPorts int) {
	fmt.Printf("Scanning %s (%d ports)\n\n", host, numPorts)
}
