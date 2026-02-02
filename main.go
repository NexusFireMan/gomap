package main

import (
	"flag"
	"fmt"
	"os"
	"time"
)

// ScanResult holds the result of a single port scan
type ScanResult struct {
	Port        int
	IsOpen      bool
	ServiceName string
	Version     string
}

func main() {
	var (
		portsFlag   string
		serviceFlag bool
		ghostFlag   bool
		updateFlag  bool
		versionFlag bool
		noDiscovery bool
	)

	flag.StringVar(&portsFlag, "p", "", "ports to scan (e.g., 80,443 or 1-1024 or - for all ports)")
	flag.BoolVar(&serviceFlag, "s", false, "detect services and versions")
	flag.BoolVar(&ghostFlag, "g", false, "ghost mode - slower, stealthy scan to evade IDS/Firewall detection")
	flag.BoolVar(&noDiscovery, "nd", false, "disable host discovery (scan all hosts in CIDR even if inactive)")
	flag.BoolVar(&updateFlag, "up", false, "update gomap to the latest version")
	flag.BoolVar(&versionFlag, "v", false, "show version information")

	// Custom usage message
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Gomap: A fast and simple port scanner written in Go.\n\n")
		fmt.Fprintf(os.Stderr, "Usage:\n  gomap <host|CIDR> [options]\n\n")
		fmt.Fprintf(os.Stderr, "Options:\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nNotes:\n")
		fmt.Fprintf(os.Stderr, "  - CIDR scans automatically discover active hosts first (can be disabled with -nd)\n")
		fmt.Fprintf(os.Stderr, "  - Host discovery probes ports: 443, 80, 22, 445, 3306, 8080, 3389\n")
		fmt.Fprintf(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "  gomap 127.0.0.1                              (Scan top ports on localhost)\n")
		fmt.Fprintf(os.Stderr, "  gomap -p 80,443,8080 192.168.1.1           (Scan specific ports on single IP)\n")
		fmt.Fprintf(os.Stderr, "  gomap -p 1-1024 -s 192.168.1.0/24          (Scan CIDR with auto host discovery)\n")
		fmt.Fprintf(os.Stderr, "  gomap -g -p 1-1024 10.0.0.0/25             (Stealthy ghost mode scan on CIDR)\n")
		fmt.Fprintf(os.Stderr, "  gomap -s -nd -p 22 192.168.1.0/24          (Scan all hosts, no discovery)\n")
	}

	flag.Parse()

	// Handle version flag
	if versionFlag {
		PrintVersion()
		os.Exit(0)
	}

	// Handle update flag
	if updateFlag {
		if err := CheckUpdate(); err != nil {
			fmt.Printf("Update failed: %v\n", err)
			PrintUpdateInfo()
			os.Exit(1)
		}
		os.Exit(0)
	}

	// Validate arguments
	if flag.NArg() != 1 {
		flag.Usage()
		os.Exit(1)
	}

	host := flag.Arg(0)

	// Initialize components
	portManager := NewPortManager()
	portsToScan, err := portManager.GetPortsToScan(portsFlag)
	if err != nil {
		fmt.Printf("Invalid port specification: %s\n", err)
		os.Exit(1)
	}

	// Parse target(s) - can be single IP, CIDR, or comma-separated IPs
	targets, err := ParseTargets(host)
	if err != nil {
		fmt.Printf("Invalid target specification: %s\n", err)
		os.Exit(1)
	}

	// If scanning CIDR/multiple hosts, perform host discovery first (unless disabled)
	if !noDiscovery && IsCIDR(host) && len(targets) > 1 {
		fmt.Printf("Discovering active hosts in %s...\n", host)

		discoveryTimeout := 500 * time.Millisecond
		discoveryWorkers := 50

		targets = DiscoverActiveHosts(targets, discoveryTimeout, discoveryWorkers)

		if len(targets) == 0 {
			fmt.Printf("No active hosts found in the specified range.\n")
			os.Exit(0)
		}
		fmt.Printf("Found %d active hosts, starting port scan...\n\n", len(targets))
	}

	// Display scan info
	if len(targets) == 1 {
		if ghostFlag {
			fmt.Printf("Scanning %s (%d ports) - Ghost mode (stealthy)\n\n", targets[0], len(portsToScan))
		} else {
			fmt.Printf("Scanning %s (%d ports)\n\n", targets[0], len(portsToScan))
		}
	} else {
		targetRange, _, _ := FormatCIDRInfo(host)
		if ghostFlag {
			fmt.Printf("Scanning %s (%d active hosts, %d ports) - Ghost mode (stealthy)\n\n", targetRange, len(targets), len(portsToScan))
		} else {
			fmt.Printf("Scanning %s (%d active hosts, %d ports)\n\n", targetRange, len(targets), len(portsToScan))
		}
	}

	// Display results
	formatter := NewOutputFormatter(serviceFlag)

	// Scan each target
	allResults := make(map[string][]ScanResult)
	for _, targetIP := range targets {
		scanner := NewScanner(targetIP, ghostFlag)
		openPorts := scanner.Scan(portsToScan, serviceFlag)
		if len(openPorts) > 0 {
			allResults[targetIP] = openPorts
		}
	}

	// Print results grouped by IP
	for _, targetIP := range targets {
		if results, exists := allResults[targetIP]; exists {
			if len(targets) > 1 {
				fmt.Printf("\n=== %s ===\n", targetIP)
			}
			formatter.PrintResults(results)
		}
	}
}
