package gomap

import (
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/NexusFireMan/gomap/pkg/output"
	"github.com/NexusFireMan/gomap/pkg/scanner"
)

func Run() {
	var (
		portsFlag   string
		serviceFlag bool
		ghostFlag   bool
		updateFlag  bool
		removeFlag  bool
		versionFlag bool
		noDiscovery bool
	)

	flag.StringVar(&portsFlag, "p", "", "ports to scan (e.g., 80,443 or 1-1024 or - for all ports)")
	flag.BoolVar(&serviceFlag, "s", false, "detect services and versions")
	flag.BoolVar(&ghostFlag, "g", false, "ghost mode - slower, stealthy scan to evade IDS/Firewall detection")
	flag.BoolVar(&noDiscovery, "nd", false, "disable host discovery (scan all hosts in CIDR even if inactive)")
	flag.BoolVar(&updateFlag, "up", false, "update gomap to the latest version")
	flag.BoolVar(&removeFlag, "remove", false, "remove gomap from the system (/usr/local/bin)")
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

	// Handle remove flag
	if removeFlag {
		if err := RemoveGomap(); err != nil {
			fmt.Printf("%s\n", output.StatusError(fmt.Sprintf("Removal failed: %v", err)))
			os.Exit(1)
		}
		os.Exit(0)
	}

	// Handle update flag
	if updateFlag {
		if err := CheckUpdate(); err != nil {
			fmt.Printf("%s\n", output.StatusError(fmt.Sprintf("Update failed: %v", err)))
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
	portManager := scanner.NewPortManager()
	portsToScan, err := portManager.GetPortsToScan(portsFlag)
	if err != nil {
		fmt.Printf("%s\n", output.StatusError(fmt.Sprintf("Invalid port specification: %s", err)))
		os.Exit(1)
	}

	// Parse target(s) - can be single IP, CIDR, or comma-separated IPs
	targets, err := scanner.ParseTargets(host)
	if err != nil {
		fmt.Printf("%s\n", output.StatusError(fmt.Sprintf("Invalid target specification: %s", err)))
		os.Exit(1)
	}

	// If scanning CIDR/multiple hosts, perform host discovery first (unless disabled)
	if !noDiscovery && scanner.IsCIDR(host) && len(targets) > 1 {
		fmt.Printf("%s\n", output.Info(fmt.Sprintf("🔍 Discovering active hosts in %s...", output.Host(host))))

		discoveryTimeout := 500 * time.Millisecond
		discoveryWorkers := 50

		targets = scanner.DiscoverActiveHosts(targets, discoveryTimeout, discoveryWorkers)

		if len(targets) == 0 {
			fmt.Printf("%s\n", output.StatusWarn("No active hosts found in the specified range."))
			os.Exit(0)
		}
		fmt.Printf("%s\n\n", output.Success(fmt.Sprintf("✓ Found %s active hosts, starting port scan...", output.Count(len(targets)))))
	}

	// Display scan info
	if len(targets) == 1 {
		if ghostFlag {
			fmt.Printf("%s\n\n", output.Info(fmt.Sprintf("🎯 Scanning %s (%s ports) - %s (stealthy)", output.Host(targets[0]), output.Count(len(portsToScan)), output.Warning("Ghost mode"))))
		} else {
			fmt.Printf("%s\n\n", output.Info(fmt.Sprintf("🎯 Scanning %s (%s ports)", output.Host(targets[0]), output.Count(len(portsToScan)))))
		}
	} else {
		targetRange, _, _ := scanner.FormatCIDRInfo(host)
		if ghostFlag {
			fmt.Printf("%s\n\n", output.Info(fmt.Sprintf("🎯 Scanning %s (%s active hosts, %s ports) - %s (stealthy)", output.Highlight(targetRange), output.Count(len(targets)), output.Count(len(portsToScan)), output.Warning("Ghost mode"))))
		} else {
			fmt.Printf("%s\n\n", output.Info(fmt.Sprintf("🎯 Scanning %s (%s active hosts, %s ports)", output.Highlight(targetRange), output.Count(len(targets)), output.Count(len(portsToScan)))))
		}
	}

	// Display results
	formatter := output.NewOutputFormatter(serviceFlag)

	// Scan each target
	allResults := make(map[string][]scanner.ScanResult)
	for _, targetIP := range targets {
		scanner := scanner.NewScanner(targetIP, ghostFlag)
		openPorts := scanner.Scan(portsToScan, serviceFlag)
		if len(openPorts) > 0 {
			allResults[targetIP] = openPorts
		}
	}

	// Print results grouped by IP
	for _, targetIP := range targets {
		if results, exists := allResults[targetIP]; exists {
			if len(targets) > 1 {
				fmt.Printf("\n%s\n", output.Highlight(fmt.Sprintf("═══ %s ═══", output.Host(targetIP))))
			}
			formatter.PrintResults(results)
		}
	}
}
