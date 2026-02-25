package app

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/NexusFireMan/gomap/v2/pkg/output"
	"github.com/NexusFireMan/gomap/v2/pkg/scanner"
)

// ScanRequest contains normalized scan options coming from CLI.
type ScanRequest struct {
	Target          string
	PortsFlag       string
	ExcludePorts    string
	TopPorts        int
	Rate            int
	MaxHosts        int
	ServiceDetect   bool
	GhostMode       bool
	NoDiscovery     bool
	Format          string
	OutputPath      string
	TimeoutMS       int
	Workers         int
	Retries         int
	BackoffMS       int
	MaxTimeoutMS    int
	AdaptiveTimeout bool
	Details         bool
	RandomAgent     bool
	RandomIP        bool
}

// ExecuteScan runs the complete scan workflow: target expansion, host discovery, scan, and rendering.
func ExecuteScan(req ScanRequest) error {
	machineOutput := req.Format != "text"

	destWriter := output.DefaultWriter()
	var outFile *os.File
	if req.OutputPath != "" {
		var err error
		outFile, err = os.Create(req.OutputPath)
		if err != nil {
			return fmt.Errorf("cannot create output file: %w", err)
		}
		defer func() { _ = outFile.Close() }()
		destWriter = outFile
	}

	portManager := scanner.NewPortManager()
	var (
		portsToScan []int
		err         error
	)
	if req.TopPorts > 0 {
		top := scanner.GetTop1000Ports()
		limit := req.TopPorts
		if limit > len(top) {
			limit = len(top)
		}
		portsToScan = top[:limit]
	} else {
		portsToScan, err = portManager.GetPortsToScan(req.PortsFlag)
		if err != nil {
			return fmt.Errorf("invalid port specification: %w", err)
		}
	}
	if req.ExcludePorts != "" {
		portsToScan, err = filterExcludedPorts(portManager, portsToScan, req.ExcludePorts)
		if err != nil {
			return fmt.Errorf("invalid exclude-ports specification: %w", err)
		}
		if len(portsToScan) == 0 {
			return fmt.Errorf("no ports left to scan after applying --exclude-ports")
		}
	}

	targets, err := scanner.ParseTargets(req.Target)
	if err != nil {
		return fmt.Errorf("invalid target specification: %w", err)
	}
	if req.RandomIP && !scanner.IsCIDR(req.Target) && !machineOutput {
		fmt.Printf("%s\n", output.StatusWarn("--random-ip is most useful with CIDR targets; using local /24 approximation per host."))
	}

	if !req.NoDiscovery && scanner.IsCIDR(req.Target) && len(targets) > 1 {
		if !machineOutput {
			fmt.Printf("%s\n", output.Info(fmt.Sprintf("🔍 Discovering active hosts in %s...", output.Host(req.Target))))
		}
		discoveryOpts := scanner.DiscoveryOptions{
			Ports:      []int{443, 80, 22, 445, 3306, 8080, 3389},
			Timeout:    500 * time.Millisecond,
			NumWorkers: 50,
		}
		if req.GhostMode {
			// Ultra-stealth profile for CIDR discovery: fewer probe ports and lower concurrency.
			discoveryOpts = scanner.DiscoveryOptions{
				Ports:      []int{443, 80, 22},
				Timeout:    900 * time.Millisecond,
				NumWorkers: 12,
			}
			if !machineOutput {
				fmt.Printf("%s\n", output.StatusWarn("Ghost discovery profile active: low-noise probes on 443,80,22. Use -nd to skip discovery completely."))
			}
		}
		targets = scanner.DiscoverActiveHostsWithOptions(targets, discoveryOpts)
		if len(targets) == 0 {
			if machineOutput {
				empty := map[string][]scanner.ScanResult{}
				switch req.Format {
				case "json":
					_ = output.PrintJSONReport(destWriter, req.Target, portsToScan, targets, empty, req.ServiceDetect, 0)
				case "jsonl":
					_ = output.PrintJSONLReport(destWriter, req.Target, targets, empty)
				case "csv":
					_ = output.PrintCSVReport(destWriter, empty, targets)
				}
				if req.OutputPath != "" {
					fmt.Printf("%s\n", output.StatusOK(fmt.Sprintf("Saved %s output to %s", strings.ToUpper(req.Format), req.OutputPath)))
				}
				return nil
			}
			fmt.Printf("%s\n", output.StatusWarn("No active hosts found in the specified range."))
			return nil
		}

		if !machineOutput {
			fmt.Printf("%s\n\n", output.Success(fmt.Sprintf("✓ Found %s active hosts, starting port scan...", output.Count(len(targets)))))
		}
	}
	if req.MaxHosts > 0 && len(targets) > req.MaxHosts {
		if !machineOutput {
			fmt.Printf("%s\n", output.StatusWarn(fmt.Sprintf("Limiting scan to first %d host(s) due to --max-hosts.", req.MaxHosts)))
		}
		targets = targets[:req.MaxHosts]
	}

	if !machineOutput {
		if len(targets) == 1 {
			if req.GhostMode {
				fmt.Printf("%s\n\n", output.Info(fmt.Sprintf("🎯 Scanning %s (%s ports) - %s (stealthy)", output.Host(targets[0]), output.Count(len(portsToScan)), output.Warning("Ghost mode"))))
			} else {
				fmt.Printf("%s\n\n", output.Info(fmt.Sprintf("🎯 Scanning %s (%s ports)", output.Host(targets[0]), output.Count(len(portsToScan)))))
			}
		} else {
			targetRange, _, _ := scanner.FormatCIDRInfo(req.Target)
			if req.GhostMode {
				fmt.Printf("%s\n\n", output.Info(fmt.Sprintf("🎯 Scanning %s (%s active hosts, %s ports) - %s (stealthy)", output.Highlight(targetRange), output.Count(len(targets)), output.Count(len(portsToScan)), output.Warning("Ghost mode"))))
			} else {
				fmt.Printf("%s\n\n", output.Info(fmt.Sprintf("🎯 Scanning %s (%s active hosts, %s ports)", output.Highlight(targetRange), output.Count(len(targets)), output.Count(len(portsToScan)))))
			}
		}
	}

	formatter := output.NewOutputFormatter(req.ServiceDetect, req.Details)
	allResults := make(map[string][]scanner.ScanResult)
	scanStart := time.Now()

	var timeoutDuration time.Duration
	if req.TimeoutMS > 0 {
		timeoutDuration = time.Duration(req.TimeoutMS) * time.Millisecond
	}
	var maxTimeoutDuration time.Duration
	if req.MaxTimeoutMS > 0 {
		maxTimeoutDuration = time.Duration(req.MaxTimeoutMS) * time.Millisecond
	}
	for _, targetIP := range targets {
		s := scanner.NewScanner(targetIP, req.GhostMode)
		cidrForHeaders := ""
		if req.RandomIP && scanner.IsCIDR(req.Target) {
			cidrForHeaders = req.Target
		}
		s.Configure(scanner.ScanConfig{
			NumWorkers:      req.Workers,
			Timeout:         timeoutDuration,
			Retries:         req.Retries,
			Rate:            req.Rate,
			AdaptiveTimeout: req.AdaptiveTimeout,
			BackoffBase:     time.Duration(req.BackoffMS) * time.Millisecond,
			MaxTimeout:      maxTimeoutDuration,
			RandomAgent:     req.RandomAgent,
			RandomIP:        req.RandomIP,
			TargetCIDR:      cidrForHeaders,
		})
		openPorts := s.Scan(portsToScan, req.ServiceDetect)
		if len(openPorts) > 0 {
			allResults[targetIP] = openPorts
		}
	}
	scanDuration := time.Since(scanStart)

	if machineOutput {
		var renderErr error
		switch req.Format {
		case "json":
			renderErr = output.PrintJSONReport(destWriter, req.Target, portsToScan, targets, allResults, req.ServiceDetect, scanDuration)
		case "jsonl":
			renderErr = output.PrintJSONLReport(destWriter, req.Target, targets, allResults)
		case "csv":
			renderErr = output.PrintCSVReport(destWriter, allResults, targets)
		default:
			renderErr = fmt.Errorf("unsupported output format: %s", req.Format)
		}
		if renderErr != nil {
			return fmt.Errorf("failed to render %s output: %w", req.Format, renderErr)
		}
		if req.OutputPath != "" {
			fmt.Printf("%s\n", output.StatusOK(fmt.Sprintf("Saved %s output to %s", strings.ToUpper(req.Format), req.OutputPath)))
		}
		return nil
	}

	totalOpen := 0
	for _, targetIP := range targets {
		if results, exists := allResults[targetIP]; exists {
			totalOpen += len(results)
			if len(targets) > 1 {
				fmt.Printf("\n%s\n", output.Highlight(fmt.Sprintf("═══ %s ═══", output.Host(targetIP))))
			}
			formatter.PrintResults(results)
		}
	}
	printHostSummaries(targets, allResults)
	fmt.Printf("\n%s\n", output.StatusOK(fmt.Sprintf("Completed scan in %s | hosts: %d | open ports: %d", scanDuration.Round(time.Millisecond), len(targets), totalOpen)))
	return nil
}

func filterExcludedPorts(pm *scanner.PortManager, ports []int, excludeSpec string) ([]int, error) {
	excluded, err := pm.ParsePorts(excludeSpec)
	if err != nil {
		return nil, err
	}
	excludedSet := make(map[int]struct{}, len(excluded))
	for _, p := range excluded {
		excludedSet[p] = struct{}{}
	}

	filtered := make([]int, 0, len(ports))
	for _, p := range ports {
		if _, skip := excludedSet[p]; skip {
			continue
		}
		filtered = append(filtered, p)
	}
	return filtered, nil
}

func printHostSummaries(targets []string, allResults map[string][]scanner.ScanResult) {
	fmt.Printf("\n%s\n", output.Bold("Host Exposure Summary"))
	for _, host := range targets {
		results := allResults[host]
		open := len(results)
		critical := criticalServices(results)
		exposure := exposureLevel(open, len(critical))

		criticalStr := "none"
		if len(critical) > 0 {
			criticalStr = strings.Join(critical, ", ")
		}
		fmt.Printf("- %s | open ports: %d | critical: %s | exposure: %s\n",
			host,
			open,
			criticalStr,
			exposure,
		)
	}
}

func criticalServices(results []scanner.ScanResult) []string {
	criticalSet := map[string]struct{}{
		"ssh":           {},
		"ftp":           {},
		"microsoft-ds":  {},
		"msrpc":         {},
		"ms-wbt-server": {},
		"winrm":         {},
		"mysql":         {},
		"mssql":         {},
		"postgresql":    {},
		"redis":         {},
		"ldap":          {},
		"ldaps":         {},
	}

	found := make(map[string]struct{})
	for _, r := range results {
		if _, ok := criticalSet[r.ServiceName]; ok {
			found[r.ServiceName] = struct{}{}
		}
	}

	out := make([]string, 0, len(found))
	for svc := range found {
		out = append(out, svc)
	}
	sort.Strings(out)
	return out
}

func exposureLevel(openPorts int, criticalCount int) string {
	switch {
	case criticalCount >= 3 || openPorts >= 10:
		return "high"
	case criticalCount >= 1 || openPorts >= 4:
		return "medium"
	default:
		return "low"
	}
}
