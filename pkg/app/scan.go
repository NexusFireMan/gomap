package app

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/NexusFireMan/gomap/v2/pkg/output"
	"github.com/NexusFireMan/gomap/v2/pkg/scanner"
)

// ScanRequest contains normalized scan options coming from CLI.
type ScanRequest struct {
	Build           output.BuildInfo
	Target          string
	PortsFlag       string
	ScanType        string
	UDP             bool
	ExcludePorts    string
	TopPorts        int
	Rate            int
	GlobalRate      int
	MaxHosts        int
	ServiceDetect   bool
	DeepVersion     bool
	Exhaustive      bool
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
	Stream          bool
	RandomAgent     bool
	RandomIP        bool
	SourceInterface string
	SourceIPs       string
	HostConfig      string
	CaptureUnknown  bool
	EvidenceBytes   int
	SNMPConfig      string
}

// ExecuteScan runs the complete scan workflow: target expansion, host discovery, scan, and rendering.
func ExecuteScan(req ScanRequest) (resultErr error) {
	runStart := time.Now()
	var discoveryDuration time.Duration
	if req.SNMPConfig != "" && (!req.UDP || req.GhostMode || req.RandomIP || req.SourceInterface != "") {
		return errors.New("--snmp-config requires UDP and cannot combine with controlled-profile or source-identity options")
	}
	snmpConfig, configErr := loadSNMPConfig(req.SNMPConfig, req.OutputPath)
	if configErr != nil {
		return configErr
	}
	if req.SNMPConfig != "" {
		req.ServiceDetect = true
	}
	if req.GlobalRate < 0 {
		return errors.New("--global-rate cannot be negative")
	}
	limiter := scanner.NewAttemptLimiter(req.GlobalRate)
	machineOutput := req.Format != "text"
	if req.ScanType == "" {
		req.ScanType = "connect"
	}
	if req.HostConfig != "" && req.ScanType == "syn" {
		return errors.New("--host-config supports CONNECT/UDP, not native SYN")
	}
	hostConfig, err := loadHostConfig(req.HostConfig)
	if err != nil {
		return err
	}
	if req.CaptureUnknown {
		req.ServiceDetect = true
		if req.EvidenceBytes == 0 {
			req.EvidenceBytes = scanner.DefaultEvidenceBytes
		}
		if req.EvidenceBytes < 1 || req.EvidenceBytes > scanner.MaxEvidenceBytes {
			return errors.New("evidence bytes must be between 1 and 1024")
		}
	}
	if req.Stream && (req.UDP || req.ScanType != "connect" || (req.Format != "text" && req.Format != "jsonl")) {
		return errors.New("--stream requires CONNECT scanning with text or JSONL output")
	}
	scanLabel := strings.ToUpper(req.ScanType)
	if req.UDP {
		scanLabel = "UDP"
	}
	if req.DeepVersion {
		scanLabel += "+DV"
	}
	if req.Exhaustive {
		scanLabel += "+EXH"
	}

	destWriter := output.DefaultWriter()
	var outFile *os.File

	portManager := scanner.NewPortManager()
	var (
		portsToScan []int
	)
	if req.TopPorts > 0 {
		top := scanner.GetTop1000Ports()
		if req.UDP {
			top = scanner.GetTopUDPPorts()
		}
		limit := req.TopPorts
		if limit > len(top) {
			limit = len(top)
		}
		portsToScan = top[:limit]
	} else if req.UDP && req.PortsFlag == "" {
		portsToScan = scanner.GetTopUDPPorts()
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
	if err := validateHostConfigScope(hostConfig, targets, req); err != nil {
		return err
	}
	metrics := newScanMetrics(req, len(targets))
	if err := validateSNMPScope(snmpConfig, targets); err != nil {
		return err
	}
	if req.OutputPath != "" {
		if req.HostConfig != "" {
			input, inputErr := os.Stat(req.HostConfig)
			outputFile, outputErr := os.Stat(req.OutputPath)
			if inputErr == nil && outputErr == nil && os.SameFile(input, outputFile) {
				return errors.New("--out must not overwrite --host-config")
			}
		}
		if req.CaptureUnknown {
			if info, statErr := os.Stat(req.OutputPath); statErr == nil && !info.Mode().IsRegular() {
				return errors.New("capture-enabled --out requires a regular file")
			}
			outFile, err = os.OpenFile(req.OutputPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
		} else {
			outFile, err = os.Create(req.OutputPath)
		}
		if err != nil {
			return fmt.Errorf("cannot create output file: %w", err)
		}
		defer func() { resultErr = errors.Join(resultErr, outFile.Close()) }()
		if req.CaptureUnknown {
			info, statErr := outFile.Stat()
			if statErr != nil || !info.Mode().IsRegular() {
				return errors.New("capture-enabled --out requires a regular file; redirect stdout explicitly for other destinations")
			}
			if err := outFile.Chmod(0600); err != nil {
				return fmt.Errorf("cannot restrict evidence output permissions: %w", err)
			}
		}
		destWriter = outFile
	}
	if req.CaptureUnknown {
		if _, err := fmt.Fprintln(os.Stderr, "Evidence capture enabled: samples may contain sensitive data; filtering cannot guarantee redaction. Protect reports before sharing."); err != nil {
			return err
		}
	}
	if req.RandomIP && req.SourceInterface == "" && !machineOutput {
		fmt.Printf("%s\n", output.StatusWarn("--random-ip without --source-interface changes HTTP headers only; TCP source addresses remain unchanged."))
	}
	var sourceIPs []net.IP
	if req.SourceInterface != "" {
		if req.SourceIPs != "" {
			managed, manageErr := scanner.PrepareManagedSourceIPs(req.SourceInterface, req.SourceIPs)
			if manageErr != nil {
				return manageErr
			}
			defer func() {
				if cleanupErr := managed.Close(); cleanupErr != nil {
					resultErr = errors.Join(resultErr, cleanupErr)
				} else if !machineOutput && managed.AddedCount() > 0 {
					fmt.Printf("%s\n", output.StatusOK(fmt.Sprintf("Source IP cleanup complete: %d temporary address(es) removed from %s.", managed.AddedCount(), req.SourceInterface)))
				}
			}()
			sourceIPs = managed.IPs()
			if !machineOutput {
				fmt.Printf("%s\n", output.StatusOK(fmt.Sprintf("Source interface %s: %d managed IP(s) active; %d added for this scan.", req.SourceInterface, len(sourceIPs), managed.AddedCount())))
			}
		} else {
			sourceIPs, err = scanner.InterfaceSourceIPs(req.SourceInterface)
			if err != nil {
				return err
			}
			if !machineOutput {
				fmt.Printf("%s\n", output.StatusOK(fmt.Sprintf("Source interface %s: %d assigned IP(s) available for socket binding.", req.SourceInterface, len(sourceIPs))))
			}
		}
		if err := scanner.ValidateSourceIPsForTargets(sourceIPs, targets); err != nil {
			return err
		}
	}
	if req.UDP && !req.NoDiscovery && scanner.IsCIDR(req.Target) && len(targets) > 1 && !machineOutput {
		fmt.Printf("%s\n", output.StatusWarn("UDP CIDR scans still use TCP host discovery. Use -nd to scan every host when UDP-only targets are expected."))
	}

	if !req.NoDiscovery && scanner.IsCIDR(req.Target) && len(targets) > 1 {
		if !machineOutput {
			fmt.Printf("%s\n", output.Info(fmt.Sprintf("🔍 Discovering active hosts in %s...", output.Host(req.Target))))
		}
		discoveryOpts := scanner.DiscoveryOptions{
			Ports:      []int{443, 80, 22, 445, 3306, 8080, 3389},
			Timeout:    500 * time.Millisecond,
			NumWorkers: 50,
			SourceIPs:  sourceIPs,
		}
		if req.GhostMode {
			// Low-noise profile for CIDR discovery: fewer probe ports and lower concurrency.
			discoveryOpts = scanner.DiscoveryOptions{
				Ports:      []int{443, 80, 22},
				Timeout:    900 * time.Millisecond,
				NumWorkers: 12,
				SourceIPs:  sourceIPs,
			}
			if !machineOutput {
				fmt.Printf("%s\n", output.StatusWarn("Ghost discovery profile active: low-noise probes on 443,80,22. Use -nd to skip discovery completely."))
			}
		}
		discoveryOpts.AttemptLimiter = limiter
		discoveryStart := time.Now()
		targets = scanner.DiscoverActiveHostsWithOptions(targets, discoveryOpts)
		discoveryDuration = time.Since(discoveryStart)
		if len(targets) == 0 {
			metrics.SetTimings(time.Since(runStart), discoveryDuration, 0)
			if machineOutput {
				empty := map[string][]scanner.ScanResult{}
				var renderErr error
				switch req.Format {
				case "json":
					renderErr = output.PrintJSONReportWithMetrics(destWriter, req.Target, portsToScan, targets, empty, req.ServiceDetect, 0, nil, metrics)
				case "jsonl":
					renderErr = output.PrintJSONLReport(destWriter, req.Target, targets, empty)
				case "csv":
					renderErr = output.PrintCSVReport(destWriter, empty, targets)
				}
				if renderErr != nil {
					return fmt.Errorf("failed to render %s output: %w", req.Format, renderErr)
				}
				if req.Format != "json" {
					if err := output.WriteScanMetrics(os.Stderr, metrics); err != nil {
						return fmt.Errorf("failed to write scan metrics: %w", err)
					}
				}
				if req.OutputPath != "" {
					fmt.Printf("%s\n", output.StatusOK(fmt.Sprintf("Saved %s output to %s", strings.ToUpper(req.Format), req.OutputPath)))
				}
				return nil
			}
			if _, err := fmt.Fprintf(destWriter, "%s\n", output.StatusWarn("No active hosts found in the specified range.")); err != nil {
				return err
			}
			return output.WriteScanMetrics(destWriter, metrics)
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
				fmt.Printf("%s\n\n", output.Info(fmt.Sprintf("🎯 Scanning %s (%s ports, %s scan) - %s (low-noise)", output.Host(targets[0]), output.Count(len(portsToScan)), output.Highlight(scanLabel), output.Warning("Ghost mode"))))
			} else {
				fmt.Printf("%s\n\n", output.Info(fmt.Sprintf("🎯 Scanning %s (%s ports, %s scan)", output.Host(targets[0]), output.Count(len(portsToScan)), output.Highlight(scanLabel))))
			}
		} else {
			targetRange, _, _ := scanner.FormatCIDRInfo(req.Target)
			if req.GhostMode {
				fmt.Printf("%s\n\n", output.Info(fmt.Sprintf("🎯 Scanning %s (%s active hosts, %s ports, %s scan) - %s (low-noise)", output.Highlight(targetRange), output.Count(len(targets)), output.Count(len(portsToScan)), output.Highlight(scanLabel), output.Warning("Ghost mode"))))
			} else {
				fmt.Printf("%s\n\n", output.Info(fmt.Sprintf("🎯 Scanning %s (%s active hosts, %s ports, %s scan)", output.Highlight(targetRange), output.Count(len(targets)), output.Count(len(portsToScan)), output.Highlight(scanLabel))))
			}
		}
	}

	formatter := output.NewOutputFormatter(req.ServiceDetect, req.Details)
	if req.DeepVersion || req.CaptureUnknown {
		formatter = output.NewEvidenceOutputFormatter()
	}
	allResults := make(map[string][]scanner.ScanResult)
	connectDiagnostics := make(map[string]scanner.ConnectDiagnostics)
	scanStart := time.Now()
	var streamErr error

	for _, targetIP := range targets {
		hostStart := time.Now()
		engineUsed := req.ScanType
		s := scanner.NewScanner(targetIP, req.GhostMode)
		hostReq := req
		if len(hostConfig) > 0 {
			if addr, err := netip.ParseAddr(targetIP); err == nil {
				hostReq = applyHostOverride(req, hostConfig[addr.Unmap().String()])
			}
		}
		s.SNMPCredentials = snmpConfig[targetIP]
		cidrForHeaders := ""
		if req.RandomIP && scanner.IsCIDR(req.Target) {
			cidrForHeaders = req.Target
		}
		s.Configure(scanner.ScanConfig{
			NumWorkers:      req.Workers,
			Timeout:         time.Duration(hostReq.TimeoutMS) * time.Millisecond,
			Retries:         hostReq.Retries,
			Rate:            req.Rate,
			AttemptLimiter:  limiter,
			AdaptiveTimeout: hostReq.AdaptiveTimeout,
			BackoffBase:     time.Duration(req.BackoffMS) * time.Millisecond,
			MaxTimeout:      time.Duration(hostReq.MaxTimeoutMS) * time.Millisecond,
			RandomAgent:     req.RandomAgent,
			RandomIP:        req.RandomIP,
			SourceIPs:       sourceIPs,
			TargetCIDR:      cidrForHeaders,
			DeepVersion:     req.DeepVersion,
			Exhaustive:      req.Exhaustive,
			CaptureUnknown:  req.CaptureUnknown,
			EvidenceBytes:   req.EvidenceBytes,
		})
		if req.Stream {
			s.OnResult = func(result scanner.ScanResult) {
				if streamErr != nil {
					return
				}
				if req.Format == "jsonl" {
					streamErr = output.PrintJSONLReport(destWriter, req.Target, []string{targetIP}, map[string][]scanner.ScanResult{targetIP: {result}})
				} else {
					streamErr = formatter.WriteStreamResult(destWriter, targetIP, result)
				}
			}
		}
		var openResults []scanner.ScanResult
		if req.UDP {
			engineUsed = "udp"
			openResults = s.ScanUDP(portsToScan, req.ServiceDetect)
		} else if req.ScanType == "syn" {
			synOpenPorts, synErr := scanner.DiscoverOpenPortsSYN(targetIP, portsToScan, scanner.SYNConfig{
				Rate:           req.Rate,
				AttemptLimiter: limiter,
				Retries:        req.Retries,
				GhostMode:      req.GhostMode,
			})
			if synErr != nil {
				engineUsed = "connect (syn fallback)"
				if !machineOutput {
					fmt.Printf("%s\n", output.StatusWarn(fmt.Sprintf("SYN scan unavailable on %s (%v). Falling back to connect scan.", targetIP, synErr)))
				}
				var diag scanner.ConnectDiagnostics
				openResults, diag = s.ScanWithDiagnostics(portsToScan, req.ServiceDetect)
				connectDiagnostics[targetIP] = diag
			} else {
				openResults = scanner.BuildResultsFromKnownOpenPorts(s, synOpenPorts, req.ServiceDetect)
			}
		} else {
			var diag scanner.ConnectDiagnostics
			openResults, diag = s.ScanWithDiagnostics(portsToScan, req.ServiceDetect)
			connectDiagnostics[targetIP] = diag
		}
		if len(openResults) > 0 {
			allResults[targetIP] = openResults
		}
		var diag *scanner.ConnectDiagnostics
		if d, ok := connectDiagnostics[targetIP]; ok {
			diag = &d
		}
		coverage := output.SummarizeCoverage(portsToScan, openResults, diag)
		metrics.Coverage.Add(coverage)
		metrics.Hosts = append(metrics.Hosts, output.HostMetrics{
			Host: targetIP, Engine: engineUsed, ScanAndServicesMS: time.Since(hostStart).Milliseconds(), Coverage: coverage,
			Settings: &output.HostSettings{TimeoutMS: s.Timeout.Milliseconds(), Retries: s.Retries, MaxTimeoutMS: s.MaxAdaptiveTimeout.Milliseconds(), AdaptiveTimeout: s.AdaptiveTimeout},
		})
		if streamErr != nil {
			return fmt.Errorf("failed to write streaming output: %w", streamErr)
		}
	}
	scanDuration := time.Since(scanStart)
	metrics.SetTimings(time.Since(runStart), discoveryDuration, scanDuration)

	if machineOutput {
		if warnings := connectWarnings(targets, connectDiagnostics); warnings != "" {
			if _, err := fmt.Fprint(os.Stderr, warnings); err != nil {
				return fmt.Errorf("failed to write connection diagnostics: %w", err)
			}
		}
		var renderErr error
		switch req.Format {
		case "json":
			renderErr = output.PrintJSONReportWithMetrics(destWriter, req.Target, portsToScan, targets, allResults, req.ServiceDetect, scanDuration, connectDiagnostics, metrics)
		case "jsonl":
			if !req.Stream {
				renderErr = output.PrintJSONLReport(destWriter, req.Target, targets, allResults)
			}
		case "csv":
			renderErr = output.PrintCSVReport(destWriter, allResults, targets)
		default:
			renderErr = fmt.Errorf("unsupported output format: %s", req.Format)
		}
		if renderErr != nil {
			return fmt.Errorf("failed to render %s output: %w", req.Format, renderErr)
		}
		if req.Format != "json" {
			if err := output.WriteScanMetrics(os.Stderr, metrics); err != nil {
				return fmt.Errorf("failed to write scan metrics: %w", err)
			}
		}
		if req.OutputPath != "" {
			fmt.Printf("%s\n", output.StatusOK(fmt.Sprintf("Saved %s output to %s", strings.ToUpper(req.Format), req.OutputPath)))
		}
		return nil
	}

	var textReport bytes.Buffer
	totalOpen := 0
	for _, targetIP := range targets {
		if results, exists := allResults[targetIP]; exists {
			totalOpen += scanner.CountOpen(results)
			if req.Stream {
				continue
			}
			if len(targets) > 1 {
				fmt.Fprintf(&textReport, "\n%s\n", output.Highlight(fmt.Sprintf("═══ %s ═══", output.Host(targetIP))))
			}
			if err := formatter.WriteResults(&textReport, results); err != nil {
				return err
			}
		}
	}
	textReport.WriteString(connectWarnings(targets, connectDiagnostics))
	textReport.WriteString(hostSummaries(targets, allResults, connectDiagnostics))
	if err := output.WriteScanMetrics(&textReport, metrics); err != nil {
		return err
	}
	unresolved := metrics.Coverage.Inconclusive()
	if unresolved > 0 {
		fmt.Fprintf(&textReport, "\n%s\n", output.StatusWarn(fmt.Sprintf("Scan finished in %s | hosts: %d | open ports: %d | inconclusive host-ports: %d", scanDuration.Round(time.Millisecond), len(targets), totalOpen, unresolved)))
	} else {
		fmt.Fprintf(&textReport, "\n%s\n", output.StatusOK(fmt.Sprintf("Completed scan in %s | hosts: %d | open ports: %d", scanDuration.Round(time.Millisecond), len(targets), totalOpen)))
	}
	if _, err := destWriter.Write(textReport.Bytes()); err != nil {
		return fmt.Errorf("failed to render text output: %w", err)
	}
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

func hostSummaries(targets []string, allResults map[string][]scanner.ScanResult, diagnostics ...map[string]scanner.ConnectDiagnostics) string {
	var report strings.Builder
	fmt.Fprintf(&report, "\n%s\n", output.Bold("Host Exposure Summary"))
	for _, host := range targets {
		results := allResults[host]
		open := scanner.CountOpen(results)
		critical := criticalServices(results)
		exposure := exposureLevel(open, len(critical))
		if len(diagnostics) > 0 && diagnostics[0][host].UnresolvedPorts > 0 {
			exposure = "indeterminate (observed: " + exposure + ")"
		}
		for _, result := range results {
			if result.EffectiveState() == "open|filtered" || result.EffectiveState() == "unknown" {
				if !strings.HasPrefix(exposure, "indeterminate") {
					exposure = "indeterminate (observed: " + exposure + ")"
				}
				break
			}
		}

		criticalStr := "none"
		if len(critical) > 0 {
			criticalStr = strings.Join(critical, ", ")
		}
		fmt.Fprintf(&report, "- %s | open ports: %d | critical: %s | exposure: %s",
			host,
			open,
			criticalStr,
			exposure,
		)
		if len(diagnostics) > 0 {
			if diag, ok := diagnostics[0][host]; ok {
				fmt.Fprintf(&report, " | TCP closed: %d | filtered: %d | unknown: %d", diag.RefusedPorts, diag.FilteredPorts, diag.UnresolvedPorts-diag.FilteredPorts)
			}
		}
		report.WriteByte('\n')
	}
	return report.String()
}

func connectWarnings(targets []string, diagnostics map[string]scanner.ConnectDiagnostics) string {
	var report strings.Builder
	for _, host := range targets {
		diag := diagnostics[host]
		if diag.UnresolvedPorts == 0 {
			continue
		}
		counts := make(map[string]int)
		for _, issue := range diag.Issues {
			if !issue.Recovered {
				counts[issue.Kind]++
			}
		}
		var kinds []string
		for kind := range counts {
			kinds = append(kinds, kind)
		}
		sort.Strings(kinds)
		var parts []string
		for _, kind := range kinds {
			parts = append(parts, fmt.Sprintf("%s_ports=%d", kind, counts[kind]))
		}
		fmt.Fprintf(&report, "TCP discovery inconclusive on %s: %d unresolved ports (%s); these are not confirmed closed.\n", host, diag.UnresolvedPorts, strings.Join(parts, ", "))
		fmt.Fprintf(&report, "TCP states on %s: closed=%d (connection refused), filtered=%d (inferred from timeout), unknown=%d; configured_timeout_ms=%d", host, diag.RefusedPorts, diag.FilteredPorts, diag.UnresolvedPorts-diag.FilteredPorts, diag.TimeoutMS)
		var minTimeout, maxTimeout int64
		for _, issue := range diag.Issues {
			if issue.Recovered || issue.TimeoutMS <= 0 {
				continue
			}
			if minTimeout == 0 || issue.TimeoutMS < minTimeout {
				minTimeout = issue.TimeoutMS
			}
			maxTimeout = max(maxTimeout, issue.TimeoutMS)
		}
		if minTimeout > 0 {
			fmt.Fprintf(&report, "; last_attempt_timeout_ms=%d..%d", minTimeout, maxTimeout)
		}
		report.WriteByte('\n')
	}
	return report.String()
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
		if r.State != "" && r.State != "open" {
			continue
		}
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
