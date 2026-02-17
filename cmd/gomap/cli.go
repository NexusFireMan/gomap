package gomap

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
)

// CLIOptions holds all parsed/validated CLI arguments.
type CLIOptions struct {
	PortsFlag       string
	ExcludePorts    string
	ServiceFlag     bool
	GhostFlag       bool
	UpdateFlag      bool
	RemoveFlag      bool
	VersionFlag     bool
	NoDiscovery     bool
	JSONFlag        bool
	CSVFlag         bool
	FormatFlag      string
	OutPath         string
	TopPorts        int
	TopPortsAlias   int
	Rate            int
	MaxHosts        int
	TimeoutMS       int
	Workers         int
	Retries         int
	BackoffMS       int
	MaxTimeoutMS    int
	AdaptiveTimeout bool
	DetailsFlag     bool
	Host            string
}

var errUsage = errors.New("usage")

// ParseCLIOptions parses and validates all command-line arguments.
func ParseCLIOptions(args []string) (CLIOptions, error) {
	var opts CLIOptions

	fs := flag.NewFlagSet("gomap", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.StringVar(&opts.PortsFlag, "p", "", "ports to scan (e.g., 80,443 or 1-1024 or - for all ports)")
	fs.StringVar(&opts.ExcludePorts, "exclude-ports", "", "exclude ports (e.g., 80,443 or 1-1024)")
	fs.BoolVar(&opts.ServiceFlag, "s", false, "detect services and versions")
	fs.BoolVar(&opts.GhostFlag, "g", false, "ghost mode - slower, stealthy scan to evade IDS/Firewall detection")
	fs.BoolVar(&opts.NoDiscovery, "nd", false, "disable host discovery (scan all hosts in CIDR even if inactive)")
	fs.BoolVar(&opts.UpdateFlag, "up", false, "update gomap to the latest version")
	fs.BoolVar(&opts.RemoveFlag, "remove", false, "remove gomap from the system (/usr/local/bin)")
	fs.BoolVar(&opts.VersionFlag, "v", false, "show version information")
	fs.BoolVar(&opts.JSONFlag, "json", false, "output scan results in JSON format")
	fs.BoolVar(&opts.CSVFlag, "csv", false, "output scan results in CSV format")
	fs.StringVar(&opts.FormatFlag, "format", "text", "output format: text|json|jsonl|csv")
	fs.StringVar(&opts.OutPath, "out", "", "write output to file instead of stdout")
	fs.IntVar(&opts.TopPorts, "top", 0, "scan top N ports from curated top-1000 list")
	fs.IntVar(&opts.TopPortsAlias, "top-ports", 0, "scan top N ports from curated top-1000 list")
	fs.IntVar(&opts.Rate, "rate", 0, "max scan rate in ports/second per host (0 = unlimited)")
	fs.IntVar(&opts.MaxHosts, "max-hosts", 0, "maximum number of hosts to scan after discovery (0 = unlimited)")
	fs.IntVar(&opts.TimeoutMS, "timeout", 0, "connection timeout per attempt in milliseconds (default: auto by mode)")
	fs.IntVar(&opts.Workers, "workers", 0, "number of concurrent workers (default: auto by mode)")
	fs.IntVar(&opts.Retries, "retries", 0, "retry attempts per port on timeout/error")
	fs.IntVar(&opts.BackoffMS, "backoff-ms", 25, "base backoff in milliseconds between retries")
	fs.IntVar(&opts.MaxTimeoutMS, "max-timeout", 0, "maximum adaptive timeout in milliseconds (0 = automatic)")
	fs.BoolVar(&opts.AdaptiveTimeout, "adaptive-timeout", true, "enable adaptive timeout tuning during scan")
	fs.BoolVar(&opts.DetailsFlag, "details", false, "include latency/confidence/evidence columns in table output")

	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "Gomap: A fast and simple port scanner written in Go.\n\n")
		fmt.Fprintf(os.Stderr, "Usage:\n  gomap <host|CIDR> [options]\n\n")
		fmt.Fprintf(os.Stderr, "Options:\n")
		fs.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nNotes:\n")
		fmt.Fprintf(os.Stderr, "  - CIDR scans automatically discover active hosts first (can be disabled with -nd)\n")
		fmt.Fprintf(os.Stderr, "  - Host discovery probes ports: 443, 80, 22, 445, 3306, 8080, 3389\n")
		fmt.Fprintf(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "  gomap 127.0.0.1                              (Scan top ports on localhost)\n")
		fmt.Fprintf(os.Stderr, "  gomap -p 80,443,8080 192.168.1.1           (Scan specific ports on single IP)\n")
		fmt.Fprintf(os.Stderr, "  gomap -p 1-1024 -s 192.168.1.0/24          (Scan CIDR with auto host discovery)\n")
		fmt.Fprintf(os.Stderr, "  gomap -g -p 1-1024 10.0.0.0/25             (Stealthy ghost mode scan on CIDR)\n")
		fmt.Fprintf(os.Stderr, "  gomap -s -nd -p 22 192.168.1.0/24          (Scan all hosts, no discovery)\n")
		fmt.Fprintf(os.Stderr, "  gomap -s --top 200 --json 10.0.0.5         (Top 200 ports in JSON)\n")
		fmt.Fprintf(os.Stderr, "  gomap --csv -p 1-1024 10.0.0.0/24          (CSV output for automation)\n")
		fmt.Fprintf(os.Stderr, "  gomap -s --format jsonl --out scan.jsonl 10.0.11.6\n")
		fmt.Fprintf(os.Stderr, "  gomap -s --retries 2 --adaptive-timeout --backoff-ms 40 10.0.11.6\n")
		fmt.Fprintf(os.Stderr, "  gomap -s --top-ports 200 --exclude-ports 139,445 --rate 300 --max-hosts 50 10.0.11.0/24\n")
	}

	if err := fs.Parse(args); err != nil {
		return opts, errUsage
	}

	// Special flags can run without host argument.
	if opts.VersionFlag || opts.RemoveFlag || opts.UpdateFlag {
		return normalizeOptions(opts)
	}

	if fs.NArg() != 1 {
		fs.Usage()
		return opts, errUsage
	}
	opts.Host = fs.Arg(0)

	return normalizeOptions(opts)
}

func normalizeOptions(opts CLIOptions) (CLIOptions, error) {
	opts.FormatFlag = strings.ToLower(strings.TrimSpace(opts.FormatFlag))

	if opts.JSONFlag {
		if opts.FormatFlag != "text" && opts.FormatFlag != "json" {
			return opts, errors.New("do not combine --json with --format other than 'json'")
		}
		opts.FormatFlag = "json"
	}
	if opts.CSVFlag {
		if opts.FormatFlag != "text" && opts.FormatFlag != "csv" {
			return opts, errors.New("do not combine --csv with --format other than 'csv'")
		}
		opts.FormatFlag = "csv"
	}

	validFormats := map[string]bool{
		"text":  true,
		"json":  true,
		"jsonl": true,
		"csv":   true,
	}
	if !validFormats[opts.FormatFlag] {
		return opts, errors.New("invalid --format. Allowed: text, json, jsonl, csv")
	}
	if opts.JSONFlag && opts.CSVFlag {
		return opts, errors.New("choose only one machine output format: --json or --csv")
	}
	if opts.PortsFlag != "" && opts.TopPorts > 0 {
		return opts, errors.New("use either -p or --top, not both")
	}
	if opts.TopPorts > 0 && opts.TopPortsAlias > 0 {
		return opts, errors.New("use either --top or --top-ports, not both")
	}
	if opts.TopPortsAlias > 0 {
		opts.TopPorts = opts.TopPortsAlias
	}
	if opts.TopPorts < 0 {
		return opts, errors.New("--top must be a positive number")
	}
	if opts.Rate < 0 {
		return opts, errors.New("--rate cannot be negative")
	}
	if opts.MaxHosts < 0 {
		return opts, errors.New("--max-hosts cannot be negative")
	}
	if opts.Retries < 0 {
		return opts, errors.New("--retries cannot be negative")
	}
	if opts.TimeoutMS < 0 {
		return opts, errors.New("--timeout cannot be negative")
	}
	if opts.Workers < 0 {
		return opts, errors.New("--workers cannot be negative")
	}
	if opts.BackoffMS < 0 {
		return opts, errors.New("--backoff-ms cannot be negative")
	}
	if opts.MaxTimeoutMS < 0 {
		return opts, errors.New("--max-timeout cannot be negative")
	}
	if opts.OutPath != "" && strings.TrimSpace(opts.OutPath) == "" {
		return opts, errors.New("invalid --out file path")
	}
	if opts.DetailsFlag && opts.FormatFlag != "text" {
		return opts, errors.New("--details is only valid with text output")
	}

	return opts, nil
}
