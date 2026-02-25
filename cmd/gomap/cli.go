package gomap

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	out "github.com/NexusFireMan/gomap/v2/pkg/output"
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
	RandomAgent     bool
	RandomIP        bool
	Host            string
}

var errUsage = errors.New("usage")
var errHelp = errors.New("help")

// ParseCLIOptions parses and validates all command-line arguments.
func ParseCLIOptions(args []string) (CLIOptions, error) {
	var opts CLIOptions
	args = normalizeLegacyFlagAliases(args)

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
	fs.BoolVar(&opts.RandomAgent, "random-agent", false, "randomize HTTP User-Agent on each request (service detection)")
	fs.BoolVar(&opts.RandomIP, "random-ip", false, "send randomized X-Forwarded-For/X-Real-IP headers from target CIDR (HTTP probes)")

	fs.Usage = func() {
		printHelp(os.Stderr)
	}

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return opts, errHelp
		}
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
	if opts.RandomIP && !opts.ServiceFlag {
		return opts, errors.New("--random-ip requires -s (service detection)")
	}

	return opts, nil
}

func normalizeLegacyFlagAliases(args []string) []string {
	out := make([]string, 0, len(args))
	for _, arg := range args {
		switch {
		case arg == "--ramdom-agent":
			out = append(out, "--random-agent")
		case strings.HasPrefix(arg, "--ramdom-agent="):
			out = append(out, strings.Replace(arg, "--ramdom-agent=", "--random-agent=", 1))
		case arg == "--ip-ram":
			out = append(out, "--random-ip")
		case strings.HasPrefix(arg, "--ip-ram="):
			out = append(out, strings.Replace(arg, "--ip-ram=", "--random-ip=", 1))
		case arg == "--ip-random":
			out = append(out, "--random-ip")
		case strings.HasPrefix(arg, "--ip-random="):
			out = append(out, strings.Replace(arg, "--ip-random=", "--random-ip=", 1))
		default:
			out = append(out, arg)
		}
	}
	return out
}

func printHelp(w *os.File) {
	help := fmt.Sprintf(`%s  ██████╗  ██████╗ ███╗   ███╗ █████╗ ██████╗
 ██╔════╝ ██╔═══██╗████╗ ████║██╔══██╗██╔══██╗
 ██║  ███╗██║   ██║██╔████╔██║███████║██████╔╝
 ██║   ██║██║   ██║██║╚██╔╝██║██╔══██║██╔═══╝
 ╚██████╔╝╚██████╔╝██║ ╚═╝ ██║██║  ██║██║
  ╚═════╝  ╚═════╝ ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝%s

%sGomap%s - fast TCP scanner with service detection and stealth profiles.

%sUsage:%s
  gomap <host|CIDR> [options]
  gomap -h

%sTarget & Scan:%s
  -p <ports>                 ports to scan (80,443 | 1-1024 | -)
  --top <N>                  scan top N ports from curated top-1000 list
  --top-ports <N>            alias of --top
  --exclude-ports <ports>    remove ports from final scan set
  -s                         enable service/version detection
  -g                         ghost mode (slower, stealthier)
  -nd                        disable CIDR host discovery

%sPerformance & Robustness:%s
  --workers <N>              concurrent workers (auto by mode if 0)
  --rate <N>                 max ports/second per host (0 = unlimited)
  --timeout <ms>             dial timeout per attempt
  --retries <N>              retries per port
  --backoff-ms <ms>          exponential backoff base between retries
  --adaptive-timeout         dynamic timeout tuning (default: true)
  --max-timeout <ms>         adaptive timeout upper bound
  --max-hosts <N>            cap discovered hosts to scan

%sOutput:%s
  --format <text|json|jsonl|csv>
  --json                     shortcut for --format json
  --csv                      shortcut for --format csv
  --out <path>               write output to file
  --details                  add latency/confidence/evidence columns (text only)

%sStealth Identity (HTTP probes):%s
  --random-agent             random User-Agent per request
  --random-ip                random X-Forwarded-For/X-Real-IP from target CIDR

%sMaintenance:%s
  -up                        self-update to latest version
  --remove                   uninstall from /usr/local/bin
  -v                         show version/build information
  -h                         show this help

%sExamples:%s
  gomap 10.0.11.6
  gomap -s -p 21,22,80,445 10.0.11.9
  gomap -s --top-ports 300 10.0.11.0/24
  gomap -g -s --random-agent --random-ip 10.0.11.0/24
  gomap -g -nd -s -p 22,80,443 10.0.11.0/24
  gomap -s --format json --out scan.json 10.0.11.6

%sNotes:%s
  - CIDR discovery is enabled by default; ghost mode uses a low-noise profile.
  - --random-ip changes HTTP headers only, not the real TCP source IP.
  - Legacy aliases kept for compatibility: --ramdom-agent, --ip-ram, --ip-random.
`, out.ColorBrightCyan, out.ColorReset,
		out.ColorBold, out.ColorReset,
		out.ColorBrightBlue, out.ColorReset,
		out.ColorBrightBlue, out.ColorReset,
		out.ColorBrightBlue, out.ColorReset,
		out.ColorBrightBlue, out.ColorReset,
		out.ColorBrightBlue, out.ColorReset,
		out.ColorBrightBlue, out.ColorReset,
		out.ColorBrightBlue, out.ColorReset,
		out.ColorBrightBlue, out.ColorReset,
	)
	_, _ = fmt.Fprint(w, help)
}
