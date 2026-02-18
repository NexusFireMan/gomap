# gomap

A fast TCP port scanner written in Go, with optional service/version detection, CIDR host discovery, adaptive timeout tuning, and multi-format output.

## Current scope

- Fast concurrent TCP connect scanning.
- Optional service and version detection (`-s`).
- Single host, hostname, comma-separated targets, and CIDR ranges.
- CIDR active-host discovery by TCP probes (no ICMP ping).
- Robust scan controls for unstable networks: retries, backoff, adaptive timeout.
- Professional outputs: `text`, `json`, `jsonl`, `csv`.
- Per-host exposure summary in text mode.

## Installation

### Build from source

```bash
git clone https://github.com/NexusFireMan/gomap.git
cd gomap
go build -o gomap .
./gomap -v
```

### Optional helper scripts

```bash
./scripts/build.sh
./scripts/install.sh
```

### Install with Go

```bash
go install github.com/NexusFireMan/gomap/v2@latest
```

## Quick start

```bash
# Default scan (top common ports)
./gomap 10.0.11.6

# Service/version detection on selected ports
./gomap -s -p 21,22,80,135,139,445,5985 10.0.11.6

# CIDR scan with automatic active-host discovery
./gomap -s --top-ports 300 10.0.11.0/24

# More robust scan profile for unstable networks
./gomap -s --retries 2 --adaptive-timeout --backoff-ms 40 --max-timeout 4500 10.0.11.9

# Machine output for automation
./gomap -s --format json --out scan.json 10.0.11.6
```

## CLI reference

```text
Usage:
  gomap <host|CIDR> [options]

Main options:
  -p                ports to scan (example: 80,443 or 1-1024 or - for all)
  --top, --top-ports scan top N ports from curated top-1000 list
  --exclude-ports   remove ports from final scan set
  -s                enable service/version detection
  -g                ghost mode (slower, stealthier)
  -nd               disable host discovery for CIDR targets

Performance/robustness:
  --workers         concurrent workers (default: auto by mode)
  --rate            max scan rate in ports/second per host (0 = unlimited)
  --timeout         per-attempt dial timeout in ms (default: auto by mode)
  --retries         retries per port on timeout/error
  --backoff-ms      base exponential backoff between retries
  --adaptive-timeout enable dynamic timeout tuning (default: true)
  --max-timeout     adaptive timeout ceiling in ms
  --max-hosts       cap number of discovered hosts scanned

Output:
  --format          text|json|jsonl|csv
  --json            shortcut for --format json
  --csv             shortcut for --format csv
  --out             output file path
  --details         add latency/confidence/evidence columns (text only)

Maintenance:
  -v                show version/build info
  -up               update to latest version
  --remove          remove gomap from /usr/local/bin
```

## Detection realism (`-s`)

When `-s` is enabled, gomap combines port-based hints and protocol/banner parsing to infer:

- HTTP/HTTPS server family/version where available.
- SSH/FTP/PostgreSQL/Redis/MySQL and other protocol banners.
- SMB-oriented identification for `microsoft-ds` targets.

Important: banner-based detection is heuristic. Always validate critical findings with a second tool (`nmap -sV`, native service queries, or manual protocol checks).

## Output formats

### Text (`--format text`, default)

- Aligned table per host.
- Optional `--details` adds `LAT(ms)`, `CONF`, `EVIDENCE`.
- Final `Host Exposure Summary` with open ports, critical services, and exposure level.

### JSON (`--format json`)

Single report document with metadata:

- `schema_version`, `generated_at`, `target`, `duration_ms`
- `hosts_scanned`, `ports_requested`, `total_open_ports`
- `hosts[]` with per-port results

### JSONL (`--format jsonl`)

One JSON record per open port, suitable for streaming pipelines.

### CSV (`--format csv`)

One row per open port with columns:

`host,port,state,service,version,latency_ms,confidence,evidence,detection_path`

## Testing and quality

### Local checks

```bash
make lint
make test
make test-race
make coverage
make ci
```

`make ci` runs lint + tests + race + coverage gate.

### Lab integration tests (Metasploitable3)

Integration tests are opt-in and target live lab hosts.

```bash
export GOMAP_RUN_LAB_TESTS=1
export GOMAP_LAB_WINDOWS_IP=10.0.11.6
export GOMAP_LAB_LINUX_IP=10.0.11.9
go test ./pkg/app -run LabIntegration -v
```

## Project layout

```text
cmd/gomap/      CLI parsing, version/update/remove commands
pkg/app/        Orchestration: target expansion, discovery, scan workflow
pkg/scanner/    Scan engine + service/banner detection
pkg/output/     Table renderer + json/jsonl/csv report generation
.github/        CI and release workflows
```

## Release process

- CI: `.github/workflows/ci.yml` (lint, tests, race, coverage).
- Release PR automation: `release-please` workflow.
- Tagged releases: GoReleaser workflow builds reproducible artifacts and checksums.

## Responsible use

Use this tool only on systems and networks you are authorized to test.

---
If you liked me, you can invite me for a coffee.
[![ko-fi](https://ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/C0C61UHTB1)
