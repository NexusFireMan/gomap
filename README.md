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
- Ghost mode hardening: lower burst rate, heavier jitter, and fewer active probes.
- Ultra-stealth ghost defaults: low rate, low worker count, and reduced CIDR discovery probes.
- Optional HTTP identity randomization: `--random-agent` and `--random-ip`.

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

### Version Metadata

- Release binaries and local script builds embed `Version`, `Commit`, and `Date`.
- `gomap -up` now prefers release binaries to preserve embedded build metadata in final installations.
- Plain `go install` builds may not include ldflags, so `gomap -v` also uses Go build info fallback when available.

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

# Stealthier service detection profile
./gomap -g -s --random-agent --random-ip 10.0.11.0/24

# Maximum stealth for CIDR (skip discovery entirely)
./gomap -g -nd -s --random-agent --random-ip -p 22,80,443 10.0.11.0/24
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

Stealth/identity (HTTP probes):
  --random-agent    randomize HTTP User-Agent on each request
  --random-ip       randomize HTTP X-Forwarded-For/X-Real-IP from target CIDR

Compatibility note:
  legacy aliases (`--ramdom-agent`, `--ip-ram`, `--ip-random`) are still accepted for backward compatibility.

Ghost defaults:
  - lower default rate and worker count
  - reduced host-discovery probes on CIDR (443,80,22)
  - use `-nd` to disable host discovery completely on CIDR
  - tradeoff: discovery may miss hosts that only expose non-probed ports (for example 139/445 only)

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

Note: `--random-ip` randomizes HTTP headers only; it does not spoof the real TCP source IP.

## Stealth benchmark (lab)

Benchmark executed on **February 25, 2026** with:

- Scanner host: `10.0.11.11`
- Targets: `10.0.11.0/24` (Metasploitable3 Windows `10.0.11.6`, Linux `10.0.11.9`, Snort `10.0.11.8`)
- IDS: Snort `2.9.20` (`10.0.11.8`)
- Ports: `22,80,139,445,3389,5985`

Commands compared:

```bash
# Normal
gomap -s -p 22,80,139,445,3389,5985 10.0.11.0/24

# Ghost ultra-stealth
gomap -g -s --random-agent --random-ip -p 22,80,139,445,3389,5985 10.0.11.0/24
```

Observed results (Snort `snort.alert.fast`, TCP alerts with source `10.0.11.11`):

| Mode | New alerts (all) | New TCP alerts from scanner | Scan duration |
|------|-------------------|-----------------------------|---------------|
| Normal | 104 | 89 | ~6.2s |
| Ghost ultra-stealth | 41 | 20 | ~11.5s |

Takeaway:

- Ghost ultra-stealth reduced scanner-attributed TCP alerts by about **77.5%** (`89 -> 20`).
- Tradeoff is slower execution and less aggressive service/version fingerprinting.

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
