<div align="center">

<pre>
  ██████╗  ██████╗ ███╗   ███╗ █████╗ ██████╗
 ██╔════╝ ██╔═══██╗████╗ ████║██╔══██╗██╔══██╗
 ██║  ███╗██║   ██║██╔████╔██║███████║██████╔╝
 ██║   ██║██║   ██║██║╚██╔╝██║██╔══██║██╔═══╝
 ╚██████╔╝╚██████╔╝██║ ╚═╝ ██║██║  ██║██║
  ╚═════╝  ╚═════╝ ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝
</pre>

# gomap

**Fast TCP/UDP scanner in Go with service fingerprinting, native SYN scanning, stealth profiles, and multi-format output.**

[![CI](https://github.com/NexusFireMan/gomap/actions/workflows/ci.yml/badge.svg)](https://github.com/NexusFireMan/gomap/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/NexusFireMan/gomap?display_name=tag)](https://github.com/NexusFireMan/gomap/releases)
[![Go](https://img.shields.io/badge/Go-1.24%2B-00ADD8?logo=go&logoColor=white)](https://go.dev/)
[![Docker](https://img.shields.io/badge/Docker-GHCR-2496ED?logo=docker&logoColor=white)](https://github.com/NexusFireMan/gomap/pkgs/container/gomap)
[![CLI](https://img.shields.io/badge/Interface-CLI-2C2C2C)](https://github.com/NexusFireMan/gomap)
[![License](https://img.shields.io/github/license/NexusFireMan/gomap)](https://github.com/NexusFireMan/gomap/blob/main/LICENSE)
[![Ko-fi](https://img.shields.io/badge/Ko--fi-Support-FF5E5B?logo=kofi&logoColor=white)](https://ko-fi.com/C0C61UHTB1)

</div>

## Navigation

- [Current scope](#current-scope)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [CLI Reference](#cli-reference)
- [Detection Realism (`-s`)](#detection-realism--s)
- [Stealth Benchmark (Lab)](#stealth-benchmark-lab)
- [Output Formats](#output-formats)
- [Responsible Use](#responsible-use)
- [Quick Links](#quick-links)

A fast TCP/UDP port scanner written in Go, with optional service/version detection, CIDR host discovery, adaptive timeout tuning, and multi-format output.

## Current scope

- Fast concurrent TCP scanning with selectable engine (`connect` or `syn`).
- UDP probing with `-u` for responsive UDP services.
- Default quick scan uses a curated top-port list normalized to unique ports (current effective size: 996).
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

### Install with APT (Kali / Parrot / Debian)

GoMap is also prepared to be consumed from a signed APT repository published on GitHub Pages:

```bash
curl -fsSL https://nexusfireman.github.io/gomap/gomap-archive-keyring.gpg \
  | sudo gpg --dearmor -o /usr/share/keyrings/gomap-archive-keyring.gpg

echo "deb [signed-by=/usr/share/keyrings/gomap-archive-keyring.gpg] https://nexusfireman.github.io/gomap stable main" \
  | sudo tee /etc/apt/sources.list.d/gomap.list > /dev/null

sudo apt update
sudo apt install gomap
```

Notes:
- This is intended for Kali, Parrot, Debian, and close derivatives.
- Arch users should prefer an AUR package in a later phase rather than this APT repository.
- The Debian package installs the binary at `/usr/bin/gomap`.
- If `gomap -v` still shows an older version after `apt install`, check for older copies earlier in `PATH`:

```bash
which -a gomap
gomap --doctor
/usr/bin/gomap -v
hash -r
```

`gomap --doctor` reports:
- the active binary currently resolved in `PATH`
- all detected `gomap` copies in common locations
- the detected version of each copy
- the probable origin (`apt`, `go install`, manual install, user-local binary)
- whether `gomap --remove` can remove it safely

Behavior note:
- `gomap --remove` skips package-managed binaries such as `/usr/bin/gomap`
- to remove the APT installation itself, use `sudo apt remove gomap`

Example cleanup when an older user-local binary shadows the packaged one:

```bash
which -a gomap
gomap --doctor
/usr/bin/gomap -v
rm -f ~/.local/bin/gomap
hash -r
gomap -v
```

Validated in lab:
- `apt update` resolves `InRelease` and `Packages` correctly from `https://nexusfireman.github.io/gomap`
- `apt install gomap` installs the current release successfully on Kali
- `/usr/bin/gomap -v` shows embedded release metadata (`version`, `commit`, `date`)

### Container image

Published images are available on GHCR:

```bash
docker pull ghcr.io/nexusfireman/gomap:latest
```

Run a standard scan:

```bash
docker run --rm --network host ghcr.io/nexusfireman/gomap:latest 10.0.11.6
```

Run native SYN scan:

```bash
docker run --rm --network host --cap-add NET_RAW ghcr.io/nexusfireman/gomap:latest --scan-type syn 10.0.11.6
```

Notes:
- `--network host` is recommended on Linux for predictable scan behavior.
- Native SYN scan additionally requires `--cap-add NET_RAW`.

### Debian package artifacts

Each tagged release publishes `.deb` artifacts alongside archives and checksums. They can be installed directly with:

```bash
sudo dpkg -i gomap_<version>_linux_amd64.deb
```

### Version metadata

- Release binaries and local script builds embed `Version`, `Commit`, and `Date`.
- `gomap -up` now prefers release binaries to preserve embedded build metadata in final installations.
- Plain `go install` builds may not include ldflags, so `gomap -v` also uses Go build info fallback when available.

## Quick Start

```bash
# Default scan (top common ports)
./gomap 10.0.11.6

# Native SYN scan discovery (requires root/CAP_NET_RAW)
./gomap --scan-type syn 10.0.11.6

# UDP scan (responsive UDP services only)
./gomap -u 10.0.11.6

# UDP scan on selected ports
./gomap -u -s -p 53,123,137,161,1900 10.0.11.6

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

## CLI Reference

```text
Usage:
  gomap <host|CIDR> [options]

Main options:
  -p                ports to scan (example: 80,443 or 1-1024 or - for all)
  -u                scan UDP instead of TCP
  --scan-type       connect|syn (default: connect)
  --top, --top-ports scan top N ports from curated protocol list
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
  --remove          remove non-package gomap copies found in PATH/common locations
  --doctor          inspect active binary, PATH copies, and install origin
```

## Detection Realism (`-s`)

When `-s` is enabled, gomap combines port-based hints and protocol/banner parsing to infer:

- HTTP/HTTPS server family/version where available.
- SSH/FTP/PostgreSQL/Redis/MySQL and other protocol banners.
- SMB-oriented identification for `microsoft-ds` targets.
- TLS handshake metadata where applicable (`tls_version`, `tls_cipher`, ALPN, certificate issuer).
- Generic active probes for open ports without a known port mapping, useful when services run on non-standard ports.

Important: banner-based detection is heuristic. Always validate critical findings with a second tool.

Non-standard port note:
- For unknown open TCP ports, `-s` may spend a few extra seconds sending lightweight generic probes (`GET`, `HELP`, `FEAT`, `CAPA`, IMAP capability) to identify moved services.
- This improves realism on CTF/lab targets and custom deployments where a service is intentionally exposed away from its default port.

`--scan-type syn` notes:
- Uses GoMap native raw TCP SYN probes for port discovery, then optional service detection on open ports.
- If SYN scan cannot run (insufficient privileges or unsupported OS), GoMap falls back to `connect` scan automatically.
- For noisy links, tune reliability explicitly with `--retries` and `--rate`.

`-u` UDP notes:
- TCP remains the default scan mode.
- `-u` switches port probing to UDP and uses a compact UDP default port set unless `-p` is provided.
- GoMap reports UDP ports as open only when a UDP response is received.
- No-response UDP ports are intentionally omitted because they may be closed, filtered, or open-but-silent.
- `-u` cannot be combined with `--scan-type syn`, because SYN is TCP-specific.
- CIDR scans with `-u` still use TCP host discovery unless `-nd` is set.

Note: `--random-ip` randomizes HTTP headers only; it does not spoof the real TCP source IP.

## Stealth Benchmark (Lab)

Benchmark executed on **March 9, 2026** with:

- Scanner host: `10.0.11.11`
- Targets: `10.0.11.0/24` (Windows `10.0.11.6`, Linux `10.0.11.9`, Snort `10.0.11.8`)
- IDS: Snort `2.9.20` (`10.0.11.8`)
- Port set: `22,80,139,445,3389,5985`
- Log analyzed: `/var/log/snort/snort.alert.fast`
- Attribution filter: source `10.0.11.11`

Commands compared:

```bash
# CONNECT normal
gomap -s -p 22,80,139,445,3389,5985 10.0.11.0/24

# CONNECT ghost
gomap -g -s --random-agent --random-ip -p 22,80,139,445,3389,5985 10.0.11.0/24

# SYN normal (native, requires root/CAP_NET_RAW)
sudo gomap --scan-type syn -s -p 22,80,139,445,3389,5985 10.0.11.0/24

# SYN ghost
sudo gomap -g -s --scan-type syn --random-agent --random-ip -p 22,80,139,445,3389,5985 10.0.11.0/24
```

Observed results (single run per profile):

| Profile | Duration | Hosts scanned | Open ports found | New alerts (all) | New alerts from scanner IP | New TCP alerts from scanner IP |
|---|---:|---:|---:|---:|---:|---:|
| CONNECT normal | 6.801s | 4 | 10 | 97 | 97 | 96 |
| CONNECT ghost | 10.893s | 3 | 9 | 64 | 64 | 62 |
| SYN normal | 9.26s | 4 | 10 | 104 | 104 | 103 |
| SYN ghost | 11.793s | 3 | 9 | 48 | 48 | 47 |

Takeaways:

- `ghost` mode reduced scanner-attributed TCP alerts in both engines:
  - CONNECT: `96 -> 62` (about `-35.4%`)
  - SYN: `103 -> 47` (about `-54.4%`)
- In this Snort rule set, SYN generated more alerts than CONNECT for the same target/ports.
- Ghost CIDR discovery is intentionally conservative and may scan fewer active hosts (`3` vs `4` in this run).

## Output Formats

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

`host,port,state,service,version,tls,tls_version,tls_cipher,tls_alpn,tls_server_name,tls_issuer,latency_ms,confidence,evidence,detection_path`

## Responsible Use

Use this tool only on systems and networks you are authorized to test.

---
## Quick Links

- Releases: [github.com/NexusFireMan/gomap/releases](https://github.com/NexusFireMan/gomap/releases)
- Container: [github.com/NexusFireMan/gomap/pkgs/container/gomap](https://github.com/NexusFireMan/gomap/pkgs/container/gomap)
- Support: [ko-fi.com/C0C61UHTB1](https://ko-fi.com/C0C61UHTB1)

If you find the project useful, you can support it here:
[![ko-fi](https://ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/C0C61UHTB1)
