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

**Fast TCP scanner in Go with service fingerprinting, native SYN scanning, stealth profiles, and multi-format output.**

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
- [Testing and Quality](#testing-and-quality)
- [Project Layout](#project-layout)
- [Release Process](#release-process)
- [APT Repository Publishing](#apt-repository-publishing)
- [Responsible Use](#responsible-use)
- [Quick Links](#quick-links)

A fast TCP port scanner written in Go, with optional service/version detection, CIDR host discovery, adaptive timeout tuning, and multi-format output.

## Current scope

- Fast concurrent TCP scanning with selectable engine (`connect` or `syn`).
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
/usr/bin/gomap -v
hash -r
```

Validated in lab:
- `apt update` resolves `InRelease` and `Packages` correctly from `https://nexusfireman.github.io/gomap`
- `apt install gomap` installs `2.4.3` successfully on Kali
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
  --scan-type       connect|syn (default: connect)
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

## Detection Realism (`-s`)

When `-s` is enabled, gomap combines port-based hints and protocol/banner parsing to infer:

- HTTP/HTTPS server family/version where available.
- SSH/FTP/PostgreSQL/Redis/MySQL and other protocol banners.
- SMB-oriented identification for `microsoft-ds` targets.
- TLS handshake metadata where applicable (`tls_version`, `tls_cipher`, ALPN, certificate issuer).

Important: banner-based detection is heuristic. Always validate critical findings with a second tool.

`--scan-type syn` notes:
- Uses GoMap native raw TCP SYN probes for port discovery, then optional service detection on open ports.
- If SYN scan cannot run (insufficient privileges or unsupported OS), GoMap falls back to `connect` scan automatically.
- For noisy links, tune reliability explicitly with `--retries` and `--rate`.

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

## Testing and Quality

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

## Project Layout

```text
cmd/gomap/      CLI parsing, version/update/remove commands
pkg/app/        Orchestration: target expansion, discovery, scan workflow
pkg/scanner/    Scan engine + service/banner detection
pkg/output/     Table renderer + json/jsonl/csv report generation
.github/        CI and release workflows
```

## Release Process

Quick links:

- Source: `git clone https://github.com/NexusFireMan/gomap.git`
- Latest release: `https://github.com/NexusFireMan/gomap/releases/latest`
- Container image: `ghcr.io/nexusfireman/gomap:latest`
- Debian packages: assets attached to each tagged release

- CI: `.github/workflows/ci.yml` (lint, tests, race, coverage).
- Container publishing: `.github/workflows/container.yml` (GHCR image on `main` and tags).
- Release PR automation: `release-please` workflow.
- Tagged releases: GoReleaser workflow builds archives, checksums, and `.deb` packages.

## APT Repository Publishing

The APT repository is published automatically to GitHub Pages at:

- `https://nexusfireman.github.io/gomap`

Workflow:

- `.github/workflows/release.yml` publishes GitHub release assets, including `.deb` packages.
- `.github/workflows/apt-repo.yml` runs after the `Release` workflow completes successfully.
- It downloads all released `.deb` assets, rebuilds the APT metadata, signs `Release`/`InRelease`, and deploys the result to GitHub Pages.

Required GitHub configuration:

1. Enable **GitHub Pages** for this repository.
2. Set Pages source to **GitHub Actions**.
3. Add repository secrets:
   - `APT_GPG_PRIVATE_KEY`
   - `APT_GPG_PASSPHRASE`

Recommended GPG setup:

```bash
gpg --full-generate-key
gpg --armor --export-secret-keys "<your-key-id>" > gomap-apt-private.asc
gpg --export "<your-key-id>" > gomap-archive-keyring.gpg
```

Then:

- store the contents of `gomap-apt-private.asc` in `APT_GPG_PRIVATE_KEY`
- store the passphrase in `APT_GPG_PASSPHRASE`
- keep `gomap-archive-keyring.gpg` as the public key distributed to users

Local dry-run:

```bash
mkdir -p .apt-input
cp dist/*.deb .apt-input/
bash ./scripts/build-apt-repo.sh .apt-input .pages https://nexusfireman.github.io/gomap
```

Operational note:

- The APT repository is validated, but user shells may still resolve older local binaries first if `~/.local/bin` or `/usr/local/bin` appears before `/usr/bin` in `PATH`.

## Responsible Use

Use this tool only on systems and networks you are authorized to test.

---
## Quick Links

- Releases: [github.com/NexusFireMan/gomap/releases](https://github.com/NexusFireMan/gomap/releases)
- Container: [github.com/NexusFireMan/gomap/pkgs/container/gomap](https://github.com/NexusFireMan/gomap/pkgs/container/gomap)
- CI: [github.com/NexusFireMan/gomap/actions/workflows/ci.yml](https://github.com/NexusFireMan/gomap/actions/workflows/ci.yml)
- Support: [ko-fi.com/C0C61UHTB1](https://ko-fi.com/C0C61UHTB1)

If you find the project useful, you can support it here:
[![ko-fi](https://ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/C0C61UHTB1)
