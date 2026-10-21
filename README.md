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

**Fast TCP/UDP scanner in Go for authorized reconnaissance, with service fingerprinting, native SYN scanning, low-noise profiles, and automation-friendly output.**

[![CI](https://github.com/NexusFireMan/gomap/actions/workflows/ci.yml/badge.svg)](https://github.com/NexusFireMan/gomap/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/NexusFireMan/gomap?display_name=tag)](https://github.com/NexusFireMan/gomap/releases)
[![Go](https://img.shields.io/badge/Go-1.26.9%2B-00ADD8?logo=go&logoColor=white)](https://go.dev/)
[![Docker](https://img.shields.io/badge/Docker-GHCR-2496ED?logo=docker&logoColor=white)](https://github.com/NexusFireMan/gomap/pkgs/container/gomap)
[![CLI](https://img.shields.io/badge/Interface-CLI-2C2C2C)](https://github.com/NexusFireMan/gomap)
[![License](https://img.shields.io/github/license/NexusFireMan/gomap)](https://github.com/NexusFireMan/gomap/blob/main/LICENSE)
[![Ko-fi](https://img.shields.io/badge/Ko--fi-Support-FF5E5B?logo=kofi&logoColor=white)](https://ko-fi.com/C0C61UHTB1)

</div>

## Navigation

- [Current scope](#current-scope)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Authenticated SNMPv3](#authenticated-snmpv3)
- [UDP Queries And Reassembly](#udp-queries-and-reassembly)
- [Example Output](#example-output)
- [CLI Reference](#cli-reference)
- [Detection Realism (`-s`)](#detection-realism--s)
- [Real Source-IP Selection](#real-source-ip-selection)
- [HTB Performance Benchmark (Lab)](#htb-performance-benchmark-lab)
- [Metasploitable3 Lab Benchmark](#metasploitable3-lab-benchmark)
- [Per-Host Settings And Unknown Evidence](#per-host-settings-and-unknown-evidence)
- [Output Formats](#output-formats)
- [Responsible Use](#responsible-use)
- [Quick Links](#quick-links)

A fast TCP/UDP port scanner written in Go, with optional service/version detection, CIDR host discovery, adaptive timeout tuning, and multi-format output.

## Why gomap?

- Quick first look before deeper enumeration.
- Lightweight single-binary workflow.
- Structured output for Bash, Python, and CI/lab pipelines.
- CIDR-aware scanning with optional host discovery.
- Useful in CTFs, internal labs, and authorized assessments.

## Current scope

- Fast concurrent TCP scanning with selectable engine (`connect` or `syn`).
- UDP probing with `-u`, retaining confirmed and uncertain port states.
- Default quick scan uses a curated top-port list normalized to unique ports (current effective size: 996).
- Optional service and version detection (`-s`).
- Single host, hostname, comma-separated targets, and CIDR ranges.
- CIDR active-host discovery by TCP probes (no ICMP ping).
- Robust scan controls for unstable networks: retries, backoff, adaptive timeout.
- Professional outputs: `text`, `json`, `jsonl`, `csv`.
- Per-host exposure summary in text mode.
- Low-noise mode: controlled rate, heavier jitter, and fewer active probes through the existing `-g` ghost mode flag.
- Conservative low-noise defaults: low rate, low worker count, and reduced CIDR discovery probes.
- Optional HTTP identity randomization and real source-IP selection from preconfigured interface addresses.

## Installation

### Build from source

Use Go 1.26.9 or newer. CI and release builds follow `go.mod`; the Docker builder uses the same baseline to avoid shipping older standard-library security defects.

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
- Maintainer release, GHCR, Debian package, checksum, and APT repository steps are documented in [GoMap Release Workflow](docs/RELEASE_WORKFLOW.md).

## Quick Start

```bash
# Default scan (top common ports)
./gomap 10.0.11.6

# Native SYN scan discovery (requires root/CAP_NET_RAW)
./gomap --scan-type syn 10.0.11.6

# UDP scan with explicit port states
./gomap -u 10.0.11.6

# UDP scan on selected ports
./gomap -u -s -p 53,123,137,161,1900 10.0.11.6

# Optional bounded SNMP variant discovery (UDP/161)
./gomap -u -Dv -p 161 --timeout 500 --retries 0 10.0.11.6

# Service/version detection on selected ports
./gomap -s -p 21,22,80,135,139,445,5985 10.0.11.6

# Deeper bounded version detection on selected ports
./gomap -Dv -p 21,22,53,2121 10.0.11.6

# CIDR scan with automatic active-host discovery
./gomap -s --top-ports 300 10.0.11.0/24

# More robust scan profile for unstable networks
./gomap -s --retries 2 --adaptive-timeout --backoff-ms 40 --max-timeout 4500 10.0.11.9

# Machine output for automation
./gomap -s --format json --out scan.json 10.0.11.6

# Low-noise service detection profile
./gomap -g -s --random-agent --random-ip 10.0.11.0/24

# Temporarily add an explicit source pool, rotate it, and clean it up
sudo ./gomap --random-ip --source-interface eth0 \
  --source-ips 10.0.11.20/24,10.0.11.21/24,10.0.11.22/24 \
  -p 22,80,443 10.0.11.6

# Conservative CIDR scan (skip discovery entirely)
./gomap -g -nd -s --random-agent --random-ip -p 22,80,443 10.0.11.0/24
```

## Authenticated SNMPv3

Use a private, per-IP credential file for an explicitly authorized, read-only
SNMPv3 session on UDP/161:

```bash
chmod 600 /path/to/snmp-private.json
./gomap -u -p 161 --snmp-config /path/to/snmp-private.json 10.0.11.9
```

Supported authentication is `sha256` or `sha512`; privacy is explicitly `none`
(authNoPriv) or `aes128` (authPriv). No credentials are accepted directly as CLI
arguments. This option enables service detection and requires UDP. It cannot
combine with `-g` or source-identity options. Without it, existing scans are
unchanged. The bounded session sends at most two messages: engine discovery and
one authenticated GET. It does not walk MIBs or change device configuration.
See [SNMP sessions](docs/SNMP_SESSIONS.md) for the JSON schema, limits, privacy
requirements and validation scope. Do not commit credential files or captures.

## UDP Queries And Reassembly

On UDP/137, `-u -Dv` (also implied by `-De`) replaces the generic probe with
one read-only, unicast wildcard NBSTAT query. Responses must match its fresh
transaction ID, name, type and class before identification. There are no
broadcasts, redirects or automatic retries; default/`-g` scans are unchanged.
Names and MAC addresses are not disclosed. A timeout stays `open|filtered`,
not a confirmed closed port. See [UDP validation](docs/UDP_VALIDATION.md).

```bash
./gomap -u -Dv -p 11211 --timeout 1000 10.0.11.9
```

On UDP/11211, `-Dv` (also implied by `-De`) sends one framed, read-only
Memcached `stats` query. The response is correlated by request ID and may be
reassembled out of order. Limits are 16 fragments, 16 KiB total, 2048 bytes per
datagram, 32 reads and one fixed receive deadline (configured timeout, capped
at five seconds). Identical duplicates are tolerated; conflicting duplicates,
inconsistent counts, invalid reserved fields and expired responses are rejected.
The deadline is never extended by incoming fragments.

Evidence reports fragment/byte counts, not raw statistics. Only a validated
numeric `version` field becomes a product version; a complete stats response
without one is labeled generically. Incomplete/malformed replies remain
responsive but low confidence. No cache keys or items are read or modified.
The query is not repeated by `--retries`; default scans and `-g` are unchanged.
On UDP/138, deep scans send one read-only unicast NetBIOS datagram query.
Control replies are matched to its identifier/name; data datagrams use a bounded
two-fragment assembler and are explicitly not claimed to match that query.
No broadcast or application operation follows a positive reply. Names, MAC
addresses and reconstructed payloads are excluded from metadata.

IPv4/IPv6 fragments are reassembled by the operating system before GoMap reads
the UDP socket. Linux isolated tests exercise that production path with real
fragments; this is not a second raw-packet capture/reassembly engine. Per-protocol
size bounds still apply to the complete datagram. See [fragment handling](docs/UDP_FRAGMENTS.md)
and [UDP validation](docs/UDP_VALIDATION.md) for limits and test commands.

### SNMP Variant Discovery

With `-u -Dv` (also implied by `-De`), UDP/161 may send two additional queries
only when the existing SNMPv1 probe has not identified the protocol: one SNMPv2c
GET for `sysDescr.0` using the existing `public` community, then one SNMPv3
noAuthNoPriv engine-discovery request. No additional queries run with `-g`,
without service detection, after a confirmed identification, or when the initial
probe/retries finish with connection refusal. Each fallback runs once through the global attempt limiter
and existing UDP deadlines; `--retries` applies only to the initial probe.
Silence can therefore cost two additional timeout intervals. A received reply
is never discarded solely because a later variant times out or refuses.
Matching replies remain unauthenticated, medium-confidence protocol evidence,
not a confirmed product version. Communities, engine IDs and returned values
are not included in identification metadata. Credentialed sessions use the
separate `--snmp-config` option described above. See [UDP validation scope](docs/UDP_VALIDATION.md).

## Example Output

Text output varies by target, network conditions, and enabled detection options. A typical authorized lab scan may look like:

```text
$ gomap -s --details -p 21,22,80,139,445 10.0.11.6

PORT    STATE  SERVICE         VERSION                              LAT(ms) CONF     EVIDENCE
21      open   ftp             InFreight FTP v1.1                   73      high     protocol banner
22      open   ssh             SSH-2.0 - OpenSSH 8.2p1 Ubuntu       80      high     protocol banner
139     open   netbios-ssn     SMB 2.1-3.1.1                       78      high     raw smb negotiate
445     open   microsoft-ds    SMB 2.1-3.1.1                       82      high     raw smb negotiate

Host Exposure Summary
- 10.0.11.6 | open ports: 4 | critical: ftp, microsoft-ds, ssh | exposure: high
```

## CLI Reference

Options can appear before or after the target. Use `--` to end option parsing.

```text
Usage:
  gomap [options] <host|CIDR>

Main options:
  -p                ports to scan (example: 80,443 or 1-1024 or - for all)
  -u                scan UDP instead of TCP
  --scan-type       connect|syn (default: connect)
  --top, --top-ports scan top N ports from curated protocol list
  --exclude-ports   remove ports from final scan set
  -s                enable service/version detection
  -Dv               deeper bounded service/version detection
  -De               exhaustive bounded service detection (implies -Dv)
  -g                ghost mode: controlled-rate low-noise profile
  -nd               disable host discovery for CIDR targets

Performance/robustness:
  --workers         concurrent workers (default: auto by mode)
  --rate            max scan rate in ports/second per host (0 = unlimited)
  --global-rate     max connection/probe starts/second across the entire scan (0 = unlimited)
  --timeout         per-attempt dial timeout in ms (default: auto by mode)
  --host-config     JSON per-IP CONNECT/UDP timeout and retry overrides
  --retries         retries per port on timeout/transient connection error
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
  --capture-unknown opt-in bounded hex samples for unknown responses (implies -s)
  --evidence-bytes  sample size, 1-1024 bytes (default: 256)
  --stream          emit completed open-port results immediately (CONNECT, text/JSONL)

Source and HTTP identity controls:
  --random-agent    randomize HTTP User-Agent on each request
  --random-ip       enable randomized IP identity controls
  --source-interface <NIC> interface used for real source-IP binding
  --source-ips <IP/CIDR,...> temporarily add and rotate explicit addresses

Compatibility note:
  legacy aliases (`--ramdom-agent`, `--ip-ram`, `--ip-random`) are still accepted for backward compatibility.

Low-noise defaults for `-g` ghost mode:
  - lower default rate and worker count
  - reduced host-discovery probes on CIDR (443,80,22)
  - use `-nd` to disable host discovery completely on CIDR
  - tradeoff: discovery may miss hosts that only expose non-probed ports (for example 139/445 only)

Maintenance:
  -v, --version     show version/build info
  -up               update to latest version
  --remove          remove non-package gomap copies found in PATH/common locations
  --doctor          inspect active binary, PATH copies, and install origin
```

## Detection Realism (`-s`)

When `-s` is enabled, gomap combines port-based hints and protocol/banner parsing to infer:

- HTTP/HTTPS server family/version where available.
- Java RMI on TCP/1099 and TCP/8686 through JRMP acknowledgment and transport ping; no remote method invocation or deserialization.
- DCE/RPC bind acknowledgment on mapped RPC ports and unmapped TCP/49152-65535. A rejected interface context confirms RPC, not support for that interface. `DCE/RPC 5.0` is the wire protocol version, not a Windows version.
- SSH/FTP/PostgreSQL/Redis/MySQL and other protocol banners.
- SMB-oriented identification for `microsoft-ds` targets, including native dialect negotiation and conservative NetBIOS evidence.
- SMB probes use bounded native connections; an unanswered negotiation produces a generic service hint rather than an OS assertion.
- Native SMB negotiation reports an offered dialect (SMB 2.0.2 through 3.0.2), not the server's highest supported dialect or its operating system. Port 139 remains a low-confidence hint when no NetBIOS session is established.
- TLS handshake metadata where applicable (`tls_version`, `tls_cipher`, ALPN, certificate issuer).
- HTTPS probing includes TLS-wrapped application ports such as TCP/3920, TCP/4848, and TCP/8181, and reuses the successful HTTP TLS handshake metadata. Elasticsearch root JSON is checked before generic HTTP identification.
- Native fingerprints cover GlassFish, OpenMQ/JMS, Java RMI, DCE/RPC, and IRC responses when the service discloses enough product information.
- Deep HTTP evidence includes available `Server` and `Location` headers; redirects are reported, not followed. MySQL rejection packets expose their error code/message without inventing a server version.
- Generic active probes for open ports without a known port mapping, useful when services run on non-standard ports. An open port that remains unrecognized is reported as `unknown` with low confidence; it is not treated as closed.

`-Dv` enables the same service/version output as `-s`, shows a compact evidence column in text output, and adds a bounded deep-version pass for open ports whose first result is generic, weak, or empty. It is intended as GoMap's fast native version-detection profile for authorized lab/internal reconnaissance: more focused than the default `-s`, but still controlled so it does not turn a quick scan into a long script scan.

`-De` (or `--exhaustive-services`) enables `-Dv` and adds a second, bounded probe matrix for open ports that remain unidentified after the normal service pass. It checks TLS on non-standard ports plus common text protocol interactions, including SMTP, POP3, Redis, IMAP, IRC, RTSP, and SIP. The profile is opt-in because silent ports can add latency; an unrecognized response remains `unknown` rather than being assigned an unsupported product or version.

Important: banner-based detection is heuristic. Always validate critical findings with a second tool.

Generic banner descriptions carry medium confidence. High banner confidence means a recognized disclosure, not independent confirmation of a product version or operating system. RFB and SMB versions describe their protocols; TLS metadata describes the encrypted transport. SIP/RTSP identification requires a valid response status line, and product headers are read only before the response body.

IIS headers disclose the IIS version only, not a Windows release inferred from it. MySQL rejection packets and text-only SMB mentions remain medium-confidence hints. Native SMB accepts only responses matching its SMB2/3 request and an offered dialect; ONC RPC NULL success confirms the requested program/protocol version, not a daemon build or OS. The [current confidence review](docs/SERVICE_DETECTION_TESTS.md#identification-confidence-review) records the scope of each specialized path. See [release readiness and lab validation](docs/RELEASE_READINESS.md) before promoting development changes.

HTTP page titles are content hints and carry medium confidence, even when they mention a product version. A TLS-only handshake confirms the transport, not the application: an application label inferred from its port stays low confidence. HTTP and SSH response lines must be syntactically valid before their banners are accepted.

TCP CHAOS `version.bind` replies are reported as `DNS version.bind: <declared text>` at medium confidence, not automatically as BIND. This bounded path requires matching query ID/name/type/class, successful response flags and one unambiguous TXT answer; its fixed query ID and server-configurable text do not authenticate identity. See [ISC's explanation of configurable version replies](https://kb.isc.org/docs/aa-00359).

The existing `OPTIONS /wsman` probe on candidate WinRM ports reports confirmed HTTP/HTTPS and an independently complete Server header, if present. HTTPAPI and Negotiate also occur outside WinRM; evidence therefore explicitly says `WinRM not confirmed`. It does not perform a WS-Management exchange or authentication. Header/body separation, duplicate-header rejection and bounded fragmented-response collection apply here too. See [Microsoft's WinRM overview](https://learn.microsoft.com/windows/desktop/winrm/portal) and [HTTP.sys server documentation](https://learn.microsoft.com/en-us/aspnet/core/fundamentals/servers/httpsys).

RDP negotiation replies identify the protocol at medium confidence, not Microsoft Terminal Services or Windows. A rejection is explicitly labeled `RDP service (negotiation rejected)`; an X.224-only confirmation remains a low-confidence `RDP service (unconfirmed)` hint. Selecting TLS/CredSSP does not prove a completed TLS handshake or authenticated session. Evidence distinguishes TLS completion/failure, labels certificate CNs unverified, and preserves the original negotiation deadline through the TLS upgrade. No CredSSP authentication follows. See [RDP negotiation fields](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/b2975bdc-6d56-49ee-9c57-f2ff3a0b6817).

Validated TDS PRELOGIN replies report `TDS PRELOGIN` and, when nonzero, the server-declared major/minor/build fields at medium confidence. The `mssql` and `ms-wbt-server` service labels remain conventional service names, not independent vendor/OS confirmation. TDS evidence includes the server's ENCRYPTION option, not proof of active encryption. PRELOGIN's sender VERSION does not establish the negotiated TDS wire version; GoMap performs no TDS TLS, login or query exchange. Zero sender versions remain generic, and unrelated optional fields are not disclosed. See [TDS PRELOGIN](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-tds/60f56408-0188-4cd5-8b90-25c6f2423868) and [TDS version negotiation](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-tds/6809de85-1665-44ad-a459-6f6621e02257).

Operational limits:
- CONNECT completes one requested connection attempt before releasing the remaining workers; this avoids the initial parallel burst without adding probes. Banner reads do not block that release. A silent first port can add one attempt's wait before parallel scanning starts.
- `--retries` applies to timeouts and transient connection errors, not explicit connection refusals or permission errors. Its default remains zero; bounded scans can still miss temporarily unavailable services.
- Configured CONNECT retries use at most eight concurrent connections (never more than the worker count) and share `--rate` with initial attempts. A successful retry retains its connection for banner detection. Many filtered ports can still make retries expensive; inspect diagnostics before retrying a full range.
- JSON host entries include `connect_diagnostics` when CONNECT was used: attempted/refused/unresolved/recovered/filtered counts and per-port issues with attempts, last error, state, recovery status and the last attempt's actual timeout budget (`timeout_ms`). `configured_timeout_ms` is the scanner's base timeout; adaptive tuning can change an individual attempt's budget. These values are milliseconds, not port counts.
- CONNECT refusals count as `closed`; exhausted timeouts are labeled `filtered` (inferred from silence, not proof of a firewall). Local resource, permission, unreachable and other inconclusive errors remain `unknown`. Packet loss or an unavailable host can also cause timeouts. `filtered_ports` is a subset of `unresolved_ports`, retained for compatibility and completeness checks; it never inflates confirmed-open counts. Text warnings use unambiguous counters such as `timeout_ports=14`, separately from `configured_timeout_ms` and `last_attempt_timeout_ms`. These diagnostics do not establish SYN/UDP completeness.
- Inconclusive CONNECT scans show a warning and `indeterminate (observed: ...)` text exposure. JSONL/CSV keep one record per open port and report the warning on stderr; use JSON for per-port failure details. A finished scan with unresolved ports still exits successfully; callers requiring completeness must inspect `unresolved_ports`.
- `--stream` emits each completed CONNECT open-port result in completion order, before other ports or hosts finish. Text uses one self-contained `host:port open ...` line plus final diagnostics/summary; JSONL keeps its existing record schema and writes no duplicate final records. Without this flag, the sorted table/report is unchanged. With service detection, a result is emitted after its bounded detection finishes, not immediately after the TCP connection succeeds. Discovery still precedes port scanning; a slow output consumer can slow reporting. UDP, SYN, JSON documents and CSV do not support this flag. `--out` directs streamed records to the selected file instead of stdout.
- Service names inferred only from ports do not prove a product or operating system. A missing banner may reflect filtering, a silent service, or a timeout.
- Repeated unauthenticated connections can trigger server-side connection-error limits. MySQL errors such as 1129 (blocked host) and 1130 (host denied) are reported; GoMap does not authenticate or reset server limits automatically.
- `--rate` limits initial CONNECT attempts and configured CONNECT retries per host; it is not a global limit for host discovery or additional service probes.
- `--global-rate N` shares one non-burst budget across hosts, TCP host discovery, CONNECT retries, additional TCP/TLS service connections, UDP exchanges, and SYN transmissions. Combine it with `--rate` when both global and per-host pacing are needed. It defaults to zero (disabled) and can increase total scan time.
- The global budget counts attempt starts, not packets or application messages on an established connection. DNS resolution, local route selection, and kernel retransmissions are outside this budget; it is not a wire-level bandwidth limit.
- Raw-socket deadlines and closure are validated in an isolated loopback-only Linux namespace; signal cleanup uses deterministic subprocess tests with fake address backends. End-to-end SYN discovery and native netlink address rollback still require separate lab validation. See [Contributing](CONTRIBUTING.md#lab-tests) for the opt-in checks.
- DNS/TCP, MySQL, ONC RPC, SMB, AJP, DCE/RPC, JRMP, RDP, LDAP/LDAPS anonymous bind replies and TDS 7.x PRELOGIN have deterministic fragmented/truncated stream regressions. LDAP checks the request's message ID and result structure; TDS checks bounded packet sequences and option ranges. Existing RESP2 INFO, IRC registration and generic write-first probes now collect bounded protocol transactions rather than one arbitrary read. SMTP numeric replies, POP3 CAPA, tagged IMAP CAPABILITY and HTTP/RTSP/SIP framing are covered. HTTP and RESP collection is capped at 64 KiB; other text transactions at 4096 bytes. See the [service regression matrix](docs/SERVICE_DETECTION_TESTS.md) for count/depth limits and unsupported variants.
- Runtime parsing withholds a product/version disclosed only in an unfinished line, unfinished numeric multiline reply, incomplete RESP value or incomplete HTTP-like headers. Such observations remain low confidence with an explicit evidence note; the port stays open. A complete earlier greeting or product header may still support identification when later unrelated text/body bytes are incomplete. HTTP title hints remain content-level evidence. Redis bulk bodies require a complete envelope and one unambiguous `redis_version` field; IRC evidence selects the same complete line as the displayed version. These checks do not authenticate the server.
- Duplicate targets and ports are scanned once. CIDR discovery uses a bounded worker pool and preserves target order, including when applying `--max-hosts` afterward.
- When duplicate observations are combined, service, version, confidence, evidence, and detection path stay together. Higher-confidence identifications take precedence; equal-confidence results prefer a known service and fuller metadata, retaining the first observation on a complete tie. This selects an observation, not independent confirmation or consensus. Complete TLS handshake metadata is not replaced by partial TLS fields.
- IPv4 CIDRs omit network/broadcast addresses except for /31 and /32; IPv6 ranges preserve endpoints. Expansion is limited to 65,536 addresses per CIDR.

```bash
# Completion-order text results, followed by the final coverage summary
gomap -s --stream -p - 10.0.11.6

# One existing-schema JSONL record per completed open port; diagnostics use stderr
gomap -s --stream --format jsonl -p 22,80,443 10.0.11.9
```

Non-standard port note:
- For unknown open TCP ports, `-s` sends a bounded set of lightweight probes (`GET`, `CRLF`, and `HELP`) to identify moved services.
- This improves realism on CTF/lab targets and custom deployments where a service is intentionally exposed away from its default port.

`--scan-type syn` notes:
- Uses GoMap native raw TCP SYN probes for port discovery, then optional service detection on open ports.
- If SYN scan cannot run (insufficient privileges or unsupported OS), GoMap falls back to `connect` scan automatically.
- For noisy links, tune reliability explicitly with `--retries` and `--rate`.

`-u` UDP notes:
- TCP remains the default scan mode.
- `-u` switches port probing to UDP and uses a compact UDP default port set unless `-p` is provided.
- GoMap reports UDP ports as open only when a UDP response is received.
- UDP timeouts are retained as `open|filtered`; a socket connection-refused error is reported as `closed`. Other exchange errors remain `unknown`.
- UDP reports contain one result per requested port. `open` remains a boolean for compatibility and is true only for confirmed responses; the additive `state` field describes UDP outcomes. Open-port totals exclude uncertain and closed results.
- Starting with v2.5.0, automation consuming UDP reports must filter by `state == "open"` (or the JSON `open` boolean) rather than treating every returned row as confirmed open. CSV column names remain unchanged.
- `-u` cannot be combined with `--scan-type syn`, because SYN is TCP-specific.
- CIDR scans with `-u` still use TCP host discovery unless `-nd` is set.
- A UDP reply establishes responsiveness, not the application identity. Port-only service hints use the UDP map (never TCP names) and remain low confidence with an empty version. Unknown payload text is not promoted to a product version.
- NTP classification checks a bounded server-mode header and reports the protocol version at medium confidence, not a daemon version or correlated time exchange. The header layout follows [RFC 5905](https://www.rfc-editor.org/rfc/rfc5905.html).
- SSDP classification requires a bounded HTTP/1.1 200 response with ST, USN, and a HTTP(S) LOCATION header; SERVER disclosure is read from headers only. LOCATION is never fetched. These are shape checks based on [UPnP Device Architecture](https://openconnectivity.org/upnp-specs/UPnP-arch-DeviceArchitecture-v2.0-20200417.pdf), not full device verification.
- Standalone SNMP classification validates bounded ASN.1 v1/v2c responses and plaintext v3 USM `noAuthNoPriv` responses/reports; it does not authenticate identity or expose communities, users, engine IDs or binding values. Non-minimal definite BER lengths are supported within bounds; indefinite lengths and constructed simple values are rejected. Deep scans can add correlated v2c/v3 discovery queries, while `--snmp-config` selects the separate authenticated SHA-256/SHA-512 session with optional AES-128. See [SNMP sessions](docs/SNMP_SESSIONS.md) and the [UDP variant matrix](docs/UDP_VALIDATION.md) for exact bounds and unsupported forms.
- DNS, mDNS, and LLMNR classification uses the Go-native `golang.org/x/net/dns/dnsmessage` parser with bounded framing checks: section counts, names/compression, supported record bodies and lengths, response flags, and protocol-specific header/class rules. Validated shapes report only `DNS response`, `mDNS response`, or `LLMNR response` at medium confidence, not a server product/version or authenticated identity. Standalone shape checks do not correlate requests; runtime DNS replies are compared to the actual sent query as described below. Record names/values are not copied into identification metadata. See [DNS wire format](https://www.rfc-editor.org/rfc/rfc1035.html), [mDNS](https://www.rfc-editor.org/rfc/rfc6762.html), and [LLMNR](https://www.rfc-editor.org/rfc/rfc4795.html).
- These DNS-format checks deliberately support a conservative subset up to 2048 bytes. Truncated packets, unsupported record bodies/classes, and tentative LLMNR replies remain low-confidence hints. No new mDNS/LLMNR queries or multicast listeners are added; their existing generic probes may elicit no reply.
- NetBIOS name service on UDP/137 validates a bounded subset of positive NB/NBSTAT and negative name-query replies, based on [RFC 1002](https://www.rfc-editor.org/rfc/rfc1002.html). Deep scans use the correlated NBSTAT query described above; the default generic probe may elicit no reply. Metadata contains protocol/error labels, not Windows/Samba versions, hostnames, workgroups or MAC addresses. An application error does not mean a responsive port is closed. UDP/138 datagrams and TCP/139 sessions are outside these UDP/137 checks; see the [variant matrix](docs/UDP_VALIDATION.md).
- NetBIOS redirects are recognized only when RFC 1002 section 4.2.15 flags and section counts match, with one IN-class NS record pointing to an encoded NetBIOS name and one matching IN-class A record. Targets must match exactly after name decompression. This conservative subset does not cover every redirect form or authenticate the sender. Redirects are never followed; names and destination addresses are not included in output.
- Runtime matching checks actual sent query fields for DNS, compatible SNMP queries and optional NetBIOS NBSTAT. A mismatch keeps responsiveness but clears its version and lowers identification confidence. Unauthenticated matching stays medium confidence and does not prevent replay; default DNS/SNMPv1 identifiers remain fixed, while optional discovery uses random identifiers. Other probes lack usable correlation fields, including NTP's zero transmit timestamp. Authenticated SNMP uses its separate session checks. See the [UDP validation and unsupported-variant matrix](docs/UDP_VALIDATION.md).

### Real Source-IP Selection

`--random-ip --source-interface <NIC>` selects a compatible address assigned to that interface and binds each TCP, TLS, or UDP socket to it. When several addresses of the required IP family are available, GoMap chooses one per connection. This is real source-address selection with a valid return path, not arbitrary source-IP spoofing.

On Linux, `--source-ips` lets GoMap manage an explicit temporary pool. Entries may be bare IPs or CIDR addresses, separated by commas. The operation requires root privileges because it changes interface addresses through native netlink calls:

```bash
sudo gomap --random-ip --source-interface eth0 \
  --source-ips 192.0.2.20/24,192.0.2.21/24,192.0.2.22/24 \
  -p 22,80,443 192.0.2.50
```

GoMap records successful address additions and attempts to remove them after the scan, on setup failure, or on `Ctrl+C` and `SIGTERM`. Cleanup waits for in-flight additions and reports removal errors. Pre-existing addresses are skipped during setup. Cleanup cannot be guaranteed after `SIGKILL`, a system crash, or concurrent external changes to the interface. Do not run overlapping managed pools on the same interface; verify interface state after an abnormal termination.

The managed pool accepts at most 64 explicit addresses. Replace the documentation-only addresses above with addresses allocated to you and routed on that interface. GoMap cannot determine whether another device owns an address, so the operator remains responsible for preventing address conflicts. Managed source pools are intentionally unavailable for raw SYN scans; use the default connect scan or UDP mode.

Without `--source-ips`, `--source-interface` continues to rotate addresses that were configured before GoMap started and does not require root privileges.

For backward compatibility, `--random-ip` without `--source-interface` still randomizes HTTP `X-Forwarded-For` and `X-Real-IP` headers only; it does not change the actual TCP source IP.

## HTB Performance Benchmark (Lab)

Benchmark executed on **May 13, 2026** against an authorized Hack The Box lab target.

- Scanner host: Kali Linux, kernel `6.19.14+kali-amd64`
- Go toolchain: `go1.26.2 linux/amd64`
- GoMap binary: historical local build used for the May 13 benchmark; the exact commit was not recorded
- Target: `10.129.109.169` (private HTB lab address)
- Profile: CONNECT scan with service/version detection
- Quick profile command: `gomap -s 10.129.109.169`
- Full-port profile command: `gomap -s -p - 10.129.109.169`
- Quick profile runs: `5`
- Full-port profile runs: `4`

Quick profile duration (`996` TCP ports):

| Run | Duration | Hosts scanned | Open ports found |
|---:|---:|---:|---:|
| 1 | 2.251s | 1 | 8 |
| 2 | 2.220s | 1 | 8 |
| 3 | 2.245s | 1 | 8 |
| 4 | 2.095s | 1 | 8 |
| 5 | 2.205s | 1 | 8 |

Quick profile summary:

| Metric | Duration |
|---|---:|
| Min | 2.095s |
| Max | 2.251s |
| Mean | 2.203s |
| Median | 2.220s |

Full-port profile duration (`65,535` TCP ports):

| Run | Duration | Hosts scanned | Open ports found |
|---:|---:|---:|---:|
| 1 | 44.128s | 1 | 9 |
| 2 | 60.632s | 1 | 9 |
| 3 | 58.315s | 1 | 8 |
| 4 | 58.404s | 1 | 9 |

Full-port profile summary:

| Metric | Duration |
|---|---:|
| Min | 44.128s |
| Max | 60.632s |
| Mean | 55.370s |
| Median | 58.359s |

Representative quick profile output:

```text
PORT    STATE  SERVICE         VERSION
22      open   ssh             SSH-2.0 - OpenSSH 8.2p1 Ubuntu-4ubuntu0.3
25      open   smtp            SMTP service (no greeting)
53      open   domain          BIND 9.16.1-Ubuntu
110     open   pop3            InFreight POP3 v9.188
143     open   imap            IMAP4rev1
993     open   imap            IMAP4rev1
995     open   pop3            InFreight POP3 v9.188
3306    open   mysql           MySQL service (no handshake)

Host Exposure Summary
- 10.129.109.169 | open ports: 8 | critical: mysql, ssh | exposure: medium
```

Representative full-port additional finding:

```text
33060   open   mysqlx          MySQL X Protocol service
```

Notes:

- This is historical captured output, not the current identification policy: current TCP DNS disclosures use `DNS version.bind: <declared text>` rather than assuming BIND.
- `SMTP service (no greeting)` means the TCP port is open, but the server did not return an SMTP greeting within GoMap's bounded service-detection window.
- `MySQL service (no handshake)` means the TCP port is open, but the server did not emit a standard MySQL handshake, so GoMap reports the service without inventing a product version.
- The full-port profile found `33060/mysqlx`, which is outside the default quick scan set.
- HTB lab latency and VPN conditions can change; treat these numbers as a practical reference point, not a universal guarantee.

## Metasploitable3 Lab Benchmark

Benchmark executed on **September 17, 2026** against two authorized local VirtualBox lab machines: a Windows Metasploitable3 instance (`10.0.11.6`) and a Linux Metasploitable3 instance (`10.0.11.9`). The addresses are private lab fixtures and are included only to make the run reproducible in that environment.

- Profile: CONNECT scan with service/version detection
- Command: `go run . -s -p - 10.0.11.6,10.0.11.9`
- Port range: `65,535` TCP ports per host
- Workers: default CONNECT profile (`200` workers)
- Retries: default (`0`)
- Result: `51` open ports in `23.84s` (`37` Windows, `14` Linux)
- Inconclusive TCP ports: `6,923` on Windows; none reported on Linux in this run

Representative result:

```text
Host                         Open ports  Service highlights
10.0.11.6 (Windows)         37          IIS, SMB, RDP, WinRM, GlassFish, Java RMI, Elasticsearch
10.0.11.9 (Linux)            14          ProFTPD, OpenSSH, Apache, SMB, CUPS, Jetty, IRC, rpc.statd
```

The run identified services on standard and non-standard ports, including Java RMI on `8686`, GlassFish on `8080/8181`, JMS on `7676`, IRC on `6667/6697`, and `rpc.statd` on `57086`. Open ports without a recognizable application response are retained as `unknown` with low confidence. `unresolved` ports did not provide a completed TCP response within the bounded discovery window and must not be interpreted as closed.

This benchmark is a practical local-lab reference, not a universal performance guarantee. Metasploitable services can restart or expose dynamic ports between runs. It is not directly comparable with the historical HTB benchmark above: that benchmark used a different target, network path, and port set.

The historical `WinRM` highlight predates the current confidence review. A generic response to `OPTIONS /wsman` now reports HTTP/HTTPS with `WinRM not confirmed`; no new benchmark measurement is implied by this documentation update.

### Controlled Release Regression, October 21, 2026

A newer authorized two-VM regression on unreleased code used explicit rate and timeout limits, not the older default-speed profile:

| Profile | Ports Per Host | Open Windows / Linux | Unresolved Windows / Linux | Duration, Both Hosts |
| --- | ---: | ---: | ---: | ---: |
| Quick, first run | 996 | 22 / 7 | 0 / 987 | 28.754 s |
| Quick, second run | 996 | 22 / 7 | 0 / 987 | 27.526 s |
| Deep, selected ports | 20 | 16 / 7 | 0 / 12 | 1.975 s |
| Full TCP range | 65535 | 39 / 9 | 8 / 65524 | 332.694 s |

Baseline services, coverage accounting and JSON/JSONL/CSV preservation passed in every final profile. This does **not** establish complete network coverage: silent ports remain inconclusive, and an earlier preliminary run missed Linux baseline services. Settings, revision, failed/aborted attempts and limitations are recorded in the [release readiness report](docs/RELEASE_READINESS.md). Rates were 500 starts/s per host and 1000 globally; the full profile used 128 workers and a 150 ms dial timeout, versus 32 workers and 750 ms for the other profiles. Hosts were scanned sequentially, with zero retries and adaptive dial timeouts disabled. These controlled, non-CPU-isolated measurements are not comparable to the older 23.84 s benchmark.

## Per-Host Settings And Unknown Evidence

Use `--host-config host-settings.json` to override CONNECT/UDP settings for exact unzoned literal IPs in the expanded target scope. For example:

```json
{
  "10.0.11.6": {"timeout_ms": 800, "max_timeout_ms": 2000, "retries": 2, "adaptive_timeout": false},
  "10.0.11.9": {"timeout_ms": 300, "retries": 0}
}
```

```bash
./gomap -s --host-config host-settings.json 10.0.11.6,10.0.11.9
./gomap --capture-unknown --evidence-bytes 128 --format json --out private-report.json 10.0.11.6
```

Unspecified fields inherit scan-wide flags; explicit `0` retries and `false` adaptive timing override them. Timeout values are integer milliseconds; zero requests automatic defaults. Host retries are bounded to 0-10, and a nonzero maximum timeout cannot be below a nonzero configured timeout. The file is limited to 64 KiB; duplicate IPs/settings, unknown fields, nulls, malformed values and IPs outside the expanded scope are rejected before probes or output truncation. IPv4-mapped aliases normalize to the same IP. Overrides apply after host discovery, not to CIDR discovery itself. Native SYN does not support these overrides and rejects the combination. JSON `metrics.hosts[].settings` records the initial per-host configuration; adaptive deadlines and protocol-specific timeout floors/caps may differ during execution. The config file path is not copied into reports.

`--capture-unknown` enables `-s` and shows a compact evidence column in text mode. It adds a bounded `response_sample_hex` to the existing evidence field for unparsed TCP banners and unvalidated UDP payloads. JSON, JSONL and CSV retain their existing per-result shape/columns. Samples reuse already collected data, not capture-specific probes, and do not raise confidence. Empty responses produce no invented sample. The default prefix is 256 bytes, with a hard 1024-byte limit; observed/captured lengths and prefix truncation are reported. Existing readers may already bound the received response, so this is not a complete packet capture.

**Treat capture output as sensitive.** Capture is off by default. Samples with common credential markers or a leading ASN.1 sequence are withheld entirely, including when the marker lies beyond the requested prefix. This conservative suppression cannot guarantee redaction of arbitrary binary or custom protocols. Review reports manually before sharing; do not commit them. Capture-enabled `--out` requires a regular file and uses mode `0600` on Unix, including existing files; Windows users must configure appropriate ACLs. stdout/stderr redirection permissions remain the caller's responsibility. Known protocol disclosures and specialized probes are not converted into exhaustive raw captures.

## Output Formats

### Text (`--format text`, default)

- Aligned table per host.
- `--out` writes the report and summary to a file; progress messages may still appear on the terminal.
- Optional `--details` adds `LAT(ms)`, `CONF`, `EVIDENCE`.
- Final `Host Exposure Summary` with open ports, critical services, and exposure level.
- Performance and coverage summaries per host and across the scanned scope, including inconclusive outcomes.

### JSON (`--format json`)

Single report document with metadata:

- `schema_version`, `generated_at`, `target`, `duration_ms`
- `hosts_scanned`, `ports_requested`, `total_open_ports`
- `hosts[]` with per-port results
- Additive `metrics` object with build/version, whitelisted requested scan options, per-host engine actually used, phase timings, throughput and coverage.

Metrics count **host-port pairs**, not packets or connection attempts: two hosts and 100 ports mean a scope of 200. `scope_host_ports_per_second` divides that selected scope by the scan interval; `open_closed_host_ports_per_second` uses only confirmed open/closed states over the same interval. A high scope rate with low `open_closed_percent` is not evidence of a complete scan or successful service identification.

Coverage separates `open`, `closed`, `filtered`, `open_filtered`, `unresolved` and `unreported`. CONNECT diagnostics partition unresolved outcomes into inferred-filtered timeouts and other unknown failures without counting either twice. Filtered outcomes remain inconclusive for open/closed coverage. Missing results alone never imply closed or filtered. UDP silence remains `open|filtered`; the current SYN engine lacks complete non-open diagnostics, so missing SYN outcomes remain `unreported`. Global percentages are weighted by host-port scope, not averaged per host. Empty scanned scopes report zero, not 100% coverage. Hosts omitted by discovery or `--max-hosts` are outside this denominator; `expanded_hosts` and `hosts_scanned` make that distinction visible.

CONNECT text summaries explicitly label `closed (refused)`, `filtered (timeout-inferred)` and `unresolved (other failures)`. Zero closed means no connection refusal was observed, not proof that the underlying closed-port count is zero. Silent ports can reflect filtering, packet loss or an insufficient wait; GoMap cannot turn them into confirmed closures. See [Linux connect error semantics](https://man7.org/linux/man-pages/man2/connect.2.html) and [scan-state interpretation](https://nmap.org/book/man-port-scanning-basics.html).

The `inconclusive subtotal` overlaps the uncertain state columns; do not add it to them. Open/closed evidence includes the exact confirmed/requested fraction: one confirmed result out of 65535 is shown as `<0.1% (1/65535)`, not `0.0%`. Likewise incomplete near-total coverage uses `>99.9%`, not a rounded `100.0%`. Numeric JSON percentages remain unrounded. In JSON coverage, `unresolved` excludes `filtered`, whereas `connect_diagnostics.unresolved_ports` includes timeout-inferred filtered ports; these views retain their existing schemas and must not be added together.

To investigate a silence-heavy result, compare a small, authorized port set with a longer timeout and lower concurrency, rather than automatically repeating the full range. For example, on an owned lab host:

```bash
gomap -s -p 22,80,443 --timeout 1500 --workers 4 --rate 10 --global-rate 10 --retries 1 --adaptive-timeout=false 10.0.11.6
```

This may recover losses but cannot distinguish a closed port hidden by a dropping firewall. `--retries` remains opt-in (default zero); no automatic extra scan or timeout/rate change is introduced by these display clarifications.

Timings distinguish preparation/orchestration, TCP host discovery, and the scan interval including inline service detection. With `--stream`, the scan interval also includes inline result writes and output backpressure. `metrics.timings.total_ms` ends before final report rendering and deferred cleanup; the legacy `duration_ms` remains the scan interval. Separate service-detection time is not measured because it overlaps port work. Rates use unrounded durations; timing fields are integer milliseconds. Requested option values of zero may mean automatic defaults; adaptive timing, network state, randomization and unrecorded source/header settings prevent exact replay. Metadata intentionally excludes raw argv, output paths, source-IP pools and raw response bytes.

### JSONL (`--format jsonl`)

One JSON record per reported port, emitted after scanning completes by default (including uncertain and closed UDP outcomes). With `--stream`, CONNECT open-port records are emitted as their bounded detection finishes, in completion order, without duplicate final records. UDP streaming is not supported. Diagnostics and final performance/coverage summaries use stderr, never the JSONL record stream.

JSONL and CSV keep their existing per-result records/columns. Performance and coverage summaries go to stderr; use JSON when run metadata must be stored in one report document, or redirect stderr separately for a text summary.

### CSV (`--format csv`)

One row per reported port, including uncertain and closed UDP outcomes, with columns:

`host,port,state,service,version,hostname,tls,tls_version,tls_cipher,tls_alpn,tls_server_name,tls_issuer,latency_ms,confidence,evidence,detection_path`

## Responsible Use

Use this tool only on systems and networks you are authorized to test.

---
## Quick Links

- Releases: [github.com/NexusFireMan/gomap/releases](https://github.com/NexusFireMan/gomap/releases)
- Container: [github.com/NexusFireMan/gomap/pkgs/container/gomap](https://github.com/NexusFireMan/gomap/pkgs/container/gomap)
- Support: [ko-fi.com/C0C61UHTB1](https://ko-fi.com/C0C61UHTB1)

If you find the project useful, you can support it here:
[![ko-fi](https://ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/C0C61UHTB1)
