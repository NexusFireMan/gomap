# Changelog

All notable changes to this project will be documented in this file.

Note: this changelog is maintained from this point forward in the project history.

## Unreleased

### Added
- Documented the maintainer release workflow for tags, GitHub Releases, binaries, Debian packages, GHCR images, checksums, and the signed GitHub Pages APT repository.
- Added `-Dv`, a bounded deep-version detection profile that enables service/version output and adds focused extra probes only for open ports with weak, generic, or empty version evidence.

### Changed
- Marked the APT/GHCR release workflow documentation roadmap item as completed.
- `-Dv` now makes text output visibly distinct with a compact evidence column and uses a faster FTP deep-version probe path before falling back to no-greeting evidence.

### Fixed
- **Deep-version evidence quality**: `-Dv` now avoids empty RDP versions, reports `Microsoft Terminal Services` for RDP, extracts RDP negotiation/certificate evidence when available, and uses concrete WinRM/RPC/SMB evidence strings instead of generic probe labels.
- **Alternate FTP banner detection**: port `2121` now maps to `ftp`, uses the FTP probe path, normalizes generic ProFTPD greetings to `ProFTPD`, and reports silent FTP services as `FTP service (no greeting)` instead of leaving the version empty.

## [2.4.8] - 2026-05-13

### Added
- **MySQL X Protocol mapping**: port `33060` is now identified as `mysqlx` with a clear `MySQL X Protocol service` hint.
- **HTB performance benchmark**: README now documents measured quick-scan and full-port scan timings against an authorized Hack The Box lab target.

### Changed
- **Native-only service detection**: scanner-side SMB and service fingerprinting paths no longer shell out to external tools such as `nmap`, `smbclient`, or `rpcclient`.
- **Bounded service probes**: SMTP, POP3, IMAP, and MySQL probes now use tighter service-detection windows so silent services do not dominate total scan time.
- **README positioning**: documentation now emphasizes authorized reconnaissance, structured output, low-noise profiles, and automation-friendly CLI usage.
- **Benchmark documentation**: replaced the old Snort lab benchmark with current HTB quick-scan and full-port measurements.

### Fixed
- **Silent MySQL reporting**: open MySQL ports that do not emit a standard handshake now report `MySQL service (no handshake)` instead of leaving the version column empty.
- **Silent SMTP reporting**: open SMTP ports that do not return a greeting now report `SMTP service (no greeting)` instead of leaving the version column empty.
- **MySQL scan latency**: MySQL detection now reads from the already-open scan connection and avoids long secondary connection attempts.
- **SMTP scan latency**: SMTP probing now reuses the already-open connection where possible and avoids slow duplicate probes.
- **Stale external-tool evidence**: README examples and output golden tests no longer reference removed `nmap`/`smbclient` evidence paths.

## [2.4.7] - 2026-04-30

### Added
- **Richer service fingerprinting**: TCP service detection now includes generic probes for services exposed on non-standard ports.
- **ONC RPC/NFS detection**: `-s` can now identify `rpcbind`, `nfs`, `mountd`, `nlockmgr`, `rpc.statd`, and related dynamic RPC services.
- **SMB/Samba detection**: SMB fingerprinting now uses native raw SMB negotiation and the Go SMB client library without shelling out to external tools.

### Changed
- **FTP banner probing**: FTP detection now waits longer for slow greetings, sends `SYST`, `FEAT`, and `HELP`, and prefers product banners such as `InFreight FTP v1.1` over generic protocol hints.
- **SMB fallback behavior**: SMB output no longer defaults to `Microsoft Windows` when native probes only confirm that the service is open.

### Fixed
- **SMTP vs FTP ambiguity**: `220 ... ESMTP` banners are no longer misclassified as FTP.
- **NetBIOS/SMB coverage**: port `139` now receives SMB-oriented enrichment instead of remaining a plain `netbios-ssn` port-map result.
- **NFS port mapping**: port `2049` is now mapped as `nfs` even when active fingerprinting cannot complete.

## [2.4.6] - 2026-04-28

### Added
- **UDP scan mode**: new `-u` flag to scan UDP instead of TCP.
- **UDP default port set**: UDP scans now use a compact curated list of common UDP services unless `-p` is provided.
- **UDP response classification**: initial service hints for responsive UDP services such as DNS, NTP, SNMP, SSDP, mDNS, LLMNR, and memcached-style responses.

### Changed
- **CLI and README**: help text and documentation now describe TCP/UDP usage, UDP examples, and UDP-specific limitations.
- **Public README cleanup**: moved maintainer-focused testing, release, project-layout, and APT publishing notes out of the public README to keep the landing page focused on users.

### Notes
- UDP mode reports a port as open only when a UDP response is received.
- Silent UDP ports are omitted because no response can mean closed, filtered, or open-but-silent.
- `-u` cannot be combined with `--scan-type syn`, because SYN scanning is TCP-specific.

## [2.4.5] - 2026-03-18

### Fixed
- **Doctor output polish**: `gomap --doctor` now presents a cleaner `Summary` plus `Detected Installations` layout, removes redundant active-path repetition, and only warns when additional copies are genuinely relevant.

## [2.4.4] - 2026-03-18

### Added
- **Installation doctor**: new `gomap --doctor` command to inspect the active binary, detect multiple copies in `PATH`, report version/origin per copy, and highlight PATH shadowing issues.

### Changed
- **Safer removal flow**: `gomap --remove` now targets non-package copies found in `PATH` and common locations instead of assuming only `/usr/local/bin`.
- **APT coexistence guidance**: README now documents how `apt` installations interact with older `go install` or manual copies and how to cleanly resolve conflicts.

### Fixed
- **Version parsing for managed installs**: internal version detection now understands the current colored `gomap -v` output format, improving updater and diagnostic accuracy.

## [2.4.3] - 2026-03-18

### Added
- **APT repository publishing**: GitHub Actions can now build and publish a signed APT repository for Kali, Parrot, Debian, and close derivatives via GitHub Pages.
- **APT repository builder**: added a reusable script to assemble `pool/`, `Packages`, `Release`, `InRelease`, and the public installation landing page.

### Changed
- **Installation documentation**: README now documents APT installation, Pages setup, required GPG secrets, and local dry-run steps for the repository publisher.
- **Repository hygiene**: local APT staging directories are now ignored by Git.

## [2.4.2] - 2026-03-18

### Added
- **Container packaging**: project now includes a production-oriented `Dockerfile` and `.dockerignore` for fast containerized use of `gomap`.
- **GHCR publishing workflow**: GitHub Actions now builds and publishes multi-arch container images to `ghcr.io`.
- **Debian package release base**: GoReleaser now produces `.deb` artifacts for tagged releases.

### Changed
- **README installation docs**: added container usage, native SYN requirements inside containers, and direct `.deb` installation guidance.
- **Release pipeline coverage**: documented and wired release outputs now include archives, checksums, `.deb` packages, and container images.

### Fixed
- **CI lint reproducibility**: CI now installs and runs a pinned `golangci-lint` version with config verification, aligned with the repository config schema.

## [2.4.1] - 2026-03-09

### Added
- **TLS fingerprint metadata in service detection** (`-s`): scanner now captures TLS handshake details when applicable (`tls_version`, `tls_cipher`, `tls_alpn`, `tls_server_name`, `tls_issuer`).
- **Machine-output schema expansion**: JSON/JSONL/CSV now expose TLS metadata fields for automation and reporting.

### Changed
- **Detection flow tuning**: TLS fingerprint attempts are restricted to likely TLS ports/services to avoid unnecessary probe overhead.
- **Top port set normalization**: duplicate ports are removed from the default top-port list, resulting in a stable effective set.

### Fixed
- **Performance regression in adaptive timeout**: timeout escalation now reacts primarily to real timeout conditions and is bounded, improving scan speed on hosts with many closed ports.
- **Duplicate open-port rows**: final open-port results are deduplicated by port with best-available metadata retained.

## [2.4.0] - 2026-03-09

### Added
- **Selectable scan engine**: new `--scan-type connect|syn` flag.
- **Native SYN discovery mode**: `syn` mode uses GoMap raw TCP SYN probes to discover open ports before optional service detection.

### Changed
- **Scan headers**: text output now indicates which scan type is being used.
- **README benchmark section**: expanded with detailed CONNECT vs SYN vs GHOST lab measurements against Snort.

### Fixed
- **Resilience**: automatic fallback to `connect` scan when SYN requirements are not met (unsupported OS or insufficient privileges).
- **Native SYN response parsing**: improved packet decoding and batched response collection to reduce false negatives under heavier scans.

## [2.3.1] - 2026-02-25

### Fixed
- **Updater reliability on end-user installs**: `gomap -up` now prefers downloading the latest GitHub release binary (with checksum verification) instead of relying only on `go install`.
- **Version metadata after update**: release-binary update path preserves embedded `Version`, `Commit`, and `Date`, avoiding ambiguous `dev/unknown` outputs in `gomap -v`.
- **Cross-platform asset handling**: updater now resolves the correct release archive per `GOOS/GOARCH` and extracts the binary automatically.
- **Safe fallback path**: if release-binary update fails, updater falls back to previous `go install` method.

## [2.3.0] - 2026-02-25

### Added
- **Professional CLI help UX**: `gomap -h` now uses a sectioned layout with banner, grouped flags, and clearer examples.
- **Consistent CLI visuals**: banner is now shown both in help and in text-mode scan runs.
- **Version output upgrade**: `gomap -v` now renders structured version/build sections.

### Changed
- **Ghost mode defaults refined** for low-noise scanning:
  - lower default rate
  - lower worker cap
  - reduced CIDR discovery probes (`443,80,22`) with explicit messaging
- **Flag naming consistency**:
  - canonical flags are `--random-agent` and `--random-ip`
  - legacy aliases (`--ramdom-agent`, `--ip-ram`, `--ip-random`) are still accepted

### Fixed
- **Build metadata reliability**:
  - runtime fallback in `-v` now uses Go build info (`vcs.revision`, `vcs.time`) and pseudo-version parsing when ldflags are absent
  - scripts now embed `Version`, `Commit`, and `Date` via ldflags
  - git-based self-update rebuild now embeds commit/date metadata

## [2.2.2] - 2026-02-17

### Fixed
- **Reliable `-up` flow**: updater now returns a real error if it cannot replace the active binary, avoiding false “updated successfully” messages.
- **Proxy lag fallback**: if `go install @latest` still resolves to the current version, updater retries once with `GOPROXY=direct`.
- **Interactive sudo**: updater now runs sudo replacement steps with terminal stdin/stdout/stderr, preventing non-TTY password prompt failures.
- **Post-install visibility**: updater now prints detected installed version from the new binary to make update state explicit.

## [2.2.1] - 2026-02-17

### Fixed
- **Updater binary replacement**: `gomap -up` now updates the active binary using atomic replacement (`*.new` + `mv`) to avoid `text file busy` errors when `/usr/local/bin/gomap` is currently executing.
- **Manual fallback command** updated to the same atomic pattern for reliable system-wide updates.

## [2.2.0] - 2026-02-17

### Changed
- **Go module path migrated to v2**: `go.mod` now declares `module github.com/NexusFireMan/gomap/v2`.
- **Import paths updated** across the codebase to `/v2` to comply with Go Modules major versioning.
- **Installer/update guidance updated** to use:
  - `go install github.com/NexusFireMan/gomap/v2@latest`
- **Release build ldflags updated** to inject version metadata using `/v2` package paths.

### Why
- Ensures `go install ...@latest` and semver `v2.x.y` tags behave correctly and predictably.

## [2.1.1] - 2026-02-17

### Fixed
- **Updater install target**: `gomap -up` now uses the correct Go module path (`github.com/NexusFireMan/gomap/v2@latest`) instead of a repository URL, fixing `argument must be a clean package path`.
- **Active binary synchronization**: after `go install`, updater now attempts to replace the binary currently resolved in `PATH` so `gomap -v` reflects the new version immediately.
- **Go bin path resolution**: updater now resolves installation path using `go env GOBIN` / `go env GOPATH` with fallback, improving reliability across environments.

## [2.1.0] - 2026-02-17

### Added
- **Professional outputs**: native `text`, `json`, `jsonl`, and `csv` reporting paths with stable schemas.
- **Golden tests for output formatting**: guardrails to prevent regressions in table layout/tabulation.
- **Lab integration tests**: optional end-to-end checks for Metasploitable3 Windows/Linux environments.
- **Advanced scan flags**: `--top-ports`, `--exclude-ports`, `--rate`, and `--max-hosts`.
- **Robust scan controls**: `--retries`, `--backoff-ms`, `--adaptive-timeout`, and `--max-timeout`.
- **Host exposure summary**: per-host risk summary after text-mode scans.
- **Quality pipeline**: CI with lint, unit tests, race tests, and minimum coverage enforcement.
- **Release pipeline**: automated release management with Release Please and GoReleaser.

### Changed
- **Architecture**: separated CLI parsing, scan orchestration, scanner engine, and output/reporting into clearer packages.
- **Service detection realism**: expanded banner parsing and confidence/evidence tracking for more realistic version fingerprints.
- **README**: fully rewritten and aligned with the current codebase, flags, testing flow, and release process.

### Fixed
- **Output alignment**: corrected table spacing so result columns match headers consistently.
- **CLI validation consistency**: improved validation and conflict handling for output and port-selection flags.

## [2.0.5] - 2026-02-04

### Fixed
- **Import cycle**: Added missing scanner import to output.go
- **Type references**: Updated output.go to use scanner.ScanResult from imported package
- **Variable shadowing**: Fixed scanner variable shadowing in main.go loop
- **Linter errors**: Resolved all remaining compiler warnings

## [2.0.4] - 2026-02-04

### Fixed
- **Compiler errors**: Resolved package declaration conflicts in reorganized structure
- **Build cache**: Cleaned and rebuilt all packages to ensure consistency
- **Import references**: Fixed all references to scanner and output packages

## [2.0.3] - 2026-02-04

### Changed
- **Repository structure**: Reorganized codebase with proper Go project layout
  * `cmd/gomap/` - Application entry point and main logic
  * `pkg/scanner/` - Core scanning functionality
  * `pkg/output/` - Output formatting and colors
  * `scripts/` - Build and installation scripts
  * `docs/` - Documentation files
- **Code organization**: Improved maintainability and separation of concerns

## [2.0.2] - 2026-02-04

### Fixed
- **go.mod module path**: Corrected module declaration from `gomap` to `github.com/NexusFireMan/gomap` for proper go install compatibility
- **Typo**: Fixed comment typo 'idirect' → 'indirect'

## [2.0.1] - 2026-02-03

### Added
- **Colorized Terminal Output**: ANSI color codes for better visibility
  - Ports in bright magenta
  - Services in green
  - Versions in bright yellow
  - Status indicators with emoji (✓ success, ✗ error, ⚠ warning, 🔍 discovery)
- **Installation Scripts**:
  - `install.sh` - Automatic installation to system PATH
  - `build.sh` - Optimized build with proper flags
- **Improved PATH Handling**:
  - Automatic detection of installation location
  - Fallback instructions for users without sudo
  - Support for `/usr/local/bin` and `/usr/bin`

### Changed
- Updated installation instructions in README.md
- Repository structure cleanup (documentation moved to `Doc_MD/`)
- Enhanced user experience with visual hierarchy in terminal output
- Improved version information display with colors

### Fixed
- `go install` now provides better feedback about PATH
- Installation path detection for system-wide usage

### Deprecated
- Plain text output (still available but colorized by default)

---

## [2.0.0] - 2026-02-02

### Added
- **Performance Optimizations**
  - 4x faster scanning (500ms timeout vs 2s before)
  - 2x more parallel workers (200 vs 100)
  - Eliminated retry delays
  - Optimized HTTP banner grabbing
  
- **Enhanced Service Detection**
  - SMB version detection (specific Windows Server versions)
  - Samba identification and version detection
  - 50+ services with precise version information
  - SSH protocol version detection

- **Network Scanning Features**
  - CIDR range support (e.g., 192.168.1.0/24)
  - Multiple IP targets (comma-separated)
  - Automatic host discovery (85-90% faster)
  - DNS hostname resolution
  - Network filtering (excludes network/broadcast addresses)

- **Low-noise controls**
  - No ICMP/Ping scanning
  - TCP-only connections
  - Ghost mode with controlled randomization
  - Jitter implementation for IDS noise reduction

### Changed
- Refactored scanner architecture for better performance
- Improved banner parsing with service-specific handlers
- Enhanced CIDR parsing and host discovery logic

### Technical Details
- Max 65,536 hosts per CIDR range
- Configurable workers: 200 normal / 10 ghost mode
- Default timeout: 500ms (normal) / 2s (ghost)
- 7-port host discovery: 443, 80, 22, 445, 3306, 8080, 3389

---

## [1.0.0] - 2026-01-15

### Added
- Initial public release
- Basic port scanning functionality
- Service detection
- Ghost mode for controlled-rate low-noise scanning
- Auto-update mechanism (`-up` flag)
- Version information (`-v` flag)
- Support for single host scanning
- Top 997 common ports mapping
- Basic HTTP/SSH/FTP service detection

### Features
- TCP connect scanning
- Concurrent worker pool
- Timeout configuration
- Port range support

---

## Version Numbering

This project follows [Semantic Versioning](https://semver.org/):

- **MAJOR** (X.0.0): Breaking changes
- **MINOR** (0.X.0): New features (backwards compatible)
- **PATCH** (0.0.X): Bug fixes (backwards compatible)

### Recent Version History
- **2.4.8** - Native service-detection fixes, bounded probes, clearer silent-service reporting, and updated HTB benchmarks.
- **2.4.7** - Richer service fingerprinting for FTP, ONC RPC/NFS, SMB/Samba, and related port-map fallbacks.
- **2.4.6** - UDP scan mode and responsive UDP service classification.
- **2.4.4** - Installation doctor and safer cleanup flows for multiple installed copies.
- **2.4.0** - Selectable `connect`/`syn` scan engines with native SYN discovery.
- **2.3.0** - Professional CLI help, structured version output, and low-noise profile refinements.
- **2.2.0** - Go module path migrated to `github.com/NexusFireMan/gomap/v2`.
- **2.1.0** - Structured output formats, exposure summaries, robust scan controls, and CI/release pipeline.
- **2.0.0** - Major performance, CIDR, host discovery, and service-detection improvements.
- **1.0.0** - Initial public release.
