# Changelog

All notable changes to this project will be documented in this file.

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
- **Ghost mode defaults hardened** for ultra-stealth:
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

## [2.0] - 2026-02-02

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

- **Stealth Features**
  - No ICMP/Ping scanning
  - TCP-only connections
  - Ghost mode with randomization
  - Jitter implementation for IDS evasion

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

## [1.0] - 2026-01-15

### Added
- Initial public release
- Basic port scanning functionality
- Service detection
- Ghost mode for stealthy scanning
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

### Version History
- **1.0.0** - Initial release with basic features
- **2.0.0** - Major improvements (performance, CIDR, host discovery)
- **2.0.2** - Current (go.mod fix for go install)
- **2.0.1** - Colorized output, installation improvements
