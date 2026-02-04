# Changelog

All notable changes to this project will be documented in this file.

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
