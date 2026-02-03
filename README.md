
<div align="center">

```
  ██████╗  ██████╗ ███╗   ███╗ █████╗ ██████╗ 
 ██╔════╝ ██╔═══██╗████╗ ████║██╔══██╗██╔══██╗
 ██║  ███╗██║   ██║██╔████╔██║███████║██████╔╝
 ██║   ██║██║   ██║██║╚██╔╝██║██╔══██║██╔═══╝ 
 ╚██████╔╝╚██████╔╝██║ ╚═╝ ██║██║  ██║██║     
  ╚═════╝  ╚═════╝ ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝     
```

**A fast, stealthy, and intelligent port scanner written in Go.**

</div>

---

## Overview

**GOMAP** is a lightweight, fast, and versatile port scanner designed for quick network reconnaissance. It offers multiple scanning modes with advanced features like automatic host discovery, CIDR support, precise service detection, and stealthy scanning to evade IDS/firewall detection.

### Key Highlights

- ⚡ **4x faster** than before (optimized timeouts and parallel workers)
- � **Colorized output** (ANSI colors for better visibility)
- �🎯 **Precise SMB detection** (identifies Windows Server versions and Samba)
- 🌐 **CIDR & network scanning** (scan ranges, not just single IPs)
- 🔍 **Automatic host discovery** (85-90% faster on sparse networks)
- 👻 **Ghost mode** (stealthy scanning to evade IDS/Firewall)
- 🔒 **No ping/ICMP** (doesn't reveal you're scanning)
- 🚀 **Concurrent scanning** (200 parallel workers in normal mode)

---

## Features

### Core Scanning
- **Fast Concurrent Scanning**: 200 goroutines in normal mode, 10 in ghost mode
- **Colorized Terminal Output**: ANSI colors for better readability and visual hierarchy
- **Single IP Scanning**: Quick port scanning on individual hosts
- **CIDR Range Scanning**: Scan entire networks (192.168.1.0/24, 10.0.0.0/25, etc.)
- **Multiple IP Targets**: Scan specific hosts simultaneously (192.168.1.1,192.168.1.5)
- **Flexible Port Selection**: Specific ports, ranges, or all 65535 ports
- **DNS Resolution**: Scan by hostname (localhost, example.com, etc.)

### Service & Version Detection
- **Smart Banner Grabbing**: Identifies 50+ services with precise version detection
- **Windows Server Detection**: Identifies specific versions (2008 R2, 2012, 2016, 2019)
- **Samba Detection**: Differentiates between Samba versions (3.X, 4.X)
- **HTTP Server Fingerprinting**: Apache, Nginx, IIS, Tomcat, Node.js, GlassFish, etc.
- **SSH/FTP/MySQL Detection**: Protocol version and implementation detection
- **Database Detection**: PostgreSQL, Redis, MongoDB, Elasticsearch, etc.

### Network Discovery
- **Automatic Host Discovery**: Scans CIDR ranges and skips inactive hosts (85-90% faster)
- **Intelligent Port Probing**: Tests 7 common ports (443, 80, 22, 445, 3306, 8080, 3389)
- **Optional Manual Scanning**: Disable auto-discovery with `-nd` flag if needed
- **Network Filtering**: Automatically excludes network and broadcast addresses

### Stealth & Performance
- **Ghost Mode** (`-g`): Slower, randomized, with jitter to evade detection
- **No ICMP/Ping**: Doesn't use ICMP (pure TCP scanning)
- **500ms Default Timeout**: 4x faster than previous versions
- **Configurable Workers**: 200 normal / 10 ghost mode for automatic optimization

### Auto-Update & Info
- **Auto-Update**: `-up` flag updates to latest version from GitHub
- **Version Info**: `-v` flag shows version and repository details

---

## Installation

### Option 1: From Source with Automatic Installation (Recommended)
```bash
git clone https://github.com/NexusFireMan/gomap.git
cd gomap
./install.sh
```
The script will automatically install to `/usr/local/bin/` or `/usr/bin/`

### Option 2: Manual Build and Installation
```bash
git clone https://github.com/NexusFireMan/gomap.git
cd gomap
./build.sh              # Uses optimized build flags
sudo mv gomap /usr/local/bin/
```

### Option 3: Using Go Install
```bash
go install github.com/NexusFireMan/gomap@latest
# Add to PATH: export PATH=$PATH:$HOME/go/bin
gomap -v
```

### Option 4: From Pre-built Binary
Download the latest release from the [Releases](https://github.com/NexusFireMan/gomap/releases) page.

---

## Colorized Terminal Output

Gomap v2.0.1 features **ANSI color output** for better readability:

### Output Colors
- **Port Numbers**: Bright Magenta
- **Service Names**: Green  
- **Versions**: Bright Yellow
- **Status Indicators**: 
  - ✓ Success (Green)
  - ✗ Error (Red)
  - ⚠ Warning (Yellow)
  - 🔍 Discovery (Blue)

### Example Output
```
🔍 Discovering active hosts in 192.168.1.0/24...
✓ Found 12 active hosts, starting port scan...

═══ 192.168.1.100 ═══
PORT    STATE SERVICE         VERSION
445     open  microsoft-ds    Windows Server 2008 R2
80      open  http            Apache/2.4.41
22      open  ssh             SSH-2.0-OpenSSH_7.4
```

---

## Quick Start

### Scan a Single Host
```bash
# Top 997 ports with service detection
./gomap -s 192.168.1.100

# Specific ports
./gomap -s -p 22,80,443 192.168.1.100
```

### Scan a CIDR Range (Auto Host Discovery)
```bash
# Automatically discovers active hosts first
./gomap -s -p 22,80,443 192.168.1.0/24

# Output:
# Discovering active hosts in 192.168.1.0/24...
# Found 45 active hosts, starting port scan...
```

### Scan Multiple IPs
```bash
./gomap -s -p 22,445 192.168.1.1,192.168.1.5,192.168.1.10
```

### Stealthy Ghost Mode
```bash
# Slower, randomized, with jitter
./gomap -g -s -p 1-1024 192.168.1.0/25
```

### Skip Host Discovery (Full CIDR Scan)
```bash
# Scans all hosts, even inactive ones
./gomap -s -nd -p 22 192.168.1.0/24
```

---

## Usage

```
Gomap: A fast and simple port scanner written in Go.

Usage:
  gomap <host|CIDR> [options]

Options:
  -g       ghost mode (slower, stealthy to evade IDS/Firewall)
  -nd      disable host discovery (scan all hosts in CIDR)
  -p       ports to scan (e.g., 80,443 or 1-1024 or - for all)
  -s       detect services and versions
  -up      update to the latest version
  -v       show version information

Notes:
  - CIDR scans automatically discover active hosts first (disable with -nd)
  - Host discovery probes ports: 443, 80, 22, 445, 3306, 8080, 3389
  - No ICMP/ping used - only TCP connections

Examples:
  gomap 127.0.0.1                              (Scan localhost)
  gomap -p 80,443,8080 192.168.1.1           (Scan specific ports)
  gomap -p 1-1024 -s 192.168.1.0/24          (Scan CIDR with service detection)
  gomap -g -p 1-1024 10.0.0.0/25             (Stealthy ghost mode on CIDR)
  gomap -s -nd -p 22 192.168.1.0/24          (Scan all hosts, no discovery)
```

---

## Performance Comparison

### Single Host Scan (Top 997 Ports)
| Mode | Timeout | Workers | Speed |
|------|---------|---------|-------|
| Normal | 500ms | 200 | ~5 seconds |
| Ghost | 2s | 10 | ~30 seconds |

### CIDR /24 Scan (254 hosts, 22 ports)
| Method | Time | Hosts Scanned | Improvement |
|--------|------|--------------|-------------|
| Without Discovery (-nd) | 30-40 min | 254 | Baseline |
| With Discovery (default) | 3-5 min | ~45-60 | **85-90% faster** |

---

## Service Detection Examples

### Windows Server
```
PORT    STATE  SERVICE      VERSION
 445    open   microsoft-ds Windows Server 2008 R2
 3389   open   ms-wbt-server
 5985   open   http         Microsoft-HTTPAPI/2.0
```

### Linux with Samba
```
PORT    STATE  SERVICE      VERSION
 22     open   ssh          SSH-2.0 - OpenSSH 6.6.1p1
 80     open   http         Apache 2.4.7 (Ubuntu)
 445    open   microsoft-ds Samba smbd 3.X
```

### Web Server
```
PORT    STATE  SERVICE      VERSION
 80     open   http         Apache 2.4.6
 443    open   https        Nginx 1.14.0
 8080   open   http         Jetty 8.1.7
```

---

## Advanced Features

### CIDR Scanning with Auto-Discovery
```bash
# Scans /24 network, automatically finds active hosts
./gomap -s -p 22,80,443,445 192.168.1.0/24

# Takes ~3-5 minutes instead of 30-40 minutes
```

### DNS Hostname Resolution
```bash
# Resolves hostname to IP and scans
./gomap -s localhost
./gomap -s example.com
```

### Batch Multiple Targets
```bash
# Combine IPs, CIDR, and comma-separated targets
./gomap -s 192.168.1.1,192.168.1.0/25,10.0.0.1
```

### All 65535 Ports
```bash
# Use "-" to scan all ports (slow!)
./gomap -s -p - 192.168.1.100
```

---

## Architecture & Improvements

### v2.0 Enhancements (Current)

#### Performance
- ✅ 4x faster (500ms timeout vs 2s before)
- ✅ 2x more parallel workers (200 vs 100)
- ✅ Eliminated retry delays
- ✅ Optimized HTTP banner grabbing

#### Detection
- ✅ SMB version detection (Windows Server specific versions)
- ✅ Samba identification and version detection
- ✅ 50+ services with precise version info
- ✅ SSH protocol version detection

#### Networking
- ✅ CIDR range support
- ✅ Multiple IP targets
- ✅ Automatic host discovery (85-90% faster)
- ✅ DNS hostname resolution
- ✅ Network filtering (excl. network/broadcast addresses)

#### Stealth
- ✅ No ICMP/Ping (no host discovery)
- ✅ TCP-only scanning
- ✅ Ghost mode randomization
- ✅ Jitter implementation

---

## Updating

### Method 1: Using the -up Flag
```bash
./gomap -up
```
Automatically pulls latest changes and rebuilds.

### Method 2: Using go install
```bash
go install github.com/NexusFireMan/gomap@latest
```

### Method 3: Manual Update
```bash
cd /path/to/gomap
git pull origin main
go build
```

### Check Version
```bash
./gomap -v
```

---

## Security Considerations

- ✅ **No Root Required**: Pure TCP scanning, no raw sockets
- ✅ **No ICMP**: Doesn't send ping packets
- ✅ **Firewall Compatible**: Works behind restrictive firewalls
- ✅ **IDS Evasion**: Ghost mode with jitter and randomization
- ✅ **Stealthy**: Can be run continuously without triggering alerts

---

## Technical Specifications

### Supported Platforms
- Linux (primary)
- macOS
- Windows
- Any OS with Go runtime

### Language & Dependencies
- **Language**: Go 1.13+
- **Dependencies**: Minimal (standard library + SMB protocol library)
- **Size**: ~5MB executable

### Port Scanning
- **Method**: TCP Connect Scan
- **Max Hosts/CIDR**: 65,536 (2^16)
- **Ports**: 1-65535 (all ports)
- **Timeout**: Configurable (default 500ms)

---

## License

GOMAP is open source and available under the [MIT License](LICENSE).

---

## Contributing

Contributions are welcome! Please feel free to:
- Report bugs
- Suggest features
- Submit pull requests

---

## Author

Created by [NexusFireMan](https://github.com/NexusFireMan)

### Repository
[github.com/NexusFireMan/gomap](https://github.com/NexusFireMan/gomap)

---

## Changelog

### v2.0.1 (Current)
- ✅ **Colorized terminal output** (ANSI colors, emoji indicators)
- ✅ **Improved installation** (install.sh, build.sh scripts)
- ✅ **Better PATH handling** (automatic system installation)
- ✅ **Repository cleanup** (documentation in Doc_MD/)
- ✅ **Enhanced UX** (visual hierarchy, status indicators)

### v2.0
- ✅ Performance optimizations (4x faster)
- ✅ SMB/Samba version detection
- ✅ CIDR range scanning
- ✅ Multiple IP targets
- ✅ Automatic host discovery
- ✅ No ICMP scanning
- ✅ 50+ service detection

### v1.0 (Initial Release)
- Basic port scanning
- Service detection
- Ghost mode
- Auto-update

---

**Made with ❤️ for security professionals and network administrators.**
