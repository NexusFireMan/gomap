
<div align="center">

```
  ██████╗  ██████╗ ███╗   ███╗ █████╗ ██████╗ 
 ██╔════╝ ██╔═══██╗████╗ ████║██╔══██╗██╔══██╗
 ██║  ███╗██║   ██║██╔████╔██║███████║██████╔╝
 ██║   ██║██║   ██║██║╚██╔╝██║██╔══██║██╔═══╝ 
 ╚██████╔╝╚██████╔╝██║ ╚═╝ ██║██║  ██║██║     
  ╚═════╝  ╚═════╝ ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝     
```

**A fast and simple port scanner written in Go.**

</div>

---

GOMAP is a lightweight, fast, and versatile port scanner designed for quick network reconnaissance. It offers multiple scanning modes, from a high-speed parallel scan to a slow, stealthy "ghost" mode designed to evade detection.

## Features

- **Fast Concurrent Scanning**: Utilizes goroutines to scan a large number of ports very quickly.
- **Service & Version Detection**: The `-s` flag enables banner grabbing to identify the services and versions running on open ports.
- **Stealthy "Ghost" Mode**: The `-g` flag slows down the scan, randomizes the port order, and adds jitter to make the scanning activity less obvious to firewalls and Intrusion Detection Systems (IDS).
- **Flexible Port Selection**: Scan specific ports, ranges, or all 65535 ports.
- **User-Friendly Output**: Clean, table-based output for easy reading.

## Installation

To install GOMAP, you need to have Go installed on your system. You can then install the application directly from the command line.

**1. From Source (Local):**
Clone the repository and run `go install` from the project directory.
```bash
git clone <repository-url>
cd gomap
go install .
```

**2. From GitHub:**
Once the project is hosted on GitHub, you can install it with a single command (replace `your-username/gomap` with the actual repository path).
```bash
go install github.com/your-username/gomap@latest
```
This will compile the application and place the `gomap` executable in your Go binary directory (`$GOPATH/bin` or `$HOME/go/bin`), allowing you to run it from anywhere.

## Usage

The basic syntax is `gomap <host> [options]`.

```
Gomap: A fast and simple port scanner written in Go.

Usage:
  gomap <host> [options]

Options:
  -p string
    	ports to scan (e.g., 80,443 or 1-1024 or - for all ports)
  -s	detect services and versions
  -g	ghost mode for stealthy scanning (slower, less detectable)

Examples:
  gomap 127.0.0.1                      (Scan top ports on localhost)
  gomap -p 80,443,8080 192.168.1.1   (Scan specific ports)
  gomap -p 1-1024 -s 10.0.0.1          (Scan a range with service detection)
  gomap -p - -g 192.168.1.1            (Stealthy scan of all ports)
```
