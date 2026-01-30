/*
  ██████╗  ██████╗ ███╗   ███╗ █████╗ ██████╗ 
 ██╔════╝ ██╔═══██╗████╗ ████║██╔══██╗██╔══██╗
 ██║  ███╗██║   ██║██╔████╔██║███████║██████╔╝
 ██║   ██║██║   ██║██║╚██╔╝██║██╔══██║██╔═══╝ 
 ╚██████╔╝╚██████╔╝██║ ╚═╝ ██║██║  ██║██║     
  ╚═════╝  ╚═════╝ ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝     
*/
package main

import (
	"flag"
	"fmt"
	"math/rand"
	"net"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	portsFlag   string
	serviceFlag bool
	ghostFlag   bool
)

// ScanResult holds the result of a single port scan
type ScanResult struct {
	Port        int
	IsOpen      bool
	ServiceName string
	Version     string
}

func main() {
	flag.StringVar(&portsFlag, "p", "", "ports to scan (e.g., 80,443 or 1-1024 or - for all ports)")
	flag.BoolVar(&serviceFlag, "s", false, "detect services and versions")
	flag.BoolVar(&ghostFlag, "g", false, "ghost mode for stealthy scanning (slower, less detectable)")

	// Custom usage message
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Gomap: A fast and simple port scanner written in Go.\n\n")
		fmt.Fprintf(os.Stderr, "Usage:\n  gomap <host> [options]\n\n")
		fmt.Fprintf(os.Stderr, "Options:\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "  gomap 127.0.0.1                      (Scan top ports on localhost)\n")
		fmt.Fprintf(os.Stderr, "  gomap -p 80,443,8080 192.168.1.1   (Scan specific ports)\n")
		fmt.Fprintf(os.Stderr, "  gomap -p 1-1024 -s 10.0.0.1          (Scan a range with service detection)\n")
		fmt.Fprintf(os.Stderr, "  gomap -p - -g 192.168.1.1            (Stealthy scan of all ports)\n")
	}

	flag.Parse()

	if flag.NArg() != 1 {
		flag.Usage()
		os.Exit(1)
	}

	host := flag.Arg(0)

	portsToScan, err := getPortsToScan(portsFlag)
	if err != nil {
		fmt.Printf("Invalid port specification: %s\n", err)
		os.Exit(1)
	}

	if ghostFlag {
		fmt.Println("Ghost mode active: scanning will be slow, sequential, and randomized.")
	}
	fmt.Printf("Scanning %s (%d ports)\n\n", host, len(portsToScan))

	openPorts := runScan(host, portsToScan, serviceFlag, ghostFlag)

	printResults(openPorts, serviceFlag)
}

func getPortsToScan(portsStr string) ([]int, error) {
	if portsStr == "-" {
		ports := make([]int, 65535)
		for i := 1; i <= 65535; i++ {
			ports[i-1] = i
		}
		return ports, nil
	}
	if portsStr != "" {
		return parsePorts(portsStr)
	}
	return getTop1000Ports(), nil
}

func runScan(host string, ports []int, doServiceScan bool, isGhostMode bool) []ScanResult {
	if isGhostMode {
		return runGhostScan(host, ports, doServiceScan)
	}
	return runFastScan(host, ports, doServiceScan)
}

func runFastScan(host string, ports []int, doServiceScan bool) []ScanResult {
	numWorkers := 100
	portsChan := make(chan int, numWorkers)
	resultsChan := make(chan ScanResult, len(ports))
	var wg sync.WaitGroup

	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for port := range portsChan {
				resultsChan <- scanPort(host, port, doServiceScan)
			}
		}()
	}

	for _, port := range ports {
		portsChan <- port
	}
	close(portsChan)

	wg.Wait()
	close(resultsChan)

	var openPorts []ScanResult
	for result := range resultsChan {
		if result.IsOpen {
			openPorts = append(openPorts, result)
		}
	}

	sort.Slice(openPorts, func(i, j int) bool {
		return openPorts[i].Port < openPorts[j].Port
	})

	return openPorts
}

func runGhostScan(host string, ports []int, doServiceScan bool) []ScanResult {
	var openPorts []ScanResult
	
	// 1. Randomize port order
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	r.Shuffle(len(ports), func(i, j int) {
		ports[i], ports[j] = ports[j], ports[i]
	})
	
	for i, port := range ports {
		fmt.Printf("\rScanning... %d/%d", i+1, len(ports))

		result := scanPort(host, port, doServiceScan)
		if result.IsOpen {
			openPorts = append(openPorts, result)
		}
		
		// 2. Add delay with jitter
		// Delay between 1 and 4 seconds
		jitter := time.Duration(r.Intn(3000)) * time.Millisecond 
		time.Sleep(1*time.Second + jitter)
	}
	fmt.Println("\rScan finished.                        ") // Clear the line

	sort.Slice(openPorts, func(i, j int) bool {
		return openPorts[i].Port < openPorts[j].Port
	})

	return openPorts
}

func printResults(results []ScanResult, serviceScan bool) {
	if serviceScan {
		fmt.Printf("%-7s %-6s %-12s %s\n", "PORT", "STATE", "SERVICE", "VERSION")
	} else {
		fmt.Printf("%-7s %s\n", "PORT", "STATE")
	}

	for _, result := range results {
		if serviceScan {
			fmt.Printf("%-7d %-6s %-12s %s\n", result.Port, "open", result.ServiceName, result.Version)
		} else {
			fmt.Printf("%-7d %s\n", result.Port, "open")
		}
	}
}

func parsePorts(portsStr string) ([]int, error) {
	var ports []int
	// ... (rest of the function is unchanged, omitted for brevity)
	if strings.Contains(portsStr, "-") {
		parts := strings.Split(portsStr, "-")
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid port range")
		}
		start, err := strconv.Atoi(parts[0])
		if err != nil {
			return nil, err
		}
		end, err := strconv.Atoi(parts[1])
		if err != nil {
			return nil, err
		}
		if start < 1 || end > 65535 || start > end {
			return nil, fmt.Errorf("invalid port range")
		}
		for i := start; i <= end; i++ {
			ports = append(ports, i)
		}
	} else if strings.Contains(portsStr, ",") {
		parts := strings.Split(portsStr, ",")
		for _, part := range parts {
			port, err := strconv.Atoi(part)
			if err != nil {
				return nil, err
			}
			if port < 1 || port > 65535 {
				return nil, fmt.Errorf("invalid port number")
			}
			ports = append(ports, port)
		}
	} else {
		port, err := strconv.Atoi(portsStr)
		if err != nil {
			return nil, err
		}
		if port < 1 || port > 65535 {
			return nil, fmt.Errorf("invalid port number")
		}
		ports = append(ports, port)
	}
	return ports, nil
}

func scanPort(host string, port int, doServiceScan bool) ScanResult {
	address := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	conn, err := net.DialTimeout("tcp", address, 2*time.Second) // Increased timeout
	if err != nil {
		return ScanResult{Port: port, IsOpen: false}
	}
	defer conn.Close()

	result := ScanResult{Port: port, IsOpen: true}

	if !doServiceScan {
		result.ServiceName = getServiceName(port, "")
		return result
	}

	// Send probe for HTTP-like services
	if isHTTPPort(port) {
		_, _ = conn.Write([]byte("GET / HTTP/1.1\r\nHost: " + host + "\r\n\r\n"))
	}

	buffer := make([]byte, 4096)
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := conn.Read(buffer)
	if err != nil {
		result.ServiceName = getServiceName(port, "") // Still get default service name
		return result                                 // Port is open, but no banner/response
	}

	banner := string(buffer[:n])
	serviceName, version := parseBanner(banner)

	result.ServiceName = getServiceName(port, serviceName)
	result.Version = version

	return result
}

func isHTTPPort(port int) bool {
	switch port {
	case 80, 81, 443, 631, 3000, 8000, 8008, 8080, 8181, 8443, 9000:
		return true
	default:
		return false
	}
}

// Improved banner parsing
func parseBanner(banner string) (service, version string) {
	banner = strings.TrimSpace(banner)

	// SSH: SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.3
	sshRegex := regexp.MustCompile(`^SSH-2\.0-(.*)`) // More greedy
	if match := sshRegex.FindStringSubmatch(banner); match != nil {
		// Clean up version string
		version = strings.TrimSpace(match[1])
		version = strings.Replace(version, "_", " ", 1)
		return "ssh", version
	}

	// FTP: 220 (vsFTPd 3.0.3), 220 ProFTPD 1.3.5 Server
	ftpRegex := regexp.MustCompile(`220 .*?(ProFTPD|vsFTPd|Pure-FTPd)[\s\(]?([\d\.]+\w?)`)
	if match := ftpRegex.FindStringSubmatch(banner); match != nil {
		return "ftp", fmt.Sprintf("%s %s", match[1], match[2])
	}

	// HTTP Server: Server: Apache/2.4.7 (Ubuntu) or Jetty(8.1.7.v20120910)
	httpServerRegex := regexp.MustCompile(`(?i)Server:\s*([^\r\n]+)`)
	if match := httpServerRegex.FindStringSubmatch(banner); match != nil {
		version = strings.TrimSpace(match[1])
		// Handle cases like Jetty(version) and extra spaces
		version = strings.Replace(version, "(", " ", 1)
		version = strings.Replace(version, ")", "", 1)
		version = strings.Join(strings.Fields(version), " ") // Normalize spaces
		return "http", version
	}
	// Fallback for basic HTTP
	if strings.HasPrefix(banner, "HTTP/1") {
		// Try to get server from CUPS
		cupsRegex := regexp.MustCompile(`CUPS/([\d\.]+)`)
		if match := cupsRegex.FindStringSubmatch(banner); match != nil {
			return "http", "CUPS " + match[1]
		}
		return "http", ""
	}

	// MySQL: Unauthorized or version number
	if strings.Contains(banner, "MySQL") {
		if strings.Contains(banner, "is not allowed to connect") {
			return "mysql", "unauthorized"
		}
		mysqlVersionRegex := regexp.MustCompile(`(\d+\.\d+\.\d+.*)`)
		if match := mysqlVersionRegex.FindStringSubmatch(banner); match != nil {
			return "mysql", match[1]
		}
		return "mysql", ""
	}

	// IRC
	if strings.Contains(banner, "NOTICE AUTH") && strings.Contains(banner, "irc") {
		return "irc", "" // Version not easily parsed from typical banners
	}

	// Fallback to a sanitized first line if no specific match
	firstLine := strings.Split(banner, "\n")[0]
	sanitized := strings.TrimSpace(strings.Map(func(r rune) rune {
		if r >= 32 && r < 127 {
			return r
		}
		return '?' // Replace non-printable chars
	}, firstLine))

	// Limit fallback banner length
	if len(sanitized) > 60 {
		sanitized = sanitized[:60]
	}

	return "", sanitized
}

func getServiceName(port int, bannerService string) string {
	serviceMap := map[int]string{
		21:   "ftp",
		22:   "ssh",
		23:   "telnet",
		25:   "smtp",
		53:   "domain",
		80:   "http",
		110:  "pop3",
		111:  "rpcbind",
		135:  "msrpc",
		139:  "netbios-ssn",
		143:  "imap",
		443:  "https",
		445:  "microsoft-ds",
		631:  "ipp",
		993:  "imaps",
		995:  "pop3s",
		1723: "pptp",
		3306: "mysql",
		3389: "ms-wbt-server",
		5900: "vnc",
		8080: "http-proxy",
		8181: "intermapper",
		3500: "rtmp-port",
		6697: "ircs-u",
	}
	defaultService, hasDefault := serviceMap[port]

	// Logic to decide which service name to use
	if hasDefault {
		// Prefer the specific default over a generic banner-parsed name
		if bannerService == "http" && (port == 631 || port == 8080 || port == 8181) {
			return defaultService
		}
		// Otherwise, if banner parsing gave us something, use it
		if bannerService != "" {
			return bannerService
		}
		// Fallback to the default
		return defaultService
	}

	// If no default, use whatever the banner gave us
	return bannerService
}

func getTop1000Ports() []int {
	// Top 1000 ports sorted
	return []int{
		7, 9, 13, 21, 22, 23, 25, 26, 37, 53, 67, 68, 79, 80, 81, 88, 106, 110, 111,
		113, 119, 123, 135, 137, 138, 139, 143, 144, 161, 162, 177, 179, 199, 389,
		427, 434, 443, 444, 445, 465, 513, 514, 515, 543, 544, 548, 554, 587, 626,
		631, 636, 646, 800, 873, 990, 993, 995, 1025, 1026, 1027, 1028, 1029, 1080,
		1110, 1433, 1720, 1723, 1755, 1812, 1813, 1900, 2000, 2001, 2002, 2049,
		2121, 2222, 2323, 2717, 3000, 3128, 3260, 3283, 3306, 3389, 3390, 3500,
		3986, 4444, 4899, 5000, 5001, 5002, 5009, 5051, 5060, 5101, 5190, 5222,
		5223, 5269, 5357, 5432, 5631, 5632, 5666, 5667, 5800, 5900, 5901, 5902,
		5903, 5985, 5986, 6000, 6001, 6002, 6003, 6004, 6005, 6006, 6007, 6008,
		6009, 6646, 6697, 7000, 7001, 7002, 7003, 7004, 7005, 7006, 7007, 7008,
		7009, 7070, 8000, 8002, 8008, 8009, 8080, 8081, 8082, 8083, 8084, 8085,
		8086, 8087, 8088, 8089, 8090, 8180, 8222, 8443, 8800, 8888, 9000, 9090,
		9091, 9100, 9418, 9999, 10000, 10001, 10002, 10003, 10004, 10005, 10006,
		10007, 10008, 10009, 10010, 11211, 11214, 11215, 12345, 15672, 20000,
		20005, 27017, 27018, 27019, 28017, 30000, 30718, 32768, 3478, 49152,
		49153, 49154, 49155, 49156, 49157, 49400, 50000,
	}
}
