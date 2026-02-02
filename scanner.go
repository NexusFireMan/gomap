package main

import (
	"context"
	"fmt"
	"math/rand/v2"
	"net"
	"os/exec"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/stacktitan/smb/smb"
)

// Scanner handles the port scanning logic
type Scanner struct {
	Host        string
	NumWorkers  int
	Timeout     time.Duration
	PortManager *PortManager
	GhostMode   bool
}

// NewScanner creates a new Scanner instance
func NewScanner(host string, ghostMode bool) *Scanner {
	numWorkers := 200
	timeout := 500 * time.Millisecond

	if ghostMode {
		numWorkers = 10
		timeout = 2 * time.Second
	}

	return &Scanner{
		Host:        host,
		NumWorkers:  numWorkers,
		Timeout:     timeout,
		PortManager: NewPortManager(),
		GhostMode:   ghostMode,
	}
}

// Scan performs the port scanning operation
func (s *Scanner) Scan(ports []int, detectServices bool) []ScanResult {
	if s.GhostMode {
		rand.Shuffle(len(ports), func(i, j int) {
			ports[i], ports[j] = ports[j], ports[i]
		})
	}

	portsChan := make(chan int, s.NumWorkers)
	resultsChan := make(chan ScanResult, len(ports))
	var wg sync.WaitGroup

	for i := 0; i < s.NumWorkers; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for port := range portsChan {
				if s.GhostMode {
					s.addJitter()
				}
				resultsChan <- s.scanPort(port, detectServices)
			}
		}(i)
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

// scanPort scans a single port
func (s *Scanner) scanPort(port int, detectServices bool) ScanResult {
	address := net.JoinHostPort(s.Host, fmt.Sprintf("%d", port))

	// Single attempt - no retries for speed
	conn, err := net.DialTimeout("tcp", address, s.Timeout)
	if err != nil {
		return ScanResult{Port: port, IsOpen: false}
	}
	defer conn.Close()

	result := ScanResult{Port: port, IsOpen: true}

	if !detectServices {
		result.ServiceName = s.PortManager.GetServiceName(port, "")
		return result
	}

	s.grabBanner(conn, port, &result)
	return result
}

// addJitter adds random delay to make scanning less detectable
func (s *Scanner) addJitter() {
	minDelay := 100 * time.Millisecond
	maxDelay := 500 * time.Millisecond
	delayMs := rand.Float64() * float64(maxDelay-minDelay) / float64(time.Millisecond)
	delay := time.Duration(delayMs) * time.Millisecond
	time.Sleep(minDelay + delay)
}

// tryExternalSMBDetection attempts to use external tools (nmap, smbclient) for SMB detection
func tryExternalSMBDetection(host string, _ int) string {
	if nmapPath, err := exec.LookPath("nmap"); err == nil {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		cmd := exec.CommandContext(ctx, nmapPath, "-p", "445", "--script", "smb-os-discovery", "-n", "-Pn", host)
		output, err := cmd.CombinedOutput()
		if err == nil {
			result := string(output)
			if strings.Contains(result, "Windows Server 2008 R2") {
				return "Windows Server 2008 R2"
			} else if strings.Contains(result, "Windows Server 2012") {
				return "Windows Server 2012"
			} else if strings.Contains(result, "Windows Server 2016") {
				return "Windows Server 2016"
			} else if strings.Contains(result, "Windows Server 2019") {
				return "Windows Server 2019"
			} else if strings.Contains(result, "Windows 7") {
				return "Windows 7"
			} else if strings.Contains(result, "Windows 10") {
				return "Windows 10"
			} else if strings.Contains(result, "Samba") {
				if strings.Contains(result, "3.") {
					return "Samba smbd 3.X"
				} else if strings.Contains(result, "4.") {
					return "Samba smbd 4.X"
				}
				return "Samba smbd"
			}
			return "Microsoft Windows"
		}
	}

	return ""
}

// grabBanner attempts to grab the service banner
func (s *Scanner) grabBanner(conn net.Conn, port int, result *ScanResult) {
	var banner string

	// For HTTP ports, send active request first
	if shouldParseAsHTTP(port) {
		banner = s.grabHTTPBanner(conn)
	}

	// If no banner yet, try passive read
	if banner == "" {
		banner = s.tryPassiveBanner(conn)
	}

	// Special handling for SMB (port 445)
	if banner == "" && port == 445 {
		smbInfo := s.detectSMBVersion(port)
		if smbInfo != "" {
			result.ServiceName = "microsoft-ds"
			result.Version = smbInfo
			return
		}
	}

	// If we still have no banner, use default service name
	if banner == "" {
		result.ServiceName = s.PortManager.GetServiceName(port, "")
		if result.ServiceName == "msrpc" {
			result.Version = "Microsoft Windows RPC"
		}
		return
	}

	// Parse the banner to extract service and version
	serviceName, version := parseBanner(banner)

	// Use service name from banner if found, otherwise use port mapping
	if serviceName != "" {
		result.ServiceName = serviceName
		result.Version = version
	} else {
		result.ServiceName = s.PortManager.GetServiceName(port, "")
	}
}

// tryPassiveBanner reads banner without sending any data
func (s *Scanner) tryPassiveBanner(conn net.Conn) string {
	buffer := make([]byte, 4096)
	conn.SetReadDeadline(time.Now().Add(s.Timeout))
	n, err := conn.Read(buffer)
	if err == nil && n > 0 {
		return string(buffer[:n])
	}
	return ""
}

// grabHTTPBanner attempts to grab HTTP banner and all headers
func (s *Scanner) grabHTTPBanner(conn net.Conn) string {
	_, _ = conn.Write([]byte("GET / HTTP/1.1\r\nHost: " + s.Host + "\r\nConnection: close\r\n\r\n"))
	_ = conn.SetReadDeadline(time.Now().Add(300 * time.Millisecond))

	var allData strings.Builder
	buffer := make([]byte, 1024)

	for {
		n, err := conn.Read(buffer)
		if err != nil {
			break
		}
		if n > 0 {
			allData.Write(buffer[:n])
		}
	}

	return allData.String()
}

// detectSMBVersion attempts to detect SMB version through multiple methods
func (s *Scanner) detectSMBVersion(port int) string {
	address := net.JoinHostPort(s.Host, fmt.Sprintf("%d", port))

	// Try external tools first (nmap) - it's very reliable
	if external := tryExternalSMBDetection(s.Host, port); external != "" {
		return external
	}

	// Method 2: Try to detect by reading raw SMB response
	if rawSMB := s.attemptRawSMBDetection(address); rawSMB != "" {
		return rawSMB
	}

	// Method 3: Try SMB library
	if smbLib := s.attemptSMBLibrary(address); smbLib != "" {
		return smbLib
	}

	// Default: we know port is open
	return "Microsoft Windows SMB"
}

// attemptRawSMBDetection tries to detect SMB by reading raw response
func (s *Scanner) attemptRawSMBDetection(address string) string {
	conn, err := net.DialTimeout("tcp", address, s.Timeout)
	if err != nil {
		return ""
	}
	defer conn.Close()

	// Send SMB2 negotiate request (SMB2 protocol)
	// This will trigger SMB servers to respond with their capabilities
	smbNegotiate := []byte{
		0x00, 0x00, 0x00, 0x54, // Length
		0xFF, 0x53, 0x4D, 0x42, // SMB signature
		0x00, 0x00, 0x00, 0x00, // Reserved
		0x00, 0x00, 0x00, 0x00, // Flags
		0x00, 0x00, 0x00, 0x00, // Flags2
		0x00, 0x00, 0x00, 0x00, // PIDHigh
		0x00, 0x00, 0x00, 0x00, // Signature
		0x00, 0x00, 0x00, 0x00, // Reserved
		0x00, 0x00, // TreeID
		0x00, 0x00, // ProcessID
		0x00, 0x00, // UserID
		0x00, 0x00, // MultiplexID
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}

	conn.SetWriteDeadline(time.Now().Add(s.Timeout))
	_, _ = conn.Write(smbNegotiate)

	conn.SetReadDeadline(time.Now().Add(s.Timeout))
	buffer := make([]byte, 2048)
	n, err := conn.Read(buffer)

	if err == nil && n > 0 {
		return s.analyzeSMBResponse(buffer[:n])
	}

	return ""
}

// analyzeSMBResponse analyzes the SMB server response for version and OS info
func (s *Scanner) analyzeSMBResponse(data []byte) string {
	if len(data) < 4 {
		return ""
	}

	lowerData := strings.ToLower(string(data))

	// Look for version strings in the response
	if strings.Contains(lowerData, "samba") {
		// Extract Samba version
		sambaRegex := regexp.MustCompile(`(?i)samba\s+smbd?\s+([\d\.]+)`)
		if match := sambaRegex.FindStringSubmatch(string(data)); match != nil {
			return "Samba " + match[1]
		}
		// Generic Samba detection
		if strings.Contains(lowerData, "3.") {
			return "Samba 3.X"
		} else if strings.Contains(lowerData, "4.") {
			return "Samba 4.X"
		}
		return "Samba"
	}

	// Windows version detection from server string
	if strings.Contains(lowerData, "windows") {
		if strings.Contains(lowerData, "2008 r2") || strings.Contains(lowerData, "2008r2") {
			return "Windows Server 2008 R2"
		} else if strings.Contains(lowerData, "2008") {
			return "Windows Server 2008"
		} else if strings.Contains(lowerData, "2012 r2") || strings.Contains(lowerData, "2012r2") {
			return "Windows Server 2012 R2"
		} else if strings.Contains(lowerData, "2012") {
			return "Windows Server 2012"
		} else if strings.Contains(lowerData, "2016") {
			return "Windows Server 2016"
		} else if strings.Contains(lowerData, "2019") {
			return "Windows Server 2019"
		} else if strings.Contains(lowerData, "windows 10") {
			return "Windows 10"
		} else if strings.Contains(lowerData, "windows 7") {
			return "Windows 7"
		}
	}

	// Check for SMB2/3 signature (0xFE + "SMB")
	b0 := data[0]
	b1 := data[1]
	b2 := data[2]
	b3 := data[3]

	if b0 == 0xFE && b1 == 0x53 && b2 == 0x4D && b3 == 0x42 {
		if len(data) >= 38 {
			return s.extractSMB2Dialect(data)
		}
		return "SMB 2.0+"
	}

	// Check for SMB1 signature (0xFF + "SMB")
	if b0 == 0xFF && b1 == 0x53 && b2 == 0x4D && b3 == 0x42 {
		return "SMB 1.0 (legacy)"
	}

	return ""
}

// extractSMB2Dialect detects specific SMB2/3 dialect
func (s *Scanner) extractSMB2Dialect(data []byte) string {
	if len(data) < 38 {
		return "SMB 2.0+"
	}

	// Dialect revision at offset 36-37 (little endian)
	dialectRevision := uint16(data[36]) | (uint16(data[37]) << 8)

	switch dialectRevision {
	case 0x0202:
		return "SMB 2.0.2"
	case 0x0210:
		return "SMB 2.1"
	case 0x0300:
		return "SMB 3.0"
	case 0x0302:
		return "SMB 3.0.2"
	case 0x0310:
		return "SMB 3.1.0"
	case 0x0311:
		return "SMB 3.1.1"
	default:
		if dialectRevision >= 0x0202 && dialectRevision <= 0x0311 {
			return fmt.Sprintf("SMB %d.%d", (dialectRevision >> 8), (dialectRevision & 0xFF))
		}
	}

	return "SMB 2.0+"
}

// attemptSMBLibrary tries to use SMB library for detection
func (s *Scanner) attemptSMBLibrary(address string) string {
	opts := smb.Options{
		Host:     s.Host,
		Port:     445,
		User:     "",
		Password: "",
	}

	session, err := smb.NewSession(opts, false)
	if err == nil {
		defer session.Close()
		return "Microsoft Windows SMB"
	}

	return ""
}

// grabSMBBanner is kept for compatibility but not actively used
func (s *Scanner) grabSMBBanner(conn net.Conn) string {
	opts := smb.Options{
		Host:     s.Host,
		Port:     445,
		User:     "",
		Password: "",
	}

	session, err := smb.NewSession(opts, false)
	if err == nil {
		defer session.Close()
		return "Microsoft Windows SMB"
	}

	return ""
}
