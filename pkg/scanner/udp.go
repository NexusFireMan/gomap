package scanner

import (
	"bytes"
	"fmt"
	"math/rand/v2"
	"net"
	"sort"
	"strings"
	"sync"
	"time"
)

// GetTopUDPPorts returns a compact high-signal UDP default set.
func GetTopUDPPorts() []int {
	return uniquePortsOrdered([]int{
		53, 67, 68, 69, 111, 123, 137, 138, 161, 162,
		500, 514, 520, 623, 1194, 1434, 1900, 4500, 5353, 5355,
		11211, 27015, 33434, 47808,
	})
}

// ScanUDP probes UDP ports and returns only ports that send a UDP response.
func (s *Scanner) ScanUDP(ports []int, detectServices bool) []ScanResult {
	if s.GhostMode {
		rand.Shuffle(len(ports), func(i, j int) {
			ports[i], ports[j] = ports[j], ports[i]
		})
	}

	portsChan := make(chan int, s.NumWorkers)
	resultsChan := make(chan ScanResult, len(ports))
	var rateLimiter <-chan time.Time
	if s.Rate > 0 {
		interval := time.Second / time.Duration(s.Rate)
		if interval < time.Millisecond {
			interval = time.Millisecond
		}
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		rateLimiter = ticker.C
	}

	var wg sync.WaitGroup
	for i := 0; i < s.NumWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for port := range portsChan {
				if s.GhostMode {
					s.addJitter()
				}
				if rateLimiter != nil {
					<-rateLimiter
				}
				resultsChan <- s.scanUDPPort(port, detectServices)
			}
		}()
	}

	for _, port := range ports {
		portsChan <- port
	}
	close(portsChan)

	wg.Wait()
	close(resultsChan)

	openPorts := make([]ScanResult, 0)
	for result := range resultsChan {
		if result.IsOpen {
			openPorts = append(openPorts, result)
		}
	}

	sort.Slice(openPorts, func(i, j int) bool {
		return openPorts[i].Port < openPorts[j].Port
	})
	return dedupeOpenResults(openPorts)
}

func (s *Scanner) scanUDPPort(port int, detectServices bool) ScanResult {
	address := net.JoinHostPort(s.Host, fmt.Sprintf("%d", port))
	start := time.Now()
	probe := udpProbePayload(port)

	var (
		response []byte
		err      error
	)
	for attempt := 0; attempt <= s.Retries; attempt++ {
		response, err = s.exchangeUDP(address, probe)
		if err == nil {
			break
		}
		if attempt < s.Retries && !s.GhostMode {
			time.Sleep(s.retryBackoff(attempt))
		}
	}

	latency := time.Since(start)
	latencyMs := latency.Milliseconds()
	if latencyMs == 0 {
		latencyMs = 1
	}
	if err != nil {
		return ScanResult{Port: port, IsOpen: false, Latency: latency, LatencyMs: latencyMs}
	}

	service, version, confidence, evidence := s.classifyUDPResponse(port, response, detectServices)
	return ScanResult{
		Port:          port,
		IsOpen:        true,
		ServiceName:   service,
		Version:       version,
		Latency:       latency,
		LatencyMs:     latencyMs,
		Confidence:    confidence,
		Evidence:      evidence,
		DetectionPath: "udp-probe",
	}
}

func (s *Scanner) exchangeUDP(address string, payload []byte) ([]byte, error) {
	conn, err := net.DialTimeout("udp", address, s.currentTimeout())
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()

	deadline := time.Now().Add(s.currentTimeout())
	if err := conn.SetDeadline(deadline); err != nil {
		return nil, err
	}
	if _, err := conn.Write(payload); err != nil {
		return nil, err
	}

	buf := make([]byte, 2048)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}

func (s *Scanner) classifyUDPResponse(port int, response []byte, detectServices bool) (service, version, confidence, evidence string) {
	service = s.PortManager.GetServiceName(port, "")
	if service == "" {
		service = udpServiceName(port)
	}
	confidence = "medium"
	evidence = "udp response"

	if !detectServices {
		if service != "" {
			confidence = "low"
			evidence = "udp response + port map"
		}
		return service, "", confidence, evidence
	}

	switch port {
	case 53:
		return "domain", "DNS response", "medium", "dns udp response"
	case 123:
		return "ntp", udpNTPVersion(response), "medium", "ntp udp response"
	case 137:
		return "netbios-ns", "NetBIOS name service response", "medium", "netbios udp response"
	case 161:
		return "snmp", "SNMP response", "medium", "snmp udp response"
	case 1900:
		return "ssdp", udpSSDPVersion(response), "medium", "ssdp udp response"
	case 5353:
		return "mdns", "mDNS response", "medium", "mdns udp response"
	case 5355:
		return "llmnr", "LLMNR response", "medium", "llmnr udp response"
	}

	text := strings.TrimSpace(string(bytes.Map(printableASCII, response)))
	if text != "" && len(text) <= 120 {
		version = text
	}
	return service, version, confidence, evidence
}

func udpProbePayload(port int) []byte {
	switch port {
	case 53:
		return []byte{
			0x13, 0x37, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x07, 'v', 'e', 'r',
			's', 'i', 'o', 'n', 0x04, 'b', 'i', 'n',
			'd', 0x00, 0x00, 0x10, 0x00, 0x03,
		}
	case 123:
		return append([]byte{0x1b}, make([]byte, 47)...)
	case 161:
		return []byte{
			0x30, 0x26, 0x02, 0x01, 0x00, 0x04, 0x06, 'p',
			'u', 'b', 'l', 'i', 'c', 0xa0, 0x19, 0x02,
			0x04, 0x71, 0x4b, 0x4b, 0x46, 0x02, 0x01, 0x00,
			0x02, 0x01, 0x00, 0x30, 0x0b, 0x30, 0x09, 0x06,
			0x05, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x05, 0x00,
		}
	case 1900:
		return []byte("M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\nST: ssdp:all\r\n\r\n")
	case 11211:
		return []byte("stats\r\n")
	default:
		return []byte{0}
	}
}

func udpServiceName(port int) string {
	services := map[int]string{
		53:    "domain",
		67:    "dhcps",
		68:    "dhcpc",
		69:    "tftp",
		123:   "ntp",
		137:   "netbios-ns",
		138:   "netbios-dgm",
		161:   "snmp",
		162:   "snmptrap",
		500:   "isakmp",
		514:   "syslog",
		520:   "route",
		623:   "asf-rmcp",
		1194:  "openvpn",
		1434:  "ms-sql-m",
		1900:  "ssdp",
		4500:  "ipsec-nat-t",
		5353:  "mdns",
		5355:  "llmnr",
		11211: "memcached",
		47808: "bacnet",
	}
	return services[port]
}

func udpNTPVersion(response []byte) string {
	if len(response) == 0 {
		return "NTP response"
	}
	version := (response[0] >> 3) & 0x7
	if version == 0 {
		return "NTP response"
	}
	return fmt.Sprintf("NTPv%d response", version)
}

func udpSSDPVersion(response []byte) string {
	text := string(response)
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		lower := strings.ToLower(line)
		if strings.HasPrefix(lower, "server:") {
			return strings.TrimSpace(line[len("server:"):])
		}
	}
	return "SSDP response"
}

func printableASCII(r rune) rune {
	if r == '\r' || r == '\n' || r == '\t' {
		return r
	}
	if r < 32 || r > 126 {
		return -1
	}
	return r
}
