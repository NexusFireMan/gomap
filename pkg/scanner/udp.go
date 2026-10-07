package scanner

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
)

const maxUDPResponseBytes = 2048

// GetTopUDPPorts returns a compact high-signal UDP default set.
func GetTopUDPPorts() []int {
	return uniquePortsOrdered([]int{
		53, 67, 68, 69, 111, 123, 137, 138, 161, 162,
		500, 514, 520, 623, 1194, 1434, 1900, 4500, 5353, 5355,
		11211, 27015, 33434, 47808,
	})
}

// ScanUDP retains uncertain outcomes as well as confirmed responses.
func (s *Scanner) ScanUDP(ports []int, detectServices bool) []ScanResult {
	ports = uniquePortsOrdered(ports)
	if s.GhostMode {
		rand.Shuffle(len(ports), func(i, j int) {
			ports[i], ports[j] = ports[j], ports[i]
		})
	}

	workers := max(1, min(s.NumWorkers, len(ports)))
	portsChan := make(chan int, workers)
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
	for i := 0; i < workers; i++ {
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
		openPorts = append(openPorts, result)
	}

	sort.Slice(openPorts, func(i, j int) bool {
		return openPorts[i].Port < openPorts[j].Port
	})
	return openPorts
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
		state, evidence := udpErrorState(err)
		return ScanResult{Port: port, State: state, Latency: latency, LatencyMs: latencyMs,
			Evidence: evidence, Confidence: "low", DetectionPath: "udp-probe"}
	}

	service, version, confidence, evidence := s.classifyUDPResponseForProbe(port, response, probe, detectServices)
	return ScanResult{
		Port:          port,
		IsOpen:        true,
		State:         "open",
		ServiceName:   service,
		Version:       version,
		Latency:       latency,
		LatencyMs:     latencyMs,
		Confidence:    confidence,
		Evidence:      evidence,
		DetectionPath: "udp-probe",
	}
}

func (s *Scanner) classifyUDPResponseForProbe(port int, response, probe []byte, detectServices bool) (service, version, confidence, evidence string) {
	service, version, confidence, evidence = s.classifyUDPResponse(port, response, detectServices)
	if !detectServices || version == "" {
		return
	}
	checked, matched := udpProbeFieldsMatch(port, probe, response)
	if checked && !matched {
		return service, "", "low", "UDP response received; protocol-shaped payload does not match sent probe fields"
	}
	if checked {
		return service, version, "medium", version + "; sent probe fields matched; fixed identifiers; not authenticated"
	}
	return
}

func udpErrorState(err error) (string, string) {
	if errors.Is(err, syscall.ECONNREFUSED) {
		return "closed", "UDP socket reported connection refused"
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return "open|filtered", "no UDP response before deadline"
	}
	return "unknown", "UDP exchange failed; port state undetermined"
}

func (s *Scanner) exchangeUDP(address string, payload []byte) ([]byte, error) {
	conn, err := s.dialUDP(address, s.currentTimeout())
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

	buf := make([]byte, maxUDPResponseBytes)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}

func (s *Scanner) classifyUDPResponse(port int, response []byte, detectServices bool) (service, version, confidence, evidence string) {
	// UDP hints must not inherit the TCP service map.
	service = udpServiceName(port)
	if service == "" {
		service = "unknown"
	}
	confidence = "low"
	evidence = fmt.Sprintf("udp response (%d bytes); unrecognized payload", len(response))
	if service != "unknown" {
		evidence = fmt.Sprintf("udp response (%d bytes); service inferred from UDP port only; payload not validated", len(response))
	}

	if !detectServices {
		return service, "", confidence, evidence
	}

	switch port {
	case 137:
		if version := udpNetBIOSVersion(response); version != "" {
			if version == netbiosRedirectLabel {
				return "netbios-ns", version, "medium", version + "; bounded NS/A fields validated; redirect not followed; request not correlated"
			}
			return "netbios-ns", version, "medium", version + "; bounded NBNS fields validated; request not correlated"
		}
	case 53, 5353, 5355:
		if version := udpDNSVersion(port, response); version != "" {
			return service, version, "medium", version + "; bounded DNS-format fields validated; request not correlated"
		}
	case 161:
		if version := udpSNMPVersion(response); version != "" {
			return "snmp", version, "medium", version + "; ASN.1 fields validated; request not correlated or authenticated"
		}
	case 123:
		if version := udpNTPVersion(response); version != "" {
			return "ntp", version, "medium", "ntp-shaped udp response; server mode; timestamps not correlated"
		}
	case 1900:
		if version := udpSSDPVersion(response); version != "" {
			return "ssdp", version, "medium", "ssdp-shaped HTTP/1.1 200 response; ST, USN and LOCATION headers present"
		}
	}

	return service, "", confidence, evidence
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
		111:   "rpcbind",
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
	if len(response) < 48 || len(response) > maxUDPResponseBytes || response[0]&0x7 != 4 {
		return ""
	}
	version := (response[0] >> 3) & 0x7
	if version < 1 || version > 4 {
		return ""
	}
	return fmt.Sprintf("NTPv%d response", version)
}

func udpSSDPVersion(response []byte) string {
	if len(response) == 0 || len(response) > maxUDPResponseBytes {
		return ""
	}
	parsed, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(response)), nil)
	if err != nil {
		return ""
	}
	defer func() { _ = parsed.Body.Close() }()
	if parsed.ProtoMajor != 1 || parsed.ProtoMinor != 1 || parsed.StatusCode != http.StatusOK {
		return ""
	}
	for _, name := range []string{"ST", "USN", "LOCATION"} {
		if len(parsed.Header.Values(name)) != 1 || strings.TrimSpace(parsed.Header.Get(name)) == "" {
			return ""
		}
	}
	if !strings.HasPrefix(parsed.Header.Get("USN"), "uuid:") || len(parsed.Header.Get("USN")) <= len("uuid:") {
		return ""
	}
	location, err := url.Parse(parsed.Header.Get("LOCATION"))
	if err != nil || (location.Scheme != "http" && location.Scheme != "https") || location.Hostname() == "" {
		return ""
	}
	if len(parsed.Header.Values("SERVER")) > 1 {
		return ""
	}
	if server := strings.TrimSpace(parsed.Header.Get("SERVER")); server != "" {
		return server
	}
	return "SSDP response"
}
