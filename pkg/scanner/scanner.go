package scanner

import (
	"context"
	"crypto/tls"
	"fmt"
	"math/rand/v2"
	"net"
	"net/netip"
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
	Host               string
	NumWorkers         int
	Rate               int
	Timeout            time.Duration
	Retries            int
	AdaptiveTimeout    bool
	BackoffBase        time.Duration
	BackoffMax         time.Duration
	MinAdaptiveTimeout time.Duration
	MaxAdaptiveTimeout time.Duration
	PortManager        *PortManager
	GhostMode          bool
	RandomAgent        bool
	RandomIP           bool
	targetPrefix       netip.Prefix

	adaptiveMu    sync.Mutex
	ewmaLatency   time.Duration
	failureStreak int
	successCount  int
	failureCount  int
}

// ScanConfig contains runtime tuning controls for robust scans.
type ScanConfig struct {
	NumWorkers      int
	Rate            int
	Timeout         time.Duration
	Retries         int
	AdaptiveTimeout bool
	BackoffBase     time.Duration
	MaxTimeout      time.Duration
	RandomAgent     bool
	RandomIP        bool
	TargetCIDR      string
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
		Host:               host,
		NumWorkers:         numWorkers,
		Rate:               0,
		Timeout:            timeout,
		Retries:            0,
		AdaptiveTimeout:    true,
		BackoffBase:        25 * time.Millisecond,
		BackoffMax:         600 * time.Millisecond,
		MinAdaptiveTimeout: timeout,
		MaxAdaptiveTimeout: 4 * time.Second,
		PortManager:        NewPortManager(),
		GhostMode:          ghostMode,
		RandomAgent:        false,
		RandomIP:           false,
	}
}

// Configure overrides scanner defaults with validated values.
func (s *Scanner) Configure(cfg ScanConfig) {
	if cfg.NumWorkers > 0 {
		s.NumWorkers = cfg.NumWorkers
	}
	if cfg.Rate >= 0 {
		s.Rate = cfg.Rate
	}
	if cfg.Timeout > 0 {
		s.Timeout = cfg.Timeout
		s.MinAdaptiveTimeout = cfg.Timeout
	}
	if cfg.Retries >= 0 {
		s.Retries = cfg.Retries
	}
	s.AdaptiveTimeout = cfg.AdaptiveTimeout
	if cfg.BackoffBase > 0 {
		s.BackoffBase = cfg.BackoffBase
	}
	s.RandomAgent = cfg.RandomAgent
	s.RandomIP = cfg.RandomIP
	if s.RandomIP {
		s.targetPrefix = parseTargetPrefix(cfg.TargetCIDR, s.Host)
	}
	if cfg.MaxTimeout > 0 {
		s.MaxAdaptiveTimeout = cfg.MaxTimeout
	} else if s.GhostMode {
		s.MaxAdaptiveTimeout = 8 * time.Second
	} else {
		s.MaxAdaptiveTimeout = 4 * time.Second
	}
	if s.BackoffMax < s.BackoffBase*4 {
		s.BackoffMax = s.BackoffBase * 4
	}
	if s.GhostMode {
		// Conservative defaults in ghost mode reduce traffic spikes.
		if s.Rate == 0 {
			s.Rate = 8
		}
		if s.NumWorkers > 4 {
			s.NumWorkers = 4
		}
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
		go func(workerID int) {
			defer wg.Done()
			for port := range portsChan {
				if s.GhostMode {
					s.addJitter()
				}
				if rateLimiter != nil {
					<-rateLimiter
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
	start := time.Now()

	var (
		conn net.Conn
		err  error
	)

	for attempt := 0; attempt <= s.Retries; attempt++ {
		attemptStart := time.Now()
		conn, err = net.DialTimeout("tcp", address, s.currentTimeout())
		s.recordDialOutcome(err == nil, time.Since(attemptStart))
		if err == nil {
			break
		}
		if attempt < s.Retries && !s.GhostMode {
			time.Sleep(s.retryBackoff(attempt))
		}
	}

	if err != nil {
		latency := time.Since(start)
		return ScanResult{
			Port:      port,
			IsOpen:    false,
			Latency:   latency,
			LatencyMs: latency.Milliseconds(),
		}
	}
	defer func() { _ = conn.Close() }()

	latency := time.Since(start)
	latencyMs := latency.Milliseconds()
	if latencyMs == 0 {
		latencyMs = 1
	}
	result := ScanResult{
		Port:      port,
		IsOpen:    true,
		Latency:   latency,
		LatencyMs: latencyMs,
	}

	if !detectServices {
		result.ServiceName = s.PortManager.GetServiceName(port, "")
		if result.ServiceName != "" {
			result.Confidence = "low"
			result.Evidence = "port map"
		}
		return result
	}

	s.grabBanner(conn, port, &result)
	return result
}

func (s *Scanner) currentTimeout() time.Duration {
	base := s.Timeout
	if !s.AdaptiveTimeout {
		return base
	}

	s.adaptiveMu.Lock()
	ewma := s.ewmaLatency
	streak := s.failureStreak
	s.adaptiveMu.Unlock()

	timeout := base
	if ewma > 0 {
		timeout = ewma*3 + 100*time.Millisecond
	}
	if timeout < s.MinAdaptiveTimeout {
		timeout = s.MinAdaptiveTimeout
	}
	if streak > 0 {
		timeout += time.Duration(streak) * 75 * time.Millisecond
	}
	if timeout > s.MaxAdaptiveTimeout {
		timeout = s.MaxAdaptiveTimeout
	}
	return timeout
}

func (s *Scanner) ioTimeout(min time.Duration) time.Duration {
	timeout := s.currentTimeout()
	if timeout < min {
		return min
	}
	return timeout
}

func (s *Scanner) recordDialOutcome(success bool, latency time.Duration) {
	s.adaptiveMu.Lock()
	defer s.adaptiveMu.Unlock()

	if success {
		s.successCount++
		s.failureStreak = 0
		if s.ewmaLatency == 0 {
			s.ewmaLatency = latency
		} else {
			// EWMA (75% historical + 25% newest) keeps timeout stable under bursty conditions.
			s.ewmaLatency = (s.ewmaLatency*3 + latency) / 4
		}
		return
	}

	s.failureCount++
	s.failureStreak++
}

func (s *Scanner) retryBackoff(attempt int) time.Duration {
	if attempt < 0 {
		return s.BackoffBase
	}

	delay := s.BackoffBase
	for i := 0; i < attempt; i++ {
		delay *= 2
		if delay >= s.BackoffMax {
			delay = s.BackoffMax
			break
		}
	}

	// Add 0-50% jitter to reduce synchronized retry storms.
	jitterMax := int(delay / 2)
	if jitterMax < 1 {
		jitterMax = 1
	}
	jitter := time.Duration(rand.IntN(jitterMax)) * time.Nanosecond
	return delay + jitter
}

// addJitter adds random delay to make scanning less detectable
func (s *Scanner) addJitter() {
	minDelay := 220 * time.Millisecond
	maxDelay := 900 * time.Millisecond
	delayMs := rand.Float64() * float64(maxDelay-minDelay) / float64(time.Millisecond)
	delay := time.Duration(delayMs) * time.Millisecond
	time.Sleep(minDelay + delay)
}

// tryExternalSMBDetection attempts to use external tools (nmap, smbclient) for SMB detection
func tryExternalSMBDetection(host string) string {
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
				if strings.Contains(result, "3.X - 4.X") || strings.Contains(result, "3.x - 4.x") {
					return "Samba smbd 3.X-4.X"
				} else if strings.Contains(result, "3.") {
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
	if shouldParseAsHTTP(port) && !s.GhostMode {
		banner = s.grabHTTPBanner(port)
	}

	// If no banner yet, try passive read
	if banner == "" {
		banner = s.tryPassiveBanner(conn)
	}

	// If still no banner, use active probes only outside ghost mode.
	if banner == "" && !s.GhostMode {
		banner = s.tryServiceProbe(port)
	}

	// Special handling for SMB (port 445)
	if banner == "" && port == 445 && !s.GhostMode {
		smbInfo, method := s.detectSMBVersion(port)
		if smbInfo != "" {
			result.ServiceName = "microsoft-ds"
			result.Version = smbInfo
			result.Confidence = "high"
			result.Evidence = method
			result.DetectionPath = "smb-specialized"
			return
		}
	}

	// If we still have no banner, use default service name
	if banner == "" {
		result.ServiceName = s.PortManager.GetServiceName(port, "")
		if result.ServiceName == "msrpc" {
			result.Version = "Microsoft Windows RPC"
			result.Confidence = "medium"
			result.Evidence = "port+protocol behavior"
			result.DetectionPath = "portmap+heuristic"
			return
		}
		if result.ServiceName != "" {
			result.Confidence = "low"
			result.Evidence = "port map"
			result.DetectionPath = "portmap"
		}
		return
	}

	// Parse the banner to extract service and version
	serviceName, version := parseBanner(banner)

	// Use service name from banner if found, otherwise use port mapping
	if serviceName != "" {
		result.ServiceName = serviceName
		result.Version = version
		if (port == 5985 || port == 5986) && serviceName == "http" {
			lowerBanner := strings.ToLower(banner)
			if strings.Contains(lowerBanner, "wsman") || strings.Contains(lowerBanner, "microsoft-httpapi") {
				result.ServiceName = "winrm"
				if result.Version == "" {
					result.Version = "Microsoft WinRM"
				}
			}
		}
		if version != "" {
			result.Confidence = "high"
			result.Evidence = "protocol banner"
		} else {
			result.Confidence = "medium"
			result.Evidence = "protocol banner (generic)"
		}
		result.DetectionPath = "banner-parser"
	} else {
		if !s.GhostMode {
			if service, ver, confidence, evidence, path, ok := s.tryProtocolFingerprint(port); ok {
				result.ServiceName = service
				result.Version = ver
				result.Confidence = confidence
				result.Evidence = evidence
				result.DetectionPath = path
				return
			}
		}
		result.ServiceName = s.PortManager.GetServiceName(port, "")
		if result.ServiceName != "" {
			result.Confidence = "low"
			result.Evidence = "port map (unparsed banner)"
			result.DetectionPath = "portmap-fallback"
		}
	}
}

// tryPassiveBanner reads banner without sending any data
func (s *Scanner) tryPassiveBanner(conn net.Conn) string {
	buffer := make([]byte, 4096)
	passiveTimeout := s.currentTimeout()
	if passiveTimeout < 900*time.Millisecond {
		passiveTimeout = 900 * time.Millisecond
	}
	_ = conn.SetReadDeadline(time.Now().Add(passiveTimeout))
	n, err := conn.Read(buffer)
	if err == nil && n > 0 {
		return string(buffer[:n])
	}
	return ""
}

// grabHTTPBanner attempts to grab HTTP banner and all headers
func (s *Scanner) grabHTTPBanner(port int) string {
	address := net.JoinHostPort(s.Host, fmt.Sprintf("%d", port))
	timeout := s.currentTimeout()
	if timeout < 750*time.Millisecond {
		timeout = 750 * time.Millisecond
	}

	var conn net.Conn
	var err error

	// Try TLS first on common HTTPS ports for realistic service/version discovery.
	if shouldUseTLSForHTTP(port) {
		dialer := &net.Dialer{Timeout: timeout}
		tlsConn, tlsErr := tls.DialWithDialer(dialer, "tcp", address, &tls.Config{
			InsecureSkipVerify: true, // Banner grabbing only
			ServerName:         s.Host,
		})
		if tlsErr == nil {
			conn = tlsConn
		}
	}

	if conn == nil {
		conn, err = net.DialTimeout("tcp", address, timeout)
		if err != nil {
			return ""
		}
	}
	defer func() { _ = conn.Close() }()

	_, _ = conn.Write([]byte(s.buildHTTPRequest("GET", "/")))
	_ = conn.SetReadDeadline(time.Now().Add(timeout))

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

// tryServiceProbe sends minimal protocol-specific probes to improve detection when passive banners are absent
func (s *Scanner) tryServiceProbe(port int) string {
	switch port {
	case 21:
		return s.probeFTP()
	case 25, 465, 587, 2525:
		return s.probeTextService(port, "EHLO gomap.local\r\n")
	case 110, 995:
		return s.probeTextService(port, "CAPA\r\n")
	case 143, 993:
		return s.probeTextService(port, "a001 CAPABILITY\r\n")
	case 6379:
		return s.probeTextService(port, "INFO\r\n")
	default:
		return ""
	}
}

func (s *Scanner) probeFTP() string {
	address := net.JoinHostPort(s.Host, "21")
	timeout := s.ioTimeout(1500 * time.Millisecond)
	if timeout < 1500*time.Millisecond {
		timeout = 1500 * time.Millisecond
	}

	conn, err := net.DialTimeout("tcp", address, timeout)
	if err != nil {
		return ""
	}
	defer func() { _ = conn.Close() }()

	_ = conn.SetDeadline(time.Now().Add(timeout))
	buf := make([]byte, 2048)

	// First attempt: capture greeting banner only (often includes product/version).
	if n, err := conn.Read(buf); err == nil && n > 0 {
		banner := string(buf[:n])
		if strings.HasPrefix(strings.TrimSpace(banner), "220") || strings.Contains(strings.ToLower(banner), "ftp") {
			return banner
		}
	}

	// Fallback: ask for supported features.
	_, _ = conn.Write([]byte("FEAT\r\n"))
	if n, err := conn.Read(buf); err == nil && n > 0 {
		return string(buf[:n])
	}
	return ""
}

// probeTextService performs a short connect/write/read interaction for text-based protocols
func (s *Scanner) probeTextService(port int, payload string) string {
	address := net.JoinHostPort(s.Host, fmt.Sprintf("%d", port))
	timeout := s.ioTimeout(750 * time.Millisecond)
	if timeout < 750*time.Millisecond {
		timeout = 750 * time.Millisecond
	}

	conn, err := net.DialTimeout("tcp", address, timeout)
	if err != nil {
		return ""
	}
	defer func() { _ = conn.Close() }()

	_ = conn.SetDeadline(time.Now().Add(timeout))

	var response strings.Builder
	buf := make([]byte, 2048)

	// Read initial greeting if present
	if n, err := conn.Read(buf); err == nil && n > 0 {
		response.Write(buf[:n])
	}

	_, _ = conn.Write([]byte(payload))

	// Read probe response
	if n, err := conn.Read(buf); err == nil && n > 0 {
		response.WriteByte('\n')
		response.Write(buf[:n])
	}

	return response.String()
}

// tryProtocolFingerprint performs protocol-aware detection for services that often need active handshakes.
func (s *Scanner) tryProtocolFingerprint(port int) (service, version, confidence, evidence, path string, ok bool) {
	switch port {
	case 3306:
		if version = s.detectMySQLHandshake(port); version != "" {
			return "mysql", version, "high", "mysql handshake", "protocol-fingerprint", true
		}
	case 1433:
		if s.detectMSSQLTDS(port) {
			return "mssql", "Microsoft SQL Server (TDS)", "medium", "tds prelogin response", "protocol-fingerprint", true
		}
	case 3389:
		if s.detectRDPX224(port) {
			return "ms-wbt-server", "RDP service (X.224)", "medium", "rdp x224 response", "protocol-fingerprint", true
		}
	case 389:
		if s.detectLDAPBind(port, false) {
			return "ldap", "LDAP", "medium", "ldap bind response", "protocol-fingerprint", true
		}
	case 636:
		if s.detectLDAPBind(port, true) {
			return "ldaps", "LDAP over TLS", "medium", "ldap bind response (tls)", "protocol-fingerprint", true
		}
	case 5985, 5986:
		if version = s.detectWinRM(port); version != "" {
			return "winrm", version, "high", "wsman/httpapi response", "protocol-fingerprint", true
		}
	}
	return "", "", "", "", "", false
}

func (s *Scanner) detectMySQLHandshake(port int) string {
	address := net.JoinHostPort(s.Host, fmt.Sprintf("%d", port))
	timeout := s.ioTimeout(1200 * time.Millisecond)
	if timeout < 1200*time.Millisecond {
		timeout = 1200 * time.Millisecond
	}

	conn, err := net.DialTimeout("tcp", address, timeout)
	if err != nil {
		return ""
	}
	defer func() { _ = conn.Close() }()

	_ = conn.SetReadDeadline(time.Now().Add(timeout))
	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil || n < 7 {
		return ""
	}

	// MySQL packet: [3-byte len][1-byte seq][protocol=0x0a][version string...]
	if buf[4] != 0x0a {
		return ""
	}

	payload := string(buf[5:n])
	end := strings.IndexByte(payload, 0x00)
	if end <= 0 {
		return "MySQL"
	}
	v := payload[:end]
	if strings.Contains(strings.ToLower(v), "mariadb") {
		return "MariaDB " + sanitizeVersionString(v)
	}
	return "MySQL " + sanitizeVersionString(v)
}

func sanitizeVersionString(version string) string {
	version = strings.TrimSpace(version)
	version = strings.Trim(version, "-")
	version = strings.ReplaceAll(version, "\n", " ")
	version = strings.ReplaceAll(version, "\r", " ")
	return version
}

func (s *Scanner) detectMSSQLTDS(port int) bool {
	address := net.JoinHostPort(s.Host, fmt.Sprintf("%d", port))
	timeout := s.ioTimeout(1200 * time.Millisecond)
	if timeout < 1200*time.Millisecond {
		timeout = 1200 * time.Millisecond
	}

	conn, err := net.DialTimeout("tcp", address, timeout)
	if err != nil {
		return false
	}
	defer func() { _ = conn.Close() }()

	prelogin := []byte{
		0x12, 0x01, 0x00, 0x34, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x1a, 0x00, 0x06, 0x01, 0x00, 0x20,
		0x00, 0x01, 0x02, 0x00, 0x21, 0x00, 0x01, 0x03,
		0x00, 0x22, 0x00, 0x04, 0x04, 0x00, 0x26, 0x00,
		0x01, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
	}

	_ = conn.SetDeadline(time.Now().Add(timeout))
	_, _ = conn.Write(prelogin)

	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	if err != nil || n < 8 {
		return false
	}

	// Typical TDS response packet type is 0x04 (tabular result) or 0x12 (prelogin response).
	return buf[0] == 0x04 || buf[0] == 0x12
}

func (s *Scanner) detectRDPX224(port int) bool {
	address := net.JoinHostPort(s.Host, fmt.Sprintf("%d", port))
	timeout := s.ioTimeout(1200 * time.Millisecond)
	if timeout < 1200*time.Millisecond {
		timeout = 1200 * time.Millisecond
	}

	conn, err := net.DialTimeout("tcp", address, timeout)
	if err != nil {
		return false
	}
	defer func() { _ = conn.Close() }()

	req := []byte{0x03, 0x00, 0x00, 0x0b, 0x06, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00}
	_ = conn.SetDeadline(time.Now().Add(timeout))
	_, _ = conn.Write(req)

	buf := make([]byte, 128)
	n, err := conn.Read(buf)
	if err != nil || n < 7 {
		return false
	}

	return buf[0] == 0x03 && buf[1] == 0x00 && (buf[5] == 0xd0 || buf[5] == 0xe0 || buf[5] == 0xf0)
}

func (s *Scanner) detectLDAPBind(port int, useTLS bool) bool {
	address := net.JoinHostPort(s.Host, fmt.Sprintf("%d", port))
	timeout := s.ioTimeout(1200 * time.Millisecond)
	if timeout < 1200*time.Millisecond {
		timeout = 1200 * time.Millisecond
	}

	var (
		conn net.Conn
		err  error
	)

	if useTLS {
		dialer := &net.Dialer{Timeout: timeout}
		conn, err = tls.DialWithDialer(dialer, "tcp", address, &tls.Config{
			InsecureSkipVerify: true,
			ServerName:         s.Host,
		})
	} else {
		conn, err = net.DialTimeout("tcp", address, timeout)
	}
	if err != nil {
		return false
	}
	defer func() { _ = conn.Close() }()

	// Anonymous LDAPv3 bind request.
	bindReq := []byte{0x30, 0x0c, 0x02, 0x01, 0x01, 0x60, 0x07, 0x02, 0x01, 0x03, 0x04, 0x00, 0x80, 0x00}
	_ = conn.SetDeadline(time.Now().Add(timeout))
	_, _ = conn.Write(bindReq)

	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	if err != nil || n < 8 {
		return false
	}

	// LDAPMessage sequence + bindResponse application tag.
	if buf[0] != 0x30 {
		return false
	}
	return strings.Contains(string(buf[:n]), "LDAP") || (n > 5 && buf[5] == 0x61)
}

func (s *Scanner) detectWinRM(port int) string {
	address := net.JoinHostPort(s.Host, fmt.Sprintf("%d", port))
	timeout := s.ioTimeout(1500 * time.Millisecond)
	if timeout < 1500*time.Millisecond {
		timeout = 1500 * time.Millisecond
	}

	var (
		conn net.Conn
		err  error
	)
	if port == 5986 {
		dialer := &net.Dialer{Timeout: timeout}
		conn, err = tls.DialWithDialer(dialer, "tcp", address, &tls.Config{
			InsecureSkipVerify: true,
			ServerName:         s.Host,
		})
	} else {
		conn, err = net.DialTimeout("tcp", address, timeout)
	}
	if err != nil {
		return ""
	}
	defer func() { _ = conn.Close() }()

	_ = conn.SetDeadline(time.Now().Add(timeout))
	_, _ = conn.Write([]byte(s.buildHTTPRequest("OPTIONS", "/wsman")))

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil || n == 0 {
		return ""
	}

	resp := strings.ToLower(string(buf[:n]))
	if strings.Contains(resp, "wsman") || strings.Contains(resp, "microsoft-httpapi") || strings.Contains(resp, "www-authenticate: negotiate") {
		return "Microsoft WinRM"
	}
	return ""
}

// detectSMBVersion attempts to detect SMB version through multiple methods
func (s *Scanner) detectSMBVersion(port int) (string, string) {
	address := net.JoinHostPort(s.Host, fmt.Sprintf("%d", port))

	// Try external tools first (nmap) - it's very reliable
	if external := tryExternalSMBDetection(s.Host); external != "" {
		return external, "nmap smb-os-discovery"
	}

	// Method 2: Try to detect by reading raw SMB response
	if rawSMB := s.attemptRawSMBDetection(address); rawSMB != "" {
		return rawSMB, "raw smb negotiate"
	}

	// Method 3: Try SMB library
	if smbLib := s.attemptSMBLibrary(address); smbLib != "" {
		return smbLib, "smb library"
	}

	// Default: we know port is open
	return "Microsoft Windows SMB", "port 445 open"
}

func shouldUseTLSForHTTP(port int) bool {
	switch port {
	case 443, 5986, 6443, 7443, 8443, 9443:
		return true
	default:
		return false
	}
}

// attemptRawSMBDetection tries to detect SMB by reading raw response
func (s *Scanner) attemptRawSMBDetection(address string) string {
	conn, err := net.DialTimeout("tcp", address, s.Timeout)
	if err != nil {
		return ""
	}
	defer func() { _ = conn.Close() }()

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

	_ = conn.SetWriteDeadline(time.Now().Add(s.Timeout))
	_, _ = conn.Write(smbNegotiate)

	_ = conn.SetReadDeadline(time.Now().Add(s.Timeout))
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

func (s *Scanner) buildHTTPRequest(method, path string) string {
	headers := []string{
		fmt.Sprintf("%s %s HTTP/1.1", method, path),
		"Host: " + s.Host,
		"Connection: close",
		"Accept: */*",
		"User-Agent: " + s.httpUserAgent(),
	}
	if spoofIP := s.randomHeaderIP(); spoofIP != "" {
		headers = append(headers, "X-Forwarded-For: "+spoofIP, "X-Real-IP: "+spoofIP)
	}
	return strings.Join(headers, "\r\n") + "\r\n\r\n"
}

func (s *Scanner) httpUserAgent() string {
	if !s.RandomAgent {
		return "gomap/2.x"
	}
	agents := []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36",
		"Mozilla/5.0 (X11; Linux x86_64; rv:134.0) Gecko/20100101 Firefox/134.0",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15",
		"curl/8.10.1",
		"Wget/1.24.5",
	}
	return agents[rand.IntN(len(agents))]
}

func (s *Scanner) randomHeaderIP() string {
	if !s.RandomIP || !s.targetPrefix.IsValid() || !s.targetPrefix.Addr().Is4() {
		return ""
	}
	p := s.targetPrefix.Masked()
	addr := p.Addr()
	prefixBits := p.Bits()
	if prefixBits >= 31 {
		return ""
	}
	base := ip4ToUint(addr)
	hostBits := 32 - prefixBits
	hostCount := uint32(1) << hostBits
	if hostCount <= 2 {
		return ""
	}
	hostOffset := uint32(rand.IntN(int(hostCount-2))) + 1
	ip := uintToIP4(base + hostOffset)
	return ip.String()
}

func parseTargetPrefix(cidr, host string) netip.Prefix {
	if cidr != "" {
		if p, err := netip.ParsePrefix(cidr); err == nil {
			return p.Masked()
		}
	}
	ip, err := netip.ParseAddr(host)
	if err != nil || !ip.Is4() {
		return netip.Prefix{}
	}
	// Fallback approximation when scanning a single host.
	return netip.PrefixFrom(ip, 24).Masked()
}

func ip4ToUint(ip netip.Addr) uint32 {
	b := ip.As4()
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

func uintToIP4(v uint32) netip.Addr {
	return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
}
