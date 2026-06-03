package scanner

import (
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"net/netip"
	"regexp"
	"sort"
	"strings"
	"sync"
	"syscall"
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
	DeepVersion        bool
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
	DeepVersion     bool
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
		DeepVersion:        false,
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
	s.DeepVersion = cfg.DeepVersion
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

	return dedupeOpenResults(openPorts)
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
		s.recordDialOutcome(err, time.Since(attemptStart))
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
		if streak > 6 {
			streak = 6
		}
		timeout += time.Duration(streak) * 50 * time.Millisecond
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

func (s *Scanner) boundedServiceTimeout(min, max time.Duration) time.Duration {
	timeout := s.ioTimeout(min)
	if max > 0 && timeout > max {
		return max
	}
	return timeout
}

func (s *Scanner) recordDialOutcome(dialErr error, latency time.Duration) {
	s.adaptiveMu.Lock()
	defer s.adaptiveMu.Unlock()

	if dialErr == nil {
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
	if isDialTimeoutError(dialErr) {
		s.failureStreak++
		return
	}
	if s.failureStreak > 0 {
		s.failureStreak--
	}
}

func isDialTimeoutError(err error) bool {
	if err == nil {
		return false
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return true
	}
	return errors.Is(err, syscall.ETIMEDOUT)
}

func dedupeOpenResults(results []ScanResult) []ScanResult {
	if len(results) < 2 {
		return results
	}

	seen := make(map[int]ScanResult, len(results))
	for _, r := range results {
		prev, ok := seen[r.Port]
		if !ok {
			seen[r.Port] = r
			continue
		}
		seen[r.Port] = mergeOpenResult(prev, r)
	}

	out := make([]ScanResult, 0, len(seen))
	for _, r := range seen {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Port < out[j].Port })
	return out
}

func mergeOpenResult(a, b ScanResult) ScanResult {
	// Prefer richer fields from b where present.
	out := a
	if b.ServiceName != "" {
		out.ServiceName = b.ServiceName
	}
	if b.Version != "" {
		out.Version = b.Version
	}
	if b.Confidence != "" {
		out.Confidence = b.Confidence
	}
	if b.Evidence != "" {
		out.Evidence = b.Evidence
	}
	if b.DetectionPath != "" {
		out.DetectionPath = b.DetectionPath
	}
	if b.TLS {
		out.TLS = true
		out.TLSVersion = b.TLSVersion
		out.TLSCipher = b.TLSCipher
		out.TLSALPN = b.TLSALPN
		out.TLSServerName = b.TLSServerName
		out.TLSIssuer = b.TLSIssuer
	}
	if b.LatencyMs > 0 {
		out.Latency = b.Latency
		out.LatencyMs = b.LatencyMs
	}
	return out
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

// grabBanner attempts to grab the service banner
func (s *Scanner) grabBanner(conn net.Conn, port int, result *ScanResult) {
	var banner string
	deepProbeUsed := false
	deepProbeAttempted := false
	mappedService := s.PortManager.GetServiceName(port, "")
	mappedFTP := normalizeVersionProbeService(mappedService) == "ftp"

	if !s.GhostMode && port == 3306 {
		if version := detectMySQLHandshakeFromConn(conn, s.boundedServiceTimeout(1200*time.Millisecond, 2500*time.Millisecond)); version != "" {
			result.ServiceName = "mysql"
			result.Version = version
			result.Confidence = "high"
			result.Evidence = "mysql handshake"
			result.DetectionPath = "protocol-fingerprint"
			return
		}
		result.ServiceName = "mysql"
		result.Version = "MySQL service (no handshake)"
		result.Confidence = "low"
		result.Evidence = "port open; no mysql handshake"
		result.DetectionPath = "mysql-portmap"
		return
	}
	if !s.GhostMode && port == 33060 {
		result.ServiceName = "mysqlx"
		result.Version = "MySQL X Protocol service"
		result.Confidence = "low"
		result.Evidence = "port map"
		result.DetectionPath = "portmap"
		return
	}

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

	// For HTTP ports, send active request first
	if shouldParseAsHTTP(port) && !s.GhostMode {
		banner = s.grabHTTPBanner(port)
	}

	if banner == "" && !s.GhostMode && s.DeepVersion && mappedFTP {
		deepProbeAttempted = true
		banner = s.probeTextServiceOnConn(conn, "\r\n\r\n")
		deepProbeUsed = banner != ""
	}

	// If no banner yet, try passive read
	if banner == "" && (!s.DeepVersion || !mappedFTP) {
		banner = s.tryPassiveBanner(conn)
	}

	if banner == "" && !s.GhostMode {
		if connectedBanner, attempted := s.tryConnectedTextProbe(conn, port); attempted {
			banner = connectedBanner
			if banner == "" {
				result.ServiceName = s.PortManager.GetServiceName(port, "")
				if result.ServiceName != "" {
					result.Version = noGreetingVersionForPort(port)
					result.Confidence = "low"
					result.Evidence = noGreetingEvidenceForPort(port)
					result.DetectionPath = "connected-probe"
				}
				if !s.DeepVersion || normalizeVersionProbeService(result.ServiceName) != "ftp" {
					return
				}
			}
		}
	}

	// Deep version mode tries focused, bounded probes before the default fallback path.
	if banner == "" && !s.GhostMode && s.DeepVersion && !deepProbeAttempted {
		deepProbeAttempted = true
		banner = s.tryDeepVersionProbe(port, s.PortManager.GetServiceName(port, ""))
		deepProbeUsed = banner != ""
	}
	// If still no banner, use active probes only outside ghost mode.
	if banner == "" && !s.GhostMode && (!deepProbeAttempted || !mappedFTP) {
		banner = s.tryServiceProbe(port)
	}
	if banner == "" && !s.GhostMode && s.PortManager.GetServiceName(port, "") == "" {
		banner = s.tryGenericServiceProbes(port)
	}

	// Special handling for SMB/NetBIOS session service.
	if banner == "" && (port == 139 || port == 445) && !s.GhostMode {
		smbInfo, method := s.detectSMBVersion(port)
		if smbInfo != "" {
			result.ServiceName = s.PortManager.GetServiceName(port, "")
			if result.ServiceName == "" {
				result.ServiceName = "microsoft-ds"
			}
			result.Version = smbInfo
			result.Confidence = "high"
			result.Evidence = method
			result.DetectionPath = "smb-specialized"
			return
		}
	}

	// If we still have no banner, use default service name
	if banner == "" {
		mappedService := s.PortManager.GetServiceName(port, "")
		if !s.GhostMode && shouldAttemptTLSFingerprint(port, mappedService) {
			if fp, ok := s.detectTLSFingerprint(port); ok {
				result.TLS = true
				result.TLSVersion = fp.Version
				result.TLSCipher = fp.Cipher
				result.TLSALPN = fp.ALPN
				result.TLSServerName = fp.SNI
				result.TLSIssuer = fp.Issuer
				result.ServiceName = inferTLServiceByPort(port, mappedService)
				result.Version = strings.TrimSpace(strings.Join([]string{fp.Version, fp.Cipher}, " "))
				if result.ServiceName == "winrm" && result.Version == "" {
					result.Version = "Microsoft WinRM over TLS"
				}
				result.Confidence = "high"
				result.Evidence = "tls handshake"
				result.DetectionPath = "tls-fingerprint"
				return
			}
		}
		result.ServiceName = mappedService
		if result.ServiceName == "msrpc" {
			result.Version = "Microsoft Windows RPC"
			result.Confidence = "medium"
			result.Evidence = "DCE/RPC Endpoint Mapper on tcp/135"
			result.DetectionPath = "portmap+heuristic"
			return
		}
		if result.ServiceName != "" {
			if version := noGreetingVersionForPort(port); version != "" {
				result.Version = version
				result.Evidence = noGreetingEvidenceForPort(port)
			} else {
				result.Evidence = "port map"
			}
			result.Confidence = "low"
			result.DetectionPath = "portmap"
		}
		return
	}

	// Parse the banner to extract service and version
	serviceName, version := parseBanner(banner)
	if !s.GhostMode && (port == 21 || serviceName == "ftp") && (serviceName == "" || (serviceName == "ftp" && isWeakFTPVersion(version))) {
		if ftpBanner := s.probeFTP(port); ftpBanner != "" {
			if ftpService, ftpVersion := parseBanner(ftpBanner); ftpService == "ftp" {
				serviceName = ftpService
				if ftpVersion != "" && (version == "" || !isWeakFTPVersion(ftpVersion)) {
					version = ftpVersion
				}
			}
		}
	}
	if !s.GhostMode && s.DeepVersion && serviceName != "" && shouldDeepenVersion(serviceName, version) {
		if deepBanner := s.tryDeepVersionProbe(port, serviceName); deepBanner != "" {
			if deepService, deepVersion := parseBanner(deepBanner); deepService != "" {
				deepProbeUsed = true
				serviceName = deepService
				if deepVersion != "" && (version == "" || isWeakVersion(version)) {
					version = deepVersion
				}
			}
		}
	}

	// Use service name from banner if found, otherwise use port mapping
	if serviceName != "" {
		result.ServiceName = serviceName
		result.Version = version
		if result.ServiceName == "http" && isLikelyHTTPProxyPort(port) {
			result.ServiceName = "http-proxy"
		}
		if (port == 5985 || port == 5986 || port == 47001) && serviceName == "http" {
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
		if s.DeepVersion {
			if evidence := evidenceFromBanner(banner); evidence != "" {
				result.Evidence = evidence
			}
		}
		result.DetectionPath = "banner-parser"
		if deepProbeUsed {
			if evidence := evidenceFromBanner(banner); evidence != "" {
				result.Evidence = evidence
			} else {
				result.Evidence = "deep version probe"
			}
			result.DetectionPath = "deep-version"
			if version == "" && result.Evidence == "" {
				result.Evidence = "deep version probe (generic)"
			}
		}
		if !s.GhostMode && shouldAttemptTLSFingerprint(port, result.ServiceName) {
			if fp, ok := s.detectTLSFingerprint(port); ok {
				result.TLS = true
				result.TLSVersion = fp.Version
				result.TLSCipher = fp.Cipher
				result.TLSALPN = fp.ALPN
				result.TLSServerName = fp.SNI
				result.TLSIssuer = fp.Issuer
				if result.ServiceName == "http" {
					result.ServiceName = inferTLServiceByPort(port, result.ServiceName)
				}
				if result.Version == "" {
					result.Version = strings.TrimSpace(strings.Join([]string{fp.Version, fp.Cipher}, " "))
				}
				if result.Evidence == "" {
					result.Evidence = "tls handshake"
				} else {
					result.Evidence += "+tls"
				}
				result.DetectionPath += "+tls"
			}
		}
	} else {
		if !s.GhostMode && shouldRetryMappedTextProbe(port, result.ServiceName) {
			if retryBanner := s.tryServiceProbe(port); retryBanner != "" {
				if retryService, retryVersion := parseBanner(retryBanner); retryService != "" {
					result.ServiceName = retryService
					result.Version = retryVersion
					result.Confidence = "high"
					if retryVersion == "" {
						result.Confidence = "medium"
					}
					result.Evidence = "protocol probe"
					result.DetectionPath = "active-probe"
					return
				}
			}
		}
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

func isLikelyHTTPProxyPort(port int) bool {
	switch port {
	case 8080, 3128, 8000, 8008, 8888:
		return true
	default:
		return false
	}
}

func shouldRetryMappedTextProbe(port int, currentService string) bool {
	if currentService != "" {
		return false
	}
	switch port {
	case 25, 110, 143, 465, 587, 993, 995:
		return true
	default:
		return false
	}
}

func (s *Scanner) tryConnectedTextProbe(conn net.Conn, port int) (string, bool) {
	switch port {
	case 25, 587, 2525:
		return s.probeTextServiceOnConn(conn, "EHLO gomap.local\r\n"), true
	case 110:
		return s.probeTextServiceOnConn(conn, "CAPA\r\n"), true
	case 143:
		return s.probeTextServiceOnConn(conn, "a001 CAPABILITY\r\n"), true
	default:
		return "", false
	}
}

func (s *Scanner) probeTextServiceOnConn(conn net.Conn, payload string) string {
	timeout := s.boundedServiceTimeout(900*time.Millisecond, 1800*time.Millisecond)
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if _, err := conn.Write([]byte(payload)); err != nil {
		return ""
	}
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil || n == 0 {
		return ""
	}
	return string(buf[:n])
}

func noGreetingVersionForPort(port int) string {
	switch port {
	case 21, 2121:
		return "FTP service (no greeting)"
	case 25, 465, 587, 2525:
		return "SMTP service (no greeting)"
	case 110, 995:
		return "POP3 service (no greeting)"
	case 143, 993:
		return "IMAP service (no greeting)"
	case 3389:
		return "Microsoft Terminal Services"
	default:
		return ""
	}
}

func noGreetingEvidenceForPort(port int) string {
	switch port {
	case 21, 2121:
		return "port open; no ftp greeting"
	case 25, 465, 587, 2525:
		return "port open; no smtp greeting"
	case 110, 995:
		return "port open; no pop3 greeting"
	case 143, 993:
		return "port open; no imap greeting"
	case 3389:
		return "RDP TCP/3389 open; no negotiation response"
	default:
		return "port open; no greeting"
	}
}

func isWeakFTPVersion(version string) bool {
	v := strings.ToLower(strings.TrimSpace(version))
	return v == "" ||
		v == "ftp service" ||
		v == "service ready" ||
		v == "service ready for new user" ||
		v == "ftp server ready" ||
		v == "ready"
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
	if shouldUseFTPProbe(port) {
		return s.probeFTP(port)
	}
	switch port {
	case 25, 465, 587, 2525:
		return s.probeMailService(port, "EHLO gomap.local\r\n", port == 465)
	case 110, 995:
		return s.probeMailService(port, "CAPA\r\n", port == 995)
	case 143, 993:
		return s.probeMailService(port, "a001 CAPABILITY\r\n", port == 993)
	case 6379:
		return s.probeTextService(port, "INFO\r\n")
	case 8009:
		return s.probeAJP(port)
	default:
		return ""
	}
}

func shouldUseFTPProbe(port int) bool {
	switch port {
	case 21, 2121:
		return true
	default:
		return false
	}
}

func shouldDeepenVersion(serviceName, version string) bool {
	if serviceName == "" {
		return false
	}
	return isWeakVersion(version)
}

func isWeakVersion(version string) bool {
	v := strings.ToLower(strings.TrimSpace(version))
	if v == "" {
		return true
	}
	switch v {
	case "service", "service ready", "ready", "unknown":
		return true
	case "ftp service", "ftp server ready", "smtp service", "pop3 service", "imap4rev1", "http":
		return true
	default:
		return false
	}
}

func (s *Scanner) probeFTP(port int) string {
	address := net.JoinHostPort(s.Host, fmt.Sprintf("%d", port))
	timeout := s.boundedServiceTimeout(1200*time.Millisecond, 4*time.Second)

	conn, err := net.DialTimeout("tcp", address, timeout)
	if err != nil {
		return ""
	}
	defer func() { _ = conn.Close() }()

	_ = conn.SetDeadline(time.Now().Add(timeout))
	buf := make([]byte, 2048)
	var response strings.Builder

	if n, err := conn.Read(buf); err == nil && n > 0 {
		response.Write(buf[:n])
		response.WriteByte('\n')
	}

	for _, payload := range []string{"SYST\r\n", "FEAT\r\n", "HELP\r\n"} {
		_ = conn.SetDeadline(time.Now().Add(timeout))
		if _, err := conn.Write([]byte(payload)); err != nil {
			break
		}
		if n, err := conn.Read(buf); err == nil && n > 0 {
			response.Write(buf[:n])
			response.WriteByte('\n')
		}
	}
	return response.String()
}

func (s *Scanner) probeMailService(port int, payload string, useTLS bool) string {
	address := net.JoinHostPort(s.Host, fmt.Sprintf("%d", port))
	timeout := s.boundedServiceTimeout(1200*time.Millisecond, 2500*time.Millisecond)

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
		return ""
	}
	defer func() { _ = conn.Close() }()

	_ = conn.SetDeadline(time.Now().Add(timeout))
	var response strings.Builder
	buf := make([]byte, 4096)

	if n, err := conn.Read(buf); err == nil && n > 0 {
		response.Write(buf[:n])
		response.WriteByte('\n')
	}

	if payload != "" {
		_, _ = conn.Write([]byte(payload))
		if n, err := conn.Read(buf); err == nil && n > 0 {
			response.Write(buf[:n])
			response.WriteByte('\n')
		}
	}

	return response.String()
}

func (s *Scanner) tryDeepVersionProbe(port int, serviceName string) string {
	serviceName = normalizeVersionProbeService(serviceName)
	if serviceName == "" {
		return ""
	}
	if serviceName == "ftp" {
		if response := s.probeFTPGenericLines(port); response != "" {
			return response
		}
	}
	if response := s.tryServiceProbeForService(port, serviceName); response != "" {
		return response
	}
	for _, payload := range deepVersionPayloads(port, serviceName) {
		if response := s.probeTextServiceWriteFirstWithTimeout(port, payload, 700*time.Millisecond, 1500*time.Millisecond); response != "" {
			if service, _ := parseBanner(response); service != "" {
				return response
			}
		}
	}
	return ""
}

func (s *Scanner) probeFTPGenericLines(port int) string {
	address := net.JoinHostPort(s.Host, fmt.Sprintf("%d", port))
	timeout := s.boundedServiceTimeout(700*time.Millisecond, 1500*time.Millisecond)

	conn, err := net.DialTimeout("tcp", address, timeout)
	if err != nil {
		return ""
	}
	defer func() { _ = conn.Close() }()

	_ = conn.SetDeadline(time.Now().Add(timeout))
	if _, err := conn.Write([]byte("\r\n\r\n")); err != nil {
		return ""
	}

	var response strings.Builder
	buf := make([]byte, 2048)
	for {
		n, err := conn.Read(buf)
		if n > 0 {
			response.Write(buf[:n])
			if response.Len() >= 4096 {
				break
			}
		}
		if err != nil {
			break
		}
	}
	return response.String()
}

func (s *Scanner) tryServiceProbeForService(port int, serviceName string) string {
	serviceName = normalizeVersionProbeService(serviceName)
	switch serviceName {
	case "ftp":
		return s.probeFTP(port)
	case "smtp":
		return s.probeMailService(port, "EHLO gomap.local\r\n", port == 465)
	case "pop3":
		return s.probeMailService(port, "CAPA\r\n", port == 995)
	case "imap":
		return s.probeMailService(port, "a001 CAPABILITY\r\n", port == 993)
	case "redis":
		return s.probeTextService(port, "INFO\r\n")
	case "ajp13":
		return s.probeAJP(port)
	default:
		return ""
	}
}

func deepVersionPayloads(port int, serviceName string) []string {
	serviceName = normalizeVersionProbeService(serviceName)
	switch serviceName {
	case "http", "http-proxy", "winrm":
		return []string{"HEAD / HTTP/1.0\r\n\r\n", "OPTIONS / HTTP/1.0\r\n\r\n"}
	case "ftp":
		return []string{"SYST\r\n", "FEAT\r\n"}
	case "smtp":
		return []string{"EHLO gomap.local\r\n", "HELP\r\n"}
	case "pop3":
		return []string{"CAPA\r\n"}
	case "imap":
		return []string{"a001 CAPABILITY\r\n"}
	case "redis":
		return []string{"INFO\r\n"}
	default:
		return nil
	}
}

func normalizeVersionProbeService(serviceName string) string {
	switch strings.ToLower(strings.TrimSpace(serviceName)) {
	case "smtps":
		return "smtp"
	case "pop3s":
		return "pop3"
	case "imaps":
		return "imap"
	default:
		return strings.ToLower(strings.TrimSpace(serviceName))
	}
}

func evidenceFromBanner(banner string) string {
	for _, line := range strings.Split(banner, "\n") {
		line = sanitizeVersionString(line)
		if line == "" {
			continue
		}
		return line
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

// tryGenericServiceProbes improves detection for services exposed on non-standard ports.
func (s *Scanner) tryGenericServiceProbes(port int) string {
	probes := []string{
		"GET / HTTP/1.0\r\n\r\n",
		s.buildHTTPRequest("GET", "/"),
		"\r\n",
		"HELP\n",
		"HELP\r\n",
		"SYST\r\n",
		"FEAT\r\n",
		"CAPA\r\n",
		"a001 CAPABILITY\r\n",
	}

	for _, payload := range probes {
		if response := s.probeTextServiceWriteFirst(port, payload); response != "" {
			if service, _ := parseBanner(response); service != "" {
				return response
			}
		}
	}
	return ""
}

func (s *Scanner) probeTextServiceWriteFirst(port int, payload string) string {
	return s.probeTextServiceWriteFirstWithTimeout(port, payload, 1500*time.Millisecond, 0)
}

func (s *Scanner) probeTextServiceWriteFirstWithTimeout(port int, payload string, minTimeout, maxTimeout time.Duration) string {
	address := net.JoinHostPort(s.Host, fmt.Sprintf("%d", port))
	timeout := s.boundedServiceTimeout(minTimeout, maxTimeout)

	conn, err := net.DialTimeout("tcp", address, timeout)
	if err != nil {
		return ""
	}
	defer func() { _ = conn.Close() }()

	_ = conn.SetDeadline(time.Now().Add(timeout))
	_, _ = conn.Write([]byte(payload))

	buf := make([]byte, 2048)
	n, err := conn.Read(buf)
	if err != nil || n == 0 {
		return ""
	}
	return string(buf[:n])
}

// tryProtocolFingerprint performs protocol-aware detection for services that often need active handshakes.
func (s *Scanner) tryProtocolFingerprint(port int) (service, version, confidence, evidence, path string, ok bool) {
	switch port {
	case 53:
		if version = s.detectDNSVersionTCP(port); version != "" {
			return "domain", version, "high", "dns chaos version.bind", "protocol-fingerprint", true
		}
	case 111:
		if ver, detected := s.detectONCRPCProgram(port, 100000, []uint32{4, 3, 2}); detected {
			return "rpcbind", fmt.Sprintf("rpcbind v%d", ver), "high", rpcAcceptedEvidence(100000, ver, port), "protocol-fingerprint", true
		}
	case 2049:
		if ver, detected := s.detectONCRPCProgram(port, 100003, []uint32{4, 3, 2}); detected {
			return "nfs", fmt.Sprintf("NFS v%d", ver), "high", rpcAcceptedEvidence(100003, ver, port), "protocol-fingerprint", true
		}
	case 1433:
		if s.detectMSSQLTDS(port) {
			return "mssql", "Microsoft SQL Server (TDS)", "medium", "tds prelogin response", "protocol-fingerprint", true
		}
	case 3389:
		if version, evidence, detected := s.detectRDPInfo(port); detected {
			return "ms-wbt-server", version, "high", evidence, "protocol-fingerprint", true
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
		if version, evidence := s.detectWinRM(port); version != "" {
			return "winrm", version, "high", evidence, "protocol-fingerprint", true
		}
	case 47001:
		if version, evidence := s.detectWinRM(port); version != "" {
			return "winrm", version, "high", evidence, "protocol-fingerprint", true
		}
	case 8009:
		if s.detectAJP(port) {
			return "ajp13", "Apache JServ Protocol (AJP/1.3)", "high", "ajp cping/cpong", "protocol-fingerprint", true
		}
	}
	if port > 1024 {
		if service, version, ok := s.detectDynamicONCRPCService(port); ok {
			return service, version, "high", rpcAcceptedEvidence(rpcProgramForService(service), rpcVersionFromServiceVersion(service, version), port), "protocol-fingerprint", true
		}
	}
	return "", "", "", "", "", false
}

type oncRPCProbe struct {
	program  uint32
	versions []uint32
	service  string
	name     string
}

func (s *Scanner) detectDynamicONCRPCService(port int) (service, version string, ok bool) {
	probes := []oncRPCProbe{
		{program: 100005, versions: []uint32{3, 2, 1}, service: "mountd", name: "mountd"},
		{program: 100021, versions: []uint32{4, 3, 1}, service: "nlockmgr", name: "NFS lock manager"},
		{program: 100024, versions: []uint32{1}, service: "status", name: "rpc.statd"},
		{program: 100003, versions: []uint32{4, 3, 2}, service: "nfs", name: "NFS"},
		{program: 100227, versions: []uint32{3, 2}, service: "nfs_acl", name: "NFS ACL"},
	}
	for _, probe := range probes {
		for _, ver := range probe.versions {
			accepted, responded := s.oncRPCNullCall(port, probe.program, ver)
			if accepted {
				return probe.service, fmt.Sprintf("%s v%d", probe.name, ver), true
			}
			if !responded {
				return "", "", false
			}
		}
	}
	return "", "", false
}

func rpcProgramForService(service string) uint32 {
	switch service {
	case "rpcbind":
		return 100000
	case "nfs":
		return 100003
	case "mountd":
		return 100005
	case "nlockmgr":
		return 100021
	case "status":
		return 100024
	case "nfs_acl":
		return 100227
	default:
		return 0
	}
}

func rpcServiceName(service string) string {
	switch service {
	case "nfs":
		return "NFS"
	case "nlockmgr":
		return "NFS lock manager"
	case "status":
		return "rpc.statd"
	case "nfs_acl":
		return "NFS ACL"
	default:
		return service
	}
}

func rpcVersionFromServiceVersion(service, version string) uint32 {
	prefix := rpcServiceName(service) + " v"
	if strings.HasPrefix(version, prefix) {
		var v uint32
		if _, err := fmt.Sscanf(strings.TrimPrefix(version, prefix), "%d", &v); err == nil {
			return v
		}
	}
	return 0
}

func rpcAcceptedEvidence(program, version uint32, port int) string {
	if version == 0 {
		return fmt.Sprintf("RPC #%d accepted on tcp/%d", program, port)
	}
	return fmt.Sprintf("RPC #%d accepted v%d on tcp/%d", program, version, port)
}

func (s *Scanner) detectONCRPCProgram(port int, program uint32, versions []uint32) (uint32, bool) {
	for _, version := range versions {
		accepted, _ := s.oncRPCNullCall(port, program, version)
		if accepted {
			return version, true
		}
	}
	return 0, false
}

func (s *Scanner) oncRPCNullCall(port int, program, version uint32) (accepted, responded bool) {
	address := net.JoinHostPort(s.Host, fmt.Sprintf("%d", port))
	timeout := s.ioTimeout(1200 * time.Millisecond)
	if timeout < 1200*time.Millisecond {
		timeout = 1200 * time.Millisecond
	}

	conn, err := net.DialTimeout("tcp", address, timeout)
	if err != nil {
		return false, false
	}
	defer func() { _ = conn.Close() }()

	xid := uint32(0x676f0000) | uint32(rand.IntN(0xffff))
	call := buildONCRPCNullCall(xid, program, version)
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if _, err := conn.Write(call); err != nil {
		return false, false
	}

	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil || n < 28 {
		return false, false
	}
	return parseONCRPCReply(buf[:n], xid)
}

func buildONCRPCNullCall(xid, program, version uint32) []byte {
	payload := make([]byte, 40)
	binary.BigEndian.PutUint32(payload[0:4], xid)
	binary.BigEndian.PutUint32(payload[4:8], 0)  // CALL
	binary.BigEndian.PutUint32(payload[8:12], 2) // RPC version
	binary.BigEndian.PutUint32(payload[12:16], program)
	binary.BigEndian.PutUint32(payload[16:20], version)
	binary.BigEndian.PutUint32(payload[20:24], 0) // NULL procedure
	binary.BigEndian.PutUint32(payload[24:28], 0) // AUTH_NULL credential
	binary.BigEndian.PutUint32(payload[28:32], 0)
	binary.BigEndian.PutUint32(payload[32:36], 0) // AUTH_NULL verifier
	binary.BigEndian.PutUint32(payload[36:40], 0)

	msg := make([]byte, 4+len(payload))
	binary.BigEndian.PutUint32(msg[0:4], uint32(len(payload))|0x80000000)
	copy(msg[4:], payload)
	return msg
}

func parseONCRPCReply(data []byte, xid uint32) (accepted, valid bool) {
	if len(data) < 28 {
		return false, false
	}
	if binary.BigEndian.Uint32(data[0:4])&0x7fffffff == 0 {
		return false, false
	}
	payload := data[4:]
	if len(payload) < 24 {
		return false, false
	}
	if binary.BigEndian.Uint32(payload[0:4]) != xid {
		return false, false
	}
	if binary.BigEndian.Uint32(payload[4:8]) != 1 {
		return false, false
	}
	if binary.BigEndian.Uint32(payload[8:12]) != 0 {
		return false, true
	}

	verifierLen := int(binary.BigEndian.Uint32(payload[16:20]))
	acceptOffset := 20 + roundUp4(verifierLen)
	if acceptOffset+4 > len(payload) {
		return false, false
	}
	return binary.BigEndian.Uint32(payload[acceptOffset:acceptOffset+4]) == 0, true
}

func roundUp4(n int) int {
	if n%4 == 0 {
		return n
	}
	return n + (4 - n%4)
}

func (s *Scanner) detectAJP(port int) bool {
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

	// AJP13 CPING packet: 0x1234 + len=1 + payload=0x0a
	cping := []byte{0x12, 0x34, 0x00, 0x01, 0x0a}
	_ = conn.SetDeadline(time.Now().Add(timeout))
	_, _ = conn.Write(cping)

	buf := make([]byte, 32)
	n, err := conn.Read(buf)
	if err != nil || n < 5 {
		return false
	}

	// Expected CPONG response payload 0x09 with AJP magic.
	return buf[0] == 0x12 && buf[1] == 0x34 && buf[4] == 0x09
}

func (s *Scanner) probeAJP(port int) string {
	if s.detectAJP(port) {
		return "AJP/1.3"
	}
	return ""
}

func (s *Scanner) detectDNSVersionTCP(port int) string {
	address := net.JoinHostPort(s.Host, fmt.Sprintf("%d", port))
	timeout := s.ioTimeout(1500 * time.Millisecond)
	if timeout < 1500*time.Millisecond {
		timeout = 1500 * time.Millisecond
	}

	conn, err := net.DialTimeout("tcp", address, timeout)
	if err != nil {
		return ""
	}
	defer func() { _ = conn.Close() }()

	query := buildDNSVersionBindQuery()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if _, err := conn.Write(query); err != nil {
		return ""
	}

	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil || n < 14 {
		return ""
	}
	return parseDNSVersionBindResponse(buf[:n])
}

func buildDNSVersionBindQuery() []byte {
	payload := []byte{
		0x13, 0x37, // ID
		0x01, 0x00, // standard query, recursion desired
		0x00, 0x01, // QDCOUNT
		0x00, 0x00, // ANCOUNT
		0x00, 0x00, // NSCOUNT
		0x00, 0x00, // ARCOUNT
		0x07, 'v', 'e', 'r', 's', 'i', 'o', 'n',
		0x04, 'b', 'i', 'n', 'd',
		0x00,
		0x00, 0x10, // TXT
		0x00, 0x03, // CH
	}
	msg := make([]byte, 2+len(payload))
	binary.BigEndian.PutUint16(msg[0:2], uint16(len(payload)))
	copy(msg[2:], payload)
	return msg
}

func parseDNSVersionBindResponse(data []byte) string {
	if len(data) < 2 {
		return ""
	}
	msgLen := int(binary.BigEndian.Uint16(data[0:2]))
	if msgLen <= 0 || 2+msgLen > len(data) {
		return ""
	}
	msg := data[2 : 2+msgLen]
	if len(msg) < 12 || binary.BigEndian.Uint16(msg[0:2]) != 0x1337 {
		return ""
	}
	answerCount := int(binary.BigEndian.Uint16(msg[6:8]))
	offset := 12
	for offset < len(msg) && msg[offset] != 0 {
		offset += int(msg[offset]) + 1
	}
	offset += 1 + 4
	for i := 0; i < answerCount && offset+12 <= len(msg); i++ {
		if msg[offset]&0xc0 == 0xc0 {
			offset += 2
		} else {
			for offset < len(msg) && msg[offset] != 0 {
				offset += int(msg[offset]) + 1
			}
			offset++
		}
		if offset+10 > len(msg) {
			return ""
		}
		typ := binary.BigEndian.Uint16(msg[offset : offset+2])
		class := binary.BigEndian.Uint16(msg[offset+2 : offset+4])
		rdLen := int(binary.BigEndian.Uint16(msg[offset+8 : offset+10]))
		offset += 10
		if offset+rdLen > len(msg) {
			return ""
		}
		rdata := msg[offset : offset+rdLen]
		offset += rdLen
		if typ == 16 && class == 3 && len(rdata) > 1 {
			txtLen := int(rdata[0])
			if txtLen > 0 && 1+txtLen <= len(rdata) {
				return "BIND " + sanitizeVersionString(string(rdata[1:1+txtLen]))
			}
		}
	}
	return ""
}

func detectMySQLHandshakeFromConn(conn net.Conn, timeout time.Duration) string {
	_ = conn.SetReadDeadline(time.Now().Add(timeout))
	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil || n < 7 {
		return ""
	}

	return parseMySQLHandshakePacket(buf[:n])
}

func parseMySQLHandshakePacket(packet []byte) string {
	// MySQL packet: [3-byte len][1-byte seq][protocol=0x0a][version string...]
	if len(packet) < 7 || packet[4] != 0x0a {
		return ""
	}

	payload := string(packet[5:])
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

func (s *Scanner) detectRDPInfo(port int) (version, evidence string, ok bool) {
	address := net.JoinHostPort(s.Host, fmt.Sprintf("%d", port))
	timeout := s.boundedServiceTimeout(900*time.Millisecond, 1800*time.Millisecond)

	conn, err := net.DialTimeout("tcp", address, timeout)
	if err != nil {
		return "", "", false
	}
	defer func() { _ = conn.Close() }()

	// TPKT + X.224 connection request with RDP Negotiation Request:
	// request SSL or CredSSP, then inspect the selected protocol.
	req := []byte{
		0x03, 0x00, 0x00, 0x13,
		0x0e, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x01, 0x00, 0x08, 0x00,
		0x03, 0x00, 0x00, 0x00,
	}
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if _, err := conn.Write(req); err != nil {
		return "", "", false
	}

	buf := make([]byte, 128)
	n, err := conn.Read(buf)
	if err != nil || n < 7 {
		return "", "", false
	}
	if buf[0] != 0x03 || buf[1] != 0x00 || (buf[5] != 0xd0 && buf[5] != 0xe0 && buf[5] != 0xf0) {
		return "", "", false
	}

	selected, selectedOK := parseRDPNegotiationProtocol(buf[:n])
	evidence = "X.224 connection confirm"
	if selectedOK {
		evidence = "RDP negotiation: " + rdpProtocolName(selected)
		if selected != 0 {
			if cn := s.readRDPTLSCertificateCN(conn, timeout); cn != "" {
				evidence += "; cert CN=" + cn
			}
		}
	}
	return "Microsoft Terminal Services", evidence, true
}

func parseRDPNegotiationProtocol(data []byte) (uint32, bool) {
	for i := 0; i+8 <= len(data); i++ {
		if data[i] == 0x02 && data[i+2] == 0x08 && data[i+3] == 0x00 {
			return binary.LittleEndian.Uint32(data[i+4 : i+8]), true
		}
	}
	return 0, false
}

func rdpProtocolName(protocol uint32) string {
	names := make([]string, 0, 3)
	if protocol == 0 {
		return "standard RDP security"
	}
	if protocol&0x01 != 0 {
		names = append(names, "TLS")
	}
	if protocol&0x02 != 0 {
		names = append(names, "CredSSP")
	}
	if protocol&0x08 != 0 {
		names = append(names, "CredSSP Early User Auth")
	}
	if len(names) == 0 {
		return fmt.Sprintf("protocol 0x%x", protocol)
	}
	return strings.Join(names, "/")
}

func (s *Scanner) readRDPTLSCertificateCN(conn net.Conn, timeout time.Duration) string {
	tlsConn := tls.Client(conn, &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         s.Host,
	})
	_ = tlsConn.SetDeadline(time.Now().Add(timeout))
	if err := tlsConn.Handshake(); err != nil {
		return ""
	}
	state := tlsConn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return ""
	}
	return sanitizeVersionString(state.PeerCertificates[0].Subject.CommonName)
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

func (s *Scanner) detectWinRM(port int) (string, string) {
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
		return "", ""
	}
	defer func() { _ = conn.Close() }()

	_ = conn.SetDeadline(time.Now().Add(timeout))
	_, _ = conn.Write([]byte(s.buildHTTPRequest("OPTIONS", "/wsman")))

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil || n == 0 {
		return "", ""
	}

	raw := string(buf[:n])
	resp := strings.ToLower(raw)
	if strings.Contains(resp, "wsman") || strings.Contains(resp, "microsoft-httpapi") || strings.Contains(resp, "www-authenticate: negotiate") {
		if server := httpHeaderValue(raw, "Server"); server != "" {
			return winRMVersionFromServerHeader(server), "Server: " + server
		}
		if auth := httpHeaderValue(raw, "WWW-Authenticate"); auth != "" {
			return "Microsoft WinRM", "WWW-Authenticate: " + auth
		}
		if status := firstHTTPStatusLine(raw); status != "" {
			return "Microsoft WinRM", status
		}
		return "Microsoft WinRM", "WSMan/HTTPAPI response"
	}
	return "", ""
}

func httpHeaderValue(response, header string) string {
	prefix := strings.ToLower(header) + ":"
	for _, line := range strings.Split(response, "\n") {
		line = strings.TrimSpace(strings.TrimRight(line, "\r"))
		if strings.HasPrefix(strings.ToLower(line), prefix) {
			return strings.TrimSpace(line[len(prefix):])
		}
	}
	return ""
}

func firstHTTPStatusLine(response string) string {
	for _, line := range strings.Split(response, "\n") {
		line = strings.TrimSpace(strings.TrimRight(line, "\r"))
		if strings.HasPrefix(strings.ToUpper(line), "HTTP/") {
			return line
		}
	}
	return ""
}

func winRMVersionFromServerHeader(server string) string {
	if strings.Contains(strings.ToLower(server), "microsoft-httpapi") {
		return "Microsoft HTTPAPI httpd " + strings.TrimPrefix(server, "Microsoft-HTTPAPI/")
	}
	return "Microsoft WinRM"
}

// detectSMBVersion attempts to detect SMB version through multiple methods
func (s *Scanner) detectSMBVersion(port int) (string, string) {
	address := net.JoinHostPort(s.Host, fmt.Sprintf("%d", port))

	if rawSMB := s.attemptRawSMBDetection(address); rawSMB != "" {
		return rawSMB, "raw smb negotiate"
	}

	if smbLib := s.attemptSMBLibrary(address); smbLib != "" {
		return smbLib, "smb library"
	}

	if port == 139 {
		return "Microsoft Windows netbios-ssn", "NetBIOS session service on tcp/139"
	}
	return "SMB service", "SMB negotiate attempted; no dialect returned"
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
