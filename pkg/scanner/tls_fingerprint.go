package scanner

import (
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"time"
)

type tlsFingerprint struct {
	Version string
	Cipher  string
	ALPN    string
	SNI     string
	Issuer  string
}

func (s *Scanner) detectTLSFingerprint(port int) (tlsFingerprint, bool) {
	var fp tlsFingerprint
	address := net.JoinHostPort(s.Host, fmt.Sprintf("%d", port))
	timeout := s.ioTimeout(1600 * time.Millisecond)
	if timeout < 1600*time.Millisecond {
		timeout = 1600 * time.Millisecond
	}

	dialer := &net.Dialer{Timeout: timeout}
	cfg := &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         s.Host,
		NextProtos:         []string{"h2", "http/1.1"},
	}
	conn, err := tls.DialWithDialer(dialer, "tcp", address, cfg)
	if err != nil {
		return fp, false
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	state := conn.ConnectionState()
	fp.Version = tlsVersionString(state.Version)
	fp.Cipher = tls.CipherSuiteName(state.CipherSuite)
	if state.NegotiatedProtocol != "" {
		fp.ALPN = state.NegotiatedProtocol
	}
	fp.SNI = cfg.ServerName
	if len(state.PeerCertificates) > 0 {
		issuer := strings.TrimSpace(state.PeerCertificates[0].Issuer.CommonName)
		if issuer != "" {
			fp.Issuer = issuer
		}
	}
	return fp, true
}

func tlsVersionString(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLS1.0"
	case tls.VersionTLS11:
		return "TLS1.1"
	case tls.VersionTLS12:
		return "TLS1.2"
	case tls.VersionTLS13:
		return "TLS1.3"
	default:
		return fmt.Sprintf("TLS(0x%x)", v)
	}
}

func inferTLServiceByPort(port int, currentService string) string {
	if currentService != "" && currentService != "http" {
		return currentService
	}
	switch port {
	case 443, 8443, 9443:
		return "https"
	case 993:
		return "imaps"
	case 995:
		return "pop3s"
	case 465:
		return "smtps"
	case 636:
		return "ldaps"
	case 5986:
		return "winrm"
	default:
		if currentService != "" {
			return currentService
		}
		return "tls"
	}
}

func shouldAttemptTLSFingerprint(port int, mappedService string) bool {
	switch port {
	case 443, 465, 563, 636, 853, 989, 990, 992, 993, 995, 5986, 6443, 8443, 9443, 10443:
		return true
	}

	switch mappedService {
	case "https", "https-alt", "smtps", "imaps", "pop3s", "ldaps":
		return true
	}

	return false
}
