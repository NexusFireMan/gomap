package scanner

import (
	"net"
	"testing"
	"time"
)

func TestServiceDetectionFixtureSetsConfidenceEvidence(t *testing.T) {
	result := grabBannerFromFixture(t, 2222, "SSH-2.0-OpenSSH_9.6p1 Debian-4\r\n")

	if result.ServiceName != "ssh" {
		t.Fatalf("expected ssh service, got %q", result.ServiceName)
	}
	if result.Version != "SSH-2.0 - OpenSSH 9.6p1 Debian-4" {
		t.Fatalf("unexpected ssh version: %q", result.Version)
	}
	if result.Confidence != "high" {
		t.Fatalf("expected high confidence, got %q", result.Confidence)
	}
	if result.Evidence != "protocol banner" {
		t.Fatalf("expected protocol banner evidence, got %q", result.Evidence)
	}
	if result.DetectionPath != "banner-parser" {
		t.Fatalf("expected banner-parser path, got %q", result.DetectionPath)
	}
}

func TestServiceDetectionHTTPProxyOnNonStandardPort(t *testing.T) {
	result := grabBannerFromFixture(t, 8080, "HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\nConnection: close\r\n\r\n")

	if result.ServiceName != "http-proxy" {
		t.Fatalf("expected http-proxy service, got %q", result.ServiceName)
	}
	if result.Version != "Nginx 1.24.0" {
		t.Fatalf("unexpected http version: %q", result.Version)
	}
	if result.Confidence != "high" || result.Evidence != "protocol banner" || result.DetectionPath != "banner-parser" {
		t.Fatalf("unexpected detection metadata: confidence=%q evidence=%q path=%q", result.Confidence, result.Evidence, result.DetectionPath)
	}
}

func TestHTTPAndHTTPSDetectionHeuristics(t *testing.T) {
	if !shouldParseAsHTTP(80) {
		t.Fatal("expected port 80 to be parsed as HTTP")
	}
	if !shouldParseAsHTTP(8443) {
		t.Fatal("expected port 8443 to be parsed as HTTP/HTTPS")
	}
	if shouldParseAsHTTP(3306) {
		t.Fatal("did not expect port 3306 to be parsed as HTTP")
	}
	if got := inferTLServiceByPort(443, "http"); got != "https" {
		t.Fatalf("expected https on 443, got %q", got)
	}
	if got := inferTLServiceByPort(8443, "http"); got != "https" {
		t.Fatalf("expected https on 8443, got %q", got)
	}
	if got := inferTLServiceByPort(8443, "custom-tls"); got != "custom-tls" {
		t.Fatalf("expected existing non-http service to be preserved, got %q", got)
	}
}

func TestSMBOrientedParsingFixtures(t *testing.T) {
	tests := []struct {
		name    string
		banner  string
		version string
	}{
		{
			name:    "samba smbd version",
			banner:  "Samba smbd 4.15.13-Ubuntu",
			version: "Samba 4.15.13",
		},
		{
			name:    "windows server",
			banner:  "Microsoft Windows SMB Windows Server 2019",
			version: "Windows Server 2019",
		},
		{
			name:    "dialect range",
			banner:  "SMB 2.1",
			version: "SMB 2.1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			service, version := parseSMB(tt.banner)
			if service != "microsoft-ds" {
				t.Fatalf("expected microsoft-ds service, got %q", service)
			}
			if version != tt.version {
				t.Fatalf("expected version %q, got %q", tt.version, version)
			}
		})
	}
}

func TestNoGreetingDetectionMetadata(t *testing.T) {
	tests := []struct {
		port     int
		version  string
		evidence string
	}{
		{21, "FTP service (no greeting)", "port open; no ftp greeting"},
		{2121, "FTP service (no greeting)", "port open; no ftp greeting"},
		{25, "SMTP service (no greeting)", "port open; no smtp greeting"},
		{110, "POP3 service (no greeting)", "port open; no pop3 greeting"},
		{143, "IMAP service (no greeting)", "port open; no imap greeting"},
		{2525, "SMTP service (no greeting)", "port open; no smtp greeting"},
	}

	for _, tt := range tests {
		t.Run(tt.version, func(t *testing.T) {
			if got := noGreetingVersionForPort(tt.port); got != tt.version {
				t.Fatalf("port %d: expected version %q, got %q", tt.port, tt.version, got)
			}
			if got := noGreetingEvidenceForPort(tt.port); got != tt.evidence {
				t.Fatalf("port %d: expected evidence %q, got %q", tt.port, tt.evidence, got)
			}
		})
	}
}

func TestDeepVersionHelpers(t *testing.T) {
	if !shouldDeepenVersion("imap", "IMAP4rev1") {
		t.Fatal("expected generic IMAP capability to be eligible for deeper version probing")
	}
	if shouldDeepenVersion("ssh", "OpenSSH 9.6p1") {
		t.Fatal("did not expect concrete SSH version to be deepened")
	}
	if got := normalizeVersionProbeService("imaps"); got != "imap" {
		t.Fatalf("expected imaps to normalize to imap, got %q", got)
	}
	payloads := deepVersionPayloads(8443, "http")
	if len(payloads) == 0 || payloads[0] != "HEAD / HTTP/1.0\r\n\r\n" {
		t.Fatalf("unexpected HTTP deep version payloads: %#v", payloads)
	}
	if got := deepVersionPayloads(22, "ssh"); got != nil {
		t.Fatalf("expected no generic deep probes for ssh, got %#v", got)
	}
}

func TestDeepVersionFTPGenericLinesOnExistingConnection(t *testing.T) {
	client, server := net.Pipe()
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer func() { _ = server.Close() }()
		buf := make([]byte, 8)
		_, _ = server.Read(buf)
		_, _ = server.Write([]byte("220 ProFTPD Server (Ceil's FTP) [10.0.11.6]\r\n500 Invalid command\r\n"))
	}()

	t.Cleanup(func() { _ = client.Close() })

	s := NewScanner("fixture.local", false)
	s.DeepVersion = true
	s.AdaptiveTimeout = false
	s.Timeout = 25 * time.Millisecond
	s.PortManager = NewPortManager()

	result := ScanResult{Port: 2121, IsOpen: true}
	s.grabBanner(client, 2121, &result)

	if result.ServiceName != "ftp" {
		t.Fatalf("expected ftp service, got %q", result.ServiceName)
	}
	if result.Version != "ProFTPD (Ceil's FTP)" {
		t.Fatalf("unexpected version: %q", result.Version)
	}
	if result.Evidence != "deep version probe" || result.DetectionPath != "deep-version" {
		t.Fatalf("unexpected deep metadata: evidence=%q path=%q", result.Evidence, result.DetectionPath)
	}

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("fixture server did not finish")
	}
}

func grabBannerFromFixture(t *testing.T, port int, banner string) ScanResult {
	t.Helper()

	client, server := net.Pipe()
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer func() { _ = server.Close() }()
		_, _ = server.Write([]byte(banner))
	}()

	t.Cleanup(func() { _ = client.Close() })

	s := NewScanner("fixture.local", true)
	s.AdaptiveTimeout = false
	s.Timeout = 25 * time.Millisecond
	s.PortManager = NewPortManager()

	result := ScanResult{Port: port, IsOpen: true}
	s.grabBanner(client, port, &result)

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("fixture writer did not finish")
	}

	return result
}
