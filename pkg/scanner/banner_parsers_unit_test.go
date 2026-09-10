package scanner

import "testing"

func TestParseBannerHTTPIIS(t *testing.T) {
	banner := "HTTP/1.1 200 OK\r\nServer: Microsoft-IIS/7.5\r\nConnection: close\r\n\r\n"
	service, version := parseBanner(banner)
	if service != "http" {
		t.Fatalf("expected http service, got %q", service)
	}
	if version != "IIS 7.5 (Windows Server 2008 R2 or Windows 7)" {
		t.Fatalf("unexpected IIS version: %q", version)
	}
}

func TestParseMySQLHandshake(t *testing.T) {
	// Simplified MySQL handshake payload with protocol 10 and version string.
	banner := string([]byte{
		0x0a, '5', '.', '5', '.', '2', '0', '-', 'l', 'o', 'g', 0x00,
	})
	service, version := parseMySQL(banner)
	if service != "mysql" {
		t.Fatalf("expected mysql service, got %q", service)
	}
	if version != "MySQL 5.5.20-log" {
		t.Fatalf("unexpected MySQL version: %q", version)
	}
}

func TestParseMySQLHandshakePacket(t *testing.T) {
	packet := []byte{
		0x10, 0x00, 0x00, 0x00,
		0x0a, '8', '.', '0', '.', '2', '7', '-', '0', 'u', 'b', 'u', 'n', 't', 'u', 0x00,
	}
	got := parseMySQLHandshakePacket(packet)
	if got != "MySQL 8.0.27-0ubuntu" {
		t.Fatalf("unexpected MySQL packet version: %q", got)
	}
}

func TestParseBannerMicrosoftHTTPAPI(t *testing.T) {
	banner := "HTTP/1.1 401 Unauthorized\r\nServer: Microsoft-HTTPAPI/2.0\r\nWWW-Authenticate: Negotiate\r\n\r\n"
	service, version := parseBanner(banner)
	if service != "http" {
		t.Fatalf("expected http service, got %q", service)
	}
	if version != "Microsoft-HTTPAPI/2.0" {
		t.Fatalf("unexpected HTTPAPI version: %q", version)
	}
}

func TestParseRedis(t *testing.T) {
	banner := "redis_version:6.2.5 v=6.2.5"
	service, version := parseRedis(banner)
	if service != "redis" {
		t.Fatalf("expected redis service, got %q", service)
	}
	if version != "Redis 6.2.5" {
		t.Fatalf("unexpected Redis version: %q", version)
	}
}

func TestParseDNSVersionBindResponse(t *testing.T) {
	response := []byte{
		0x00, 0x38,
		0x13, 0x37, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01,
		0x00, 0x00, 0x00, 0x00,
		0x07, 'v', 'e', 'r', 's', 'i', 'o', 'n',
		0x04, 'b', 'i', 'n', 'd', 0x00,
		0x00, 0x10, 0x00, 0x03,
		0xc0, 0x0c, 0x00, 0x10, 0x00, 0x03,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x0e,
		0x0d, '9', '.', '1', '6', '.', '1', '-', 'U', 'b', 'u', 'n', 't', 'u',
	}
	got := parseDNSVersionBindResponse(response)
	if got != "BIND 9.16.1-Ubuntu" {
		t.Fatalf("unexpected DNS version: %q", got)
	}
}
