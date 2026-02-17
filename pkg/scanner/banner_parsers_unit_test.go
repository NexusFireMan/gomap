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
