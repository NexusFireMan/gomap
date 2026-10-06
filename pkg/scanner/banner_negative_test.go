package scanner

import "testing"

func TestAdditionalServicesRejectUnrelatedAndMalformedText(t *testing.T) {
	for _, banner := range []string{
		"documentation mentions SIP/2.0", "SIP/2.0 invalid", "SIP/2.0 999 invalid",
		"RTSP/garbage", "RTSP/1.0 not-a-status", "RFB invalid", "RFB 3.8", "RFB 003.008 extra",
		"VERSION unknown", "VERSION 1.6.21 unrelated", "HTTP/1.1 200 OK\r\n\r\nSIP/2.0 200 OK",
	} {
		if service, version := parseAdditionalTextServices(banner); service != "" || version != "" {
			t.Fatalf("false positive for %q: %s/%s", banner, service, version)
		}
	}
}

func TestTextServiceHeaderStopsBeforeBody(t *testing.T) {
	for _, protocol := range []string{"RTSP/1.0", "SIP/2.0"} {
		banner := protocol + " 200 OK\r\nContent-Length: 20\r\n\r\nServer: forged-product"
		if got := responseServerVersion(banner, "generic"); got != "generic" {
			t.Fatalf("accepted body as Server header: %q", got)
		}
	}
}

func TestBannerConfidenceForGenericDescriptions(t *testing.T) {
	for _, version := range []string{"", "IRC service", "RTSP service", "SIP service", "IMAP4rev1", "Redis", "PostgreSQL"} {
		if got := bannerConfidence(version); got != "medium" {
			t.Fatalf("%q: got %s", version, got)
		}
	}
	for _, version := range []string{"OpenSSH 9.6p1", "Apache 2.4.7", "VERSION 1.6.21"} {
		if got := bannerConfidence(version); got != "high" {
			t.Fatalf("%q: got %s", version, got)
		}
	}
}

func TestVersionsMustBelongToIdentifiedProduct(t *testing.T) {
	for _, tt := range []struct {
		name, banner, version string
		parse                 func(string) (string, string)
	}{
		{"SMB year", "SMB maintenance 2019", "SMB", parseSMB},
		{"Windows year", "Microsoft Windows SMB build log 2019", "Windows SMB", parseSMB},
		{"Samba unrelated number", "Samba uptime 4.2 hours", "Samba", parseSMB},
		{"Redis unrelated version", "Redis error v=9.9", "Redis", parseRedis},
		{"Redis disclosed version", "redis_version:6.2.5 v=9.9", "Redis 6.2.5", parseRedis},
		{"JMS fields", "101 (imqbroker) 301", "Java Message Service 301", parseJMS},
	} {
		t.Run(tt.name, func(t *testing.T) {
			_, version := tt.parse(tt.banner)
			if version != tt.version {
				t.Fatalf("got %q, want %q", version, tt.version)
			}
		})
	}
	if got := parseNodeVersion("Node.js/20.1.0 backend/99.0"); got != "Node.js/Express 20.1.0" {
		t.Fatalf("Node version: %q", got)
	}
	if got := parseNodeVersion("Express backend/99.0"); got != "" {
		t.Fatalf("borrowed backend version: %q", got)
	}
}

func TestIRCRejectsProductMentionsOutsideProtocol(t *testing.T) {
	for _, banner := range []string{"unreal game 3.2", "documentation for ircd", "notice auth in documentation"} {
		if service, _ := parseIRC(banner); service != "" {
			t.Fatalf("classified unrelated text as IRC: %q", banner)
		}
	}
}
