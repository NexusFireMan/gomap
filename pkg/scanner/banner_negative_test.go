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
