package scanner

import (
	"fmt"
	"strings"
	"testing"
)

func TestObservedBannerWithholdsTruncatedVersions(t *testing.T) {
	for _, tc := range []struct{ name, banner, service string }{
		{"SSH", "SSH-2.0-OpenSSH_9.6p", "ssh"},
		{"SMTP", "220 fixture ESMTP Exim 4.96", "smtp"},
		{"FTP multiline", "220-ProFTPD 1.3.5\r\n unfinished", "ftp"},
		{"POP3", "+OK Dovecot 2.3", "pop3"},
		{"IMAP", "* OK IMAP4rev1 Dovecot ready", "imap"},
		{"HTTP header", "HTTP/1.1 200 OK\r\nServer: nginx/1.24", "http"},
		{"RTSP header", "RTSP/1.0 200 OK\r\nServer: GStreamer/1.0", "rtsp"},
		{"SIP header", "SIP/2.0 200 OK\r\nServer: Asterisk/20", "sip"},
		{"RESP missing terminator", strings.TrimSuffix(redisTransactionFixture(), "\r\n"), ""},
		{"binary in text", "SSH-2.0-OpenSSH_9.\x006\r\n", ""},
		{"DEL in text", "SSH-2.0-OpenSSH_9.\x7f6\r\n", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			service, version := parseObservedBanner(tc.banner)
			if service != tc.service || version != "" || bannerIdentificationConfidence(tc.banner, version) != "low" {
				t.Fatalf("service=%q version=%q", service, version)
			}
			result := grabBannerFromFixture(t, 65000, tc.banner)
			if !result.IsOpen || result.Confidence != "low" || result.Version != "" || !strings.Contains(result.Evidence, "product/version withheld") {
				t.Fatalf("partial disclosure promoted: %+v", result)
			}
		})
	}
}

func TestObservedBannerRetainsCompleteEarlierDisclosures(t *testing.T) {
	for _, tc := range []struct{ banner, service, version, confidence string }{
		{"SSH-2.0-OpenSSH_9.6p1\r\nunfinished second line", "ssh", "SSH-2.0 - OpenSSH 9.6p1", "high"},
		{"220 fixture ESMTP Exim 4.96\r\n250-partial", "smtp", "Exim 4.96", "high"},
		{"HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\nContent-Length: 500\r\n\r\npartial", "http", "Nginx 1.24.0", "high"},
		{":irc NOTICE AUTH :Checking hostname\r\n:irc 004 gomap UnrealIRCd-6.1", "irc", "IRC service", "medium"},
		{":irc NOTICE AUTH :Checking hostname\r\n:irc 004 gomap irc UnrealIRCd-6.1.0 oi oi\r\n", "irc", "UnrealIRCd 6.1.0", "high"},
		{":irc NOTICE AUTH :Checking hostname\r\nforged UnrealIRCd-9.9.9\r\n", "irc", "IRC service", "medium"},
		{redisTransactionFixture(), "redis", "Redis 7.2.4", "high"},
		{"-NOAUTH Authentication required.\r\n", "redis", "Redis (authentication required)", "medium"},
	} {
		service, version := parseObservedBanner(tc.banner)
		if service != tc.service || version != tc.version || bannerIdentificationConfidence(tc.banner, version) != tc.confidence {
			t.Fatalf("%q: service=%q version=%q confidence=%q", tc.banner, service, version, bannerIdentificationConfidence(tc.banner, version))
		}
		result := grabBannerFromFixture(t, 65000, tc.banner)
		if result.ServiceName != tc.service || result.Version != tc.version || result.Confidence != tc.confidence {
			t.Fatalf("metadata differs from supported disclosure: %+v", result)
		}
	}
}

func TestRedisBulkParsingAndPassiveCollection(t *testing.T) {
	for _, body := range []string{
		"# Server\r\nredis_version:7.2.4\r\n" + strings.Repeat("fixture_data:xxxx\r\n", 400),
		"redis_version:7.2.4\r\n",
	} {
		frame := fmt.Sprintf("$%d\r\n%s\r\n", len(body), body)
		result := grabBannerFromFixture(t, 6379, frame)
		if result.ServiceName != "redis" || result.Version != "Redis 7.2.4" || result.Confidence != "high" {
			t.Fatalf("bulk body was reduced to its length line: %+v", result)
		}
	}
	for _, body := range []string{"redis_version:7.2.4\r\nredis_version:8.0.0\r\n", "redis_version:7.2.4 trailing\r\n", "SSH-2.0-OpenSSH_9.6p1\r\n", "documentation for Redis 7.2.4"} {
		frame := fmt.Sprintf("$%d\r\n%s\r\n", len(body), body)
		if _, version := parseObservedBanner(frame); version != "" {
			t.Fatalf("arbitrary bulk text promoted: %q", version)
		}
	}
	if service, version := parseObservedBanner("redis_version:7.2.4\r\n"); service != "" || version != "" {
		t.Fatal("unframed Redis text promoted to a version")
	}
	if service, version := parseObservedBanner("*1\r\n$26\r\nSSH-2.0-OpenSSH_9.6p1xxxxxx\r\n"); service != "" || version != "" {
		t.Fatal("array payload treated as a greeting")
	}
}

func TestIRCAndRESPEvidenceMatchesDisclosure(t *testing.T) {
	for _, tc := range []struct{ banner, version, evidence string }{
		{":irc NOTICE AUTH :Checking\r\n:irc 004 gomap irc UnrealIRCd-6.1.0 oi oi\r\n", "UnrealIRCd 6.1.0", ":irc 004 gomap irc UnrealIRCd-6.1.0 oi oi"},
		{":irc NOTICE AUTH :UnrealIRCd 6.1.0\r\n:irc 004 gomap irc UnrealIRCd-6.2.0 oi oi\r\n", "UnrealIRCd 6.1.0", ":irc NOTICE AUTH :UnrealIRCd 6.1.0"},
		{":irc notice auth :UnrealIRCd 6.1.0\r\n", "UnrealIRCd 6.1.0", ":irc notice auth :UnrealIRCd 6.1.0"},
		{redisTransactionFixture(), "Redis 7.2.4", "RESP bulk reply; redis_version:7.2.4"},
	} {
		_, version := parseObservedBanner(tc.banner)
		if version != tc.version || evidenceFromBanner(tc.banner) != tc.evidence {
			t.Fatalf("mixed observation: version=%q evidence=%q", version, evidenceFromBanner(tc.banner))
		}
	}
}

func FuzzObservedBannerConfidence(f *testing.F) {
	f.Add("SSH-2.0-OpenSSH_9.6p")
	f.Add(redisTransactionFixture())
	f.Add(":irc NOTICE AUTH :Checking hostname\r\n:irc 004 gomap UnrealIRCd-6")
	f.Fuzz(func(t *testing.T, banner string) {
		if len(banner) > respTransactionLimit {
			return
		}
		_, incomplete := observedBannerText(banner)
		_, version := parseObservedBanner(banner)
		if incomplete && (version != "" || bannerIdentificationConfidence(banner, version) != "low") {
			t.Fatal("incomplete observation disclosed a version or elevated confidence")
		}
	})
}
