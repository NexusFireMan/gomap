package scanner

import "testing"

func TestParseSMTP(t *testing.T) {
	tests := []struct {
		name    string
		banner  string
		service string
		version string
	}{
		{
			name:    "Postfix",
			banner:  "220 mail.local ESMTP Postfix",
			service: "smtp",
			version: "Postfix SMTP",
		},
		{
			name:    "Exim",
			banner:  "220 mx.local ESMTP Exim 4.96",
			service: "smtp",
			version: "Exim 4.96",
		},
		{
			name:    "No SMTP",
			banner:  "HTTP/1.1 200 OK",
			service: "",
			version: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			service, version := parseSMTP(tt.banner)
			if service != tt.service || version != tt.version {
				t.Fatalf("expected (%q,%q), got (%q,%q)", tt.service, tt.version, service, version)
			}
		})
	}
}

func TestParseBannerPrefersSMTPBeforeGenericFTP220(t *testing.T) {
	service, version := parseBanner("220 mail.example.local ESMTP Postfix")
	if service != "smtp" {
		t.Fatalf("expected smtp, got %q (%q)", service, version)
	}
	if version != "Postfix SMTP" {
		t.Fatalf("expected Postfix SMTP, got %q", version)
	}
}

func TestParseFTPKnownVersions(t *testing.T) {
	tests := []struct {
		banner  string
		version string
	}{
		{"220 (vsFTPd 3.0.3)", "vsFTPd 3.0.3"},
		{"220 ProFTPD 1.3.5e Server ready", "ProFTPD 1.3.5e"},
		{"220 Pure-FTPd 1.0.49 ready", "Pure-FTPd 1.0.49"},
		{"220\r\n215 UNIX Type: L8\r\n", "SYST UNIX Type: L8"},
		{"220", "FTP service"},
	}

	for _, tt := range tests {
		service, version := parseBanner(tt.banner)
		if service != "ftp" || version != tt.version {
			t.Fatalf("for %q expected ftp/%q, got %q/%q", tt.banner, tt.version, service, version)
		}
	}
}

func TestParsePOP3AndIMAP(t *testing.T) {
	pop3Service, pop3Version := parsePOP3("+OK Dovecot ready.")
	if pop3Service != "pop3" || pop3Version != "Dovecot" {
		t.Fatalf("unexpected POP3 parse result: (%q,%q)", pop3Service, pop3Version)
	}

	imapService, imapVersion := parseIMAP("* OK [CAPABILITY IMAP4rev1] Dovecot ready.")
	if imapService != "imap" || imapVersion != "Dovecot IMAP" {
		t.Fatalf("unexpected IMAP parse result: (%q,%q)", imapService, imapVersion)
	}
}

func TestParseSSHWithExtraInfo(t *testing.T) {
	service, version := parseSSH("SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.13")
	if service != "ssh" {
		t.Fatalf("expected ssh service, got %q", service)
	}
	if version != "SSH-2.0 - OpenSSH 6.6.1p1 Ubuntu-2ubuntu2.13" {
		t.Fatalf("unexpected SSH version: %q", version)
	}
}
