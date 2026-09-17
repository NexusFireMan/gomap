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
			name:    "Generic product",
			banner:  "220 InFreight ESMTP v2.11\r\n250-mail1",
			service: "smtp",
			version: "InFreight ESMTP v2.11",
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

func TestParseJMSGlassFishAndIRCProducts(t *testing.T) {
	if service, version := parseJMS("OpenMQ Java Message Service 301"); service != "jms" || version != "Java Message Service 301" {
		t.Fatalf("unexpected JMS parse: %q/%q", service, version)
	}
	if service, version := parseGlassFish("Oracle Glassfish Application Server"); service != "http" || version != "GlassFish Server" {
		t.Fatalf("unexpected GlassFish parse: %q/%q", service, version)
	}
	if service, version := parseIRC(":irc.example NOTICE AUTH :*** UnrealIRCd 6.1.0"); service != "irc" || version != "UnrealIRCd 6.1.0" {
		t.Fatalf("unexpected IRC parse: %q/%q", service, version)
	}
	if service, version := parseIRC(":server 004 gomap Unreal3.2.10.4"); service != "irc" || version != "UnrealIRCd 3.2.10.4" {
		t.Fatalf("unexpected numeric IRC parse: %q/%q", service, version)
	}
}

func TestParseAdditionalTextServices(t *testing.T) {
	tests := []struct {
		name, banner, service, version string
	}{
		{"RTSP", "RTSP/1.0 200 OK\r\nServer: GStreamer/1.0", "rtsp", "GStreamer/1.0"},
		{"SIP", "SIP/2.0 200 OK\r\nServer: Asterisk PBX", "sip", "Asterisk PBX"},
		{"VNC", "RFB 003.008\r\n", "vnc", "RFB 003.008"},
		{"Memcached", "VERSION 1.6.21\r\n", "memcached", "VERSION 1.6.21"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			service, version := parseBanner(tt.banner)
			if service != tt.service || version != tt.version {
				t.Fatalf("expected %s/%s, got %s/%s", tt.service, tt.version, service, version)
			}
		})
	}
}

func TestParseFTPKnownVersions(t *testing.T) {
	tests := []struct {
		banner  string
		version string
	}{
		{"220 (vsFTPd 3.0.3)", "vsFTPd 3.0.3"},
		{"220 ProFTPD 1.3.5e Server ready", "ProFTPD 1.3.5e"},
		{"220 ProFTPD Server ready", "ProFTPD"},
		{"220 ProFTPD Server (Ceil's FTP) [10.0.11.6]", "ProFTPD (Ceil's FTP)"},
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
	genericPOP3Service, genericPOP3Version := parsePOP3("+OK InFreight POP3 v9.188")
	if genericPOP3Service != "pop3" || genericPOP3Version != "InFreight POP3 v9.188" {
		t.Fatalf("unexpected generic POP3 parse result: (%q,%q)", genericPOP3Service, genericPOP3Version)
	}

	imapService, imapVersion := parseIMAP("* OK [CAPABILITY IMAP4rev1] Dovecot ready.")
	if imapService != "imap" || imapVersion != "Dovecot IMAP" {
		t.Fatalf("unexpected IMAP parse result: (%q,%q)", imapService, imapVersion)
	}
	genericIMAPService, genericIMAPVersion := parseIMAP("* OK [CAPABILITY IMAP4rev1 SASL-IR] HTB{redacted}")
	if genericIMAPService != "imap" || genericIMAPVersion != "IMAP4rev1" {
		t.Fatalf("unexpected generic IMAP parse result: (%q,%q)", genericIMAPService, genericIMAPVersion)
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
