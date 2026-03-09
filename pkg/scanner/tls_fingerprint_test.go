package scanner

import (
	"crypto/tls"
	"testing"
)

func TestTLSVersionString(t *testing.T) {
	if got := tlsVersionString(tls.VersionTLS12); got != "TLS1.2" {
		t.Fatalf("expected TLS1.2, got %q", got)
	}
	if got := tlsVersionString(0x9999); got == "" {
		t.Fatal("expected non-empty fallback tls version")
	}
}

func TestInferTLServiceByPort(t *testing.T) {
	tests := []struct {
		port int
		in   string
		out  string
	}{
		{443, "", "https"},
		{5986, "", "winrm"},
		{993, "", "imaps"},
		{8443, "http", "https"},
		{8443, "http-proxy", "http-proxy"},
	}
	for _, tt := range tests {
		if got := inferTLServiceByPort(tt.port, tt.in); got != tt.out {
			t.Fatalf("port %d in=%q: expected %q, got %q", tt.port, tt.in, tt.out, got)
		}
	}
}

func TestShouldAttemptTLSFingerprint(t *testing.T) {
	if !shouldAttemptTLSFingerprint(443, "https") {
		t.Fatal("expected tls fingerprint on 443")
	}
	if !shouldAttemptTLSFingerprint(5986, "winrm") {
		t.Fatal("expected tls fingerprint on 5986")
	}
	if shouldAttemptTLSFingerprint(445, "microsoft-ds") {
		t.Fatal("did not expect tls fingerprint on 445")
	}
}
