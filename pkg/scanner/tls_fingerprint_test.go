package scanner

import (
	"crypto/tls"
	"strings"
	"testing"
)

func TestTLSOnlyIdentificationDoesNotConfirmApplication(t *testing.T) {
	for _, service := range []string{"https", "imaps", "winrm", "intermapper", "custom-tls"} {
		confidence, evidence := tlsOnlyIdentification(service)
		if confidence != "low" || !strings.Contains(evidence, "inferred from port only") {
			t.Errorf("TLS alone confirmed %s: %s %s", service, confidence, evidence)
		}
	}
	for _, service := range []string{"tls", "ssl"} {
		confidence, evidence := tlsOnlyIdentification(service)
		if confidence != "high" || !strings.Contains(evidence, "no application banner") {
			t.Errorf("transport evidence missing: %s %s", confidence, evidence)
		}
	}
}

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
		{4848, "http", "https"},
		{3920, "", "ssl"},
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
	if !shouldAttemptTLSFingerprint(3920, "ssl") || !shouldAttemptTLSFingerprint(4848, "http") {
		t.Fatal("expected tls fingerprints on non-standard TLS ports")
	}
	if shouldAttemptTLSFingerprint(445, "microsoft-ds") {
		t.Fatal("did not expect tls fingerprint on 445")
	}
}
