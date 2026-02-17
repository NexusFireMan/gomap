package scanner

import "testing"

func TestParseHTTPCUPSAsIPP(t *testing.T) {
	banner := "HTTP/1.1 200 OK\r\nServer: CUPS/1.7 IPP/2.1\r\nConnection: close\r\n\r\n"
	service, version := parseHTTP(banner)
	if service != "ipp" {
		t.Fatalf("expected service ipp, got %q", service)
	}
	if version != "CUPS/1.7 IPP/2.1" {
		t.Fatalf("unexpected version %q", version)
	}
}
