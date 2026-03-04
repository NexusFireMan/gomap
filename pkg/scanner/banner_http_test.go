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

func TestParseHTTPTomcatFromTitle(t *testing.T) {
	banner := "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html><head><title>Apache Tomcat/9.0.17</title></head><body></body></html>"
	service, version := parseHTTP(banner)
	if service != "http" {
		t.Fatalf("expected service http, got %q", service)
	}
	if version != "Apache Tomcat 9.0.17" {
		t.Fatalf("unexpected version %q", version)
	}
}
