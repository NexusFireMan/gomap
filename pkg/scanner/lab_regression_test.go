package scanner

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestSearchHTTPFixtures(t *testing.T) {
	body := `{"tagline":"You Know, for Search","version":{"number":"1.1.1","lucene_version":"4.7"}}`
	for _, tt := range []struct {
		name, contentType, body, want string
	}{
		{"root", "application/json; charset=UTF-8", body, "Elasticsearch 1.1.1"},
		{"unrelated JSON", "application/json", `{"version":{"number":"1.1.1"}}`, ""},
		{"no lucene", "application/json", `{"tagline":"You Know, for Search","version":{"number":"1.1.1"}}`, ""},
		{"wrong media", "text/html", body, ""},
		{"truncated", "application/json", body[:len(body)-1], ""},
		{"oversized", "application/json", body + strings.Repeat(" ", 65536), ""},
	} {
		t.Run(tt.name, func(t *testing.T) {
			banner := "HTTP/1.1 200 OK\r\nContent-Type: " + tt.contentType + "\r\n\r\n" + tt.body
			service, version := parseSearchHTTP(banner)
			if version != tt.want || (tt.want != "" && service != "elasticsearch") {
				t.Fatalf("got %q %q, want %q", service, version, tt.want)
			}
			if tt.want != "" {
				if s, v := parseBanner(banner); s != service || v != version {
					t.Fatalf("generic HTTP parsing masked product: %q %q", s, v)
				}
			}
		})
	}
	chunked := fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n%x\r\n%s\r\n0\r\n\r\n", len(body), body)
	if _, version := parseSearchHTTP(chunked); version != "Elasticsearch 1.1.1" {
		t.Fatalf("chunked HTTP product: %q", version)
	}
}

func TestHTTPResponseEvidence(t *testing.T) {
	banner := "HTTP/1.1 302 Found\r\nsErVeR: fixture/1.0\r\nLocation: https://example.invalid:4848/\r\n\r\nServer: forged"
	want := "HTTP/1.1 302 Found; Server: fixture/1.0; Location: https://example.invalid:4848/"
	if got := evidenceFromBanner(banner); got != want {
		t.Fatalf("evidence = %q", got)
	}
	if got := evidenceFromBanner("220 fixture FTP\r\n"); got != "220 fixture FTP" {
		t.Fatalf("text evidence changed: %q", got)
	}
}

func mysqlErrorFixture(message string) []byte {
	payload := append([]byte{0xff, 0x6a, 0x04}, []byte(message)...)
	return append([]byte{byte(len(payload)), 0, 0, 0}, payload...)
}

func TestMySQLInitialErrorFixtures(t *testing.T) {
	if version, evidence := parseMySQLInitialPacket(mysqlFixture()); version == "" || !strings.Contains(evidence, version) {
		t.Fatal("valid greeting lost its version")
	}
	blocked := mysqlErrorFixture("Host is blocked because of many connection errors")
	blocked[5] = 0x69
	if _, evidence := parseMySQLInitialPacket(blocked); !strings.Contains(evidence, "ERR 1129") {
		t.Fatalf("blocked-host evidence lost: %q", evidence)
	}
	for _, message := range []string{"Host 'client' is not allowed", "#HY000Host 'client' is not allowed"} {
		version, evidence := parseMySQLInitialPacket(mysqlErrorFixture(message))
		if version != "MySQL (connection rejected)" || evidence != "MySQL ERR 1130: Host 'client' is not allowed" {
			t.Fatalf("got %q %q", version, evidence)
		}
	}
	for _, packet := range [][]byte{nil, mysqlErrorFixture(""), mysqlErrorFixture("#HY00"), mysqlErrorFixture("rejected")[:8]} {
		if version, evidence := parseMySQLInitialPacket(packet); version != "" || evidence != "" {
			t.Fatalf("accepted malformed packet: %x", packet)
		}
	}
	packet := mysqlErrorFixture("rejected")
	packet[3] = 1
	if version, _ := parseMySQLInitialPacket(packet); version != "" {
		t.Fatal("accepted noninitial packet")
	}
}

func TestMySQLRejectionDetectionFromPipe(t *testing.T) {
	client, server := net.Pipe()
	t.Cleanup(func() { _ = client.Close() })
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer func() { _ = server.Close() }()
		_ = server.SetWriteDeadline(time.Now().Add(time.Second))
		for _, b := range mysqlErrorFixture("Host 'client' is not allowed") {
			if _, err := server.Write([]byte{b}); err != nil {
				return
			}
		}
	}()
	s := NewScanner("fixture.invalid", false)
	result := ScanResult{Port: 3306, IsOpen: true}
	s.grabBanner(client, 3306, &result)
	<-done
	if result.ServiceName != "mysql" || result.Confidence != "high" || !strings.Contains(result.Evidence, "ERR 1130") || result.Version != "MySQL (connection rejected)" {
		t.Fatalf("unexpected rejection result: %+v", result)
	}
}

func TestHTTPTransportReusesTLSMetadata(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		w.Header().Set("Server", "fixture/1.0")
		_, _ = io.WriteString(w, "fixture")
	}))
	defer server.Close()
	host, port, err := net.SplitHostPort(server.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	p, err := strconv.Atoi(port)
	if err != nil {
		t.Fatal(err)
	}
	s := NewScanner(host, false)
	banner, fp := s.grabHTTPBannerTransport(p, true)
	if fp == nil || fp.Version == "" || fp.Cipher == "" || !strings.Contains(banner, "fixture/1.0") || requests.Load() != 1 {
		t.Fatalf("banner=%q fingerprint=%+v requests=%d", banner, fp, requests.Load())
	}
	if !shouldUseTLSForHTTP(8181) || !shouldAttemptTLSFingerprint(8181, "intermapper") || inferTLServiceByPort(8181, "http") != "https" {
		t.Fatal("8181 HTTPS candidate missing")
	}
}

func TestHTTPTransportPlaintextFallback(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Server", "plain-fixture/1.0")
	}))
	defer server.Close()
	address := server.Listener.Addr().(*net.TCPAddr)
	s := NewScanner(address.IP.String(), false)
	banner, fp := s.grabHTTPBannerTransport(address.Port, true)
	if fp != nil || !strings.Contains(banner, "plain-fixture/1.0") {
		t.Fatalf("plaintext falsely marked TLS or lost: %q %+v", banner, fp)
	}
}
