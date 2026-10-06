package scanner

import (
	"strings"
	"testing"
)

const ssdpFixture = "HTTP/1.1 200 OK\r\nST: upnp:rootdevice\r\nUSN: uuid:fixture::upnp:rootdevice\r\nLOCATION: http://fixture.invalid/device.xml\r\nSERVER: FixtureOS/1.0 UPnP/1.0 FixtureDevice/2.0\r\n\r\n"

func TestUDPUnvalidatedPayloadsDoNotClaimProtocolVersions(t *testing.T) {
	s := NewScanner("fixture.invalid", false)
	for _, port := range []int{53, 123, 137, 161, 1900, 5353, 5355, 11211, 65001} {
		for _, payload := range [][]byte{nil, {0}, []byte("unrelated text version 9.9"), []byte("Server: forged/9.9\r\n")} {
			service, version, confidence, evidence := s.classifyUDPResponse(port, payload, true)
			if service == "" || version != "" || confidence != "low" || !strings.Contains(evidence, "udp response") {
				t.Fatalf("udp/%d unsupported claim: service=%q version=%q confidence=%q evidence=%q", port, service, version, confidence, evidence)
			}
		}
	}
}

func TestUDPDoesNotInheritTCPPortServiceNames(t *testing.T) {
	s := NewScanner("fixture.invalid", false)
	for _, port := range []int{22, 80, 443} {
		service, version, confidence, _ := s.classifyUDPResponse(port, []byte("fixture"), true)
		if service != "unknown" || version != "" || confidence != "low" {
			t.Fatalf("udp/%d inherited a TCP identification: %q %q %q", port, service, version, confidence)
		}
	}
	if service, _, confidence, _ := s.classifyUDPResponse(111, []byte{0}, true); service != "rpcbind" || confidence != "low" {
		t.Fatalf("lost explicit UDP port hint: %q %q", service, confidence)
	}
}

func TestUDPNTPRequiresBoundedServerHeader(t *testing.T) {
	for version := byte(1); version <= 4; version++ {
		payload := make([]byte, 48)
		payload[0] = version<<3 | 4
		if got := udpNTPVersion(payload); got == "" {
			t.Fatalf("server header v%d rejected", version)
		}
		for n := 0; n < 48; n++ {
			if got := udpNTPVersion(payload[:n]); got != "" {
				t.Fatalf("truncated header length %d accepted: %q", n, got)
			}
		}
	}
	for version := byte(0); version <= 7; version++ {
		for mode := byte(0); mode <= 7; mode++ {
			payload := make([]byte, 48)
			payload[0] = version<<3 | mode
			want := version >= 1 && version <= 4 && mode == 4
			if got := udpNTPVersion(payload); (got != "") != want {
				t.Fatalf("v%d mode%d classification: %q", version, mode, got)
			}
		}
	}
	payload := make([]byte, 2049)
	payload[0] = 0x24
	if got := udpNTPVersion(payload); got != "" {
		t.Fatalf("oversized payload accepted: %q", got)
	}
}

func TestUDPSSDPRequiresResponseShapeAndIgnoresBodyHeaders(t *testing.T) {
	if got := udpSSDPVersion([]byte(ssdpFixture)); got != "FixtureOS/1.0 UPnP/1.0 FixtureDevice/2.0" {
		t.Fatalf("valid header rejected: %q", got)
	}
	noServer := strings.ReplaceAll(ssdpFixture, "SERVER: FixtureOS/1.0 UPnP/1.0 FixtureDevice/2.0\r\n", "")
	if got := udpSSDPVersion([]byte(noServer + "Server: forged/9.9\r\n")); got != "SSDP response" {
		t.Fatalf("body accepted as product disclosure: %q", got)
	}
	for _, payload := range []string{
		"Server: forged/9.9\r\n",
		strings.ReplaceAll(ssdpFixture, "HTTP/1.1 200 OK", "HTTP/1.1 404 Not Found"),
		strings.ReplaceAll(ssdpFixture, "HTTP/1.1 200 OK", "HTTP/1.0 200 OK"),
		strings.ReplaceAll(ssdpFixture, "ST: upnp:rootdevice\r\n", ""),
		strings.ReplaceAll(ssdpFixture, "USN: uuid:fixture::upnp:rootdevice\r\n", ""),
		strings.ReplaceAll(ssdpFixture, "uuid:fixture::upnp:rootdevice", "invalid"),
		strings.ReplaceAll(ssdpFixture, "http://fixture.invalid/device.xml", "file:///etc/passwd"),
		strings.ReplaceAll(ssdpFixture, "http://fixture.invalid/device.xml", "/device.xml"),
		strings.ReplaceAll(ssdpFixture, "ST: upnp:rootdevice\r\n", "ST: upnp:rootdevice\r\nST: other\r\n"),
		strings.ReplaceAll(ssdpFixture, "SERVER:", "SERVER: conflicting\r\nSERVER:"),
		strings.TrimSuffix(ssdpFixture, "\r\n\r\n"),
		ssdpFixture + strings.Repeat("x", 2048),
	} {
		if got := udpSSDPVersion([]byte(payload)); got != "" {
			t.Fatalf("invalid SSDP shape accepted: %q -> %q", payload, got)
		}
	}
}

func TestUDPShapeEvidenceRemainsHeuristic(t *testing.T) {
	s := NewScanner("fixture.invalid", false)
	ntp := make([]byte, 48)
	ntp[0] = 0x24
	for _, tc := range []struct {
		port            int
		payload         []byte
		service, marker string
	}{
		{123, ntp, "ntp", "timestamps not correlated"},
		{1900, []byte(ssdpFixture), "ssdp", "ssdp-shaped"},
	} {
		service, version, confidence, evidence := s.classifyUDPResponse(tc.port, tc.payload, true)
		if service != tc.service || version == "" || confidence != "medium" || !strings.Contains(evidence, tc.marker) {
			t.Fatalf("incorrect shape evidence: %q %q %q %q", service, version, confidence, evidence)
		}
		_, version, confidence, _ = s.classifyUDPResponse(tc.port, tc.payload, false)
		if version != "" || confidence != "low" {
			t.Fatal("disabled detection still claims a version")
		}
	}
}

func FuzzUDPClassificationDoesNotInventUnvalidatedVersions(f *testing.F) {
	f.Add(uint16(53), []byte("fixture"))
	f.Add(uint16(123), []byte{0x24})
	f.Add(uint16(1900), []byte(ssdpFixture))
	f.Add(uint16(65001), []byte{0, 'a', 0xff, 'b'})
	f.Fuzz(func(t *testing.T, port uint16, payload []byte) {
		s := NewScanner("fixture.invalid", false)
		service, version, confidence, _ := s.classifyUDPResponse(int(port), payload, true)
		if service == "" || confidence == "high" {
			t.Fatal("empty service or excessive confidence")
		}
		if port != 53 && port != 5353 && port != 5355 && port != 123 && port != 161 && port != 1900 && (version != "" || confidence != "low") {
			t.Fatal("unvalidated payload interpreted as a protocol version")
		}
		if port == 161 && version != "" && udpSNMPv1Version(payload) == "" {
			t.Fatal("unvalidated SNMP payload interpreted as a version")
		}
		if (port == 53 || port == 5353 || port == 5355) && version != "" && udpDNSVersion(int(port), payload) == "" {
			t.Fatal("unvalidated DNS-format payload interpreted as a version")
		}
	})
}
