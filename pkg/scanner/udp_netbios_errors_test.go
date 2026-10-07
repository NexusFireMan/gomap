package scanner

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

func netbiosErrorFixture(t testing.TB, code byte, legacy bool) []byte {
	t.Helper()
	payload := netbiosFixture(t, netbiosNullRecord, nil)
	payload[2] |= 1 // Negative name-query replies echo recursion desired.
	payload[3] = (payload[3] & 0xf0) | code
	if legacy {
		binary.BigEndian.PutUint16(payload[6:8], 0)
	}
	return payload
}

func TestNetBIOSErrorMetadataAndLegacyFraming(t *testing.T) {
	for _, tc := range []struct {
		code   byte
		reason string
	}{
		{1, "format error"}, {2, "server failure"}, {3, "name not found"}, {5, "refused"},
	} {
		for _, legacy := range []bool{false, true} {
			payload := netbiosErrorFixture(t, tc.code, legacy)
			before := append([]byte(nil), payload...)
			service, version, confidence, evidence := NewScanner("fixture.invalid", false).classifyUDPResponseForProbe(137, payload, udpProbePayload(137), true)
			if service != "netbios-ns" || version != "NetBIOS name service error: "+tc.reason || confidence != "medium" || !strings.Contains(evidence, "request not correlated") {
				t.Fatalf("wrong error metadata: %q %q %q %q", service, version, confidence, evidence)
			}
			if !bytes.Equal(payload, before) {
				t.Fatal("input mutated")
			}
			if strings.Contains(version+evidence, "fixture.invalid") || strings.Contains(version+evidence, "EGFCE") {
				t.Fatal("name disclosed")
			}
			_, version, confidence, _ = NewScanner("fixture.invalid", false).classifyUDPResponseForProbe(137, payload, udpProbePayload(137), false)
			if version != "" || confidence != "low" {
				t.Fatal("disabled detection parses error")
			}
			for n := 0; n < len(payload); n++ {
				if udpNetBIOSVersion(payload[:n]) != "" {
					t.Fatalf("truncation accepted at %d", n)
				}
			}
		}
	}
}

func TestNetBIOSErrorsRejectMalformedOrUnrelatedReplies(t *testing.T) {
	for _, legacy := range []bool{false, true} {
		base := netbiosErrorFixture(t, 3, legacy)
		for _, mutate := range []func([]byte) []byte{
			func(p []byte) []byte { p[2] &^= 0x80; return p },
			func(p []byte) []byte { p[2] &^= 4; return p },
			func(p []byte) []byte { p[2] &^= 1; return p },
			func(p []byte) []byte { p[2] |= 2; return p },
			func(p []byte) []byte { p[2] |= 8; return p },
			func(p []byte) []byte { p[3] |= 0x40; return p },
			func(p []byte) []byte { p[3] |= 0x10; return p },
			func(p []byte) []byte { p[5] = 1; return p },
			func(p []byte) []byte { p[7] = 2; return p },
			func(p []byte) []byte { p[9] = 1; return p },
			func(p []byte) []byte { p[11] = 1; return p },
			func(p []byte) []byte { p[13] = 'Q'; return p },
			func(p []byte) []byte { p[12], p[13] = 0xc0, 0x0c; return p },
			func(p []byte) []byte { p[len(p)-5] = 1; return p }, // TTL must be zero.
			func(p []byte) []byte { p[len(p)-7] = 2; return p }, // Not IN class.
			func(p []byte) []byte { p[len(p)-9] = byte(netbiosNameRecord); return p },
			func(p []byte) []byte { p[len(p)-1] = 1; return append(p, 0) },
			func(p []byte) []byte { return append(p, 0) },
			func(p []byte) []byte { return append(p, make([]byte, maxUDPResponseBytes)...) },
		} {
			if udpNetBIOSVersion(mutate(append([]byte(nil), base...))) != "" {
				t.Fatal("malformed error accepted")
			}
		}
		for _, code := range []byte{0, 4, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15} {
			if udpNetBIOSVersion(netbiosErrorFixture(t, code, legacy)) != "" {
				t.Fatalf("unsupported code %d accepted", code)
			}
		}
	}
	// Ordinary DNS errors and header-only errors do not establish NBNS structure.
	query := udpProbePayload(53)
	var message dnsmessage.Message
	if err := message.Unpack(query); err != nil {
		t.Fatal(err)
	}
	message.Response = true
	message.Authoritative = true
	message.RCode = dnsmessage.RCodeNameError
	payload, err := message.Pack()
	if err != nil {
		t.Fatal(err)
	}
	if udpNetBIOSVersion(payload) != "" {
		t.Fatal("DNS error misidentified as NBNS")
	}
	if udpNetBIOSVersion(netbiosErrorFixture(t, 3, true)[:12]) != "" {
		t.Fatal("header-only error accepted")
	}
}

func FuzzNetBIOSErrorFraming(f *testing.F) {
	f.Add(netbiosErrorFixture(f, 3, true))
	f.Add(netbiosErrorFixture(f, 5, false))
	f.Add([]byte{0x00, 0x01, 0x85, 0x03})
	f.Fuzz(func(t *testing.T, payload []byte) {
		before := append([]byte(nil), payload...)
		version := udpNetBIOSVersion(payload)
		if !bytes.Equal(payload, before) {
			t.Fatal("input mutated")
		}
		if len(payload) > maxUDPResponseBytes && version != "" {
			t.Fatal("oversized reply accepted")
		}
		if strings.HasPrefix(version, "NetBIOS name service error:") {
			switch version {
			case "NetBIOS name service error: format error", "NetBIOS name service error: server failure", "NetBIOS name service error: name not found", "NetBIOS name service error: refused":
			default:
				t.Fatal("invented error or product version")
			}
		}
	})
}
