package scanner

import (
	"encoding/binary"
	"strings"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

func udpDNSFixture(t testing.TB, port int) []byte {
	t.Helper()
	name, err := dnsmessage.NewName("do-not-log.fixture.invalid.")
	if err != nil {
		t.Fatal(err)
	}
	message := dnsmessage.Message{
		Header:    dnsmessage.Header{ID: 0x1337, Response: true},
		Questions: []dnsmessage.Question{{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}},
		Answers: []dnsmessage.Resource{{
			Header: dnsmessage.ResourceHeader{Name: name, Class: dnsmessage.ClassINET, TTL: 60},
			Body:   &dnsmessage.AResource{A: [4]byte{192, 0, 2, 1}},
		}},
	}
	if port == 5353 {
		message.ID = 0
		message.Authoritative = true
		message.Questions = nil
		message.Answers[0].Header.Class |= 0x8000
	}
	payload, err := message.Pack()
	if err != nil {
		t.Fatal(err)
	}
	return payload
}

func TestUDPDNSFamilyClassification(t *testing.T) {
	s := NewScanner("fixture.invalid", false)
	for _, tc := range []struct {
		port             int
		service, version string
	}{{53, "domain", "DNS response"}, {5353, "mdns", "mDNS response"}, {5355, "llmnr", "LLMNR response"}} {
		t.Run(tc.service, func(t *testing.T) {
			payload := udpDNSFixture(t, tc.port)
			service, version, confidence, evidence := s.classifyUDPResponse(tc.port, payload, true)
			if service != tc.service || version != tc.version || confidence != "medium" || !strings.Contains(evidence, "request not correlated") {
				t.Fatalf("unexpected identification: %q %q %q %q", service, version, confidence, evidence)
			}
			if strings.Contains(version+evidence, "do-not-log") || strings.Contains(version+evidence, "192.0.2.1") {
				t.Fatal("record data leaked into identification metadata")
			}
			_, version, confidence, _ = s.classifyUDPResponse(tc.port, payload, false)
			if version != "" || confidence != "low" {
				t.Fatal("disabled detection elevated confidence")
			}
		})
	}
}

func TestUDPDNSFamilyRejectsMalformedFrames(t *testing.T) {
	for _, port := range []int{53, 5353, 5355} {
		payload := udpDNSFixture(t, port)
		for n := 0; n < len(payload); n++ {
			if got := udpDNSVersion(port, payload[:n]); got != "" {
				t.Fatalf("udp/%d accepted truncation at %d: %q", port, n, got)
			}
		}
		for _, mutate := range []func([]byte) []byte{
			func(p []byte) []byte { p[2] &^= 0x80; return p }, // Query, not response.
			func(p []byte) []byte { p[2] |= 0x08; return p },  // Unsupported opcode.
			func(p []byte) []byte { p[2] |= 0x02; return p },  // Truncated response.
			func(p []byte) []byte { p[6], p[7] = 0xff, 0xff; return p },
			func(p []byte) []byte { p[12], p[13] = 0xc0, 0x0c; return p }, // Compression cycle.
			func(p []byte) []byte { p[12], p[13] = 0xff, 0xff; return p }, // Out-of-range pointer.
			func(p []byte) []byte { p[12] = 0x40; return p },
			func(p []byte) []byte { return append(p, 0) },
			func(p []byte) []byte { return append(p, make([]byte, maxUDPResponseBytes)...) },
			func(p []byte) []byte { binary.BigEndian.PutUint16(p[len(p)-6:len(p)-4], 3); return p },
			func(p []byte) []byte { binary.BigEndian.PutUint16(p[len(p)-6:len(p)-4], 5); return append(p, 0) },
		} {
			if got := udpDNSVersion(port, mutate(append([]byte(nil), payload...))); got != "" {
				t.Fatalf("udp/%d accepted malformed frame: %q", port, got)
			}
		}
	}
}

func TestUDPDNSFamilyProtocolSpecificHeaders(t *testing.T) {
	dns := udpDNSFixture(t, 53)
	refused := append([]byte(nil), dns...)
	refused[3] |= 5
	if udpDNSVersion(53, refused) != "DNS response" || udpDNSVersion(5355, refused) != "" {
		t.Fatal("DNS refusal and LLMNR error semantics conflated")
	}
	mdns := udpDNSFixture(t, 5353)
	if udpDNSVersion(53, mdns) != "" || udpDNSVersion(5355, mdns) != "" {
		t.Fatal("questionless cache-flush response accepted as unicast DNS/LLMNR")
	}
	mdns[2] &^= 0x04
	if udpDNSVersion(5353, mdns) != "" {
		t.Fatal("non-authoritative mDNS accepted by conservative validator")
	}
	llmnr := udpDNSFixture(t, 5355)
	llmnr[2] |= 0x04 // Conflict, not DNS authoritative-answer semantics.
	if udpDNSVersion(5355, llmnr) != "LLMNR response" {
		t.Fatal("LLMNR conflict bit treated as invalid")
	}
	llmnr[2] |= 0x01 // Tentative: retain low confidence.
	if udpDNSVersion(5355, llmnr) != "" {
		t.Fatal("tentative LLMNR response accepted")
	}
	for _, port := range []int{53, 5353, 5355} {
		p := udpDNSFixture(t, port)
		p[3] |= 0x40
		if udpDNSVersion(port, p) != "" {
			t.Fatalf("reserved flags accepted on udp/%d", port)
		}
	}
}

func FuzzUDPDNSFamilyBoundedParsing(f *testing.F) {
	for _, port := range []int{53, 5353, 5355} {
		f.Add(uint16(port), udpDNSFixture(f, port))
	}
	f.Add(uint16(53), []byte{0, 0, 0x80})
	f.Fuzz(func(t *testing.T, port uint16, payload []byte) {
		version := udpDNSVersion(int(port), payload)
		if version == "" {
			return
		}
		if len(payload) < 12 || len(payload) > maxUDPResponseBytes || !udpDNSFrameValid(payload) {
			t.Fatal("out-of-bounds or unframed message accepted")
		}
		if port != 53 && port != 5353 && port != 5355 {
			t.Fatal("unsupported port identified")
		}
		var message dnsmessage.Message
		if message.Unpack(payload) != nil || !message.Response {
			t.Fatal("invalid message accepted")
		}
	})
}

func TestUDPDNSRecordFraming(t *testing.T) {
	name, err := dnsmessage.NewName("fixture.invalid.")
	if err != nil {
		t.Fatal(err)
	}
	for _, body := range []dnsmessage.ResourceBody{
		&dnsmessage.AAAAResource{},
		&dnsmessage.TXTResource{TXT: []string{"do-not-log"}},
		&dnsmessage.PTRResource{PTR: name},
		&dnsmessage.CNAMEResource{CNAME: name},
		&dnsmessage.NSResource{NS: name},
		&dnsmessage.MXResource{MX: name},
		&dnsmessage.SRVResource{Target: name},
		&dnsmessage.SOAResource{NS: name, MBox: name},
	} {
		var message dnsmessage.Message
		if err := message.Unpack(udpDNSFixture(t, 53)); err != nil {
			t.Fatal(err)
		}
		message.Answers[0].Body = body
		payload, err := message.Pack()
		if err != nil {
			t.Fatal(err)
		}
		if udpDNSVersion(53, payload) != "DNS response" {
			t.Fatalf("valid record rejected: %T", body)
		}
		if _, version, _, evidence := NewScanner("fixture.invalid", false).classifyUDPResponse(53, payload, true); strings.Contains(version+evidence, "do-not-log") {
			t.Fatal("TXT content disclosed")
		}
	}
	for _, tc := range []struct {
		kind dnsmessage.Type
		body []byte
		want bool
	}{
		{dnsmessage.TypeA, make([]byte, 4), true},
		{dnsmessage.TypeAAAA, make([]byte, 15), false},
		{dnsmessage.TypePTR, []byte{0}, true},
		{dnsmessage.TypePTR, []byte{0, 0}, false},
		{dnsmessage.TypeMX, []byte{0}, false},
		{dnsmessage.TypeSRV, make([]byte, 6), false},
		{dnsmessage.TypeSOA, make([]byte, 22), true},
		{dnsmessage.TypeSOA, make([]byte, 21), false},
		{dnsmessage.TypeTXT, []byte{1, 'x'}, true},
		{dnsmessage.TypeTXT, []byte{2, 'x'}, false},
		{dnsmessage.TypeOPT, []byte{0, 1, 0, 1, 'x'}, true},
		{dnsmessage.TypeOPT, []byte{0, 1, 0, 2, 'x'}, false},
		{dnsmessage.TypeOPT, []byte{0, 1, 0}, false},
		{dnsmessage.Type(65000), []byte{0}, false},
	} {
		if got := udpDNSBodyFrameValid(tc.body, 0, len(tc.body), tc.kind); got != tc.want {
			t.Fatalf("type %d length %d: got %v want %v", tc.kind, len(tc.body), got, tc.want)
		}
	}
}

func TestUDPDNSQuestionsAndClasses(t *testing.T) {
	for _, port := range []int{53, 5353, 5355} {
		for _, mutate := range []func(*dnsmessage.Message){
			func(m *dnsmessage.Message) { m.Answers[0].Header.Class = 0 },
			func(m *dnsmessage.Message) {
				m.Answers[0].Body = &dnsmessage.UnknownResource{Type: 65000, Data: []byte{0}}
			},
			func(m *dnsmessage.Message) {
				m.Questions = []dnsmessage.Question{{Name: m.Answers[0].Header.Name, Type: 0, Class: dnsmessage.ClassINET}}
			},
			func(m *dnsmessage.Message) {
				m.Questions = []dnsmessage.Question{{Name: m.Answers[0].Header.Name, Type: dnsmessage.TypeA, Class: 0}}
			},
		} {
			var message dnsmessage.Message
			if err := message.Unpack(udpDNSFixture(t, port)); err != nil {
				t.Fatal(err)
			}
			mutate(&message)
			payload, err := message.Pack()
			if err != nil {
				t.Fatal(err)
			}
			if got := udpDNSVersion(port, payload); got != "" {
				t.Fatalf("unsupported class/type accepted on udp/%d", port)
			}
		}
	}
	var message dnsmessage.Message
	if err := message.Unpack(udpDNSFixture(t, 53)); err != nil {
		t.Fatal(err)
	}
	message.Questions[0].Class = dnsmessage.ClassCHAOS
	message.Answers[0].Header.Class = dnsmessage.ClassCHAOS
	message.Answers[0].Body = &dnsmessage.TXTResource{TXT: []string{"not-a-confirmed-product"}}
	payload, err := message.Pack()
	if err != nil {
		t.Fatal(err)
	}
	if got := udpDNSVersion(53, payload); got != "DNS response" {
		t.Fatalf("CHAOS TXT response rejected: %q", got)
	}
}

func BenchmarkUDPDNSFamilyValidation(b *testing.B) {
	for _, port := range []int{53, 5353, 5355} {
		payload := udpDNSFixture(b, port)
		b.Run(udpDNSVersion(port, payload), func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				udpDNSVersion(port, payload)
			}
		})
	}
}
