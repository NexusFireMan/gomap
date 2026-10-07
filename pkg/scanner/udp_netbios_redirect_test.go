package scanner

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

func netbiosRedirectFixture(t testing.TB, mutate func(*dnsmessage.Message)) []byte {
	t.Helper()
	domain := dnsmessage.MustNewName("fixture.invalid.")
	target := dnsmessage.MustNewName("EGFCEFEECACACACACACACACACACACACA.fixture.invalid.")
	message := dnsmessage.Message{
		Header: dnsmessage.Header{ID: 123, Response: true, RecursionDesired: true},
		Authorities: []dnsmessage.Resource{{
			Header: dnsmessage.ResourceHeader{Name: domain, Class: dnsmessage.ClassINET, TTL: 60},
			Body:   &dnsmessage.NSResource{NS: target},
		}},
		Additionals: []dnsmessage.Resource{{
			Header: dnsmessage.ResourceHeader{Name: target, Class: dnsmessage.ClassINET, TTL: 60},
			Body:   &dnsmessage.AResource{A: [4]byte{192, 0, 2, 55}},
		}},
	}
	if mutate != nil {
		mutate(&message)
	}
	payload, err := message.Pack()
	if err != nil {
		t.Fatal(err)
	}
	return payload
}

func TestUDPNetBIOSRedirectMetadata(t *testing.T) {
	payload := netbiosRedirectFixture(t, nil)
	original := bytes.Clone(payload)
	s := NewScanner("fixture.invalid", false)
	service, version, confidence, evidence := s.classifyUDPResponseForProbe(137, payload, udpProbePayload(137), true)
	if service != "netbios-ns" || version != netbiosRedirectLabel || confidence != "medium" ||
		!strings.Contains(evidence, "redirect not followed") || !strings.Contains(evidence, "request not correlated") {
		t.Fatalf("unexpected metadata: %q %q %q %q", service, version, confidence, evidence)
	}
	for _, sensitive := range []string{"fixture.invalid", "EGFCE", "192.0.2.55"} {
		if strings.Contains(version+evidence, sensitive) {
			t.Fatalf("redirect target disclosed: %q", sensitive)
		}
	}
	if !bytes.Equal(payload, original) {
		t.Fatal("input mutated")
	}
	_, version, confidence, _ = s.classifyUDPResponseForProbe(137, payload, udpProbePayload(137), false)
	if version != "" || confidence != "low" {
		t.Fatal("disabled detection promoted redirect")
	}
	for n := 0; n < len(payload); n++ {
		if udpNetBIOSVersion(payload[:n]) != "" {
			t.Fatalf("truncated redirect accepted at %d", n)
		}
	}
}

func TestUDPNetBIOSRedirectRejectsUnsupportedShapes(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*dnsmessage.Message)
	}{
		{"authoritative", func(m *dnsmessage.Message) { m.Authoritative = true }},
		{"truncated", func(m *dnsmessage.Message) { m.Truncated = true }},
		{"no recursion", func(m *dnsmessage.Message) { m.RecursionDesired = false }},
		{"recursion available", func(m *dnsmessage.Message) { m.RecursionAvailable = true }},
		{"opcode", func(m *dnsmessage.Message) { m.OpCode = 5 }},
		{"error", func(m *dnsmessage.Message) { m.RCode = 3 }},
		{"question", func(m *dnsmessage.Message) {
			m.Questions = []dnsmessage.Question{{Name: m.Authorities[0].Header.Name, Type: netbiosNameRecord, Class: dnsmessage.ClassINET}}
		}},
		{"answer", func(m *dnsmessage.Message) { m.Answers = m.Additionals }},
		{"missing address", func(m *dnsmessage.Message) { m.Additionals = nil }},
		{"extra address", func(m *dnsmessage.Message) { m.Additionals = append(m.Additionals, m.Additionals[0]) }},
		{"wrong authority class", func(m *dnsmessage.Message) { m.Authorities[0].Header.Class = dnsmessage.ClassCHAOS }},
		{"wrong address class", func(m *dnsmessage.Message) { m.Additionals[0].Header.Class = dnsmessage.ClassCHAOS }},
		{"wrong authority type", func(m *dnsmessage.Message) { m.Authorities[0].Body = &dnsmessage.AResource{} }},
		{"wrong address type", func(m *dnsmessage.Message) { m.Additionals[0].Body = &dnsmessage.AAAAResource{} }},
		{"mismatched target", func(m *dnsmessage.Message) { m.Additionals[0].Header.Name = m.Authorities[0].Header.Name }},
		{"ordinary DNS referral", func(m *dnsmessage.Message) {
			m.Authorities[0].Body = &dnsmessage.NSResource{NS: m.Authorities[0].Header.Name}
			m.Additionals[0].Header.Name = m.Authorities[0].Header.Name
		}},
		{"root authority", func(m *dnsmessage.Message) { m.Authorities[0].Header.Name = dnsmessage.MustNewName(".") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if udpNetBIOSVersion(netbiosRedirectFixture(t, tc.mutate)) != "" {
				t.Fatal("unsupported redirect accepted")
			}
		})
	}
	payload := netbiosRedirectFixture(t, nil)
	for _, flags := range []uint16{0x0100, 0x8110, 0x8120, 0x8140} {
		frame := bytes.Clone(payload)
		binary.BigEndian.PutUint16(frame[2:4], flags)
		if udpNetBIOSVersion(frame) != "" {
			t.Fatalf("invalid flags accepted: %x", flags)
		}
	}
	for _, frame := range [][]byte{append(bytes.Clone(payload), 0), make([]byte, maxUDPResponseBytes+1)} {
		if udpNetBIOSVersion(frame) != "" {
			t.Fatal("invalid framing accepted")
		}
	}
	// The final A record must have exactly four bytes, regardless of packet size.
	frame := bytes.Clone(payload)
	binary.BigEndian.PutUint16(frame[len(frame)-6:len(frame)-4], 3)
	if udpNetBIOSVersion(frame) != "" {
		t.Fatal("inconsistent address length accepted")
	}
}

func FuzzUDPNetBIOSRedirectFraming(f *testing.F) {
	f.Add(netbiosRedirectFixture(f, nil))
	f.Add([]byte{0x81, 0})
	f.Fuzz(func(t *testing.T, payload []byte) {
		original := bytes.Clone(payload)
		version := udpNetBIOSVersion(payload)
		if version == netbiosRedirectLabel && (len(payload) < 12 || len(payload) > maxUDPResponseBytes || binary.BigEndian.Uint16(payload[2:4]) != 0x8100) {
			t.Fatal("unbounded or invalid redirect accepted")
		}
		if !bytes.Equal(payload, original) {
			t.Fatal("input mutated")
		}
	})
}

func TestUDPNetBIOSRedirectCompressedNames(t *testing.T) {
	payload := netbiosRedirectFixture(t, nil)
	headerEnd, ok := udpDNSNameEnd(payload, 12, len(payload))
	if !ok {
		t.Fatal("invalid fixture authority")
	}
	bodyStart := headerEnd + 10
	bodyEnd := bodyStart + int(binary.BigEndian.Uint16(payload[headerEnd+8:headerEnd+10]))
	ownerEnd, ok := udpDNSNameEnd(payload, bodyEnd, len(payload))
	if !ok || bodyStart >= 256 {
		t.Fatal("invalid fixture address owner")
	}
	compressed := append(bytes.Clone(payload[:bodyEnd]), 0xc0, byte(bodyStart))
	compressed = append(compressed, payload[ownerEnd:]...)
	if udpNetBIOSVersion(compressed) != netbiosRedirectLabel {
		t.Fatal("matching compressed owner rejected")
	}
	for _, pointer := range []int{bodyStart, 0x3fff} {
		frame := bytes.Clone(payload[:bodyStart])
		binary.BigEndian.PutUint16(frame[headerEnd+8:headerEnd+10], 2)
		frame = append(frame, 0xc0|byte(pointer>>8), byte(pointer))
		frame = append(frame, payload[bodyEnd:]...)
		if udpNetBIOSVersion(frame) != "" {
			t.Fatalf("cyclic/out-of-range NS pointer accepted: %d", pointer)
		}
	}
}
