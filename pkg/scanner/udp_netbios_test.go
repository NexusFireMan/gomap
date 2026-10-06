package scanner

import (
	"strings"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

func netbiosFixture(t testing.TB, kind dnsmessage.Type, data []byte) []byte {
	t.Helper()
	name, err := dnsmessage.NewName("EGFCEFEECACACACACACACACACACACACA.fixture.invalid.")
	if err != nil {
		t.Fatal(err)
	}
	message := dnsmessage.Message{
		Header: dnsmessage.Header{ID: 123, Response: true, Authoritative: true},
		Answers: []dnsmessage.Resource{{
			Header: dnsmessage.ResourceHeader{Name: name, Class: dnsmessage.ClassINET},
			Body:   &dnsmessage.UnknownResource{Type: kind, Data: data},
		}},
	}
	payload, err := message.Pack()
	if err != nil {
		t.Fatal(err)
	}
	return payload
}

func netbiosStatusFixture() []byte {
	data := make([]byte, 1+18+46)
	data[0] = 1
	copy(data[1:17], "do-not-log-host  ")
	data[17] = 0x04
	copy(data[19:], "no-MAC-disclosure")
	return data
}

func TestUDPNetBIOSValidatesWithoutDisclosingNames(t *testing.T) {
	for _, tc := range []struct {
		kind    dnsmessage.Type
		data    []byte
		version string
	}{
		{netbiosNameRecord, []byte{0, 0, 192, 0, 2, 1}, "NetBIOS name service response"},
		{netbiosNameRecord, make([]byte, 12), "NetBIOS name service response"},
		{netbiosStatusRecord, netbiosStatusFixture(), "NetBIOS node status response"},
		{netbiosStatusRecord, make([]byte, 47), "NetBIOS node status response"},
	} {
		payload := netbiosFixture(t, tc.kind, tc.data)
		service, version, confidence, evidence := NewScanner("fixture.invalid", false).classifyUDPResponse(137, payload, true)
		if service != "netbios-ns" || version != tc.version || confidence != "medium" || !strings.Contains(evidence, "request not correlated") {
			t.Fatalf("unexpected metadata: %q %q %q %q", service, version, confidence, evidence)
		}
		if strings.Contains(version+evidence, "do-not-log") || strings.Contains(version+evidence, "disclosure") {
			t.Fatal("record data disclosed")
		}
		for n := 0; n < len(payload); n++ {
			if udpNetBIOSVersion(payload[:n]) != "" {
				t.Fatalf("truncation accepted at %d", n)
			}
		}
		_, version, confidence, _ = NewScanner("fixture.invalid", false).classifyUDPResponse(137, payload, false)
		if version != "" || confidence != "low" {
			t.Fatal("disabled detection still parses")
		}
	}
}

func TestUDPNetBIOSCompressedQuestionAndAnswer(t *testing.T) {
	var message dnsmessage.Message
	if err := message.Unpack(netbiosFixture(t, netbiosNameRecord, make([]byte, 6))); err != nil {
		t.Fatal(err)
	}
	message.Questions = []dnsmessage.Question{{Name: message.Answers[0].Header.Name, Type: netbiosNameRecord, Class: dnsmessage.ClassINET}}
	for _, mutate := range []struct {
		change func(*dnsmessage.Message)
		valid  bool
	}{
		{func(*dnsmessage.Message) {}, true},
		{func(m *dnsmessage.Message) { m.Questions[0].Class = 0 }, false},
		{func(m *dnsmessage.Message) { m.Questions[0].Type = netbiosStatusRecord }, false},
		{func(m *dnsmessage.Message) { m.Questions = append(m.Questions, m.Questions[0]) }, false},
		{func(m *dnsmessage.Message) { m.Answers[0].Header.Class = 0 }, false},
	} {
		copyMessage := message
		copyMessage.Questions = append([]dnsmessage.Question(nil), message.Questions...)
		copyMessage.Answers = append([]dnsmessage.Resource(nil), message.Answers...)
		mutate.change(&copyMessage)
		payload, err := copyMessage.Pack()
		if err != nil {
			t.Fatal(err)
		}
		if got := udpNetBIOSVersion(payload) != ""; got != mutate.valid {
			t.Fatalf("classification got=%v want=%v", got, mutate.valid)
		}
	}
}

func TestUDPNetBIOSRejectsMalformedRecords(t *testing.T) {
	for _, tc := range []struct {
		kind dnsmessage.Type
		data []byte
	}{
		{netbiosNameRecord, nil}, {netbiosNameRecord, make([]byte, 5)},
		{netbiosNameRecord, []byte{0, 1, 192, 0, 2, 1}},
		{netbiosStatusRecord, []byte{255}}, {netbiosStatusRecord, make([]byte, 48)},
		{dnsmessage.TypeA, make([]byte, 4)},
	} {
		if udpNetBIOSVersion(netbiosFixture(t, tc.kind, tc.data)) != "" {
			t.Fatal("malformed record accepted")
		}
	}
	status := netbiosStatusFixture()
	status[18] = 1
	if udpNetBIOSVersion(netbiosFixture(t, netbiosStatusRecord, status)) != "" {
		t.Fatal("reserved status flags accepted")
	}
	status = netbiosStatusFixture()
	status[17] = 0
	if udpNetBIOSVersion(netbiosFixture(t, netbiosStatusRecord, status)) != "" {
		t.Fatal("inactive node-name entry accepted")
	}
	payload := netbiosFixture(t, netbiosNameRecord, make([]byte, 6))
	for _, mutate := range []func([]byte) []byte{
		func(p []byte) []byte { p[2] &^= 0x80; return p },
		func(p []byte) []byte { p[2] |= 0x08; return p },
		func(p []byte) []byte { p[2] |= 0x02; return p },
		func(p []byte) []byte { p[3] |= 1; return p },
		func(p []byte) []byte { p[3] |= 0x40; return p },
		func(p []byte) []byte { p[13] = 'Q'; return p },
		func(p []byte) []byte { p[12], p[13] = 0xc0, 0x0c; return p },
		func(p []byte) []byte { return append(p, 0) },
		func(p []byte) []byte { return append(p, make([]byte, maxUDPResponseBytes)...) },
	} {
		if udpNetBIOSVersion(mutate(append([]byte(nil), payload...))) != "" {
			t.Fatal("malformed frame accepted")
		}
	}
}

func FuzzUDPNetBIOSBounded(f *testing.F) {
	f.Add(netbiosFixture(f, netbiosNameRecord, make([]byte, 6)))
	f.Add(netbiosFixture(f, netbiosStatusRecord, netbiosStatusFixture()))
	f.Add([]byte("unrelated"))
	f.Fuzz(func(t *testing.T, payload []byte) {
		version := udpNetBIOSVersion(payload)
		if version != "" && version != "NetBIOS name service response" && version != "NetBIOS node status response" {
			t.Fatal("invented server version")
		}
		if len(payload) > maxUDPResponseBytes && version != "" {
			t.Fatal("oversized payload accepted")
		}
	})
}
