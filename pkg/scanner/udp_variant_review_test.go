package scanner

import (
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

func TestUDPUnsupportedVariantPolicy(t *testing.T) {
	s := NewScanner("fixture.invalid", false)
	assertHint := func(port int, payload []byte) {
		t.Helper()
		_, version, confidence, _ := s.classifyUDPResponseForProbe(port, payload, udpProbePayload(port), true)
		if version != "" || confidence != "low" {
			t.Fatalf("unsupported udp/%d variant promoted: %q %q", port, version, confidence)
		}
	}
	for _, model := range []int64{0, 1, 2, 4, 2147483647} {
		assertHint(161, snmpV3Fixture(t, func(data *snmpV3FixtureData) { data.model = model }))
	}
	for _, flags := range []byte{1, 2, 3, 4, 7, 128, 255} {
		assertHint(161, snmpV3Fixture(t, func(data *snmpV3FixtureData) { data.flags = []byte{flags} }))
	}
	assertHint(161, snmpV3Fixture(t, func(data *snmpV3FixtureData) { data.encrypted = true }))
	for _, opcode := range []byte{1, 5, 6, 7, 8, 15} {
		payload := netbiosFixture(t, netbiosNameRecord, make([]byte, 6))
		payload[2] = (payload[2] & 0x87) | (opcode << 3)
		assertHint(137, payload)
	}
	for code := byte(1); code <= 15; code++ {
		payload := netbiosFixture(t, netbiosNameRecord, make([]byte, 6))
		payload[3] = (payload[3] & 0xf0) | code
		assertHint(137, payload)
	}
	// A complete DNS-framed redirect is still not a supported NB/NBSTAT reply.
	name, err := dnsmessage.NewName("EGFCEFEECACACACACACACACACACACACA.fixture.invalid.")
	if err != nil {
		t.Fatal(err)
	}
	message := dnsmessage.Message{Header: dnsmessage.Header{Response: true}, Authorities: []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: name, Class: dnsmessage.ClassINET}, Body: &dnsmessage.NSResource{NS: name}}}}
	payload, err := message.Pack()
	if err != nil {
		t.Fatal(err)
	}
	assertHint(137, payload)
	// UDP/138 datagrams are outside the name-service decoder; no inferred identity.
	assertHint(138, []byte{0x13, 0, 0, 1, 192, 0, 2, 1, 0, 138, 0x82})
}
