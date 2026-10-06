package scanner

import (
	"encoding/asn1"
	"strings"
	"testing"
)

func snmpFixtureMarshal(t testing.TB, value any) []byte {
	t.Helper()
	encoded, err := asn1.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func snmpFixtureResponse(t testing.TB, version, pduTag, status, index int, bindings []asn1.RawValue) []byte {
	t.Helper()
	content := snmpFixtureMarshal(t, int32(123))
	content = append(content, snmpFixtureMarshal(t, status)...)
	content = append(content, snmpFixtureMarshal(t, index)...)
	content = append(content, snmpFixtureMarshal(t, bindings)...)
	pdu := asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: pduTag, IsCompound: true, Bytes: content}
	message := snmpFixtureMarshal(t, version)
	message = append(message, snmpFixtureMarshal(t, []byte("fixture-community-do-not-log"))...)
	message = append(message, snmpFixtureMarshal(t, pdu)...)
	return snmpFixtureMarshal(t, asn1.RawValue{Tag: asn1.TagSequence, IsCompound: true, Bytes: message})
}

func snmpFixtureBinding(t testing.TB, value asn1.RawValue) asn1.RawValue {
	t.Helper()
	content := snmpFixtureMarshal(t, asn1.ObjectIdentifier{1, 3, 6, 1, 2, 1, 1, 1, 0})
	content = append(content, snmpFixtureMarshal(t, value)...)
	return asn1.RawValue{Tag: asn1.TagSequence, IsCompound: true, Bytes: content}
}

func TestSNMPv1ValidatesShapeWithoutDisclosingValues(t *testing.T) {
	binding := snmpFixtureBinding(t, asn1.RawValue{Tag: asn1.TagOctetString, Bytes: []byte("fixture-device-do-not-log")})
	payload := snmpFixtureResponse(t, 0, 2, 0, 0, []asn1.RawValue{binding})
	if got := udpSNMPv1Version(payload); got != "SNMPv1 response" {
		t.Fatalf("valid response rejected: %q", got)
	}
	s := NewScanner("fixture.invalid", false)
	service, version, confidence, evidence := s.classifyUDPResponse(161, payload, true)
	if service != "snmp" || version != "SNMPv1 response" || confidence != "medium" || !strings.Contains(evidence, "request not correlated") {
		t.Fatalf("wrong metadata: %q %q %q %q", service, version, confidence, evidence)
	}
	if strings.Contains(version+evidence, "do-not-log") {
		t.Fatal("community or device value exposed")
	}
	_, version, confidence, _ = s.classifyUDPResponse(161, payload, false)
	if version != "" || confidence != "low" {
		t.Fatal("disabled detection still parsed SNMP")
	}
	for n := 0; n < len(payload); n++ {
		if got := udpSNMPv1Version(payload[:n]); got != "" {
			t.Fatalf("truncated response at %d accepted", n)
		}
	}
	if got := udpSNMPv1Version(append(append([]byte(nil), payload...), 0)); got != "" {
		t.Fatal("trailing bytes accepted")
	}
}

func TestSNMPv1RejectsUnsupportedOrInconsistentMessages(t *testing.T) {
	binding := snmpFixtureBinding(t, asn1.RawValue{Tag: asn1.TagNull})
	for _, tc := range []struct {
		name                        string
		version, tag, status, index int
		bindings                    []asn1.RawValue
	}{
		{"v2c unsupported", 1, 2, 0, 0, []asn1.RawValue{binding}},
		{"v3 unsupported", 3, 2, 0, 0, []asn1.RawValue{binding}},
		{"request is not response", 0, 0, 0, 0, []asn1.RawValue{binding}},
		{"trap is not response", 0, 4, 0, 0, []asn1.RawValue{binding}},
		{"invalid status", 0, 2, 6, 0, []asn1.RawValue{binding}},
		{"negative status", 0, 2, -1, 0, []asn1.RawValue{binding}},
		{"error index on success", 0, 2, 0, 1, []asn1.RawValue{binding}},
		{"negative index", 0, 2, 0, -1, []asn1.RawValue{binding}},
		{"index outside bindings", 0, 2, 2, 2, []asn1.RawValue{binding}},
		{"missing error index", 0, 2, 2, 0, []asn1.RawValue{binding}},
		{"empty successful response", 0, 2, 0, 0, nil},
		{"binding not sequence", 0, 2, 0, 0, []asn1.RawValue{{Tag: asn1.TagNull}}},
		{"missing binding fields", 0, 2, 0, 0, []asn1.RawValue{{Tag: asn1.TagSequence, IsCompound: true}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := udpSNMPv1Version(snmpFixtureResponse(t, tc.version, tc.tag, tc.status, tc.index, tc.bindings)); got != "" {
				t.Fatalf("unsupported response accepted: %q", got)
			}
		})
	}
	for _, tc := range []struct{ status, index int }{{1, 0}, {2, 1}, {5, 1}} {
		if got := udpSNMPv1Version(snmpFixtureResponse(t, 0, 2, tc.status, tc.index, []asn1.RawValue{binding})); got == "" {
			t.Fatalf("valid error response rejected: %+v", tc)
		}
	}
}

func TestSNMPv1ValueShape(t *testing.T) {
	for _, tc := range []struct {
		name  string
		value asn1.RawValue
		valid bool
	}{
		{"null", asn1.RawValue{Tag: asn1.TagNull}, true},
		{"null with content", asn1.RawValue{Tag: asn1.TagNull, Bytes: []byte{0}}, false},
		{"string", asn1.RawValue{Tag: asn1.TagOctetString, Bytes: []byte("fixture")}, true},
		{"integer", asn1.RawValue{Tag: asn1.TagInteger, Bytes: []byte{1}}, true},
		{"empty integer", asn1.RawValue{Tag: asn1.TagInteger}, false},
		{"ipv4", asn1.RawValue{Class: asn1.ClassApplication, Tag: 0, Bytes: []byte{192, 0, 2, 1}}, true},
		{"short ip", asn1.RawValue{Class: asn1.ClassApplication, Tag: 0, Bytes: []byte{1}}, false},
		{"counter", asn1.RawValue{Class: asn1.ClassApplication, Tag: 1, Bytes: []byte{1}}, true},
		{"max counter", asn1.RawValue{Class: asn1.ClassApplication, Tag: 1, Bytes: []byte{0, 255, 255, 255, 255}}, true},
		{"counter overflow", asn1.RawValue{Class: asn1.ClassApplication, Tag: 1, Bytes: []byte{1, 0, 0, 0, 0}}, false},
		{"negative counter", asn1.RawValue{Class: asn1.ClassApplication, Tag: 1, Bytes: []byte{255}}, false},
		{"unsupported counter64", asn1.RawValue{Class: asn1.ClassApplication, Tag: 6, Bytes: []byte{1}}, false},
		{"context exception", asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0}, false},
		{"constructed value", asn1.RawValue{Tag: asn1.TagOctetString, IsCompound: true, Bytes: []byte("fixture")}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			binding := snmpFixtureBinding(t, tc.value)
			got := udpSNMPv1Version(snmpFixtureResponse(t, 0, 2, 0, 0, []asn1.RawValue{binding})) != ""
			if got != tc.valid {
				t.Fatalf("value accepted=%t want=%t", got, tc.valid)
			}
		})
	}
}

func FuzzSNMPv1ResponseBounded(f *testing.F) {
	binding := snmpFixtureBinding(f, asn1.RawValue{Tag: asn1.TagNull})
	f.Add(snmpFixtureResponse(f, 0, 2, 0, 0, []asn1.RawValue{binding}))
	f.Add([]byte{0x30, 0x80, 0, 0})
	f.Add([]byte("unrelated"))
	f.Fuzz(func(t *testing.T, payload []byte) {
		version := udpSNMPv1Version(payload)
		if version != "" && version != "SNMPv1 response" {
			t.Fatal("invented product version")
		}
		if len(payload) > maxUDPResponseBytes && version != "" {
			t.Fatal("oversized response accepted")
		}
	})
}

func TestSNMPv1RejectsExtraSequenceFieldsAndUnsupportedEncoding(t *testing.T) {
	binding := snmpFixtureBinding(t, asn1.RawValue{Tag: asn1.TagNull})
	payload := snmpFixtureResponse(t, 0, 2, 0, 0, []asn1.RawValue{binding})
	var message asn1.RawValue
	if _, err := asn1.Unmarshal(payload, &message); err != nil {
		t.Fatal(err)
	}
	message.FullBytes = nil
	message.Bytes = append(message.Bytes, snmpFixtureMarshal(t, 1)...)
	for _, data := range [][]byte{
		snmpFixtureMarshal(t, message),
		{0x30, 0x80, 0, 0},
		append(append([]byte(nil), payload...), make([]byte, maxUDPResponseBytes)...),
	} {
		if version := udpSNMPv1Version(data); version != "" {
			t.Fatalf("extra fields or unsupported encoding accepted: %q", version)
		}
	}
}

func BenchmarkSNMPv1Response(b *testing.B) {
	binding := snmpFixtureBinding(b, asn1.RawValue{Tag: asn1.TagOctetString, Bytes: []byte("fixture")})
	payload := snmpFixtureResponse(b, 0, 2, 0, 0, []asn1.RawValue{binding})
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		if udpSNMPv1Version(payload) == "" {
			b.Fatal("fixture rejected")
		}
	}
}
