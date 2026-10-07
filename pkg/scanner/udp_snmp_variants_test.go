package scanner

import (
	"encoding/asn1"
	"strings"
	"testing"
)

func snmpV3Fixture(t testing.TB, mutate func(*snmpV3FixtureData)) []byte {
	t.Helper()
	fixture := snmpV3FixtureData{
		id: 123, maxSize: 1500, flags: []byte{0}, model: 3,
		engine: []byte("fixture-engine-do-not-log"), user: []byte("user-do-not-log"),
		contextEngine: []byte("context-engine-do-not-log"), contextName: []byte("context-do-not-log"),
		pduTag: 2,
	}
	if mutate != nil {
		mutate(&fixture)
	}
	sequence := func(fields ...any) []byte {
		var data []byte
		for _, field := range fields {
			data = append(data, snmpFixtureMarshal(t, field)...)
		}
		return snmpFixtureMarshal(t, asn1.RawValue{Tag: asn1.TagSequence, IsCompound: true, Bytes: data})
	}
	decode := func(data []byte) asn1.RawValue {
		var value asn1.RawValue
		if _, err := asn1.Unmarshal(data, &value); err != nil {
			t.Fatal(err)
		}
		return value
	}
	binding := snmpFixtureBinding(t, asn1.RawValue{Class: asn1.ClassApplication, Tag: 1, Bytes: []byte{1}})
	pduContent := snmpFixtureMarshal(t, int32(123))
	pduContent = append(pduContent, snmpFixtureMarshal(t, fixture.status)...)
	pduContent = append(pduContent, snmpFixtureMarshal(t, fixture.index)...)
	pduContent = append(pduContent, snmpFixtureMarshal(t, []asn1.RawValue{binding})...)
	pdu := asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: fixture.pduTag, IsCompound: true, Bytes: pduContent}
	header := decode(sequence(fixture.id, fixture.maxSize, fixture.flags, fixture.model))
	security := sequence(fixture.engine, fixture.boots, fixture.engineTime, fixture.user, fixture.authentication, fixture.privacy)
	scoped := decode(sequence(fixture.contextEngine, fixture.contextName, pdu))
	if fixture.encrypted {
		scoped = asn1.RawValue{Tag: asn1.TagOctetString, Bytes: []byte("not-decrypted")}
	}
	return sequence(3, header, security, scoped)
}

type snmpV3FixtureData struct {
	id, maxSize, model, boots, engineTime                                    int64
	pduTag, status, index                                                    int
	flags, engine, user, authentication, privacy, contextEngine, contextName []byte
	encrypted                                                                bool
}

func TestSNMPVariantsMetadataAndBounds(t *testing.T) {
	binding := snmpFixtureBinding(t, asn1.RawValue{Tag: asn1.TagOctetString, Bytes: []byte("device-do-not-log")})
	for _, tc := range []struct {
		payload []byte
		version string
	}{
		{snmpFixtureResponse(t, 0, 2, 0, 0, []asn1.RawValue{binding}), "SNMPv1 response"},
		{snmpFixtureResponse(t, 1, 2, 0, 0, []asn1.RawValue{binding}), "SNMPv2c response"},
		{snmpV3Fixture(t, nil), "SNMPv3 response (unauthenticated)"},
		{snmpV3Fixture(t, func(f *snmpV3FixtureData) { f.pduTag = 8 }), "SNMPv3 report (unauthenticated)"},
	} {
		t.Run(tc.version, func(t *testing.T) {
			service, version, confidence, evidence := NewScanner("fixture.invalid", false).classifyUDPResponse(161, tc.payload, true)
			if service != "snmp" || version != tc.version || confidence != "medium" || !strings.Contains(evidence, "request not correlated or authenticated") {
				t.Fatalf("unexpected metadata: %q %q %q %q", service, version, confidence, evidence)
			}
			if strings.Contains(version+evidence, "do-not-log") {
				t.Fatal("sensitive values exposed")
			}
			_, version, confidence, _ = NewScanner("fixture.invalid", false).classifyUDPResponse(161, tc.payload, false)
			if version != "" || confidence != "low" {
				t.Fatal("disabled detection still parses")
			}
			for n := 0; n < len(tc.payload); n++ {
				if udpSNMPVersion(tc.payload[:n]) != "" {
					t.Fatalf("truncation accepted at %d", n)
				}
			}
			if udpSNMPVersion(append(append([]byte(nil), tc.payload...), 0)) != "" {
				t.Fatal("trailing bytes accepted")
			}
			if udpSNMPVersion(append(append([]byte(nil), tc.payload...), make([]byte, maxUDPResponseBytes)...)) != "" {
				t.Fatal("oversized message accepted")
			}
		})
	}
}

func TestSNMPv2cValuesAndErrors(t *testing.T) {
	for _, tc := range []struct {
		value asn1.RawValue
		valid bool
	}{
		{asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0}, true},
		{asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 1}, true},
		{asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 2}, true},
		{asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 3}, false},
		{asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, Bytes: []byte{0}}, false},
		{asn1.RawValue{Class: asn1.ClassApplication, Tag: 6, Bytes: []byte{0, 255, 255, 255, 255, 255, 255, 255, 255}}, true},
		{asn1.RawValue{Class: asn1.ClassApplication, Tag: 6, Bytes: []byte{1, 0, 0, 0, 0, 0, 0, 0, 0}}, false},
		{asn1.RawValue{Class: asn1.ClassApplication, Tag: 6, Bytes: []byte{255}}, false},
		{asn1.RawValue{Class: asn1.ClassApplication, Tag: 6}, false},
	} {
		binding := snmpFixtureBinding(t, tc.value)
		if got := udpSNMPVersion(snmpFixtureResponse(t, 1, 2, 0, 0, []asn1.RawValue{binding})) != ""; got != tc.valid {
			t.Fatalf("value %+v accepted=%v want=%v", tc.value, got, tc.valid)
		}
	}
	binding := snmpFixtureBinding(t, asn1.RawValue{Tag: asn1.TagNull})
	for status := 0; status <= 19; status++ {
		index := 0
		if status >= 2 {
			index = 1
		}
		got := udpSNMPVersion(snmpFixtureResponse(t, 1, 2, status, index, []asn1.RawValue{binding})) != ""
		if got != (status <= 18) {
			t.Fatalf("unexpected v2c error status %d", status)
		}
	}
	for _, version := range []int{-1, 2, 4} {
		if udpSNMPVersion(snmpFixtureResponse(t, version, 2, 0, 0, []asn1.RawValue{binding})) != "" {
			t.Fatal("unsupported version accepted")
		}
	}
	for _, tag := range []int{0, 1, 3, 4, 5, 6, 7, 8} {
		if udpSNMPVersion(snmpFixtureResponse(t, 1, tag, 0, 0, []asn1.RawValue{binding})) != "" {
			t.Fatal("non-response v2c PDU accepted")
		}
	}
}

func TestSNMPv3RejectsUnsupportedSecurityAndMalformedFields(t *testing.T) {
	for _, mutate := range []func(*snmpV3FixtureData){
		func(f *snmpV3FixtureData) { f.id = -1 },
		func(f *snmpV3FixtureData) { f.id = 1 << 31 },
		func(f *snmpV3FixtureData) { f.maxSize = 483 },
		func(f *snmpV3FixtureData) { f.maxSize = 1 << 31 },
		func(f *snmpV3FixtureData) { f.model = 2 },
		func(f *snmpV3FixtureData) { f.flags = nil },
		func(f *snmpV3FixtureData) { f.flags = []byte{0, 0} },
		func(f *snmpV3FixtureData) { f.flags = []byte{1} },
		func(f *snmpV3FixtureData) { f.flags = []byte{2} },
		func(f *snmpV3FixtureData) { f.flags = []byte{3} },
		func(f *snmpV3FixtureData) { f.flags = []byte{4} },
		func(f *snmpV3FixtureData) { f.flags = []byte{128} },
		func(f *snmpV3FixtureData) { f.engine = nil },
		func(f *snmpV3FixtureData) { f.engine = make([]byte, 33) },
		func(f *snmpV3FixtureData) { f.boots = -1 },
		func(f *snmpV3FixtureData) { f.engineTime = -1 },
		func(f *snmpV3FixtureData) { f.user = make([]byte, 33) },
		func(f *snmpV3FixtureData) { f.authentication = []byte{0} },
		func(f *snmpV3FixtureData) { f.privacy = []byte{0} },
		func(f *snmpV3FixtureData) { f.contextEngine = nil },
		func(f *snmpV3FixtureData) { f.contextName = make([]byte, 33) },
		func(f *snmpV3FixtureData) { f.pduTag = 0 },
		func(f *snmpV3FixtureData) { f.pduTag = 8; f.status = 1 },
		func(f *snmpV3FixtureData) { f.index = 1 },
		func(f *snmpV3FixtureData) { f.encrypted = true },
	} {
		if udpSNMPVersion(snmpV3Fixture(t, mutate)) != "" {
			t.Fatal("unsupported or malformed SNMPv3 accepted")
		}
	}
	payload := snmpV3Fixture(t, nil)
	var outer asn1.RawValue
	if _, err := asn1.Unmarshal(payload, &outer); err != nil {
		t.Fatal(err)
	}
	outer.FullBytes = nil
	outer.Bytes = append(outer.Bytes, snmpFixtureMarshal(t, 0)...)
	if udpSNMPVersion(snmpFixtureMarshal(t, outer)) != "" {
		t.Fatal("extra outer fields accepted")
	}
	for _, data := range [][]byte{{0x30, 0x80, 0, 0}, []byte("SNMPv3 forged")} {
		if udpSNMPVersion(data) != "" {
			t.Fatal("unsupported encoding accepted")
		}
	}
}

func FuzzSNMPVariantsBounded(f *testing.F) {
	binding := snmpFixtureBinding(f, asn1.RawValue{Tag: asn1.TagNull})
	f.Add(snmpFixtureResponse(f, 1, 2, 0, 0, []asn1.RawValue{binding}))
	f.Add(snmpV3Fixture(f, nil))
	f.Add(snmpV3Fixture(f, func(data *snmpV3FixtureData) { data.pduTag = 8 }))
	f.Add([]byte{0x30, 0x80, 0, 0})
	f.Fuzz(func(t *testing.T, payload []byte) {
		version := udpSNMPVersion(payload)
		switch version {
		case "", "SNMPv1 response", "SNMPv2c response", "SNMPv3 response (unauthenticated)", "SNMPv3 report (unauthenticated)":
		default:
			t.Fatal("invented identity")
		}
		if len(payload) > maxUDPResponseBytes && version != "" {
			t.Fatal("oversized message accepted")
		}
	})
}

func TestSNMPv3RejectsExtraNestedFields(t *testing.T) {
	type wireMessage struct {
		Version  int
		Header   asn1.RawValue
		Security []byte
		Scoped   asn1.RawValue
	}
	payload := snmpV3Fixture(t, nil)
	var message wireMessage
	if _, err := asn1.Unmarshal(payload, &message); err != nil {
		t.Fatal(err)
	}
	for _, section := range []string{"header", "security", "scoped"} {
		copyMessage := message
		var raw *asn1.RawValue
		var security asn1.RawValue
		switch section {
		case "header":
			raw = &copyMessage.Header
		case "scoped":
			raw = &copyMessage.Scoped
		case "security":
			if _, err := asn1.Unmarshal(message.Security, &security); err != nil {
				t.Fatal(err)
			}
			raw = &security
		}
		raw.FullBytes = nil
		raw.Bytes = append(append([]byte(nil), raw.Bytes...), snmpFixtureMarshal(t, 0)...)
		if section == "security" {
			copyMessage.Security = snmpFixtureMarshal(t, security)
		}
		if udpSNMPVersion(snmpFixtureMarshal(t, copyMessage)) != "" {
			t.Fatalf("extra %s field accepted", section)
		}
	}
}
