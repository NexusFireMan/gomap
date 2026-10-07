package scanner

import (
	"encoding/asn1"
	"strings"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

func udpDNSProbeReplyFixture(t testing.TB) []byte {
	t.Helper()
	var message dnsmessage.Message
	if err := message.Unpack(udpProbePayload(53)); err != nil {
		t.Fatal(err)
	}
	message.Response = true
	message.Answers = []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: message.Questions[0].Name, Class: dnsmessage.ClassCHAOS}, Body: &dnsmessage.TXTResource{TXT: []string{"do-not-log-server"}}}}
	payload, err := message.Pack()
	if err != nil {
		t.Fatal(err)
	}
	return payload
}

func udpSNMPProbeReplyFixture(t testing.TB) []byte {
	t.Helper()
	var version int
	var community []byte
	var pdu asn1.RawValue
	if !snmpSequenceFields(udpProbePayload(161), &version, &community, &pdu) {
		t.Fatal("invalid existing probe")
	}
	pdu.Tag = 2
	pdu.FullBytes = nil
	content := snmpFixtureMarshal(t, version)
	content = append(content, snmpFixtureMarshal(t, community)...)
	content = append(content, snmpFixtureMarshal(t, pdu)...)
	return snmpFixtureMarshal(t, asn1.RawValue{Tag: asn1.TagSequence, IsCompound: true, Bytes: content})
}

func TestUDPProbeMatchedMetadata(t *testing.T) {
	s := NewScanner("fixture.invalid", false)
	for _, tc := range []struct {
		port  int
		reply []byte
	}{{53, udpDNSProbeReplyFixture(t)}, {161, udpSNMPProbeReplyFixture(t)}} {
		_, version, confidence, evidence := s.classifyUDPResponseForProbe(tc.port, tc.reply, udpProbePayload(tc.port), true)
		if version == "" || confidence != "medium" || !strings.Contains(evidence, "sent probe fields matched") || !strings.Contains(evidence, "not authenticated") {
			t.Fatalf("wrong metadata: %q %q %q", version, confidence, evidence)
		}
		if strings.Contains(version+evidence, "public") || strings.Contains(version+evidence, "do-not-log") {
			t.Fatal("sensitive fields disclosed")
		}
		_, version, confidence, _ = s.classifyUDPResponseForProbe(tc.port, tc.reply, udpProbePayload(tc.port), false)
		if version != "" || confidence != "low" {
			t.Fatal("disabled service detection correlates reply")
		}
		_, version, confidence, evidence = s.classifyUDPResponseForProbe(tc.port, tc.reply, nil, true)
		if version == "" || confidence != "medium" || strings.Contains(evidence, "sent probe fields matched") {
			t.Fatal("missing query produced invented correlation")
		}
	}
}

func TestUDPDNSRejectsMismatchedProbeFields(t *testing.T) {
	var message dnsmessage.Message
	if err := message.Unpack(udpDNSProbeReplyFixture(t)); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*dnsmessage.Message){
		func(m *dnsmessage.Message) { m.ID++ },
		func(m *dnsmessage.Message) { m.Questions[0].Type = dnsmessage.TypeA },
		func(m *dnsmessage.Message) { m.Questions[0].Class = dnsmessage.ClassINET },
		func(m *dnsmessage.Message) {
			name, err := dnsmessage.NewName("other.invalid.")
			if err != nil {
				t.Fatal(err)
			}
			m.Questions[0].Name = name
		},
	} {
		copyMessage := message
		copyMessage.Questions = append([]dnsmessage.Question(nil), message.Questions...)
		mutate(&copyMessage)
		reply, err := copyMessage.Pack()
		if err != nil {
			t.Fatal(err)
		}
		_, version, confidence, evidence := NewScanner("fixture.invalid", false).classifyUDPResponseForProbe(53, reply, udpProbePayload(53), true)
		if version != "" || confidence != "low" || !strings.Contains(evidence, "does not match") {
			t.Fatal("mismatched DNS fields accepted")
		}
	}
	name, err := dnsmessage.NewName("VERSION.BIND.")
	if err != nil {
		t.Fatal(err)
	}
	message.Questions[0].Name = name
	reply, err := message.Pack()
	if err != nil {
		t.Fatal(err)
	}
	if checked, matched := udpProbeFieldsMatch(53, udpProbePayload(53), reply); !checked || !matched {
		t.Fatal("case-insensitive DNS question mismatch")
	}
}

func TestUDPSNMPRejectsMismatchedProbeFields(t *testing.T) {
	type wireMessage struct {
		Version   int
		Community []byte
		PDU       asn1.RawValue
	}
	var message wireMessage
	if _, err := asn1.Unmarshal(udpSNMPProbeReplyFixture(t), &message); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*wireMessage){
		func(m *wireMessage) { m.Version = 1 },
		func(m *wireMessage) { m.Community = []byte("other-do-not-log") },
		func(m *wireMessage) {
			var id int32
			rest, err := asn1.Unmarshal(m.PDU.Bytes, &id)
			if err != nil {
				t.Fatal(err)
			}
			m.PDU.FullBytes = nil
			m.PDU.Bytes = append(snmpFixtureMarshal(t, id+1), rest...)
		},
		func(m *wireMessage) {
			var id int32
			var status, index int
			var bindings asn1.RawValue
			if !snmpFields(m.PDU.Bytes, &id, &status, &index, &bindings) {
				t.Fatal("invalid fixture")
			}
			binding := snmpFixtureBinding(t, asn1.RawValue{Tag: asn1.TagNull})
			m.PDU.FullBytes = nil
			m.PDU.Bytes = snmpFixtureMarshal(t, id)
			m.PDU.Bytes = append(m.PDU.Bytes, snmpFixtureMarshal(t, status)...)
			m.PDU.Bytes = append(m.PDU.Bytes, snmpFixtureMarshal(t, index)...)
			m.PDU.Bytes = append(m.PDU.Bytes, snmpFixtureMarshal(t, []asn1.RawValue{binding})...)
		},
	} {
		copyMessage := message
		mutate(&copyMessage)
		_, version, confidence, evidence := NewScanner("fixture.invalid", false).classifyUDPResponseForProbe(161, snmpFixtureMarshal(t, copyMessage), udpProbePayload(161), true)
		if version != "" || confidence != "low" || !strings.Contains(evidence, "does not match") {
			t.Fatal("mismatched SNMP fields accepted")
		}
	}
	if checked, matched := udpProbeFieldsMatch(161, udpProbePayload(161), snmpV3Fixture(t, nil)); !checked || matched {
		t.Fatal("v3 reply correlated to v1 probe")
	}
}

func TestUDPGenericProbesDoNotInventCorrelation(t *testing.T) {
	for _, port := range []int{123, 137, 138, 1900, 5353, 5355} {
		if checked, matched := udpProbeFieldsMatch(port, udpProbePayload(port), []byte("fixture")); checked || matched {
			t.Fatalf("invented correlation on udp/%d", port)
		}
	}
}

func TestSNMPMatchingErrorRepliesAndV2cFixtures(t *testing.T) {
	type wireMessage struct {
		Version   int
		Community []byte
		PDU       asn1.RawValue
	}
	var message wireMessage
	if _, err := asn1.Unmarshal(udpSNMPProbeReplyFixture(t), &message); err != nil {
		t.Fatal(err)
	}
	var id int32
	var status, index int
	var bindings asn1.RawValue
	if !snmpFields(message.PDU.Bytes, &id, &status, &index, &bindings) {
		t.Fatal("invalid fixture")
	}
	for _, tc := range []struct {
		status, index int
		bindings      asn1.RawValue
	}{
		{1, 0, asn1.RawValue{Tag: asn1.TagSequence, IsCompound: true}},
		{2, 1, bindings},
	} {
		copyMessage := message
		copyMessage.PDU.FullBytes = nil
		copyMessage.PDU.Bytes = snmpFixtureMarshal(t, id)
		copyMessage.PDU.Bytes = append(copyMessage.PDU.Bytes, snmpFixtureMarshal(t, tc.status)...)
		copyMessage.PDU.Bytes = append(copyMessage.PDU.Bytes, snmpFixtureMarshal(t, tc.index)...)
		copyMessage.PDU.Bytes = append(copyMessage.PDU.Bytes, snmpFixtureMarshal(t, tc.bindings)...)
		if checked, matched := udpProbeFieldsMatch(161, udpProbePayload(161), snmpFixtureMarshal(t, copyMessage)); !checked || !matched {
			t.Fatal("matching error reply rejected")
		}
	}
	message.Version = 1
	reply := snmpFixtureMarshal(t, message)
	var query wireMessage
	if _, err := asn1.Unmarshal(udpProbePayload(161), &query); err != nil {
		t.Fatal(err)
	}
	query.Version = 1
	if checked, matched := udpProbeFieldsMatch(161, snmpFixtureMarshal(t, query), reply); !checked || !matched {
		t.Fatal("compatible v2c fixtures failed correlation")
	}
}

func BenchmarkUDPProbeMatching(b *testing.B) {
	for _, tc := range []struct {
		name  string
		port  int
		reply []byte
	}{
		{"DNS", 53, udpDNSProbeReplyFixture(b)},
		{"SNMP", 161, udpSNMPProbeReplyFixture(b)},
	} {
		probe := udpProbePayload(tc.port)
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				udpProbeFieldsMatch(tc.port, probe, tc.reply)
			}
		})
	}
}

func FuzzUDPProbeCorrelationBounded(f *testing.F) {
	f.Add(uint16(53), udpProbePayload(53), udpDNSProbeReplyFixture(f))
	f.Add(uint16(161), udpProbePayload(161), udpSNMPProbeReplyFixture(f))
	f.Fuzz(func(t *testing.T, port uint16, probe, response []byte) {
		checked, matched := udpProbeFieldsMatch(int(port), probe, response)
		if matched && !checked {
			t.Fatal("matched without correlation check")
		}
		if matched && (len(probe) > maxUDPResponseBytes || len(response) > maxUDPResponseBytes) {
			t.Fatal("oversized fields matched")
		}
	})
}
