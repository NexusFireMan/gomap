package scanner

import (
	"bytes"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"os"
	"strings"
	"syscall"
	"testing"
)

func snmpQueryReplyFixture(t testing.TB, query []byte) []byte {
	t.Helper()
	var version int
	var community []byte
	var pdu asn1.RawValue
	if !snmpSequenceFields(query, &version, &community, &pdu) {
		t.Fatal("invalid fixture community query")
	}
	pdu.FullBytes, pdu.Tag = nil, 2
	return snmpFixtureMarshal(t, struct {
		Version   int
		Community []byte
		PDU       asn1.RawValue
	}{version, community, pdu})
}

func snmpDiscoveryReplyFixture(t testing.TB, query []byte, mutate func(*snmpWireV3)) []byte {
	t.Helper()
	var message snmpWireV3
	if rest, err := asn1.Unmarshal(query, &message); err != nil || len(rest) != 0 {
		t.Fatalf("invalid fixture discovery query: %v", err)
	}
	var request snmpWirePDU
	if !snmpFields(message.Scoped.PDU.Bytes, &request.ID, &request.Status, &request.Index, &request.Bindings) {
		t.Fatal("invalid fixture request PDU")
	}
	request.Bindings = []snmpWireBinding{{
		OID:   asn1.ObjectIdentifier{1, 3, 6, 1, 6, 3, 15, 1, 1, 4, 0},
		Value: asn1.RawValue{Class: asn1.ClassApplication, Tag: 1, Bytes: []byte{1}},
	}}
	var pdu asn1.RawValue
	if _, err := asn1.Unmarshal(snmpFixtureMarshal(t, request), &pdu); err != nil {
		t.Fatal(err)
	}
	pdu.FullBytes, pdu.Class, pdu.Tag = nil, asn1.ClassContextSpecific, 8
	message.Header.Flags = []byte{0}
	message.Security = snmpFixtureMarshal(t, snmpWireSecurity{Engine: []byte("engine-do-not-log")})
	message.Scoped = snmpWireScoped{Engine: []byte("engine-do-not-log"), PDU: pdu}
	if mutate != nil {
		mutate(&message)
	}
	return snmpFixtureMarshal(t, message)
}

func mutateSNMPDiscoveryPDU(t testing.TB, message *snmpWireV3, mutate func(*snmpWirePDU)) {
	t.Helper()
	var pdu snmpWirePDU
	if !snmpFields(message.Scoped.PDU.Bytes, &pdu.ID, &pdu.Status, &pdu.Index, &pdu.Bindings) {
		t.Fatal("fixture decoding failed")
	}
	mutate(&pdu)
	var raw asn1.RawValue
	if _, err := asn1.Unmarshal(snmpFixtureMarshal(t, pdu), &raw); err != nil {
		t.Fatal(err)
	}
	message.Scoped.PDU.Bytes, message.Scoped.PDU.FullBytes = raw.Bytes, nil
}

func TestSNMPAdditionalQueryShapeAndEntropy(t *testing.T) {
	queries, err := snmpAdditionalQueries(bytes.NewReader([]byte{0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3}))
	if err != nil || len(queries) != 2 {
		t.Fatalf("queries: %v", err)
	}
	v2, valid := snmpCorrelationFields(queries[0], 0)
	if !valid || v2.version != 1 || v2.id != 1 || string(v2.community) != "public" || len(v2.oids) != 1 || !v2.oids[0].Equal(asn1.ObjectIdentifier{1, 3, 6, 1, 2, 1, 1, 1, 0}) {
		t.Fatalf("invalid v2c GET: %+v", v2)
	}
	var v3 snmpWireV3
	if _, err := asn1.Unmarshal(queries[1], &v3); err != nil {
		t.Fatal(err)
	}
	var security snmpWireSecurity
	if _, err := asn1.Unmarshal(v3.Security, &security); err != nil {
		t.Fatal(err)
	}
	var request snmpWirePDU
	if !snmpFields(v3.Scoped.PDU.Bytes, &request.ID, &request.Status, &request.Index, &request.Bindings) ||
		v3.Version != 3 || v3.Header.ID != 2 || v3.Header.MaxSize != maxUDPResponseBytes || v3.Header.Model != 3 || !bytes.Equal(v3.Header.Flags, []byte{4}) ||
		request.ID != 3 || request.Status != 0 || request.Index != 0 || len(request.Bindings) != 0 ||
		v3.Scoped.PDU.Tag != 0 || v3.Scoped.PDU.Class != asn1.ClassContextSpecific ||
		len(v3.Scoped.Engine)+len(v3.Scoped.Name)+len(security.Engine)+len(security.User)+len(security.Authentication)+len(security.Privacy) != 0 || security.Boots != 0 || security.Time != 0 {
		t.Fatal("invalid noAuthNoPriv engine-discovery request")
	}
	for _, query := range queries {
		if len(query) > maxUDPResponseBytes {
			t.Fatal("oversized query")
		}
	}
	// Fixed wire fixtures also check encoding independently of our response builder.
	for index, wire := range []string{
		"302602010104067075626c6963a019020101020100020100300e300c06082b060102010101000500",
		"3037020103300d020102020208000401040201030410300e0400020100020100040004000400301104000400a00b0201030201000201003000",
	} {
		want, err := hex.DecodeString(wire)
		if err != nil || !bytes.Equal(queries[index], want) {
			t.Fatalf("query %d differs from wire fixture: %x (%v)", index, queries[index], err)
		}
	}
	for _, input := range [][]byte{nil, make([]byte, 11)} {
		if result, err := snmpAdditionalQueries(bytes.NewReader(input)); err == nil || result != nil {
			t.Fatal("entropy failure substituted a query")
		}
	}
}

func TestSNMPDiscoveryCorrelationAndDisclosure(t *testing.T) {
	query, err := snmpV3DiscoveryQuery(123, 123)
	if err != nil {
		t.Fatal(err)
	}
	response := snmpDiscoveryReplyFixture(t, query, nil)
	if checked, matched := udpProbeFieldsMatch(161, query, response); !checked || !matched {
		t.Fatal("correlated discovery report rejected")
	}
	zeroRequestID := snmpDiscoveryReplyFixture(t, query, func(m *snmpWireV3) {
		mutateSNMPDiscoveryPDU(t, m, func(p *snmpWirePDU) { p.ID = 0 })
	})
	if checked, matched := udpProbeFieldsMatch(161, query, zeroRequestID); !checked || !matched {
		t.Fatal("RFC 3412 discovery report with unavailable request ID rejected")
	}
	wrongMessageID := snmpDiscoveryReplyFixture(t, query, func(m *snmpWireV3) {
		m.Header.ID++
		mutateSNMPDiscoveryPDU(t, m, func(p *snmpWirePDU) { p.ID = 0 })
	})
	if checked, matched := udpProbeFieldsMatch(161, query, wrongMessageID); !checked || matched {
		t.Fatal("zero request ID bypassed message correlation")
	}
	s := NewScanner("fixture.invalid", false)
	service, version, confidence, evidence := s.classifyUDPResponseForProbe(161, response, query, true)
	if service != "snmp" || version != "SNMPv3 report (unauthenticated)" || confidence != "medium" || !strings.Contains(evidence, "discovery message ID matched") || strings.Contains(evidence, "do-not-log") {
		t.Fatalf("incorrect or sensitive metadata: %q %q %q %q", service, version, confidence, evidence)
	}
	for variant, mutate := range []func(*snmpWireV3){
		func(m *snmpWireV3) { m.Header.ID++ },
		func(m *snmpWireV3) { m.Header.Flags = []byte{1} },
		func(m *snmpWireV3) { m.Header.Model = 4 },
		func(m *snmpWireV3) {
			m.Security = snmpFixtureMarshal(t, snmpWireSecurity{Engine: []byte("engine-do-not-log"), User: []byte("different-user")})
		},
		func(m *snmpWireV3) { m.Scoped.Name = []byte("different-context") },
		func(m *snmpWireV3) { m.Scoped.Engine = []byte("different-engine") },
		func(m *snmpWireV3) { m.Scoped.PDU.Tag = 2 },
		func(m *snmpWireV3) {
			mutateSNMPDiscoveryPDU(t, m, func(p *snmpWirePDU) { p.ID++ })
		},
		func(m *snmpWireV3) {
			mutateSNMPDiscoveryPDU(t, m, func(p *snmpWirePDU) { p.Bindings[0].OID = asn1.ObjectIdentifier{1, 3, 6, 1, 2, 1, 1, 1, 0} })
		},
		func(m *snmpWireV3) {
			mutateSNMPDiscoveryPDU(t, m, func(p *snmpWirePDU) { p.Bindings[0].Value = asn1.RawValue{Tag: asn1.TagInteger, Bytes: []byte{1}} })
		},
		func(m *snmpWireV3) {
			mutateSNMPDiscoveryPDU(t, m, func(p *snmpWirePDU) { p.Bindings = append(p.Bindings, p.Bindings[0]) })
		},
	} {
		reply := snmpDiscoveryReplyFixture(t, query, mutate)
		if checked, matched := udpProbeFieldsMatch(161, query, reply); !checked || matched {
			t.Fatalf("mismatched discovery variant %d accepted", variant)
		}
	}
	for _, reply := range [][]byte{nil, append(bytes.Clone(response), 0), make([]byte, maxUDPResponseBytes+1)} {
		if checked, matched := udpProbeFieldsMatch(161, query, reply); !checked || matched {
			t.Fatal("malformed discovery accepted")
		}
	}
	for end := range len(response) {
		if _, matched := udpProbeFieldsMatch(161, query, response[:end]); matched {
			t.Fatalf("truncated discovery accepted at %d", end)
		}
	}
}

func TestSNMPDeepExchangeBoundedFallbacks(t *testing.T) {
	for _, tt := range []struct {
		name        string
		mode        string
		wantCalls   int
		wantVersion string
	}{
		{"v1 sufficient", "v1", 1, "SNMPv1 response"},
		{"v2c only", "v2", 2, "SNMPv2c response"},
		{"v3 only", "v3", 3, "SNMPv3 report (unauthenticated)"},
		{"silent", "silent", 3, ""},
		{"responsive unknown preserved", "unknown", 3, ""},
		{"responsive unknown then refusal", "unknown-refused", 2, ""},
		{"mismatched v2c", "mismatch", 3, ""},
		{"refused", "closed", 1, ""},
	} {
		t.Run(tt.name, func(t *testing.T) {
			s := NewScanner("fixture.invalid", false)
			s.DeepVersion, s.Retries = true, 0
			calls := 0
			exchange := func(query []byte) ([]byte, error) {
				calls++
				switch {
				case tt.mode == "closed":
					return nil, syscall.ECONNREFUSED
				case tt.mode == "v1" && calls == 1, tt.mode == "v2" && calls == 2:
					return snmpQueryReplyFixture(t, query), nil
				case tt.mode == "v3" && calls == 3:
					return snmpDiscoveryReplyFixture(t, query, nil), nil
				case (tt.mode == "unknown" || tt.mode == "unknown-refused") && calls == 1:
					return []byte("unrecognized-fixture"), nil
				case tt.mode == "unknown-refused" && calls == 2:
					return nil, syscall.ECONNREFUSED
				case tt.mode == "mismatch" && calls == 2:
					otherQuery, err := snmpV2cQuery(0)
					if err != nil {
						t.Fatal(err)
					}
					return snmpQueryReplyFixture(t, otherQuery), nil
				default:
					return nil, os.ErrDeadlineExceeded
				}
			}
			response, probe, err := s.exchangeUDPPort(161, true, exchange)
			_, version, _, _ := s.classifyUDPResponseForProbe(161, response, probe, true)
			if calls != tt.wantCalls || version != tt.wantVersion {
				t.Fatalf("calls=%d version=%q err=%v", calls, version, err)
			}
			if (tt.wantVersion != "" || strings.HasPrefix(tt.mode, "unknown") || tt.mode == "mismatch") && err != nil {
				t.Fatal("responsive port lost")
			}
			if strings.HasPrefix(tt.mode, "unknown") && string(response) != "unrecognized-fixture" {
				t.Fatal("original evidence overwritten")
			}
			if tt.mode == "silent" && !errors.Is(err, os.ErrDeadlineExceeded) {
				t.Fatal("silence not preserved")
			}
		})
	}
}

func BenchmarkSNMPDiscoveryMatching(b *testing.B) {
	query, err := snmpV3DiscoveryQuery(123, 123)
	if err != nil {
		b.Fatal(err)
	}
	reply := snmpDiscoveryReplyFixture(b, query, nil)
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		if checked, matched := snmpV3DiscoveryMatches(query, reply); !checked || !matched {
			b.Fatal("fixture rejected")
		}
	}
}

func TestSNMPDeepExchangeOptInAndRetryBounds(t *testing.T) {
	for _, tt := range []struct {
		name                string
		port                int
		deep, detect, ghost bool
	}{
		{"normal scan", 161, false, true, false},
		{"no detection", 161, true, false, false},
		{"other port", 162, true, true, false},
		{"controlled profile", 161, true, true, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			s := NewScanner("fixture.invalid", tt.ghost)
			s.DeepVersion, s.Retries = tt.deep, 0
			calls := 0
			_, _, _ = s.exchangeUDPPort(tt.port, tt.detect, func(query []byte) ([]byte, error) {
				calls++
				if !bytes.Equal(query, udpProbePayload(tt.port)) {
					t.Fatal("default payload changed")
				}
				return nil, os.ErrDeadlineExceeded
			})
			if calls != 1 {
				t.Fatalf("unexpected extra queries: %d", calls)
			}
		})
	}
	s := NewScanner("fixture.invalid", false)
	s.DeepVersion, s.Retries, s.BackoffBase = true, 2, 0
	calls := 0
	_, _, _ = s.exchangeUDPPort(161, true, func([]byte) ([]byte, error) {
		calls++
		return nil, os.ErrDeadlineExceeded
	})
	if calls != 5 {
		t.Fatalf("expected 3 initial attempts plus 2 single fallbacks, got %d", calls)
	}
}

func FuzzSNMPDiscoveryCorrelation(f *testing.F) {
	query, err := snmpV3DiscoveryQuery(123, 123)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(query, snmpDiscoveryReplyFixture(f, query, nil))
	f.Add([]byte{0}, []byte{0})
	f.Fuzz(func(t *testing.T, probe, response []byte) {
		checked, matched := snmpV3DiscoveryMatches(probe, response)
		if matched && (!checked || udpSNMPVersion(response) != "SNMPv3 report (unauthenticated)" || len(probe) > maxUDPResponseBytes || len(response) > maxUDPResponseBytes) {
			t.Fatal("unvalidated discovery match")
		}
	})
}
