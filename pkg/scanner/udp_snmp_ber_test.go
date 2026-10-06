package scanner

import (
	"bytes"
	"encoding/asn1"
	"testing"
)

func snmpBERLongFixture(t testing.TB, data []byte) []byte {
	t.Helper()
	var raw asn1.RawValue
	rest, err := asn1.Unmarshal(data, &raw)
	if err != nil || len(rest) != 0 {
		t.Fatal("invalid fixture")
	}
	body := raw.Bytes
	if raw.IsCompound {
		body = nil
		for remaining := raw.Bytes; len(remaining) > 0; {
			var child asn1.RawValue
			remaining, err = asn1.Unmarshal(remaining, &child)
			if err != nil {
				t.Fatal(err)
			}
			body = append(body, snmpBERLongFixture(t, child.FullBytes)...)
		}
	}
	return append([]byte{data[0], 0x82, byte(len(body) >> 8), byte(len(body))}, body...)
}

func TestSNMPBERDefiniteLengths(t *testing.T) {
	binding := snmpFixtureBinding(t, asn1.RawValue{Tag: asn1.TagNull})
	for _, payload := range [][]byte{snmpFixtureResponse(t, 0, 2, 0, 0, []asn1.RawValue{binding}), snmpFixtureResponse(t, 1, 2, 0, 0, []asn1.RawValue{binding}), snmpV3Fixture(t, nil)} {
		long := snmpBERLongFixture(t, payload)
		if got, want := udpSNMPVersion(long), udpSNMPVersion(payload); got == "" || got != want {
			t.Fatalf("non-minimal definite BER: got=%q want=%q", got, want)
		}
		canonical, valid := snmpBERCanonical(long)
		if !valid || !bytes.Equal(canonical, payload) {
			t.Fatal("length normalization changed contents")
		}
	}
	// USM parameters are encoded inside an OCTET STRING and need separate framing.
	type wireMessage struct {
		Version  int
		Header   asn1.RawValue
		Security []byte
		Scoped   asn1.RawValue
	}
	var message wireMessage
	if _, err := asn1.Unmarshal(snmpV3Fixture(t, nil), &message); err != nil {
		t.Fatal(err)
	}
	message.Security = snmpBERLongFixture(t, message.Security)
	if udpSNMPVersion(snmpFixtureMarshal(t, message)) != "SNMPv3 response (unauthenticated)" {
		t.Fatal("non-minimal USM lengths rejected")
	}
	if checked, matched := udpProbeFieldsMatch(161, udpProbePayload(161), snmpBERLongFixture(t, udpSNMPProbeReplyFixture(t))); !checked || !matched {
		t.Fatal("BER reply failed correlation")
	}
}

func TestSNMPBERRejectsMalformedAndExcessiveFraming(t *testing.T) {
	deep := []byte{5, 0}
	for range 20 {
		deep = append([]byte{0x30, byte(len(deep))}, deep...)
	}
	for _, data := range [][]byte{nil, {0x30, 0x80, 0, 0}, {0x30, 0x85, 0, 0, 0, 0, 0}, {0x30, 0x84, 0xff, 0xff, 0xff, 0xff}, {0x30, 0x82, 0}, {0x30, 2, 5}, {0x24, 2, 4, 0}, {0x1f, 0}, {0, 0}, {5, 0, 5, 0}, deep, make([]byte, maxUDPResponseBytes+1)} {
		if _, valid := snmpBERCanonical(data); valid {
			t.Fatalf("invalid framing accepted: %x", data)
		}
	}
}

func FuzzSNMPBERFramingBounded(f *testing.F) {
	f.Add([]byte{0x30, 0x82, 0, 2, 5, 0})
	f.Add(snmpBERLongFixture(f, udpSNMPProbeReplyFixture(f)))
	f.Add([]byte{0x30, 0x80, 0, 0})
	f.Fuzz(func(t *testing.T, data []byte) {
		canonical, valid := snmpBERCanonical(data)
		if !valid {
			return
		}
		if len(data) > maxUDPResponseBytes || len(canonical) > len(data) {
			t.Fatal("normalizer exceeded bound")
		}
		var raw asn1.RawValue
		rest, err := asn1.Unmarshal(canonical, &raw)
		if err != nil || len(rest) != 0 {
			t.Fatal("normalized framing not ASN.1-decodable")
		}
	})
}
