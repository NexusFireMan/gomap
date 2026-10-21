package scanner

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func rdpConfirmFixture() []byte {
	return []byte{3, 0, 0, 19, 14, 0xd0, 0, 0, 0x12, 0x34, 0, 2, 0, 8, 0, 1, 0, 0, 0}
}

func TestRDPNegotiationRejectsUnframedAndMalformedResponses(t *testing.T) {
	valid := rdpConfirmFixture()
	if selected, ok := parseRDPNegotiationProtocol(valid); !ok || selected != 1 {
		t.Fatal("valid negotiation rejected")
	}
	for _, mutate := range []func([]byte) []byte{
		func(p []byte) []byte { p[0] = 2; return p },
		func(p []byte) []byte { p[1] = 1; return p },
		func(p []byte) []byte { p[3]--; return p },
		func(p []byte) []byte { p[4]--; return p },
		func(p []byte) []byte { p[5] = 0xe0; return p },
		func(p []byte) []byte { p[5] = 0xf0; return p },
		func(p []byte) []byte { p[10] = 1; return p },
		func(p []byte) []byte { p[11] = 1; return p },
		func(p []byte) []byte { p[13] = 7; return p },
		func(p []byte) []byte { p[14] = 1; return p },
		func(p []byte) []byte { p[15] = 3; return p },
		func(p []byte) []byte { p[15] = 8; return p },
		func(p []byte) []byte { p[12] = 0x80; return p },
		func(p []byte) []byte { return append(p, 0) },
		func(p []byte) []byte { return append([]byte("unframed-prefix"), p[11:]...) },
	} {
		if _, ok := parseRDPNegotiationProtocol(mutate(bytes.Clone(valid))); ok {
			t.Error("malformed/unframed negotiation accepted")
		}
	}
	for end := range len(valid) {
		if _, ok := parseRDPNegotiationProtocol(valid[:end]); ok {
			t.Fatalf("truncation accepted at %d", end)
		}
	}
	changed := bytes.Clone(valid)
	binary.BigEndian.PutUint16(changed[2:], 65535)
	if _, ok := parseRDPNegotiationProtocol(changed); ok {
		t.Fatal("inconsistent outer length accepted")
	}
}
