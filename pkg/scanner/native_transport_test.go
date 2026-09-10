package scanner

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"strings"
	"testing"
	"testing/iotest"
)

type transportFixtureConn struct {
	net.Conn
	r io.Reader
	w bytes.Buffer
}

func (c *transportFixtureConn) Read(p []byte) (int, error)  { return c.r.Read(p) }
func (c *transportFixtureConn) Write(p []byte) (int, error) { return c.w.Write(p) }

func TestRMITransportNegotiation(t *testing.T) {
	valid := []byte{0x4e, 0, 3, 'l', 'a', 'b', 0, 0, 0x30, 0x39, 0x53}
	for _, tc := range []struct {
		name string
		data []byte
		want bool
	}{
		{"valid", valid, true},
		{"not-supported", []byte{0x4f, 0, 0}, false},
		{"oversized", []byte{0x4e, 0xff, 0xff}, false},
		{"invalid-port", []byte{0x4e, 0, 0, 0, 1, 0, 0, 0x53}, false},
		{"wrong-ping", []byte{0x4e, 0, 0, 0, 0, 0, 0, 0x51}, false},
		{"http", []byte("HTTP/1.1 200 OK\r\n"), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := &transportFixtureConn{r: iotest.OneByteReader(bytes.NewReader(tc.data))}
			if got := probeRMITransport(c); got != tc.want {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
			if tc.want && !bytes.Equal(c.w.Bytes(), []byte("JRMI\x00\x02\x4b\x00\x00\x00\x00\x00\x00\x52")) {
				t.Fatalf("unexpected transport request: %x", c.w.Bytes())
			}
		})
	}
	for n := 0; n < len(valid); n++ {
		if probeRMITransport(&transportFixtureConn{r: bytes.NewReader(valid[:n])}) {
			t.Fatalf("accepted truncation at %d", n)
		}
	}
}

func rpcAckFixture() []byte {
	p := make([]byte, 56)
	copy(p, []byte{5, 0, 12, 3, 0x10})
	binary.LittleEndian.PutUint16(p[8:], uint16(len(p)))
	binary.LittleEndian.PutUint32(p[12:], 1)
	binary.LittleEndian.PutUint16(p[16:], 4280)
	binary.LittleEndian.PutUint16(p[18:], 4280)
	p[28] = 1
	copy(p[36:], buildDCERPCBind()[52:])
	return p
}

func TestDCERPCBindAckValidation(t *testing.T) {
	valid := rpcAckFixture()
	if evidence, ok := readDCERPCBindAck(iotest.OneByteReader(bytes.NewReader(valid))); !ok || !strings.Contains(evidence, "accepted") {
		t.Fatalf("fragmented ack: %q, %v", evidence, ok)
	}
	rejected := bytes.Clone(valid)
	rejected[32], rejected[34] = 2, 1
	if evidence, ok := readDCERPCBindAck(bytes.NewReader(rejected)); !ok || !strings.Contains(evidence, "rejected") {
		t.Fatalf("rejected context still confirms RPC: %q, %v", evidence, ok)
	}
	for n := 0; n < len(valid); n++ {
		if _, ok := readDCERPCBindAck(bytes.NewReader(valid[:n])); ok {
			t.Fatalf("accepted truncation at %d", n)
		}
	}
	for _, tc := range []struct {
		offset int
		value  byte
	}{
		{0, 4}, {2, 2}, {3, 1}, {4, 0}, {8, 0xff}, {9, 0xff}, {10, 1}, {12, 2},
		{24, 0xff}, {25, 0xff}, {28, 2}, {32, 3}, {34, 1}, {36, 0xff},
	} {
		p := bytes.Clone(valid)
		p[tc.offset] = tc.value
		if _, ok := readDCERPCBindAck(bytes.NewReader(p)); ok {
			t.Fatalf("accepted invalid field at %d", tc.offset)
		}
	}
}

func FuzzDCERPCBindAck(f *testing.F) {
	f.Add(rpcAckFixture())
	f.Add([]byte("HTTP/1.1 200 OK\r\n"))
	f.Fuzz(func(t *testing.T, data []byte) { _, _ = readDCERPCBindAck(bytes.NewReader(data)) })
}
