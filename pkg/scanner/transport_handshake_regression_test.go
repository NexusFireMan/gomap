package scanner

import (
	"bytes"
	"encoding/binary"
	"io"
	"os"
	"strings"
	"testing"
	"testing/iotest"
)

func rmiHandshakeFixture() []byte {
	return []byte{0x4e, 0, 3, 'l', 'a', 'b', 0, 0, 0x30, 0x39, 0x53}
}

func TestRMIHandshakeStreamErrorsAndReadBoundaries(t *testing.T) {
	valid := rmiHandshakeFixture()
	for cut := 0; cut <= len(valid); cut++ {
		reader := io.MultiReader(bytes.NewReader(valid[:cut]), iotest.OneByteReader(bytes.NewReader(valid[cut:])))
		conn := &transportFixtureConn{r: reader}
		if !probeRMITransport(conn) || conn.w.String() != "JRMI\x00\x02\x4b\x00\x00\x00\x00\x00\x00\x52" {
			t.Fatalf("split %d changed transport negotiation", cut)
		}
	}
	for cut := range len(valid) {
		conn := &transportFixtureConn{r: io.MultiReader(bytes.NewReader(valid[:cut]), framingErrorReader{os.ErrDeadlineExceeded})}
		if probeRMITransport(conn) {
			t.Fatal("timed-out handshake promoted to RMI")
		}
	}
	stream := bytes.NewReader(append(bytes.Clone(valid), []byte("NEXT")...))
	if !probeRMITransport(&transportFixtureConn{r: stream}) || stream.Len() != len("NEXT") {
		t.Fatal("RMI probe consumed bytes after PingAck")
	}
	stream = bytes.NewReader(append([]byte{0x4e, 4, 1}, []byte("UNREAD")...))
	if probeRMITransport(&transportFixtureConn{r: stream}) || stream.Len() != len("UNREAD") {
		t.Fatal("oversized endpoint consumed untrusted body bytes")
	}
	if !probeRMITransport(&transportFixtureConn{r: iotest.DataErrReader(bytes.NewReader(valid))}) {
		t.Fatal("complete PingAck alongside EOF lost")
	}
}

func TestDCERPCEndpointPaddingAndStreamBoundaries(t *testing.T) {
	base := rpcAckFixture()
	address := []byte("do-not-log-endpoint\x00")
	offset := roundUp4(26 + len(address))
	packet := make([]byte, offset+28)
	copy(packet[:26], base[:26])
	binary.LittleEndian.PutUint16(packet[8:], uint16(len(packet)))
	binary.LittleEndian.PutUint16(packet[24:], uint16(len(address)))
	copy(packet[26:], address)
	copy(packet[offset:], base[28:])
	for cut := 0; cut <= len(packet); cut++ {
		reader := io.MultiReader(bytes.NewReader(packet[:cut]), iotest.OneByteReader(bytes.NewReader(packet[cut:])))
		evidence, ok := readDCERPCBindAck(reader)
		if !ok || !strings.Contains(evidence, "accepted") || strings.Contains(evidence, "do-not-log") {
			t.Fatal("split/padded endpoint corrupted or disclosed RPC evidence")
		}
	}
	for cut := range len(packet) {
		reader := io.MultiReader(bytes.NewReader(packet[:cut]), framingErrorReader{os.ErrDeadlineExceeded})
		if _, ok := readDCERPCBindAck(reader); ok {
			t.Fatal("incomplete RPC ack accepted")
		}
	}
	stream := bytes.NewReader(append(bytes.Clone(packet), []byte("NEXT")...))
	if _, ok := readDCERPCBindAck(stream); !ok || stream.Len() != len("NEXT") {
		t.Fatal("RPC ack reader consumed next frame")
	}
	if _, ok := readDCERPCBindAck(iotest.DataErrReader(bytes.NewReader(packet))); !ok {
		t.Fatal("complete RPC ack alongside EOF lost")
	}
}

func FuzzHandshakeFragmentation(f *testing.F) {
	f.Add(rpcAckFixture())
	f.Add(rmiHandshakeFixture())
	f.Add([]byte{'A', 'B', 0, 1, 9})
	f.Fuzz(func(t *testing.T, data []byte) {
		original := bytes.Clone(data)
		evidence, ok := readDCERPCBindAck(bytes.NewReader(data))
		fragmentedEvidence, fragmentedOK := readDCERPCBindAck(iotest.OneByteReader(bytes.NewReader(data)))
		if evidence != fragmentedEvidence || ok != fragmentedOK {
			t.Fatal("DCE/RPC result depends on chunk boundaries")
		}
		whole := &transportFixtureConn{r: bytes.NewReader(data)}
		fragmented := &transportFixtureConn{r: iotest.OneByteReader(bytes.NewReader(data))}
		if probeRMITransport(whole) != probeRMITransport(fragmented) || !bytes.Equal(whole.w.Bytes(), fragmented.w.Bytes()) {
			t.Fatal("RMI result/request depends on chunk boundaries")
		}
		if readAJPReply(bytes.NewReader(data)) != readAJPReply(iotest.OneByteReader(bytes.NewReader(data))) || !bytes.Equal(original, data) {
			t.Fatal("handshake result depends on chunks or mutates input")
		}
	})
}
