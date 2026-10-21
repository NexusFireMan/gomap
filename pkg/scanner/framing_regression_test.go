package scanner

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"testing"
	"testing/iotest"
)

type framingErrorReader struct{ err error }

func (r framingErrorReader) Read([]byte) (int, error) { return 0, r.err }

func TestFramedReadersAcrossEverySplit(t *testing.T) {
	rpc := make([]byte, 28)
	binary.BigEndian.PutUint32(rpc, 0x80000018)
	binary.BigEndian.PutUint32(rpc[4:], 123)
	binary.BigEndian.PutUint32(rpc[8:], 1)
	dns := append([]byte{0, 12}, make([]byte, 12)...)
	for _, tc := range []struct {
		name  string
		frame []byte
		read  func(io.Reader) ([]byte, error)
	}{
		{"dns", dns, readDNSMessage}, {"mysql", mysqlFixture(), readMySQLPacket},
		{"rpc", rpc, readRPCRecord},
		{"rdp", rdpConfirmFixture(), readRDPConfirm},
		{"smb", smbFramingFixture(), readSMBMessage},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for cut := 0; cut <= len(tc.frame); cut++ {
				reader := io.MultiReader(bytes.NewReader(tc.frame[:cut]), iotest.OneByteReader(bytes.NewReader(tc.frame[cut:])))
				got, err := tc.read(reader)
				if err != nil || !bytes.Equal(got, tc.frame) {
					t.Fatalf("split %d: err=%v got=%x", cut, err, got)
				}
			}
			if got, err := tc.read(iotest.DataErrReader(bytes.NewReader(tc.frame))); err != nil || !bytes.Equal(got, tc.frame) {
				t.Fatal("complete final bytes alongside EOF lost")
			}
			stream := bytes.NewReader(append(bytes.Clone(tc.frame), []byte("NEXT-FRAME")...))
			if _, err := tc.read(stream); err != nil || stream.Len() != len("NEXT-FRAME") {
				t.Fatal("reader consumed bytes belonging to the next frame")
			}
			for cut := 0; cut < len(tc.frame); cut++ {
				for _, failure := range []error{io.EOF, os.ErrDeadlineExceeded, io.ErrClosedPipe} {
					reader := io.MultiReader(bytes.NewReader(tc.frame[:cut]), framingErrorReader{failure})
					if _, err := tc.read(reader); err == nil {
						t.Fatalf("incomplete frame accepted: cut=%d failure=%v", cut, failure)
					}
				}
			}
		})
	}
}

func TestFramedReadersRejectLengthsBeforeReadingBody(t *testing.T) {
	for _, tc := range []struct {
		name   string
		header []byte
		read   func(io.Reader) ([]byte, error)
	}{
		{"dns-zero", []byte{0, 0}, readDNSMessage},
		{"mysql-zero", []byte{0, 0, 0, 0}, readMySQLPacket},
		{"mysql-overflow", []byte{1, 16, 0, 0}, readMySQLPacket},
		{"mysql-maximum-wire", []byte{255, 255, 255, 0}, readMySQLPacket},
		{"rpc-overflow", []byte{0x80, 0, 16, 1}, readRPCRecord},
		{"rdp-overflow", []byte{3, 0, 255, 255}, readRDPConfirm},
		{"rdp-invalid-type", []byte{2, 0, 0, 19}, readRDPConfirm},
		{"smb-zero", []byte{0, 0, 0, 0}, readSMBMessage},
		{"smb-overflow", []byte{0, 1, 0, 1}, readSMBMessage},
		{"smb-session-type", []byte{0x85, 0, 0, 1}, readSMBMessage},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stream := bytes.NewReader(append(bytes.Clone(tc.header), []byte("UNREAD-BODY")...))
			if _, err := tc.read(stream); err == nil || stream.Len() != len("UNREAD-BODY") {
				t.Fatal("invalid declared size consumed body bytes")
			}
		})
	}
	for _, size := range []int{1, 4096} {
		header := []byte{byte(size), byte(size >> 8), byte(size >> 16), 0}
		packet := append(header, bytes.Repeat([]byte{'x'}, size)...)
		if got, err := readMySQLPacket(iotest.HalfReader(bytes.NewReader(packet))); err != nil || !bytes.Equal(got, packet) {
			t.Fatal("legal MySQL size rejected")
		}
	}
}

func TestRPCRecordFragmentBudgetsAndBoundaries(t *testing.T) {
	for _, count := range []int{1, 2, 64} {
		var wire bytes.Buffer
		for i := 0; i < count; i++ {
			var header [4]byte
			marker := uint32(1)
			if i == count-1 {
				marker |= 0x80000000
			}
			binary.BigEndian.PutUint32(header[:], marker)
			wire.Write(header[:])
			wire.WriteByte(byte(i))
		}
		got, err := readRPCRecord(iotest.OneByteReader(bytes.NewReader(wire.Bytes())))
		if err != nil || len(got) != 4+count || binary.BigEndian.Uint32(got) != 0x80000000|uint32(count) {
			t.Fatalf("fragment count %d: %v", count, err)
		}
	}
	tooMany := append(make([]byte, 64*4), []byte("UNREAD")...)
	stream := bytes.NewReader(tooMany)
	if _, err := readRPCRecord(stream); err == nil || stream.Len() != len("UNREAD") {
		t.Fatal("zero-length continuation fragments exceeded read budget")
	}
	var marker [4]byte
	binary.BigEndian.PutUint32(marker[:], 0x80001000)
	maximum := append(marker[:], make([]byte, 4096)...)
	if got, err := readRPCRecord(bytes.NewReader(maximum)); err != nil || len(got) != 4100 {
		t.Fatal("maximum RPC record rejected")
	}
	oversized := append([]byte{0, 0, 8, 0}, make([]byte, 2048)...)
	oversized = append(oversized, []byte{0x80, 0, 8, 1}...)
	oversized = append(oversized, []byte("UNREAD")...)
	stream = bytes.NewReader(oversized)
	if _, err := readRPCRecord(stream); err == nil || stream.Len() != len("UNREAD") {
		t.Fatal("cumulative RPC record size was not bounded")
	}
	if _, err := readRPCRecord(io.MultiReader(bytes.NewReader([]byte{0, 0, 0, 0}), framingErrorReader{os.ErrDeadlineExceeded})); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatal("transport deadline was not propagated")
	}
}

func FuzzBoundedStreamFraming(f *testing.F) {
	f.Add(uint8(0), []byte{0, 1, 'x'})
	f.Add(uint8(1), mysqlFixture())
	f.Add(uint8(2), []byte{0x80, 0, 0, 1, 'x'})
	f.Add(uint8(3), rdpConfirmFixture())
	f.Add(uint8(4), smbFramingFixture())
	f.Fuzz(func(t *testing.T, kind uint8, data []byte) {
		readers := []func(io.Reader) ([]byte, error){readDNSMessage, readMySQLPacket, readRPCRecord, readRDPConfirm, readSMBMessage}
		read := readers[int(kind)%len(readers)]
		original := bytes.Clone(data)
		whole, err := read(bytes.NewReader(data))
		fragmented, fragmentedErr := read(iotest.OneByteReader(bytes.NewReader(data)))
		if (err == nil) != (fragmentedErr == nil) || !bytes.Equal(whole, fragmented) || !bytes.Equal(original, data) {
			t.Fatal("reader result depends on stream fragmentation or mutates input")
		}
		limit := []int{65537, 4100, 4100, 19, 65540}[int(kind)%len(readers)]
		if len(whole) > limit {
			t.Fatal("frame exceeds allocation bound")
		}
	})
}

func smbFramingFixture() []byte {
	packet := make([]byte, 132)
	binary.BigEndian.PutUint32(packet, 128)
	body := packet[4:]
	copy(body, "\xfeSMB")
	binary.LittleEndian.PutUint16(body[4:], 64)
	binary.LittleEndian.PutUint32(body[16:], 1)
	binary.LittleEndian.PutUint16(body[64:], 65)
	binary.LittleEndian.PutUint16(body[68:], 0x0302)
	return packet
}

func TestAJPReplyRejectsTruncationAndWrongFrames(t *testing.T) {
	valid := []byte{'A', 'B', 0, 1, 9}
	for cut := 0; cut <= len(valid); cut++ {
		reader := io.MultiReader(bytes.NewReader(valid[:cut]), iotest.OneByteReader(bytes.NewReader(valid[cut:])))
		if !readAJPReply(reader) {
			t.Fatalf("valid split rejected at %d", cut)
		}
	}
	for end := range len(valid) {
		if readAJPReply(bytes.NewReader(valid[:end])) {
			t.Fatal("truncated CPONG accepted")
		}
	}
	for _, header := range [][]byte{{0x12, 0x34, 0, 1}, {'A', 'B', 0, 0}, {'A', 'B', 0xff, 0xff}} {
		stream := bytes.NewReader(append(bytes.Clone(header), []byte("UNREAD")...))
		if readAJPReply(stream) || stream.Len() != len("UNREAD") {
			t.Fatal("invalid AJP header read an untrusted body")
		}
	}
	if readAJPReply(bytes.NewReader([]byte{'A', 'B', 0, 1, 10})) {
		t.Fatal("request packet treated as a reply")
	}
	stream := bytes.NewReader(append(bytes.Clone(valid), []byte("NEXT")...))
	if !readAJPReply(stream) || stream.Len() != len("NEXT") {
		t.Fatal("CPONG over-read the next frame")
	}
	if !readAJPReply(iotest.DataErrReader(bytes.NewReader(valid))) {
		t.Fatal("complete CPONG with final EOF lost")
	}
}
