package scanner

import (
	"bytes"
	"encoding/binary"
	"io"
	"os"
	"testing"
	"testing/iotest"
)

func tdsPayloadFixture(full bool) []byte {
	values := [][]byte{{15, 0, 4, 210, 0, 0}, {2}}
	if full {
		values = append(values, []byte{0}, nil, []byte{1}, make([]byte, 36), []byte{1}, make([]byte, 32))
	}
	table := make([]byte, len(values)*5+1)
	table[len(table)-1] = 0xff
	data := bytes.Clone(table)
	for token, value := range values {
		pos := token * 5
		data[pos] = byte(token)
		binary.BigEndian.PutUint16(data[pos+1:], uint16(len(data)))
		binary.BigEndian.PutUint16(data[pos+3:], uint16(len(value)))
		data = append(data, value...)
	}
	return data
}

func tdsPacketFixture(payload []byte, status, packetID byte) []byte {
	header := []byte{4, status, 0, 0, 0, 37, packetID, 0}
	binary.BigEndian.PutUint16(header[2:], uint16(len(header)+len(payload)))
	return append(header, payload...)
}

func TestTDSPreloginStructure(t *testing.T) {
	for _, payload := range [][]byte{tdsPayloadFixture(false), tdsPayloadFixture(true)} {
		if !validTDSPrelogin(payload) {
			t.Fatal("complete PRELOGIN option table rejected")
		}
		for end := 0; end < len(payload); end++ {
			if validTDSPrelogin(payload[:end]) {
				t.Fatalf("truncated option data accepted at %d", end)
			}
		}
	}
	for _, mutate := range []func([]byte){
		func(p []byte) { p[0] = 1 },
		func(p []byte) { p[5] = 0 },
		func(p []byte) { p[5] = 8 },
		func(p []byte) { p[10] = 0 },
		func(p []byte) { binary.BigEndian.PutUint16(p[1:], 0) },
		func(p []byte) { binary.BigEndian.PutUint16(p[1:], 65535) },
		func(p []byte) { binary.BigEndian.PutUint16(p[3:], 65535) },
		func(p []byte) { binary.BigEndian.PutUint16(p[3:], 5) },
		func(p []byte) { binary.BigEndian.PutUint16(p[8:], 0) },
		func(p []byte) { binary.BigEndian.PutUint16(p[6:], 11) },
		func(p []byte) { p[len(p)-1] = 4 },
	} {
		payload := tdsPayloadFixture(false)
		mutate(payload)
		if validTDSPrelogin(payload) {
			t.Fatalf("malformed PRELOGIN accepted: %x", payload)
		}
	}
	for token := 2; token <= 7; token++ {
		payload := tdsPayloadFixture(true)
		binary.BigEndian.PutUint16(payload[token*5+3:], 2)
		if validTDSPrelogin(payload) {
			t.Fatalf("invalid option length accepted: token=%d", token)
		}
	}
}

func TestTDSFramingAcrossEverySplit(t *testing.T) {
	payload := tdsPayloadFixture(true)
	for _, wire := range [][]byte{
		tdsPacketFixture(payload, 1, 1),
		append(tdsPacketFixture(payload[:3], 0, 255), tdsPacketFixture(payload[3:], 1, 0)...),
	} {
		for cut := 0; cut <= len(wire); cut++ {
			r := io.MultiReader(bytes.NewReader(wire[:cut]), iotest.OneByteReader(bytes.NewReader(wire[cut:])))
			got, err := readTDSPrelogin(r)
			if err != nil || !bytes.Equal(got, payload) {
				t.Fatalf("split %d: err=%v got=%x", cut, err, got)
			}
		}
		for cut := 0; cut < len(wire); cut++ {
			for _, failure := range []error{io.EOF, os.ErrDeadlineExceeded, io.ErrClosedPipe} {
				r := io.MultiReader(bytes.NewReader(wire[:cut]), framingErrorReader{failure})
				if _, err := readTDSPrelogin(r); err == nil {
					t.Fatalf("accepted incomplete stream cut=%d failure=%v", cut, failure)
				}
			}
		}
		if got, err := readTDSPrelogin(iotest.DataErrReader(bytes.NewReader(wire))); err != nil || !bytes.Equal(got, payload) {
			t.Fatal("final bytes alongside EOF lost")
		}
		stream := bytes.NewReader(append(bytes.Clone(wire), []byte("NEXT-MESSAGE")...))
		if _, err := readTDSPrelogin(stream); err != nil || stream.Len() != len("NEXT-MESSAGE") {
			t.Fatal("next message consumed")
		}
	}
}

func TestTDSRejectsInvalidHeadersAndPacketSequences(t *testing.T) {
	payload := tdsPayloadFixture(false)
	for _, mutate := range []func([]byte){
		func(p []byte) { p[0] = 0x12 }, // A reflected request is not a server response.
		func(p []byte) { p[1] = 3 },
		func(p []byte) { p[7] = 1 },
		func(p []byte) { binary.BigEndian.PutUint16(p[2:], 7) },
		func(p []byte) { binary.BigEndian.PutUint16(p[2:], 8) },
		func(p []byte) { binary.BigEndian.PutUint16(p[2:], tdsMessageLimit+9) },
	} {
		wire := tdsPacketFixture(payload, 1, 1)
		mutate(wire)
		stream := bytes.NewReader(wire)
		if _, err := readTDSPrelogin(stream); err == nil || stream.Len() != len(payload) {
			t.Fatal("invalid header consumed body bytes")
		}
	}
	for _, mutate := range []func([]byte){
		func(p []byte) { p[6] = 1 },
		func(p []byte) { p[5]++ },
		func(p []byte) { p[0] = 0x12 },
	} {
		first := tdsPacketFixture(payload[:3], 0, 1)
		second := tdsPacketFixture(payload[3:], 1, 2)
		mutate(second)
		stream := bytes.NewReader(append(first, second...))
		if _, err := readTDSPrelogin(stream); err == nil || stream.Len() != len(payload)-3 {
			t.Fatal("inconsistent packet sequence accepted or body consumed")
		}
	}
	if _, err := readTDSPrelogin(bytes.NewReader(tdsPacketFixture([]byte("not a PRELOGIN"), 1, 1))); err == nil {
		t.Fatal("packet type alone confirmed TDS")
	}
}

func TestTDSMessageAndPacketBudgets(t *testing.T) {
	payload := tdsPayloadFixture(false)
	maximum := append(bytes.Clone(payload), make([]byte, tdsMessageLimit-len(payload))...)
	if got, err := readTDSPrelogin(bytes.NewReader(tdsPacketFixture(maximum, 1, 1))); err != nil || len(got) != tdsMessageLimit {
		t.Fatal("maximum bounded message rejected")
	}
	for _, count := range []int{tdsPacketLimit, tdsPacketLimit + 1} {
		payload := tdsPayloadFixture(true)
		var wire []byte
		for i := 0; i < count; i++ {
			body, status := payload[i:i+1], byte(0)
			if i == count-1 {
				body, status = payload[i:], 1
			}
			wire = append(wire, tdsPacketFixture(body, status, byte(i+1))...)
		}
		stream := bytes.NewReader(wire)
		_, err := readTDSPrelogin(stream)
		if (err == nil) != (count == tdsPacketLimit) || (count > tdsPacketLimit && stream.Len() == 0) {
			t.Fatalf("packet cap failed: count=%d err=%v", count, err)
		}
	}
	first := tdsPacketFixture(maximum[:len(maximum)-1], 0, 1)
	second := tdsPacketFixture([]byte{0, 0}, 1, 2)
	stream := bytes.NewReader(append(first, second...))
	if _, err := readTDSPrelogin(stream); err == nil || stream.Len() != 2 {
		t.Fatal("cumulative limit did not stop before reading excess body")
	}
}

func FuzzTDSPreloginFraming(f *testing.F) {
	f.Add(tdsPacketFixture(tdsPayloadFixture(false), 1, 1))
	f.Add(tdsPacketFixture(tdsPayloadFixture(true), 1, 1))
	f.Add([]byte{4, 1, 0, 8, 0, 0, 1, 0})
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > tdsMessageLimit+8*tdsPacketLimit+8 {
			return
		}
		original := bytes.Clone(data)
		a, errA := readTDSPrelogin(bytes.NewReader(data))
		b, errB := readTDSPrelogin(iotest.OneByteReader(bytes.NewReader(data)))
		validTDSPrelogin(data)
		if (errA == nil) != (errB == nil) || !bytes.Equal(a, b) || len(a) > tdsMessageLimit || !bytes.Equal(data, original) {
			t.Fatal("TDS framing depends on fragmentation or mutated input")
		}
		if errA == nil && !validTDSPrelogin(a) {
			t.Fatal("invalid PRELOGIN accepted")
		}
	})
}

func BenchmarkLDAPAndTDSBoundedParsing(b *testing.B) {
	ldap := ldapBindFixture(1, 0, nil, false)
	tds := tdsPacketFixture(tdsPayloadFixture(false), 1, 1)
	b.Run("LDAP", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			if !validLDAPBindResponse(ldap, 1) {
				b.Fatal("LDAP fixture rejected")
			}
		}
	})
	b.Run("TDS", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			if _, err := readTDSPrelogin(bytes.NewReader(tds)); err != nil {
				b.Fatal(err)
			}
		}
	})
}
