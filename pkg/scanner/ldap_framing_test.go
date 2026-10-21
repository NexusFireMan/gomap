package scanner

import (
	"bytes"
	"encoding/asn1"
	"io"
	"os"
	"testing"
	"testing/iotest"
	"time"
)

func ldapFixtureElement(tag byte, body []byte, long bool) []byte {
	header := []byte{tag}
	if long || len(body) >= 256 {
		header = append(header, 0x82, byte(len(body)>>8), byte(len(body)))
	} else if len(body) >= 128 {
		header = append(header, 0x81, byte(len(body)))
	} else {
		header = append(header, byte(len(body)))
	}
	return append(header, body...)
}

func ldapBindFixture(id, code byte, diagnostic []byte, long bool, optional ...[]byte) []byte {
	body := ldapFixtureElement(10, []byte{code}, long)
	body = append(body, ldapFixtureElement(4, nil, long)...)
	body = append(body, ldapFixtureElement(4, diagnostic, long)...)
	for _, field := range optional {
		body = append(body, field...)
	}
	message := ldapFixtureElement(2, []byte{id}, long)
	message = append(message, ldapFixtureElement(0x61, body, long)...)
	return ldapFixtureElement(0x30, message, long)
}

func TestLDAPBindResponseStructure(t *testing.T) {
	valid := ldapBindFixture(1, 0, nil, false)
	controls := ldapFixtureElement(0xa0, ldapFixtureElement(0x30, append(append(
		ldapFixtureElement(4, []byte("1.2.840.113556.1.4.319"), false), []byte{1, 1, 0xff}...),
		ldapFixtureElement(4, []byte("private-control"), false)...), false), false)
	withControls := ldapFixtureElement(0x30, append(bytes.Clone(valid[2:]), controls...), false)
	for _, data := range [][]byte{
		valid, ldapBindFixture(1, 49, []byte("private diagnostic"), false),
		ldapBindFixture(1, 14, nil, true, ldapFixtureElement(0x87, []byte("private-sasl"), true)),
		ldapBindFixture(1, 10, nil, false, ldapFixtureElement(0xa3, ldapFixtureElement(4, []byte("ldap://fixture.invalid"), false), false)),
		ldapBindFixture(1, 0, bytes.Repeat([]byte("x"), 280), true), withControls,
	} {
		original := bytes.Clone(data)
		if !validLDAPBindResponse(data, 1) || !bytes.Equal(data, original) {
			t.Fatalf("valid fixture rejected/mutated: %x", data)
		}
	}
	for name, data := range map[string][]byte{
		"wrong-id":                ldapBindFixture(2, 0, nil, false),
		"unsolicited-id":          ldapBindFixture(0, 0, nil, false),
		"request-echo":            []byte(ldapAnonymousBindRequest),
		"text-not-protocol":       []byte("LDAP service"),
		"old-text-false-positive": ldapFixtureElement(0x30, []byte("random LDAP bytes"), false),
		"negative-result":         ldapBindFixture(1, 255, nil, false),
		"invalid-utf8":            ldapBindFixture(1, 0, []byte{255}, false),
		"missing-referral":        ldapBindFixture(1, 10, nil, false),
		"empty-referral":          ldapBindFixture(1, 10, nil, false, []byte{0xa3, 0}),
		"unexpected-referral":     ldapBindFixture(1, 0, nil, false, []byte{0xa3, 0}),
		"extra-result-field":      ldapBindFixture(1, 0, nil, false, []byte{4, 0}),
		"duplicate-sasl":          ldapBindFixture(1, 14, nil, false, []byte{0x87, 0, 0x87, 0}),
		"constructed-string":      ldapFixtureElement(0x30, append([]byte{2, 1, 1}, ldapFixtureElement(0x61, []byte{10, 1, 0, 0x24, 0, 4, 0}, false)...), false),
		"empty-controls":          ldapFixtureElement(0x30, append(bytes.Clone(valid[2:]), 0xa0, 0), false),
		"duplicate-controls":      ldapFixtureElement(0x30, append(append(bytes.Clone(valid[2:]), controls...), controls...), false),
		"trailing-data":           append(bytes.Clone(valid), 0),
		"oversized":               bytes.Repeat([]byte{0}, ldapMessageLimit+1),
	} {
		t.Run(name, func(t *testing.T) {
			if validLDAPBindResponse(data, 1) {
				t.Fatalf("malformed fixture accepted: %x", data)
			}
		})
	}
	if validLDAPBindResponse(valid, 0) {
		t.Fatal("zero request ID accepted")
	}
	// Independently check the ordinary fixture against the standard ASN.1 reader.
	var message asn1.RawValue
	if rest, err := asn1.Unmarshal(valid, &message); err != nil || len(rest) != 0 {
		t.Fatalf("invalid test fixture: %v", err)
	}
}

func TestLDAPFramingAcrossEverySplit(t *testing.T) {
	for _, frame := range [][]byte{ldapBindFixture(1, 0, nil, false), ldapBindFixture(1, 49, bytes.Repeat([]byte("x"), 280), true)} {
		for cut := 0; cut <= len(frame); cut++ {
			r := io.MultiReader(bytes.NewReader(frame[:cut]), iotest.OneByteReader(bytes.NewReader(frame[cut:])))
			conn := &textFragmentConn{transportFixtureConn: transportFixtureConn{r: r}}
			if !probeLDAPBind(conn, time.Second) || conn.deadlines != 1 || conn.w.String() != ldapAnonymousBindRequest {
				t.Fatalf("split=%d: response lost or deadline/request changed", cut)
			}
		}
		for cut := 0; cut < len(frame); cut++ {
			for _, failure := range []error{io.EOF, os.ErrDeadlineExceeded, io.ErrClosedPipe} {
				r := io.MultiReader(bytes.NewReader(frame[:cut]), framingErrorReader{failure})
				if _, err := readLDAPMessage(r); err == nil || validLDAPBindResponse(frame[:cut], 1) {
					t.Fatalf("accepted truncation=%d failure=%v", cut, failure)
				}
			}
		}
		if got, err := readLDAPMessage(iotest.DataErrReader(bytes.NewReader(frame))); err != nil || !bytes.Equal(got, frame) {
			t.Fatal("complete final bytes alongside EOF lost")
		}
		stream := bytes.NewReader(append(bytes.Clone(frame), frame...))
		if _, err := readLDAPMessage(stream); err != nil || stream.Len() != len(frame) {
			t.Fatal("next LDAP message consumed")
		}
	}
}

func TestLDAPRejectsLengthBeforeBodyRead(t *testing.T) {
	for _, header := range [][]byte{{0x31, 0}, {0x30, 0}, {0x30, 0x80}, {0x30, 0x85}, {0x30, 0x82, 0x10, 0}, {0x30, 0x84, 255, 255, 255, 255}} {
		stream := bytes.NewReader(append(bytes.Clone(header), []byte("UNREAD")...))
		if _, err := readLDAPMessage(stream); err == nil || stream.Len() != len("UNREAD") {
			t.Fatalf("invalid header read payload: %x remaining=%d", header, stream.Len())
		}
	}
	frame := ldapFixtureElement(0x30, bytes.Repeat([]byte{'x'}, ldapMessageLimit-4), false)
	if got, err := readLDAPMessage(bytes.NewReader(frame)); err != nil || len(got) != ldapMessageLimit {
		t.Fatal("legal maximum frame was not read")
	}
}

func TestLDAPOptionalFieldsAndPrimitiveBounds(t *testing.T) {
	valid := ldapBindFixture(1, 0, nil, false)
	control := func(fields []byte) []byte { return ldapFixtureElement(0x30, fields, false) }
	for _, fields := range [][]byte{
		ldapFixtureElement(4, []byte("1..2"), false),
		ldapFixtureElement(4, []byte("1.02"), false),
		ldapFixtureElement(4, []byte("not-an-oid"), false),
		append(ldapFixtureElement(4, []byte("1.2"), false), 1, 1, 1),
		append(ldapFixtureElement(4, []byte("1.2"), false), 4, 0, 1, 1, 0xff),
		append(ldapFixtureElement(4, []byte("1.2"), false), 0x24, 0),
	} {
		controls := ldapFixtureElement(0xa0, control(fields), false)
		frame := ldapFixtureElement(0x30, append(bytes.Clone(valid[2:]), controls...), false)
		if validLDAPBindResponse(frame, 1) {
			t.Fatalf("invalid control accepted: %x", frame)
		}
	}
	for _, count := range []int{32, 33} {
		controls := ldapFixtureElement(0xa0, bytes.Repeat(control(ldapFixtureElement(4, []byte("1.2"), false)), count), false)
		frame := ldapFixtureElement(0x30, append(bytes.Clone(valid[2:]), controls...), false)
		if validLDAPBindResponse(frame, 1) != (count == 32) {
			t.Fatalf("control count bound: %d", count)
		}
		referral := ldapFixtureElement(0xa3, bytes.Repeat(ldapFixtureElement(4, []byte("ldap://fixture.invalid"), false), count), false)
		if validLDAPBindResponse(ldapBindFixture(1, 10, nil, false, referral), 1) != (count == 32) {
			t.Fatalf("referral count bound: %d", count)
		}
	}
	for _, fields := range [][]byte{
		{2, 0}, {2, 2, 0, 1}, {2, 1, 255}, {2, 5, 0, 128, 0, 0, 0},
	} {
		frame := ldapFixtureElement(0x30, append(bytes.Clone(fields), valid[5:]...), false)
		if validLDAPBindResponse(frame, 1) {
			t.Fatalf("invalid message ID accepted: %x", fields)
		}
	}
}

func FuzzLDAPBindFraming(f *testing.F) {
	f.Add(ldapBindFixture(1, 0, nil, false))
	f.Add(ldapBindFixture(1, 49, []byte("private diagnostic"), true))
	f.Add([]byte(ldapAnonymousBindRequest))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > ldapMessageLimit+8 {
			return
		}
		original := bytes.Clone(data)
		a, errA := readLDAPMessage(bytes.NewReader(data))
		b, errB := readLDAPMessage(iotest.OneByteReader(bytes.NewReader(data)))
		valid := validLDAPBindResponse(data, 1)
		if (errA == nil) != (errB == nil) || !bytes.Equal(a, b) || len(a) > ldapMessageLimit || !bytes.Equal(data, original) {
			t.Fatal("LDAP framing depends on fragmentation or mutated input")
		}
		if valid && (errA != nil || !bytes.Equal(a, data)) {
			t.Fatal("validated LDAP response is not exactly one complete frame")
		}
	})
}
