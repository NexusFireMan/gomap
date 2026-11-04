package scanner

import (
	"encoding/asn1"
	"errors"
	"io"
	"net"
	"time"
	"unicode/utf8"
)

const ldapMessageLimit = 4096
const ldapAnonymousBindRequest = "\x30\x0c\x02\x01\x01\x60\x07\x02\x01\x03\x04\x00\x80\x00"

var errInvalidLDAP = errors.New("invalid LDAP frame")

// LDAP uses definite BER lengths, including non-minimal long forms. Bound
// lengths before allocating; primitive/tag validation remains in encoding/asn1.
func ldapBERLength(header []byte) (int, int, bool) {
	if len(header) < 2 {
		return 0, 0, false
	}
	length, start := int(header[1]), 2
	if length&0x80 != 0 {
		count := length & 0x7f
		if count == 0 || count > 4 || len(header) < 2+count {
			return 0, 0, false
		}
		length, start = 0, 2+count
		for _, b := range header[2:start] {
			if length > ldapMessageLimit/256 {
				return 0, 0, false
			}
			length = length*256 + int(b)
		}
	}
	return start, length, length <= ldapMessageLimit-start
}

func readLDAPMessage(r io.Reader) ([]byte, error) {
	header := make([]byte, 2, 6)
	if _, err := io.ReadFull(r, header); err != nil {
		return nil, err
	}
	if header[0] != 0x30 {
		return nil, errInvalidLDAP
	}
	if header[1]&0x80 != 0 {
		count := int(header[1] & 0x7f)
		if count == 0 || count > 4 {
			return nil, errInvalidLDAP
		}
		header = header[:2+count]
		if _, err := io.ReadFull(r, header[2:]); err != nil {
			return nil, err
		}
	}
	_, length, ok := ldapBERLength(header)
	if !ok {
		return nil, errInvalidLDAP
	}
	return readFrameBody(r, header, length, ldapMessageLimit-len(header))
}

func ldapField(data []byte, value any) ([]byte, bool) {
	start, length, ok := ldapBERLength(data)
	if !ok || length > len(data)-start || data[0]&0x1f == 0x1f {
		return nil, false
	}
	// Normalize just this element's length, leaving its tag/value unchanged.
	canonical := []byte{data[0]}
	switch {
	case length < 128:
		canonical = append(canonical, byte(length))
	case length < 256:
		canonical = append(canonical, 0x81, byte(length))
	default:
		canonical = append(canonical, 0x82, byte(length>>8), byte(length))
	}
	canonical = append(canonical, data[start:start+length]...)
	rest, err := asn1.Unmarshal(canonical, value)
	return data[start+length:], err == nil && len(rest) == 0
}

func ldapTag(v asn1.RawValue, class, tag int, compound bool) bool {
	return v.Class == class && v.Tag == tag && v.IsCompound == compound
}

func validLDAPBindResponse(data []byte, expectedID int) bool {
	if len(data) > ldapMessageLimit || expectedID <= 0 {
		return false
	}
	var envelope, response asn1.RawValue
	rest, ok := ldapField(data, &envelope)
	if !ok || len(rest) != 0 || !ldapTag(envelope, asn1.ClassUniversal, asn1.TagSequence, true) {
		return false
	}
	var messageID int
	rest, ok = ldapField(envelope.Bytes, &messageID)
	if !ok || messageID != expectedID {
		return false
	}
	rest, ok = ldapField(rest, &response)
	if !ok || !ldapTag(response, asn1.ClassApplication, 1, true) {
		return false
	}
	if len(rest) > 0 && !validLDAPControls(rest) {
		return false
	}
	var result asn1.Enumerated
	var matchedDN, diagnostic []byte
	body, ok := ldapField(response.Bytes, &result)
	if !ok || result < 0 || result > 2147483647 {
		return false
	}
	body, ok = ldapField(body, &matchedDN)
	if !ok || !utf8.Valid(matchedDN) {
		return false
	}
	body, ok = ldapField(body, &diagnostic)
	if !ok || !utf8.Valid(diagnostic) {
		return false
	}
	if len(body) > 0 && body[0] == 0xa3 {
		var referral asn1.RawValue
		body, ok = ldapField(body, &referral)
		if !ok || len(referral.Bytes) == 0 || result != 10 {
			return false
		}
		for urls, n := referral.Bytes, 0; len(urls) > 0; n++ {
			var uri []byte
			urls, ok = ldapField(urls, &uri)
			if !ok || n >= 32 || len(uri) == 0 || !utf8.Valid(uri) {
				return false
			}
		}
	} else if result == 10 {
		return false
	}
	if len(body) > 0 {
		var sasl asn1.RawValue
		body, ok = ldapField(body, &sasl)
		if !ok || !ldapTag(sasl, asn1.ClassContextSpecific, 7, false) {
			return false
		}
	}
	return len(body) == 0
}

func validLDAPControls(data []byte) bool {
	var controls asn1.RawValue
	rest, ok := ldapField(data, &controls)
	if !ok || len(rest) != 0 || !ldapTag(controls, asn1.ClassContextSpecific, 0, true) || len(controls.Bytes) == 0 {
		return false
	}
	for data, count := controls.Bytes, 0; len(data) > 0; count++ {
		var control asn1.RawValue
		data, ok = ldapField(data, &control)
		if !ok || count >= 32 || !ldapTag(control, asn1.ClassUniversal, asn1.TagSequence, true) {
			return false
		}
		var oid []byte
		fields, ok := ldapField(control.Bytes, &oid)
		if !ok || !validLDAPControlOID(oid) {
			return false
		}
		if len(fields) > 0 && fields[0] == 1 {
			var critical bool
			fields, ok = ldapField(fields, &critical)
			if !ok {
				return false
			}
		}
		if len(fields) > 0 {
			var value []byte
			fields, ok = ldapField(fields, &value)
			if !ok {
				return false
			}
		}
		if len(fields) != 0 {
			return false
		}
	}
	return true
}

func validLDAPControlOID(oid []byte) bool {
	digits, dots := 0, 0
	leadingZero := false
	for _, c := range oid {
		if c == '.' && digits > 0 {
			digits, dots = 0, dots+1
		} else if c >= '0' && c <= '9' {
			if digits > 0 && leadingZero {
				return false
			}
			if digits == 0 {
				leadingZero = c == '0'
			}
			digits++
		} else {
			return false
		}
	}
	return digits > 0 && dots > 0
}

func probeLDAPBind(conn net.Conn, timeout time.Duration) bool {
	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return false
	}
	if n, err := io.WriteString(conn, ldapAnonymousBindRequest); err != nil || n != len(ldapAnonymousBindRequest) {
		return false
	}
	frame, err := readLDAPMessage(conn)
	return err == nil && validLDAPBindResponse(frame, 1)
}
