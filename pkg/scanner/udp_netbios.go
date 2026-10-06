package scanner

import (
	"encoding/binary"

	"golang.org/x/net/dns/dnsmessage"
)

const (
	netbiosNameRecord   dnsmessage.Type = 32
	netbiosStatusRecord dnsmessage.Type = 33
)

func udpNetBIOSVersion(payload []byte) string {
	if !udpNameServiceFrameValid(payload, udpNetBIOSBodyValid) {
		return ""
	}
	var parser dnsmessage.Parser
	header, err := parser.Start(payload)
	if err != nil || !header.Response || header.OpCode != 0 || header.RCode != 0 || header.Truncated ||
		binary.BigEndian.Uint16(payload[4:6]) > 1 || binary.BigEndian.Uint16(payload[6:8]) != 1 ||
		binary.BigEndian.Uint32(payload[8:12]) != 0 ||
		binary.BigEndian.Uint16(payload[2:4])&0x0070 != 0 {
		return ""
	}
	questions, err := parser.AllQuestions()
	if err != nil {
		return ""
	}
	answer, err := parser.AnswerHeader()
	if err != nil || answer.Class != dnsmessage.ClassINET || !netbiosEncodedNameValid(answer.Name) {
		return ""
	}
	// NBSTAT's type 33 overlaps DNS SRV: decode its body as opaque NBNS data.
	if _, err := parser.UnknownResource(); err != nil {
		return ""
	}
	for _, question := range questions {
		if question.Class != dnsmessage.ClassINET || question.Type != answer.Type || question.Name != answer.Name {
			return ""
		}
	}
	if answer.Type == netbiosStatusRecord {
		return "NetBIOS node status response"
	}
	return "NetBIOS name service response"
}

func netbiosEncodedNameValid(name dnsmessage.Name) bool {
	text := name.String()
	if len(text) < 33 || text[32] != '.' {
		return false
	}
	for i := 0; i < 32; i++ {
		if text[i] < 'A' || text[i] > 'P' {
			return false
		}
	}
	return true
}

func udpNetBIOSBodyValid(payload []byte, off, end int, kind dnsmessage.Type) bool {
	switch kind {
	case netbiosNameRecord:
		if end-off == 0 || (end-off)%6 != 0 {
			return false
		}
		for pos := off; pos < end; pos += 6 {
			if binary.BigEndian.Uint16(payload[pos:pos+2])&0x1fff != 0 {
				return false
			}
		}
		return true
	case netbiosStatusRecord:
		// RFC 1002: count, 18-byte name entries, then 46-byte statistics.
		if off == end || end-off != 1+18*int(payload[off])+46 {
			return false
		}
		for pos := off + 1; pos < off+1+18*int(payload[off]); pos += 18 {
			flags := binary.BigEndian.Uint16(payload[pos+16 : pos+18])
			if flags&0x01ff != 0 || flags&0x0400 == 0 {
				return false
			}
		}
		return true
	default:
		return false
	}
}
