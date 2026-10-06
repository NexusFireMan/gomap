package scanner

import (
	"encoding/binary"

	"golang.org/x/net/dns/dnsmessage"
)

// udpDNSVersion validates a conservative wire-format subset, not query correlation
// or server identity. Names and record bodies are decoded by dnsmessage.
func udpDNSVersion(port int, payload []byte) string {
	if len(payload) < 12 || len(payload) > maxUDPResponseBytes || !udpDNSFrameValid(payload) {
		return ""
	}
	var message dnsmessage.Message
	if message.Unpack(payload) != nil || !message.Response || message.OpCode != 0 || message.Truncated {
		return ""
	}
	flags := binary.BigEndian.Uint16(payload[2:4])
	for _, question := range message.Questions {
		class := question.Class
		if port == 5353 {
			class &= 0x7fff
		}
		if question.Type == 0 || (class != dnsmessage.ClassINET && (port != 53 || class != dnsmessage.ClassCHAOS)) {
			return ""
		}
	}
	for _, records := range [][]dnsmessage.Resource{message.Answers, message.Authorities, message.Additionals} {
		for _, record := range records {
			if record.Header.Type == dnsmessage.TypeOPT {
				continue // OPT class encodes the advertised UDP size, not a DNS class.
			}
			class := record.Header.Class
			if port == 5353 {
				class &= 0x7fff
			}
			if class != dnsmessage.ClassINET && (port != 53 || class != dnsmessage.ClassCHAOS) {
				return ""
			}
		}
	}
	switch port {
	case 53:
		if flags&0x0040 != 0 || len(message.Questions) != 1 || message.RCode > dnsmessage.RCodeRefused {
			return ""
		}
		return "DNS response"
	case 5353:
		if !message.Authoritative || message.RCode != 0 || len(message.Answers) == 0 || flags&0x01f0 != 0 {
			return ""
		}
		return "mDNS response"
	case 5355:
		// LLMNR repurposes AA as Conflict and RD as Tentative; neither is DNS recursion.
		if flags&0x01f0 != 0 || message.RCode != 0 || len(message.Questions) != 1 || len(message.Answers) == 0 {
			return ""
		}
		return "LLMNR response"
	default:
		return ""
	}
}

// The library decoder permits trailing bytes and some mismatched RDLENGTHs.
// Check framing independently without duplicating compression/name decoding.
func udpDNSFrameValid(payload []byte) bool {
	if len(payload) < 12 || len(payload) > maxUDPResponseBytes {
		return false
	}
	off := 12
	for section := 0; section < 4; section++ {
		count := int(binary.BigEndian.Uint16(payload[4+section*2 : 6+section*2]))
		for range count {
			var ok bool
			off, ok = udpDNSNameEnd(payload, off, len(payload))
			if !ok {
				return false
			}
			if section == 0 {
				if off+4 > len(payload) {
					return false
				}
				off += 4
				continue
			}
			if off+10 > len(payload) {
				return false
			}
			kind := dnsmessage.Type(binary.BigEndian.Uint16(payload[off : off+2]))
			length := int(binary.BigEndian.Uint16(payload[off+8 : off+10]))
			off += 10
			end := off + length
			if end > len(payload) || !udpDNSBodyFrameValid(payload, off, end, kind) {
				return false
			}
			off = end
		}
	}
	return off == len(payload)
}

func udpDNSBodyFrameValid(payload []byte, off, end int, kind dnsmessage.Type) bool {
	switch kind {
	case dnsmessage.TypeA:
		return end-off == 4
	case dnsmessage.TypeAAAA:
		return end-off == 16
	case dnsmessage.TypeTXT:
		for off < end {
			off += 1 + int(payload[off])
		}
		return off == end
	case dnsmessage.TypeOPT:
		for off < end {
			if off+4 > end {
				return false
			}
			off += 4 + int(binary.BigEndian.Uint16(payload[off+2:off+4]))
		}
		return off == end
	case dnsmessage.TypeMX:
		off += 2
	case dnsmessage.TypeSRV:
		off += 6
	case dnsmessage.TypeNS, dnsmessage.TypeCNAME, dnsmessage.TypePTR, dnsmessage.TypeSOA:
	default:
		return false // Unsupported record bodies stay low-confidence hints.
	}
	var ok bool
	off, ok = udpDNSNameEnd(payload, off, end)
	if !ok {
		return false
	}
	if kind == dnsmessage.TypeSOA {
		off, ok = udpDNSNameEnd(payload, off, end)
		return ok && off+20 == end
	}
	return off == end
}

func udpDNSNameEnd(payload []byte, off, end int) (int, bool) {
	for off < end {
		label := payload[off]
		off++
		if label == 0 {
			return off, true
		}
		if label&0xc0 == 0xc0 {
			return off + 1, off < end
		}
		if label&0xc0 != 0 || off+int(label) > end {
			return 0, false
		}
		off += int(label)
	}
	return 0, false
}
