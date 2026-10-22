package scanner

import (
	"encoding/binary"
	"fmt"
)

func rdpDisclosure(frame []byte) (version, confidence, evidence string, ok bool) {
	if !validRDPConfirm(frame) {
		return "", "", "", false
	}
	if len(frame) == 11 {
		return "RDP service (unconfirmed)", "low", "X.224 connection confirm; no RDP negotiation field; product/OS not established", true
	}
	if frame[11] == 3 {
		return "RDP service (negotiation rejected)", "medium", fmt.Sprintf("RDP negotiation failure: code=%d; no session established; product/OS not established", binary.LittleEndian.Uint32(frame[15:19])), true
	}
	selected := binary.LittleEndian.Uint32(frame[15:19])
	return "RDP service", "medium", "RDP negotiation selected " + rdpProtocolName(selected) + "; product/OS not established", true
}

// The probe offers standard RDP, TLS and CredSSP; do not infer a protocol
// from bytes outside the fixed X.224 Connection Confirm negotiation field.
func validRDPConfirm(data []byte) bool {
	if (len(data) != 11 && len(data) != 19) || data[0] != 3 || data[1] != 0 ||
		int(binary.BigEndian.Uint16(data[2:4])) != len(data) || int(data[4]) != len(data)-5 ||
		data[5] != 0xd0 || binary.BigEndian.Uint16(data[6:8]) != 0 || data[10] != 0 {
		return false
	}
	if len(data) == 11 {
		return true
	}
	if binary.LittleEndian.Uint16(data[13:15]) != 8 {
		return false
	}
	value := binary.LittleEndian.Uint32(data[15:19])
	switch data[11] {
	case 2:
		return data[12]&^byte(0x1b) == 0 && (value == 0 || value == 1 || value == 2)
	case 3:
		return data[12] == 0 && value >= 1 && value <= 7
	default:
		return false
	}
}
