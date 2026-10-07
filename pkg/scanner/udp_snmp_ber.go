package scanner

// RFC 3417 permits non-minimal definite lengths, but forbids indefinite
// lengths and constructed simple values. Only framing is normalized here;
// encoding/asn1 still validates tags, values and SNMP fields.
func snmpBERCanonical(data []byte) ([]byte, bool) {
	if len(data) == 0 || len(data) > maxUDPResponseBytes {
		return nil, false
	}
	canonical, used, valid := snmpBERElement(data, 0)
	return canonical, valid && used == len(data)
}

func snmpBERElement(data []byte, depth int) ([]byte, int, bool) {
	if depth > 16 || len(data) < 2 || data[0] == 0 || data[0]&0x1f == 0x1f {
		return nil, 0, false
	}
	tag, start, length := data[0], 2, int(data[1])
	if length&0x80 != 0 {
		count := length & 0x7f
		if count == 0 || count > 4 || start+count > len(data) {
			return nil, 0, false
		}
		length = 0
		for _, part := range data[start : start+count] {
			if length > maxUDPResponseBytes/256 {
				return nil, 0, false
			}
			length = length*256 + int(part)
		}
		start += count
	}
	if length > maxUDPResponseBytes || length > len(data)-start {
		return nil, 0, false
	}
	body := data[start : start+length]
	if tag&0x20 != 0 {
		if tag != 0x30 && (tag&0xc0 != 0x80 || tag&0x1f > 8) {
			return nil, 0, false
		}
		var content []byte
		for off := 0; off < len(body); {
			child, used, valid := snmpBERElement(body[off:], depth+1)
			if !valid {
				return nil, 0, false
			}
			content = append(content, child...)
			off += used
		}
		body = content
	}
	canonical := []byte{tag}
	switch {
	case len(body) < 128:
		canonical = append(canonical, byte(len(body)))
	case len(body) < 256:
		canonical = append(canonical, 0x81, byte(len(body)))
	default:
		canonical = append(canonical, 0x82, byte(len(body)>>8), byte(len(body)))
	}
	return append(canonical, body...), start + length, true
}
