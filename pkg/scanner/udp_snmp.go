package scanner

import (
	"encoding/asn1"
	"fmt"
)

// This validates a conservative DER-compatible subset of SNMPv1 responses.
// It does not authenticate or correlate the message with an outstanding request.
func udpSNMPv1Version(response []byte) string {
	if len(response) == 0 || len(response) > maxUDPResponseBytes {
		return ""
	}
	var message asn1.RawValue
	rest, err := asn1.Unmarshal(response, &message)
	if err != nil || len(rest) != 0 || !snmpSequence(message) {
		return ""
	}
	var version int
	rest, err = asn1.Unmarshal(message.Bytes, &version)
	if err != nil || version != 0 {
		return ""
	}
	var community []byte
	rest, err = asn1.Unmarshal(rest, &community)
	if err != nil {
		return ""
	}
	var pdu asn1.RawValue
	rest, err = asn1.Unmarshal(rest, &pdu)
	if err != nil || len(rest) != 0 || pdu.Class != asn1.ClassContextSpecific || pdu.Tag != 2 || !pdu.IsCompound {
		return ""
	}
	var requestID int32
	rest, err = asn1.Unmarshal(pdu.Bytes, &requestID)
	if err != nil {
		return ""
	}
	var status, index int
	rest, err = asn1.Unmarshal(rest, &status)
	if err != nil || status < 0 || status > 5 {
		return ""
	}
	rest, err = asn1.Unmarshal(rest, &index)
	if err != nil || index < 0 {
		return ""
	}
	var bindings asn1.RawValue
	rest, err = asn1.Unmarshal(rest, &bindings)
	if err != nil || len(rest) != 0 || !snmpSequence(bindings) {
		return ""
	}
	count, valid := snmpBindingCount(bindings.Bytes)
	if !valid || index > count || ((status == 0 || status == 1) && index != 0) || (status >= 2 && index == 0) || (status == 0 && count == 0) {
		return ""
	}
	return "SNMPv1 response"
}

func snmpSequence(value asn1.RawValue) bool {
	return value.Class == asn1.ClassUniversal && value.Tag == asn1.TagSequence && value.IsCompound
}

func snmpBindingCount(data []byte) (int, bool) {
	count := 0
	for len(data) > 0 {
		var binding asn1.RawValue
		rest, err := asn1.Unmarshal(data, &binding)
		if err != nil || !snmpSequence(binding) {
			return 0, false
		}
		var oid asn1.ObjectIdentifier
		content, err := asn1.Unmarshal(binding.Bytes, &oid)
		if err != nil || len(oid) < 2 {
			return 0, false
		}
		var value asn1.RawValue
		content, err = asn1.Unmarshal(content, &value)
		if err != nil || len(content) != 0 || value.IsCompound || !snmpV1ValueShape(value) {
			return 0, false
		}
		count++
		data = rest
	}
	return count, true
}

func snmpV1ValueShape(value asn1.RawValue) bool {
	if value.Class == asn1.ClassUniversal {
		switch value.Tag {
		case asn1.TagInteger:
			var integer int32
			_, err := asn1.Unmarshal(value.FullBytes, &integer)
			return err == nil
		case asn1.TagOctetString:
			return true
		case asn1.TagNull:
			return len(value.Bytes) == 0
		case asn1.TagOID:
			var oid asn1.ObjectIdentifier
			_, err := asn1.Unmarshal(value.FullBytes, &oid)
			return err == nil
		}
	}
	if value.Class == asn1.ClassApplication {
		switch value.Tag {
		case 0: // IpAddress
			return len(value.Bytes) == 4
		case 1, 2, 3: // Counter, Gauge, TimeTicks; unsigned 32-bit INTEGER contents.
			var integer int64
			_, err := asn1.UnmarshalWithParams(value.FullBytes, &integer, fmt.Sprintf("application,tag:%d", value.Tag))
			return err == nil && integer >= 0 && integer <= 1<<32-1
		case 4: // Opaque
			return true
		}
	}
	return false
}
