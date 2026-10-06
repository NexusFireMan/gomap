package scanner

import (
	"bytes"
	"encoding/asn1"
	"fmt"
	"math/big"
)

// This validates a bounded subset of SNMP responses, including definite BER lengths.
// It does not authenticate or correlate the message with an outstanding request.
func udpSNMPVersion(response []byte) string {
	if version := snmpDERVersion(response); version != "" {
		return version
	}
	canonical, valid := snmpBERCanonical(response)
	if !valid || bytes.Equal(response, canonical) {
		return ""
	}
	return snmpDERVersion(canonical)
}

func snmpDERVersion(response []byte) string {
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
	if err != nil {
		return ""
	}
	if version == 3 {
		return snmpV3Version(rest)
	}
	if version != 0 && version != 1 {
		return ""
	}
	var community []byte
	rest, err = asn1.Unmarshal(rest, &community)
	if err != nil {
		return ""
	}
	var pdu asn1.RawValue
	rest, err = asn1.Unmarshal(rest, &pdu)
	if err != nil || len(rest) != 0 || !snmpResponsePDUValid(pdu, version, false) {
		return ""
	}
	if version == 1 {
		return "SNMPv2c response"
	}
	return "SNMPv1 response"
}

func snmpResponsePDUValid(pdu asn1.RawValue, version int, allowReport bool) bool {
	if pdu.Class != asn1.ClassContextSpecific || !pdu.IsCompound || (pdu.Tag != 2 && (!allowReport || pdu.Tag != 8)) {
		return false
	}
	var requestID int32
	rest, err := asn1.Unmarshal(pdu.Bytes, &requestID)
	if err != nil {
		return false
	}
	var status, index int
	rest, err = asn1.Unmarshal(rest, &status)
	maxStatus := 5
	if version != 0 {
		maxStatus = 18
	}
	if err != nil || status < 0 || status > maxStatus || (pdu.Tag == 8 && status != 0) {
		return false
	}
	rest, err = asn1.Unmarshal(rest, &index)
	if err != nil || index < 0 {
		return false
	}
	var bindings asn1.RawValue
	rest, err = asn1.Unmarshal(rest, &bindings)
	if err != nil || len(rest) != 0 || !snmpSequence(bindings) {
		return false
	}
	count, valid := snmpBindingCount(bindings.Bytes, version)
	if !valid || index > count || ((status == 0 || status == 1) && index != 0) || (status >= 2 && index == 0) || (status == 0 && count == 0) {
		return false
	}
	return true
}

func snmpSequence(value asn1.RawValue) bool {
	return value.Class == asn1.ClassUniversal && value.Tag == asn1.TagSequence && value.IsCompound
}

func snmpBindingCount(data []byte, version int) (int, bool) {
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
		if err != nil || len(content) != 0 || value.IsCompound || !snmpValueShape(value, version) {
			return 0, false
		}
		count++
		data = rest
	}
	return count, true
}

func snmpValueShape(value asn1.RawValue, version int) bool {
	if version != 0 {
		if value.Class == asn1.ClassContextSpecific && value.Tag >= 0 && value.Tag <= 2 {
			return len(value.Bytes) == 0
		}
		if value.Class == asn1.ClassApplication && value.Tag == 6 {
			if len(value.Bytes) > 9 {
				return false
			}
			var integer *big.Int
			_, err := asn1.UnmarshalWithParams(value.FullBytes, &integer, "application,tag:6")
			return err == nil && integer.Sign() >= 0 && integer.BitLen() <= 64
		}
	}
	return snmpV1ValueShape(value)
}

// Decode each field explicitly: ASN.1 struct decoding can ignore extra fields.
func snmpFields(data []byte, fields ...any) bool {
	for _, field := range fields {
		var err error
		data, err = asn1.Unmarshal(data, field)
		if err != nil {
			return false
		}
	}
	return len(data) == 0
}

func snmpSequenceFields(data []byte, fields ...any) bool {
	if snmpDERSequenceFields(data, fields...) {
		return true
	}
	canonical, valid := snmpBERCanonical(data)
	return valid && !bytes.Equal(data, canonical) && snmpDERSequenceFields(canonical, fields...)
}

func snmpDERSequenceFields(data []byte, fields ...any) bool {
	var sequence asn1.RawValue
	rest, err := asn1.Unmarshal(data, &sequence)
	return err == nil && len(rest) == 0 && snmpSequence(sequence) && snmpFields(sequence.Bytes, fields...)
}

func snmpV3Version(data []byte) string {
	var header, scoped asn1.RawValue
	var security []byte
	if !snmpFields(data, &header, &security, &scoped) || !snmpSequence(header) || !snmpSequence(scoped) {
		return ""
	}
	var id, maxSize, model int32
	var flags []byte
	if !snmpFields(header.Bytes, &id, &maxSize, &flags, &model) || id < 0 || maxSize < 484 || model != 3 || len(flags) != 1 || flags[0] != 0 {
		return ""
	}
	var engine, user, authentication, privacy []byte
	var boots, engineTime int32
	if !snmpSequenceFields(security, &engine, &boots, &engineTime, &user, &authentication, &privacy) ||
		len(engine) < 5 || len(engine) > 32 || boots < 0 || engineTime < 0 || len(user) > 32 || len(authentication)+len(privacy) != 0 {
		return ""
	}
	var contextEngine, contextName []byte
	var pdu asn1.RawValue
	if !snmpFields(scoped.Bytes, &contextEngine, &contextName, &pdu) || len(contextEngine) < 5 || len(contextEngine) > 32 ||
		len(contextName) > 32 || !snmpResponsePDUValid(pdu, 3, true) {
		return ""
	}
	if pdu.Tag == 8 {
		return "SNMPv3 report (unauthenticated)"
	}
	return "SNMPv3 response (unauthenticated)"
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
