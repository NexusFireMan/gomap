package scanner

import (
	"bytes"
	"encoding/asn1"
	"strings"

	"golang.org/x/net/dns/dnsmessage"
)

// Matching fixed query fields does not authenticate the sender or prevent replay.
// Other current probes contain no usable per-request identifier.
func udpProbeFieldsMatch(port int, probe, response []byte) (checked, matched bool) {
	switch port {
	case 53:
		var query, reply dnsmessage.Message
		if !udpDNSFrameValid(probe) || query.Unpack(probe) != nil || query.Response || query.OpCode != 0 || len(query.Questions) != 1 {
			return false, false
		}
		if udpDNSVersion(53, response) == "" || reply.Unpack(response) != nil || len(reply.Questions) != 1 {
			return true, false
		}
		want, got := query.Questions[0], reply.Questions[0]
		return true, query.ID == reply.ID && query.OpCode == reply.OpCode && want.Type == got.Type && want.Class == got.Class && strings.EqualFold(want.Name.String(), got.Name.String())
	case 161:
		query, valid := snmpCorrelationFields(probe, 0)
		if !valid {
			return false, false
		}
		if udpSNMPVersion(response) == "" {
			return true, false
		}
		reply, valid := snmpCorrelationFields(response, 2)
		if !valid || query.version != reply.version || query.id != reply.id || !bytes.Equal(query.community, reply.community) {
			return true, false
		}
		// A tooBig error may legitimately omit all bindings.
		if reply.status == 1 && len(reply.oids) == 0 {
			return true, true
		}
		if len(query.oids) != len(reply.oids) {
			return true, false
		}
		for i := range query.oids {
			if !query.oids[i].Equal(reply.oids[i]) {
				return true, false
			}
		}
		return true, true
	default:
		return false, false
	}
}

type snmpQueryFields struct {
	version, status int
	id              int32
	community       []byte
	oids            []asn1.ObjectIdentifier
}

func snmpCorrelationFields(data []byte, tag int) (fields snmpQueryFields, valid bool) {
	if len(data) == 0 || len(data) > maxUDPResponseBytes {
		return fields, false
	}
	if fields, valid = snmpDecodedCorrelationFields(data, tag); valid {
		return fields, true
	}
	// Keep ordinary DER replies on the allocation-light path.
	canonical, valid := snmpBERCanonical(data)
	if !valid || bytes.Equal(data, canonical) {
		return fields, false
	}
	return snmpDecodedCorrelationFields(canonical, tag)
}

func snmpDecodedCorrelationFields(data []byte, tag int) (fields snmpQueryFields, valid bool) {
	var pdu asn1.RawValue
	if !snmpSequenceFields(data, &fields.version, &fields.community, &pdu) || (fields.version != 0 && fields.version != 1) ||
		pdu.Class != asn1.ClassContextSpecific || !pdu.IsCompound || pdu.Tag != tag {
		return fields, false
	}
	var index int
	var bindings asn1.RawValue
	if !snmpFields(pdu.Bytes, &fields.id, &fields.status, &index, &bindings) || !snmpSequence(bindings) ||
		(tag == 0 && (fields.status != 0 || index != 0)) {
		return fields, false
	}
	content := bindings.Bytes
	for len(content) > 0 {
		var binding asn1.RawValue
		var err error
		content, err = asn1.Unmarshal(content, &binding)
		if err != nil || !snmpSequence(binding) {
			return fields, false
		}
		var oid asn1.ObjectIdentifier
		var value asn1.RawValue
		if !snmpFields(binding.Bytes, &oid, &value) {
			return fields, false
		}
		fields.oids = append(fields.oids, oid)
	}
	return fields, tag != 0 || len(fields.oids) > 0
}
