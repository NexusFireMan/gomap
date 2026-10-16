package scanner

import (
	"bytes"
	"crypto/rand"
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"io"
	"syscall"
	"time"
)

type snmpWireBinding struct {
	OID   asn1.ObjectIdentifier
	Value asn1.RawValue
}

type snmpWirePDU struct {
	ID       int32
	Status   int
	Index    int
	Bindings []snmpWireBinding
}

type snmpWireHeader struct {
	ID      int32
	MaxSize int
	Flags   []byte
	Model   int
}

type snmpWireSecurity struct {
	Engine         []byte
	Boots          int
	Time           int
	User           []byte
	Authentication []byte
	Privacy        []byte
}

type snmpWireScoped struct {
	Engine []byte
	Name   []byte
	PDU    asn1.RawValue
}

type snmpWireV3 struct {
	Version  int
	Header   snmpWireHeader
	Security []byte
	Scoped   snmpWireScoped
}

func snmpRequestPDU(id int32, bindings []snmpWireBinding) (asn1.RawValue, error) {
	encoded, err := asn1.Marshal(snmpWirePDU{ID: id, Bindings: bindings})
	if err != nil {
		return asn1.RawValue{}, err
	}
	var pdu asn1.RawValue
	if _, err := asn1.Unmarshal(encoded, &pdu); err != nil {
		return pdu, err
	}
	pdu.FullBytes = nil
	pdu.Class, pdu.Tag = asn1.ClassContextSpecific, 0
	return pdu, nil
}

func snmpV2cQuery(id int32) ([]byte, error) {
	pdu, err := snmpRequestPDU(id, []snmpWireBinding{{
		OID:   asn1.ObjectIdentifier{1, 3, 6, 1, 2, 1, 1, 1, 0}, // sysDescr.0
		Value: asn1.RawValue{Tag: asn1.TagNull},
	}})
	if err != nil {
		return nil, err
	}
	return asn1.Marshal(struct {
		Version   int
		Community []byte
		PDU       asn1.RawValue
	}{1, []byte("public"), pdu})
}

func snmpV3DiscoveryQuery(messageID, requestID int32) ([]byte, error) {
	pdu, err := snmpRequestPDU(requestID, nil)
	if err != nil {
		return nil, err
	}
	security, err := asn1.Marshal(snmpWireSecurity{})
	if err != nil {
		return nil, err
	}
	return asn1.Marshal(snmpWireV3{
		Version: 3, Header: snmpWireHeader{messageID, maxUDPResponseBytes, []byte{4}, 3},
		Security: security, Scoped: snmpWireScoped{PDU: pdu},
	})
}

func snmpAdditionalQueries(random io.Reader) ([][]byte, error) {
	var entropy [12]byte
	if _, err := io.ReadFull(random, entropy[:]); err != nil {
		return nil, err
	}
	id := func(offset int) int32 {
		return max(1, int32(binary.BigEndian.Uint32(entropy[offset:])&0x7fffffff))
	}
	v2, err := snmpV2cQuery(id(0))
	if err != nil {
		return nil, err
	}
	v3, err := snmpV3DiscoveryQuery(id(4), id(8))
	if err != nil {
		return nil, err
	}
	return [][]byte{v2, v3}, nil
}

// Keep a responsive observation even when later protocol variants time out or refuse.
func (s *Scanner) exchangeUDPPort(port int, detect bool, exchange func([]byte) ([]byte, error)) (response, probe []byte, err error) {
	if port == 137 && detect && s.DeepVersion && !s.GhostMode {
		probe, err = netbiosNodeStatusQuery(rand.Reader)
		if err != nil {
			return nil, nil, err
		}
		response, err = exchange(probe)
		return // One query only; no broadcast, redirects, or automatic retries.
	}
	probe = udpProbePayload(port)
	for attempt := 0; attempt <= s.Retries; attempt++ {
		response, err = exchange(probe)
		if err == nil {
			break
		}
		if attempt < s.Retries && !s.GhostMode {
			time.Sleep(s.retryBackoff(attempt))
		}
	}
	if port != 161 || !detect || !s.DeepVersion || s.GhostMode || errors.Is(err, syscall.ECONNREFUSED) {
		return
	}
	if _, version, _, _ := s.classifyUDPResponseForProbe(port, response, probe, true); err == nil && version != "" {
		return
	}
	queries, buildErr := snmpAdditionalQueries(rand.Reader)
	if buildErr != nil {
		return // Never substitute predictable identifiers for an additional query.
	}
	for _, query := range queries {
		reply, exchangeErr := exchange(query)
		if exchangeErr == nil {
			_, version, _, _ := s.classifyUDPResponseForProbe(port, reply, query, true)
			if version != "" || err != nil {
				response, probe, err = reply, query, nil
			}
			if version != "" {
				return
			}
		} else if errors.Is(exchangeErr, syscall.ECONNREFUSED) {
			if err != nil {
				response, probe, err = nil, query, exchangeErr
			}
			break
		}
	}
	return
}

func snmpV3DiscoveryMatches(probe, response []byte) (checked, matched bool) {
	if len(probe) == 0 || len(probe) > maxUDPResponseBytes {
		return false, false
	}
	var version int
	var header, scoped asn1.RawValue
	var security []byte
	if !snmpSequenceFields(probe, &version, &header, &security, &scoped) || version != 3 {
		return false, false
	}
	var messageID, requestID int32
	var maxSize, model, status, index int
	var flags, engine, name []byte
	var pdu, bindings asn1.RawValue
	if !snmpSequence(header) || !snmpSequence(scoped) ||
		!snmpFields(header.Bytes, &messageID, &maxSize, &flags, &model) ||
		!snmpFields(scoped.Bytes, &engine, &name, &pdu) ||
		!snmpFields(pdu.Bytes, &requestID, &status, &index, &bindings) || messageID <= 0 || requestID <= 0 {
		return false, false
	}
	expected, err := snmpV3DiscoveryQuery(messageID, requestID)
	if err != nil || !bytes.Equal(expected, probe) {
		return false, false
	}
	if udpSNMPVersion(response) != "SNMPv3 report (unauthenticated)" ||
		!snmpSequenceFields(response, &version, &header, &security, &scoped) {
		return true, false
	}
	var replyMessageID, replyRequestID int32
	var boots, engineTime int
	var user, authentication, privacy, contextEngine []byte
	if !snmpFields(header.Bytes, &replyMessageID, &maxSize, &flags, &model) ||
		!snmpSequenceFields(security, &engine, &boots, &engineTime, &user, &authentication, &privacy) ||
		!snmpFields(scoped.Bytes, &contextEngine, &name, &pdu) ||
		!snmpFields(pdu.Bytes, &replyRequestID, &status, &index, &bindings) ||
		replyMessageID != messageID || (replyRequestID != requestID && replyRequestID != 0) || len(user) != 0 || len(name) != 0 || !bytes.Equal(engine, contextEngine) {
		return true, false
	}
	var binding asn1.RawValue
	var oid asn1.ObjectIdentifier
	var value asn1.RawValue
	if !snmpFields(bindings.Bytes, &binding) || !snmpFields(binding.Bytes, &oid, &value) {
		return true, false
	}
	return true, oid.Equal(asn1.ObjectIdentifier{1, 3, 6, 1, 6, 3, 15, 1, 1, 4, 0}) && value.Class == asn1.ClassApplication && value.Tag == 1
}
