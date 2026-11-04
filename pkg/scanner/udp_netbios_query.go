package scanner

import (
	"bytes"
	"encoding/binary"
	"io"
	"strings"

	"golang.org/x/net/dns/dnsmessage"
)

// An unscoped wildcard NBSTAT request is read-only and sent only by unicast.
func netbiosNodeStatusQuery(random io.Reader) ([]byte, error) {
	var entropy [2]byte
	if _, err := io.ReadFull(random, entropy[:]); err != nil {
		return nil, err
	}
	name, err := dnsmessage.NewName("CK" + strings.Repeat("A", 30) + ".")
	if err != nil {
		return nil, err
	}
	message := dnsmessage.Message{
		Header: dnsmessage.Header{ID: binary.BigEndian.Uint16(entropy[:])},
		Questions: []dnsmessage.Question{{
			Name: name, Type: netbiosStatusRecord, Class: dnsmessage.ClassINET,
		}},
	}
	return message.Pack()
}

func netbiosNodeStatusMatches(probe, response []byte) (checked, matched bool) {
	if len(probe) != 50 {
		return false, false
	}
	expected, err := netbiosNodeStatusQuery(bytes.NewReader(probe[:2]))
	if err != nil || !bytes.Equal(expected, probe) {
		return false, false
	}
	var query dnsmessage.Message
	if query.Unpack(probe) != nil || len(query.Questions) != 1 {
		return false, false
	}
	if udpNetBIOSVersion(response) != "NetBIOS node status response" ||
		binary.BigEndian.Uint16(response) != binary.BigEndian.Uint16(probe) {
		return true, false
	}
	var parser dnsmessage.Parser
	if _, err := parser.Start(response); err != nil {
		return true, false
	}
	if _, err := parser.AllQuestions(); err != nil {
		return true, false
	}
	answer, err := parser.AnswerHeader()
	return true, err == nil && answer.Type == netbiosStatusRecord &&
		answer.Class == dnsmessage.ClassINET && strings.EqualFold(answer.Name.String(), query.Questions[0].Name.String())
}
