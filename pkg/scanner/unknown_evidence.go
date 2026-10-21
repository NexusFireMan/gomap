package scanner

import (
	"bytes"
	"encoding/hex"
	"fmt"
)

const (
	DefaultEvidenceBytes = 256
	MaxEvidenceBytes     = 1024
)

func evidenceByteLimit(limit int) int {
	if limit == 0 {
		return DefaultEvidenceBytes
	}
	return min(MaxEvidenceBytes, max(1, limit))
}

func (s *Scanner) captureUnknownResponse(evidence string, response []byte) string {
	if !s.CaptureUnknown || len(response) == 0 {
		return evidence
	}
	// Conservative suppression is not a guarantee: arbitrary binary data may be sensitive.
	lower := bytes.ToLower(response)
	for _, marker := range [][]byte{
		[]byte("password"), []byte("passwd"), []byte("authorization"), []byte("cookie"),
		[]byte("token"), []byte("secret"), []byte("private key"), []byte("credential"),
		[]byte("community"), []byte("bearer "), []byte("user "), []byte("pass "),
	} {
		if bytes.Contains(lower, marker) {
			return evidence + "; response sample withheld (possible sensitive content)"
		}
	}
	if response[0] == 0x30 {
		// ASN.1 sequences may contain SNMP communities or other authentication fields.
		return evidence + "; response sample withheld (possible ASN.1 credentials)"
	}
	n := min(len(response), evidenceByteLimit(s.EvidenceBytes))
	return fmt.Sprintf("%s; response_sample_hex=%s (captured=%d observed=%d truncated=%t)", evidence, hex.EncodeToString(response[:n]), n, len(response), n < len(response))
}
