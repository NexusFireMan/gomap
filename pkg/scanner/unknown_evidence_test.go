package scanner

import (
	"bytes"
	"encoding/hex"
	"net"
	"strings"
	"testing"
)

func TestUnknownEvidenceIsOptInBoundedAndHexEncoded(t *testing.T) {
	s := NewScanner("fixture.invalid", true)
	response := []byte{0, 1, 0xff, 0x1b, '\n', 2}
	if got := s.captureUnknownResponse("original", response); got != "original" {
		t.Fatal("capture enabled by default")
	}
	s.CaptureUnknown, s.EvidenceBytes = true, 3
	got := s.captureUnknownResponse("original", response)
	if !strings.Contains(got, "response_sample_hex=0001ff") || !strings.Contains(got, "captured=3 observed=6 truncated=true") || strings.ContainsAny(got, "\x1b\n") {
		t.Fatalf("incorrect/unsafe sample: %q", got)
	}
	if got := s.captureUnknownResponse("original", nil); got != "original" {
		t.Fatal("invented evidence without a response")
	}
	for _, limit := range []int{-1, 0, 1, 1024, 999999} {
		s.EvidenceBytes = limit
		got := s.captureUnknownResponse("original", bytes.Repeat([]byte{0x80}, 2048))
		if len(got) > 2*MaxEvidenceBytes+150 {
			t.Fatalf("capture bound exceeded: %d", len(got))
		}
	}
}

func TestUnknownEvidenceSuppressesSensitiveSamplesBeforeTruncation(t *testing.T) {
	s := NewScanner("fixture.invalid", false)
	s.CaptureUnknown, s.EvidenceBytes = true, 4
	for _, response := range [][]byte{
		[]byte("prefix Authorization: Bearer fixture-value"), []byte("prefix PASS fixture-value"),
		[]byte("prefix Cookie: session=fixture-value"), []byte("prefix password=fixture-value"),
		{0x30, 0x04, 0x02, 0x01, 0x00, 0x04, 0x01, 'x'},
	} {
		got := s.captureUnknownResponse("original", response)
		if !strings.Contains(got, "withheld") || strings.Contains(got, "fixture-value") || strings.Contains(got, "response_sample_hex=") {
			t.Fatalf("possible credential sample disclosed: %q", got)
		}
	}
}

func TestUnknownTCPBannerCaptureUsesExistingRead(t *testing.T) {
	for _, tc := range []struct {
		enabled             bool
		port                int
		response            []byte
		service, confidence string
		capture             bool
	}{
		{false, 65432, []byte{0, 0xff, 'X', 0x1b, '\n'}, "unknown", "low", false},
		{true, 65432, []byte{0, 0xff, 'X', 0x1b, '\n'}, "unknown", "low", true},
		{true, 7676, []byte{0, 0xff, 'X', 0x1b, '\n'}, "jms", "low", true},
		{true, 2222, []byte("SSH-2.0-OpenSSH_9.6p1\r\n"), "ssh", "high", false},
	} {
		client, server := net.Pipe()
		t.Cleanup(func() { _ = client.Close() })
		done := make(chan struct{})
		go func() {
			defer close(done)
			defer func() { _ = server.Close() }()
			_, _ = server.Write(tc.response)
		}()
		s := NewScanner("fixture.invalid", true)
		s.CaptureUnknown, s.EvidenceBytes = tc.enabled, 32
		result := ScanResult{Port: tc.port, IsOpen: true}
		s.grabBanner(client, result.Port, &result)
		<-done
		if result.ServiceName != tc.service || result.Confidence != tc.confidence || strings.Contains(result.Evidence, "response_sample_hex=") != tc.capture {
			t.Fatalf("unexpected capture or identification: %+v", result)
		}
		if tc.capture && !strings.Contains(result.Evidence, hex.EncodeToString(tc.response)) {
			t.Fatal("original bytes not retained")
		}
	}
}
