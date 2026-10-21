package scanner

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"strconv"
	"strings"
	"testing"
)

func TestSMBNegotiationRequiresMatchingResponse(t *testing.T) {
	s := NewScanner("127.0.0.1", false)
	valid := smbFramingFixture()[4:]
	if got := s.extractSMB2Dialect(valid); got != "SMB 3.0.2" {
		t.Fatal(got)
	}
	for _, mutate := range []func([]byte){
		func(p []byte) { p[0] = 0xff },
		func(p []byte) { p[24] = 1 },
		func(p []byte) { p[40] = 1 },
		func(p []byte) { p[20] = 1 },
		func(p []byte) { binary.LittleEndian.PutUint16(p[68:], 0x0311) },
		func(p []byte) { binary.LittleEndian.PutUint16(p[122:], 1) },
		func(p []byte) { binary.LittleEndian.PutUint16(p[120:], 127); binary.LittleEndian.PutUint16(p[122:], 1) },
	} {
		changed := bytes.Clone(valid)
		mutate(changed)
		if s.extractSMB2Dialect(changed) != "" {
			t.Fatal("unmatched, unoffered or malformed SMB negotiation promoted")
		}
	}
}

func TestSMBNativeProbeRejectsUnsolicitedLegacy(t *testing.T) {
	for _, legacy := range []bool{false, true} {
		port, done := serveStreamFixture(t, func(conn net.Conn) error {
			request := buildSMBNegotiate()
			got := make([]byte, len(request))
			if _, err := io.ReadFull(conn, got); err != nil {
				return err
			}
			if string(got[4:8]) != "\xfeSMB" {
				t.Error("native request changed protocol")
			}
			response := smbFramingFixture()
			if legacy {
				response = make([]byte, 39)
				binary.BigEndian.PutUint32(response, 35)
				copy(response[4:], "\xffSMB")
				response[8], response[13] = 0x72, 0x80
			}
			_, err := conn.Write(response)
			return err
		})
		s := NewScanner("127.0.0.1", false)
		got := s.attemptRawSMBDetection(net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
		waitStreamFixture(t, done)
		if (got != "") == legacy {
			t.Fatalf("legacy=%t: %q", legacy, got)
		}
	}
}

func TestONCRPCNullSuccessRejectsExtraResults(t *testing.T) {
	reply := make([]byte, 28)
	binary.BigEndian.PutUint32(reply, 0x80000018)
	binary.BigEndian.PutUint32(reply[4:], 123)
	binary.BigEndian.PutUint32(reply[8:], 1)
	if accepted, valid := parseONCRPCReply(reply, 123); !accepted || !valid {
		t.Fatal("NULL response rejected")
	}
	reply = append(reply, 0, 0, 0, 0)
	binary.BigEndian.PutUint32(reply, 0x8000001c)
	if accepted, valid := parseONCRPCReply(reply, 123); accepted || valid {
		t.Fatal("non-NULL results promoted to NULL program/version evidence")
	}
}

func TestSpecializedGenericDisclosuresStayQualified(t *testing.T) {
	for _, version := range []string{"7.0", "7.5", "8.0", "8.5", "10.0"} {
		if got := parseIISVersion("Microsoft-IIS/" + version); got != "IIS "+version {
			t.Fatal("IIS disclosure inferred a Windows release", got)
		}
	}
	if bannerConfidence("MySQL (connection rejected)") != "medium" {
		t.Fatal("rejection became a concrete implementation disclosure")
	}
	for _, banner := range []string{"Samba smbd 4.19\r\n", "Windows Server 2019 SMB\r\n"} {
		_, version := parseObservedBanner(banner)
		if version == "" || bannerIdentificationConfidence(banner, version) != "medium" {
			t.Fatal("text-only SMB hint received native negotiation confidence")
		}
	}
	packet := mysqlFixture()
	packet[5] = 0x7f
	if version := parseMySQLHandshakePacket(packet); version != "" {
		t.Fatal("control-containing version disclosed")
	}
	if !strings.Contains(rpcAcceptedEvidence(100003, 3, 2049), "RPC #100003 accepted v3") {
		t.Fatal("RPC evidence lost program/version scope")
	}
}
