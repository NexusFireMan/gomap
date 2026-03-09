package scanner

import (
	"encoding/binary"
	"net"
	"reflect"
	"testing"
)

func TestBuildTCPHeaderFields(t *testing.T) {
	src := net.ParseIP("10.0.11.11").To4()
	dst := net.ParseIP("10.0.11.6").To4()
	hdr := buildTCPHeader(src, dst, 40123, 445, 0x11223344, tcpFlagSyn)

	if len(hdr) != 20 {
		t.Fatalf("expected tcp header len 20, got %d", len(hdr))
	}
	if got := binary.BigEndian.Uint16(hdr[0:2]); got != 40123 {
		t.Fatalf("unexpected src port: %d", got)
	}
	if got := binary.BigEndian.Uint16(hdr[2:4]); got != 445 {
		t.Fatalf("unexpected dst port: %d", got)
	}
	if got := binary.BigEndian.Uint32(hdr[4:8]); got != 0x11223344 {
		t.Fatalf("unexpected seq: %#x", got)
	}
	if hdr[13] != tcpFlagSyn {
		t.Fatalf("unexpected flags: %#x", hdr[13])
	}
	if csum := binary.BigEndian.Uint16(hdr[16:18]); csum == 0 {
		t.Fatalf("checksum should not be zero")
	}
}

func TestDedupeSortedPorts(t *testing.T) {
	in := []int{22, 22, 80, 80, 443, 445, 445}
	got := dedupeSortedPorts(in)
	want := []int{22, 80, 443, 445}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected dedupe result: got=%v want=%v", got, want)
	}
}

func TestBuildResultsFromKnownOpenPortsWithoutServices(t *testing.T) {
	s := NewScanner("127.0.0.1", false)
	got := BuildResultsFromKnownOpenPorts(s, []int{445, 22, 445}, false)
	if len(got) != 2 {
		t.Fatalf("expected 2 results, got %d", len(got))
	}
	if got[0].Port != 22 || got[1].Port != 445 {
		t.Fatalf("unexpected port order: %+v", got)
	}
	if got[0].ServiceName != "ssh" || got[1].ServiceName != "microsoft-ds" {
		t.Fatalf("unexpected services: %+v", got)
	}
}

func TestParseTCPResponsePacketTCPOnly(t *testing.T) {
	pkt := make([]byte, 20)
	binary.BigEndian.PutUint16(pkt[0:2], 445)
	binary.BigEndian.PutUint16(pkt[2:4], 40123)
	pkt[12] = 5 << 4
	pkt[13] = tcpFlagSyn | tcpFlagAck

	resp, ok, err := parseTCPResponsePacket(pkt)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ok {
		t.Fatal("expected packet to be parsed")
	}
	if resp.srcPort != 445 || resp.dstPort != 40123 {
		t.Fatalf("unexpected ports: %+v", resp)
	}
	if resp.flags != (tcpFlagSyn | tcpFlagAck) {
		t.Fatalf("unexpected flags: %#x", resp.flags)
	}
}

func TestParseTCPResponsePacketIPv4PlusTCP(t *testing.T) {
	pkt := make([]byte, 40)
	pkt[0] = (4 << 4) | 5 // IPv4 + IHL=20 bytes
	pkt[9] = 6            // TCP
	binary.BigEndian.PutUint16(pkt[20:22], 5985)
	binary.BigEndian.PutUint16(pkt[22:24], 40123)
	pkt[32] = 5 << 4
	pkt[33] = tcpFlagRst | tcpFlagAck

	resp, ok, err := parseTCPResponsePacket(pkt)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ok {
		t.Fatal("expected packet to be parsed")
	}
	if resp.srcPort != 5985 || resp.dstPort != 40123 {
		t.Fatalf("unexpected ports: %+v", resp)
	}
	if resp.flags != (tcpFlagRst | tcpFlagAck) {
		t.Fatalf("unexpected flags: %#x", resp.flags)
	}
}
