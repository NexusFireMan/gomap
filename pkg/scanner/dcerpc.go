package scanner

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
	"time"
)

func buildDCERPCBind() []byte {
	p := make([]byte, 72)
	copy(p, []byte{5, 0, 11, 3, 0x10})
	binary.LittleEndian.PutUint16(p[8:], uint16(len(p)))
	binary.LittleEndian.PutUint32(p[12:], 1)
	binary.LittleEndian.PutUint16(p[16:], 4280)
	binary.LittleEndian.PutUint16(p[18:], 4280)
	p[24], p[30] = 1, 1
	// Endpoint mapper v3 and the NDR v2 transfer syntax; no RPC operation follows.
	copy(p[32:], []byte{8, 0x83, 0xaf, 0xe1, 0x1f, 0x5d, 0xc9, 0x11, 0x91, 0xa4, 8, 0, 0x2b, 0x14, 0xa0, 0xfa})
	binary.LittleEndian.PutUint32(p[48:], 3)
	copy(p[52:], []byte{4, 0x5d, 0x88, 0x8a, 0xeb, 0x1c, 0xc9, 0x11, 0x9f, 0xe8, 8, 0, 0x2b, 0x10, 0x48, 0x60})
	binary.LittleEndian.PutUint32(p[68:], 2)
	return p
}

func readDCERPCBindAck(r io.Reader) (string, bool) {
	var h [16]byte
	if _, err := io.ReadFull(r, h[:]); err != nil ||
		!bytes.Equal(h[:8], []byte{5, 0, 12, 3, 0x10, 0, 0, 0}) ||
		binary.LittleEndian.Uint16(h[10:]) != 0 || binary.LittleEndian.Uint32(h[12:]) != 1 {
		return "", false
	}
	n := int(binary.LittleEndian.Uint16(h[8:]))
	if n < 30 || n > 4096 {
		return "", false
	}
	p := make([]byte, n)
	copy(p, h[:])
	if _, err := io.ReadFull(r, p[16:]); err != nil {
		return "", false
	}
	offset := roundUp4(26 + int(binary.LittleEndian.Uint16(p[24:])))
	if offset+28 != len(p) || p[offset] != 1 {
		return "", false
	}
	result := binary.LittleEndian.Uint16(p[offset+4:])
	reason := binary.LittleEndian.Uint16(p[offset+6:])
	if result > 2 || reason > 3 {
		return "", false
	}
	if result == 0 {
		bind := buildDCERPCBind()
		if reason != 0 || !bytes.Equal(p[offset+8:], bind[52:]) {
			return "", false
		}
		return "DCE/RPC 5.0 bind_ack; endpoint mapper v3 accepted; NDR v2", true
	}
	return fmt.Sprintf("DCE/RPC 5.0 bind_ack; context rejected (result=%d, reason=%d)", result, reason), true
}

func (s *Scanner) detectDCERPC(port int) (string, bool) {
	timeout := s.boundedServiceTimeout(750*time.Millisecond, 1500*time.Millisecond)
	conn, err := s.dialTCP(net.JoinHostPort(s.Host, strconv.Itoa(port)), timeout)
	if err != nil {
		return "", false
	}
	defer func() { _ = conn.Close() }()
	if conn.SetDeadline(time.Now().Add(timeout)) != nil {
		return "", false
	}
	if _, err := conn.Write(buildDCERPCBind()); err != nil {
		return "", false
	}
	return readDCERPCBindAck(conn)
}
