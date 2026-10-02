package scanner

import (
	"encoding/binary"
	"io"
	"net"
	"strconv"
	"time"
)

// Transport negotiation only: no registry lookup, remote calls or deserialization.
// https://docs.oracle.com/en/java/javase/26/docs/specs/rmi/protocol.html
// OpenJDK TransportConstants specifies wire version 2 (not the JVM version).
func probeRMITransport(conn net.Conn) bool {
	if _, err := io.WriteString(conn, "JRMI\x00\x02\x4b"); err != nil {
		return false
	}
	var header [3]byte
	if _, err := io.ReadFull(conn, header[:]); err != nil || header[0] != 0x4e {
		return false
	}
	n := int(binary.BigEndian.Uint16(header[1:]))
	if n > 1024 {
		return false
	}
	endpoint := make([]byte, n+4)
	if _, err := io.ReadFull(conn, endpoint); err != nil || binary.BigEndian.Uint32(endpoint[n:]) > 65535 {
		return false
	}
	// The returned endpoint describes us, not the server. Do not report it as a hostname.
	if _, err := io.WriteString(conn, "\x00\x00\x00\x00\x00\x00\x52"); err != nil {
		return false
	}
	var ack [1]byte
	_, err := io.ReadFull(conn, ack[:])
	return err == nil && ack[0] == 0x53
}

func (s *Scanner) detectRMI(port int) bool {
	timeout := s.boundedServiceTimeout(750*time.Millisecond, 1500*time.Millisecond)
	conn, err := s.dialTCP(net.JoinHostPort(s.Host, strconv.Itoa(port)), timeout)
	if err != nil {
		return false
	}
	defer func() { _ = conn.Close() }()
	if conn.SetDeadline(time.Now().Add(timeout)) != nil {
		return false
	}
	return probeRMITransport(conn)
}
