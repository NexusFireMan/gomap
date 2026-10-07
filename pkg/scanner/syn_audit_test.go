package scanner

import (
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"
)

type synDatagram struct {
	data []byte
	peer net.IP
}
type fakeSYNConn struct{ packets []synDatagram }

func (c *fakeSYNConn) ReadFrom(p []byte) (int, net.Addr, error) {
	if len(c.packets) == 0 {
		return 0, nil, io.EOF
	}
	packet := c.packets[0]
	c.packets = c.packets[1:]
	return copy(p, packet.data), &net.IPAddr{IP: packet.peer}, nil
}
func (*fakeSYNConn) WriteTo([]byte, net.Addr) (int, error) { return 0, io.ErrClosedPipe }
func (*fakeSYNConn) Close() error                          { return nil }
func (*fakeSYNConn) LocalAddr() net.Addr                   { return &net.IPAddr{IP: net.IPv4(127, 0, 0, 1)} }
func (*fakeSYNConn) SetDeadline(time.Time) error           { return nil }
func (*fakeSYNConn) SetReadDeadline(time.Time) error       { return nil }
func (*fakeSYNConn) SetWriteDeadline(time.Time) error      { return nil }

func TestSYNRejectsUnrelatedPeersAndAcknowledgements(t *testing.T) {
	target := net.ParseIP("192.0.2.1")
	packet := func(ack uint32) []byte {
		p := make([]byte, 20)
		binary.BigEndian.PutUint16(p, 443)
		binary.BigEndian.PutUint16(p[2:], 40123)
		binary.BigEndian.PutUint32(p[8:], ack)
		p[12] = 5 << 4
		p[13] = tcpFlagSyn | tcpFlagAck
		return p
	}
	conn := &fakeSYNConn{packets: []synDatagram{
		{packet(42), net.ParseIP("192.0.2.2")},
		{packet(100), target},
		{packet(42), target},
	}}
	pending := map[int]uint32{443: 41}
	open := map[int]struct{}{}
	if err := collectSYNResponses(conn, target, 40123, pending, open, time.Second); err != nil {
		t.Fatal(err)
	}
	if len(conn.packets) != 0 || len(open) != 1 || len(pending) != 0 {
		t.Fatalf("accepted unrelated packet: %#v", conn)
	}
}

func TestSYNClosedAndInvalidResponses(t *testing.T) {
	target := net.ParseIP("192.0.2.1")
	for _, tc := range []struct {
		name     string
		flags    byte
		sequence uint32
		wantOpen bool
	}{
		{"reset is closed", tcpFlagRst | tcpFlagAck, 41, false},
		{"reset plus syn is not open", tcpFlagRst | tcpFlagSyn | tcpFlagAck, 41, false},
		{"wrapped acknowledgement", tcpFlagSyn | tcpFlagAck, ^uint32(0), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			packet := make([]byte, 20)
			binary.BigEndian.PutUint16(packet, 443)
			binary.BigEndian.PutUint16(packet[2:], 40123)
			binary.BigEndian.PutUint32(packet[8:], tc.sequence+1)
			packet[12] = 5 << 4
			packet[13] = tc.flags
			wrongDestination := append([]byte(nil), packet...)
			binary.BigEndian.PutUint16(wrongDestination[2:], 40124)
			noAck := append([]byte(nil), packet...)
			noAck[13] &^= tcpFlagAck
			conn := &fakeSYNConn{packets: []synDatagram{
				{packet[:10], target}, {wrongDestination, target}, {noAck, target}, {packet, target},
			}}
			pending := map[int]uint32{443: tc.sequence}
			open := map[int]struct{}{}
			if err := collectSYNResponses(conn, target, 40123, pending, open, time.Second); err != nil {
				t.Fatal(err)
			}
			_, gotOpen := open[443]
			if gotOpen != tc.wantOpen || len(pending) != 0 || len(conn.packets) != 0 {
				t.Fatalf("incorrect response classification: open=%v pending=%v", open, pending)
			}
		})
	}
}
