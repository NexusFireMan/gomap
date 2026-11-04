package scanner

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"strings"
	"testing"
	"time"
)

func netbiosDatagramFixtureQuery(t testing.TB) []byte {
	t.Helper()
	query, err := netbiosDatagramQuery(bytes.NewReader([]byte{0x12, 0x34}), &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345})
	if err != nil {
		t.Fatal(err)
	}
	return query
}

func netbiosDatagramFixtureBody(t testing.TB) []byte {
	t.Helper()
	name := netbiosDatagramFixtureQuery(t)[10:]
	body := append(bytes.Clone(name), name...)
	return append(body, []byte("opaque-do-not-log-private-data")...)
}

func netbiosDatagramPacket(flags byte, total, offset int, payload []byte) []byte {
	packet := make([]byte, 14+len(payload))
	packet[0], packet[1] = 0x10, flags
	binary.BigEndian.PutUint16(packet[2:], 77)
	copy(packet[4:8], net.IPv4(127, 0, 0, 1).To4())
	binary.BigEndian.PutUint16(packet[8:], 138)
	binary.BigEndian.PutUint16(packet[10:], uint16(total))
	binary.BigEndian.PutUint16(packet[12:], uint16(offset))
	copy(packet[14:], payload)
	return packet
}

func TestNetBIOSDatagramQueryAndNames(t *testing.T) {
	query := netbiosDatagramFixtureQuery(t)
	if len(query) != 44 || query[0] != 0x14 || query[1] != 0 || binary.BigEndian.Uint16(query[2:]) != 0x1234 ||
		!bytes.Equal(query[4:8], []byte{127, 0, 0, 1}) || binary.BigEndian.Uint16(query[8:]) != 12345 {
		t.Fatal("invalid unicast datagram query")
	}
	for _, addr := range []*net.UDPAddr{nil, {IP: net.IPv6loopback, Port: 138}, {IP: net.IPv4zero, Port: 138}, {IP: net.IPv4(127, 0, 0, 1)}, {IP: net.IPv4(127, 0, 0, 1), Port: 65536}} {
		if _, err := netbiosDatagramQuery(bytes.NewReader([]byte{1, 2}), addr); err == nil {
			t.Fatal("invalid local endpoint accepted")
		}
	}
	if _, err := netbiosDatagramQuery(bytes.NewReader(nil), &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 138}); err == nil {
		t.Fatal("missing entropy ignored")
	}
	name := bytes.Clone(query[10:])
	scoped := append(bytes.Clone(name[:33]), []byte{3, 'l', 'a', 'b', 0}...)
	for _, data := range [][]byte{name, scoped} {
		if end, ok := netbiosDatagramNameEnd(data, 0); !ok || end != len(data) {
			t.Fatal("valid name rejected")
		}
	}
	for _, data := range [][]byte{nil, name[:33], append(bytes.Clone(name[:33]), 0xc0, 0), append(bytes.Clone(name[:33]), 64), append(bytes.Clone(name[:33]), 1, '\n', 0)} {
		if _, ok := netbiosDatagramNameEnd(data, 0); ok {
			t.Fatal("invalid name accepted")
		}
	}
	if _, ok := netbiosDatagramNameEnd(name, -1); ok {
		t.Fatal("negative name position accepted")
	}
}

func TestNetBIOSDatagramAssemblyOrderingAndOwnership(t *testing.T) {
	now := time.Unix(1, 0)
	body := netbiosDatagramFixtureBody(t)
	cut := 73
	for _, lastOffset := range []int{cut, len(body) - cut} {
		for _, order := range [][]int{{0, 0, 1}, {1, 1, 0}} {
			a := netbiosDatagramAssembly{expires: now.Add(time.Second)}
			packets := [][]byte{netbiosDatagramPacket(3, len(body), 0, body[:cut]), netbiosDatagramPacket(0, len(body), lastOffset, body[cut:])}
			for i, index := range order {
				packet := bytes.Clone(packets[index])
				joined, count, err := a.add(packet, now)
				if err != nil || (count == 2) != (i == 2) {
					t.Fatal("ordering/duplicate assembly failure")
				}
				clear(packet)
				if count == 2 && !bytes.Equal(joined, body) {
					t.Fatal("input retained or wrong reassembly")
				}
			}
			if a.expires != now.Add(time.Second) || len(a.first)+len(a.last) > maxNetBIOSDatagram+28 {
				t.Fatal("time/memory bounds changed")
			}
		}
	}
	for _, kind := range []byte{0x10, 0x11, 0x12} {
		a := netbiosDatagramAssembly{expires: now.Add(time.Second)}
		packet := netbiosDatagramPacket(2, len(body), 0, body)
		packet[0] = kind
		if joined, count, err := a.add(packet, now); err != nil || count != 1 || !bytes.Equal(joined, body) {
			t.Fatal("single datagram rejected")
		}
	}
}

func TestNetBIOSDatagramAssemblyRejectsInvalid(t *testing.T) {
	now := time.Unix(1, 0)
	body := netbiosDatagramFixtureBody(t)
	base := netbiosDatagramPacket(3, len(body), 0, body[:73])
	for _, mutate := range []func([]byte) []byte{
		func([]byte) []byte { return nil },
		func(p []byte) []byte { return p[:14] },
		func(p []byte) []byte { p[0] = 0x14; return p },
		func(p []byte) []byte { p[1] = 0x80; return p },
		func(p []byte) []byte { p[1] = 1; return p },
		func(p []byte) []byte { p[12] = 1; return p },
		func(p []byte) []byte { p[14] = 0xc0; return p },
		func(p []byte) []byte { binary.BigEndian.PutUint16(p[10:], maxNetBIOSDatagram+1); return p },
		func(p []byte) []byte { return append(p, make([]byte, maxUDPResponseBytes)...) },
	} {
		a := netbiosDatagramAssembly{expires: now.Add(time.Second)}
		if _, _, err := a.add(mutate(bytes.Clone(base)), now); err == nil {
			t.Fatal("malformed fragment accepted")
		}
	}
	for _, mutate := range []func([]byte){
		func(p []byte) { p[2] ^= 1 }, func(p []byte) { p[4] ^= 1 },
		func(p []byte) { p[8] ^= 1 }, func(p []byte) { p[0] = 0x11 },
		func(p []byte) { p[1] = 4 }, func(p []byte) { p[11]++ },
		func(p []byte) { p[13] = 1 },
	} {
		a := netbiosDatagramAssembly{expires: now.Add(time.Second)}
		if _, _, err := a.add(base, now); err != nil {
			t.Fatal(err)
		}
		last := netbiosDatagramPacket(0, len(body), 73, body[73:])
		mutate(last)
		if _, _, err := a.add(last, now); err == nil {
			t.Fatal("incompatible fragment accepted")
		}
	}
	a := netbiosDatagramAssembly{expires: now.Add(time.Second)}
	if _, _, err := a.add(base, a.expires); err == nil {
		t.Fatal("expired fragment accepted")
	}
	if _, _, err := a.add(base, now); err != nil {
		t.Fatal(err)
	}
	badDuplicate := bytes.Clone(base)
	badDuplicate[len(badDuplicate)-1] ^= 1
	if _, _, err := a.add(badDuplicate, now); err == nil {
		t.Fatal("conflicting duplicate accepted")
	}
}

type netbiosDatagramFixtureConn struct {
	memcachedFixtureConn
	peer *net.UDPAddr
}

func (c *netbiosDatagramFixtureConn) RemoteAddr() net.Addr { return c.peer }

func TestNetBIOSDatagramExchange(t *testing.T) {
	query := netbiosDatagramFixtureQuery(t)
	body := netbiosDatagramFixtureBody(t)
	control := bytes.Clone(query)
	control[0] = 0x15
	binary.BigEndian.PutUint16(control[8:], 138)
	errorPacket := append(bytes.Clone(control[:10]), 0x82)
	errorPacket[0] = 0x13
	for _, tc := range []struct {
		name    string
		packets [][]byte
		valid   bool
	}{
		{"positive", [][]byte{control}, true},
		{"error", [][]byte{errorPacket}, true},
		{"single", [][]byte{netbiosDatagramPacket(2, len(body), 0, body)}, true},
		{"fragmented", [][]byte{netbiosDatagramPacket(0, len(body), 73, body[73:]), netbiosDatagramPacket(3, len(body), 0, body[:73])}, true},
		{"incomplete", [][]byte{netbiosDatagramPacket(3, len(body), 0, body[:73])}, false},
		{"arbitrary", [][]byte{[]byte("unrecognized-do-not-log")}, false},
		{"oversized", [][]byte{make([]byte, maxUDPResponseBytes+1)}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			conn := &netbiosDatagramFixtureConn{memcachedFixtureConn: memcachedFixtureConn{packets: tc.packets, finalErr: io.EOF}, peer: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 138}}
			version, evidence, observed, err := exchangeNetBIOSDatagram(conn, query, time.Now().Add(time.Second))
			if !observed || (err == nil) != tc.valid || (version != "") != tc.valid || !bytes.Equal(conn.written.Bytes(), query) {
				t.Fatalf("incorrect exchange state: valid=%t observed=%t err=%v", tc.valid, observed, err)
			}
			if strings.Contains(version+evidence, "do-not-log") || strings.Contains(version+evidence, "CKAAAA") {
				t.Fatal("private data disclosed")
			}
		})
	}
	for _, mutate := range []func([]byte){
		func(p []byte) { p[2] ^= 1 }, func(p []byte) { p[4] ^= 1 },
		func(p []byte) { p[8] ^= 1 }, func(p []byte) { p[11] = 'A' },
		func(p []byte) { p[1] = 3 },
	} {
		packet := bytes.Clone(control)
		mutate(packet)
		conn := &netbiosDatagramFixtureConn{memcachedFixtureConn: memcachedFixtureConn{packets: [][]byte{packet}}, peer: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 138}}
		if version, _, observed, err := exchangeNetBIOSDatagram(conn, query, time.Now().Add(time.Second)); err == nil || version != "" || !observed {
			t.Fatal("unmatched control response accepted")
		}
	}
	conn := &netbiosDatagramFixtureConn{peer: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 138}}
	if _, _, observed, err := exchangeNetBIOSDatagram(conn, query, time.Now().Add(time.Second)); observed || !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatal("silence treated as response")
	}
	first := netbiosDatagramPacket(3, len(body), 0, body[:73])
	for range maxNetBIOSReads + 1 {
		conn.packets = append(conn.packets, first)
	}
	if _, _, observed, err := exchangeNetBIOSDatagram(conn, query, time.Now().Add(time.Second)); !observed || err == nil || conn.reads != maxNetBIOSReads+1 {
		t.Fatal("read processing budget exceeded")
	}
}

func FuzzNetBIOSDatagramAssembly(f *testing.F) {
	body := netbiosDatagramFixtureBody(f)
	f.Add(netbiosDatagramPacket(3, len(body), 0, body[:73]), netbiosDatagramPacket(0, len(body), 73, body[73:]))
	f.Add([]byte{0}, []byte{0})
	f.Fuzz(func(t *testing.T, first, last []byte) {
		now := time.Unix(1, 0)
		a := netbiosDatagramAssembly{expires: now.Add(time.Second)}
		for _, packet := range [][]byte{first, first, last} {
			original := bytes.Clone(packet)
			body, fragments, err := a.add(packet, now)
			if !bytes.Equal(packet, original) || len(a.first)+len(a.last) > 2*maxUDPResponseBytes || len(body) > maxNetBIOSDatagram || fragments > 2 || (fragments != 0 && err != nil) {
				t.Fatal("fragment processing invariant violated")
			}
		}
	})
}

func TestNetBIOSDatagramLoopback(t *testing.T) {
	for _, mode := range []string{"negative-query", "data", "fragmented", "incomplete", "invalid", "silent"} {
		t.Run(mode, func(t *testing.T) {
			listener, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = listener.Close() }()
			if err := listener.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
				t.Fatal(err)
			}
			port := listener.LocalAddr().(*net.UDPAddr).Port
			body := netbiosDatagramFixtureBody(t)
			done := make(chan error, 1)
			go func() {
				query := make([]byte, 64)
				n, peer, err := listener.ReadFromUDP(query)
				if err != nil {
					done <- err
					return
				}
				if n != 44 || query[0] != 0x14 || !bytes.Equal(query[4:8], peer.IP.To4()) || int(binary.BigEndian.Uint16(query[8:10])) != peer.Port {
					done <- errors.New("datagram request has incorrect source endpoint")
					return
				}
				if mode == "silent" {
					done <- nil
					return
				}
				packets := [][]byte{netbiosDatagramPacket(2, len(body), 0, body)}
				switch mode {
				case "negative-query":
					packet := bytes.Clone(query[:n])
					packet[0] = 0x16
					packets = [][]byte{packet}
				case "fragmented", "incomplete":
					packets = [][]byte{netbiosDatagramPacket(3, len(body), 0, body[:73])}
					if mode == "fragmented" {
						packets = append([][]byte{netbiosDatagramPacket(0, len(body), 73, body[73:])}, packets...)
					}
				case "invalid":
					packets = [][]byte{make([]byte, 20)}
				}
				for _, packet := range packets {
					binary.BigEndian.PutUint16(packet[8:10], uint16(port))
					if _, err := listener.WriteToUDP(packet, peer); err != nil {
						done <- err
						return
					}
				}
				done <- nil
			}()
			s := NewScanner("127.0.0.1", false)
			s.Configure(ScanConfig{Timeout: 200 * time.Millisecond, DeepVersion: true, Retries: 3})
			result := s.scanNetBIOSDatagram(port)
			if err := <-done; err != nil {
				t.Fatal(err)
			}
			if mode == "silent" {
				if result.IsOpen || result.EffectiveState() != "open|filtered" {
					t.Fatal("silent service reported as confirmed")
				}
				return
			}
			if !result.IsOpen || result.EffectiveState() != "open" || result.ServiceName != "netbios-dgm" {
				t.Fatalf("responsive datagram service lost: %+v", result)
			}
			valid := mode != "incomplete" && mode != "invalid"
			if (result.Version != "") != valid || (result.Confidence == "medium") != valid || strings.Contains(result.Evidence, "private-data") {
				t.Fatalf("incorrect or disclosing datagram metadata: %+v", result)
			}
		})
	}
}
