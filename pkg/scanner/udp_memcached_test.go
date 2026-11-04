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

func memcachedDatagram(id uint16, sequence, total int, payload []byte) []byte {
	data := make([]byte, 8+len(payload))
	binary.BigEndian.PutUint16(data, id)
	binary.BigEndian.PutUint16(data[2:], uint16(sequence))
	binary.BigEndian.PutUint16(data[4:], uint16(total))
	copy(data[8:], payload)
	return data
}

func TestMemcachedUDPQuery(t *testing.T) {
	query, id, err := memcachedStatsQuery(bytes.NewReader([]byte{0x12, 0x34}))
	want := append([]byte{0x12, 0x34, 0, 0, 0, 1, 0, 0}, []byte("stats\r\n")...)
	if err != nil || id != 0x1234 || !bytes.Equal(query, want) {
		t.Fatal("invalid structured stats query")
	}
	if _, _, err := memcachedStatsQuery(bytes.NewReader([]byte{1})); err == nil {
		t.Fatal("entropy failure ignored")
	}
}

func TestMemcachedUDPReassemblyOrderingAndCopies(t *testing.T) {
	start := time.Unix(1, 0)
	a := memcachedReassembler{id: 42, expires: start.Add(time.Second)}
	payload := []byte("STAT version 1.6.41\r\nSTAT uptime 10\r\nEND\r\n")
	parts := [][]byte{payload[:7], payload[7:22], payload[22:]}
	for index, sequence := range []int{2, 0, 0, 1} {
		packet := memcachedDatagram(42, sequence, 3, parts[sequence])
		joined, complete, err := a.add(packet, start)
		if err != nil || complete != (index == 3) {
			t.Fatal("ordering/duplicate failure")
		}
		for i := range packet {
			packet[i] = 0
		}
		if complete && !bytes.Equal(joined, payload) {
			t.Fatal("fragment input was retained or ordered incorrectly")
		}
	}
	if a.seen != 3 || a.size != len(payload) {
		t.Fatal("duplicate consumed memory budget")
	}
}

func TestMemcachedUDPReassemblyRejectsMalformedAndExpired(t *testing.T) {
	now := time.Unix(1, 0)
	for _, packet := range [][]byte{
		nil, make([]byte, 7), make([]byte, maxUDPResponseBytes+1),
		memcachedDatagram(42, 0, 0, []byte("x")), memcachedDatagram(42, 1, 1, []byte("x")),
		memcachedDatagram(42, 0, maxMemcachedFragments+1, []byte("x")), memcachedDatagram(42, 0, 1, nil),
	} {
		a := memcachedReassembler{id: 42, expires: now.Add(time.Second)}
		if _, _, err := a.add(packet, now); err == nil {
			t.Fatal("malformed fragment accepted")
		}
	}
	for _, reserved := range []byte{1, 128} {
		packet := memcachedDatagram(42, 0, 1, []byte("x"))
		packet[6] = reserved
		a := memcachedReassembler{id: 42, expires: now.Add(time.Second)}
		if _, _, err := a.add(packet, now); err == nil {
			t.Fatal("reserved bits accepted")
		}
	}
	a := memcachedReassembler{id: 42, expires: now.Add(time.Second)}
	if _, complete, err := a.add(memcachedDatagram(7, 0, 1, []byte("x")), now); err != nil || complete || a.seen != 0 {
		t.Fatal("foreign request was not ignored")
	}
	if _, _, err := a.add(memcachedDatagram(42, 0, 2, []byte("x")), now); err != nil {
		t.Fatal(err)
	}
	if _, _, err := a.add(memcachedDatagram(42, 0, 2, []byte("different")), now); err == nil {
		t.Fatal("overlapping/conflicting duplicate accepted")
	}
	if _, _, err := a.add(memcachedDatagram(42, 1, 3, []byte("x")), now); err == nil {
		t.Fatal("inconsistent fragment count accepted")
	}
	if _, _, err := a.add(memcachedDatagram(42, 1, 2, []byte("x")), a.expires); err == nil {
		t.Fatal("expired response accepted")
	}
	if a.expires != now.Add(time.Second) {
		t.Fatal("deadline was extended")
	}
}

func TestMemcachedUDPReassemblyMemoryBound(t *testing.T) {
	now := time.Unix(1, 0)
	a := memcachedReassembler{id: 42, expires: now.Add(time.Second)}
	for seq := 0; seq < maxMemcachedFragments; seq++ {
		_, _, err := a.add(memcachedDatagram(42, seq, maxMemcachedFragments, bytes.Repeat([]byte{'x'}, 1500)), now)
		if a.size > maxMemcachedResponse {
			t.Fatal("response memory limit exceeded")
		}
		if err != nil {
			return
		}
	}
	t.Fatal("oversized fragmented response accepted")
}

func TestMemcachedUDPStatsParsingAndDisclosure(t *testing.T) {
	valid := []byte("STAT version 1.6.41\r\nSTAT private_field do-not-log-value\r\nEND\r\n")
	if version, ok := memcachedStatsVersion(valid); !ok || version != "1.6.41" {
		t.Fatal("valid stats rejected")
	}
	for _, data := range []string{
		"", "END\r\n", "STAT version 1.6.41\r\n", "STAT version 1.6.41\r\nEND\r\nextra",
		"STAT version 1.6.41\r\nSTAT version 1.6.42\r\nEND\r\n", "STAT value \x00\r\nEND\r\n",
		"STAT invalid:name 0\r\nEND\r\n", strings.Repeat("STAT x 1\r\n", 513) + "END\r\n",
	} {
		if _, ok := memcachedStatsVersion([]byte(data)); ok {
			t.Fatal("malformed stats accepted")
		}
	}
	if version, ok := memcachedStatsVersion([]byte("STAT version do-not-log-value\r\nEND\r\n")); !ok || version != "" {
		t.Fatal("unvalidated version promoted")
	}
}

type memcachedFixtureConn struct {
	net.Conn
	packets  [][]byte
	reads    int
	written  bytes.Buffer
	finalErr error
	deadline time.Time
}

func (c *memcachedFixtureConn) SetDeadline(t time.Time) error { c.deadline = t; return nil }
func (c *memcachedFixtureConn) Write(p []byte) (int, error)   { return c.written.Write(p) }
func (c *memcachedFixtureConn) Read(p []byte) (int, error) {
	c.reads++
	if len(c.packets) == 0 {
		return 0, os.ErrDeadlineExceeded
	}
	data := c.packets[0]
	c.packets = c.packets[1:]
	err := error(nil)
	if len(c.packets) == 0 {
		err = c.finalErr
	}
	return copy(p, data), err
}

func TestMemcachedUDPExchangeBoundsAndFinalRead(t *testing.T) {
	query, id, err := memcachedStatsQuery(bytes.NewReader([]byte{0x12, 0x34}))
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte("STAT version 1.6.41\r\nEND\r\n")
	conn := &memcachedFixtureConn{packets: [][]byte{
		memcachedDatagram(id, 1, 2, payload[10:]), memcachedDatagram(id, 0, 2, payload[:10]),
	}, finalErr: io.EOF}
	expires := time.Now().Add(time.Minute)
	data, observed, fragments, err := exchangeMemcachedStats(conn, query, expires)
	if err != nil || !observed || fragments != 2 || !bytes.Equal(data, payload) || conn.deadline != expires || !bytes.Equal(conn.written.Bytes(), query) {
		t.Fatal("final bytes or complete response lost")
	}
	conn = &memcachedFixtureConn{packets: [][]byte{memcachedDatagram(id, 0, 2, payload[:10])}}
	if _, observed, _, err := exchangeMemcachedStats(conn, query, expires); !observed || !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatal("incomplete responsive response lost")
	}
	conn = &memcachedFixtureConn{}
	for range maxMemcachedReads + 1 {
		conn.packets = append(conn.packets, memcachedDatagram(id+1, 0, 1, payload))
	}
	if _, observed, _, err := exchangeMemcachedStats(conn, query, expires); !observed || err == nil || conn.reads != maxMemcachedReads {
		t.Fatal("unbounded foreign datagram processing")
	}
}

func FuzzMemcachedUDPFragments(f *testing.F) {
	f.Add(memcachedDatagram(42, 0, 1, []byte("STAT version 1.6.41\r\nEND\r\n")))
	f.Add([]byte{0})
	f.Fuzz(func(t *testing.T, packet []byte) {
		now := time.Unix(1, 0)
		a := memcachedReassembler{id: 42, expires: now.Add(time.Second)}
		data, complete, err := a.add(packet, now)
		if a.size > maxMemcachedResponse || a.seen > maxMemcachedFragments || (complete && (err != nil || len(data) > maxMemcachedResponse)) {
			t.Fatal("reassembly bounds violated")
		}
		version, _ := memcachedStatsVersion(data)
		if version != "" && !memcachedVersionPattern.MatchString(version) {
			t.Fatal("unvalidated metadata")
		}
	})
}

func TestMemcachedUDPLoopbackStates(t *testing.T) {
	for _, mode := range []string{"complete", "incomplete", "malformed", "unvalidated-version"} {
		t.Run(mode, func(t *testing.T) {
			conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
			if err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() {
				query := make([]byte, 64)
				n, peer, err := conn.ReadFromUDP(query)
				if err != nil {
					done <- err
					return
				}
				if n != 15 || string(query[8:n]) != "stats\r\n" {
					done <- errors.New("unexpected fixture query")
					return
				}
				id := binary.BigEndian.Uint16(query)
				payload := []byte("STAT version 1.6.41\r\nSTAT private_field do-not-log\r\nEND\r\n")
				if mode == "unvalidated-version" {
					payload = []byte("STAT version do-not-log\r\nEND\r\n")
				}
				if mode == "malformed" {
					payload = []byte("forged arbitrary response")
				}
				packets := [][]byte{memcachedDatagram(id, 1, 2, payload[10:]), memcachedDatagram(id, 0, 2, payload[:10])}
				if mode == "incomplete" {
					packets = packets[:1]
				}
				for _, packet := range packets {
					if _, err := conn.WriteToUDP(packet, peer); err != nil {
						done <- err
						return
					}
				}
				done <- nil
			}()
			t.Cleanup(func() {
				_ = conn.Close()
				if err := <-done; err != nil && !errors.Is(err, net.ErrClosed) {
					t.Error(err)
				}
			})
			s := NewScanner("127.0.0.1", false)
			s.Timeout, s.AdaptiveTimeout = 500*time.Millisecond, false
			result := s.scanMemcachedUDP(conn.LocalAddr().(*net.UDPAddr).Port)
			if !result.IsOpen || result.State != "open" {
				t.Fatalf("responsive fixture lost: %+v", result)
			}
			if strings.Contains(result.Evidence+result.Version, "do-not-log") {
				t.Fatal("raw stats values disclosed")
			}
			switch mode {
			case "complete":
				if result.Version != "Memcached 1.6.41" || result.Confidence != "medium" || !strings.Contains(result.Evidence, "fragments=2;") {
					t.Fatalf("bad identification: %+v", result)
				}
			case "unvalidated-version":
				if result.Version != "Memcached UDP stats" {
					t.Fatal("unvalidated product version promoted")
				}
			default:
				if result.Confidence != "low" || result.Version != "" {
					t.Fatal("incomplete/invalid response promoted")
				}
			}
		})
	}
}
