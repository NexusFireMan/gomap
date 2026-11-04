package scanner

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"time"
)

const (
	maxNetBIOSDatagram = 4096
	maxNetBIOSReads    = 32
)

var errNetBIOSDatagram = errors.New("invalid or expired NetBIOS datagram")

// Datagram names are uncompressed, first-level encoded names plus DNS scope labels.
func netbiosDatagramNameEnd(data []byte, start int) (int, bool) {
	if start < 0 || start >= len(data) || data[start] != 32 || len(data)-start < 34 {
		return 0, false
	}
	for _, c := range data[start+1 : start+33] {
		if c < 'A' || c > 'P' {
			return 0, false
		}
	}
	for off := start + 33; off < len(data) && off-start < 255; {
		n := int(data[off])
		off++
		if n == 0 {
			return off, true
		}
		if n > 63 || n > len(data)-off || off+n-start >= 255 {
			return 0, false
		}
		for _, c := range data[off : off+n] {
			if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' {
				continue
			}
			return 0, false
		}
		off += n
	}
	return 0, false
}

func netbiosDatagramNamesEnd(data []byte) (int, bool) {
	off, ok := netbiosDatagramNameEnd(data, 0)
	if !ok {
		return 0, false
	}
	return netbiosDatagramNameEnd(data, off)
}

type netbiosDatagramAssembly struct {
	expires time.Time
	key     [10]byte
	total   int
	first   []byte
	last    []byte
}

// RFC 1002 defines one datagram or a two-packet split, with names in the first.
func (a *netbiosDatagramAssembly) add(packet []byte, now time.Time) ([]byte, int, error) {
	if !now.Before(a.expires) || len(packet) <= 14 || len(packet) > maxUDPResponseBytes ||
		packet[0] < 0x10 || packet[0] > 0x12 || packet[1]&0xf0 != 0 {
		return nil, 0, errNetBIOSDatagram
	}
	total := int(binary.BigEndian.Uint16(packet[10:12]))
	offset := int(binary.BigEndian.Uint16(packet[12:14]))
	flags, body := packet[1]&3, packet[14:]
	if total < 69 || total > maxNetBIOSDatagram || len(body) > total ||
		(flags != 0 && flags != 2 && flags != 3) || (flags != 0 && offset != 0) {
		return nil, 0, errNetBIOSDatagram
	}
	key := [10]byte(packet[:10])
	key[1] &= 0x0c
	if a.total != 0 && (a.key != key || a.total != total) {
		return nil, 0, errNetBIOSDatagram
	}
	if flags != 0 {
		end, ok := netbiosDatagramNamesEnd(body)
		if !ok || (flags == 2 && (len(body) != total || len(body) == end)) || (flags == 3 && len(body) >= total) {
			return nil, 0, errNetBIOSDatagram
		}
		if flags == 2 {
			if a.first != nil || a.last != nil {
				return nil, 0, errNetBIOSDatagram
			}
			return bytes.Clone(body), 1, nil
		}
	} else if offset == 0 || offset >= total || len(body) >= total {
		return nil, 0, errNetBIOSDatagram
	}
	a.key, a.total = key, total
	slot := &a.first
	if flags == 0 {
		slot = &a.last
	}
	if *slot != nil {
		if !bytes.Equal(*slot, packet) {
			return nil, 0, errNetBIOSDatagram
		}
		return nil, 0, nil
	}
	*slot = bytes.Clone(packet)
	if a.first == nil || a.last == nil {
		return nil, 0, nil
	}
	first, last := a.first[14:], a.last[14:]
	lastOffset := int(binary.BigEndian.Uint16(a.last[12:14]))
	// The RFC transmission pseudocode uses remaining length; byte-position
	// implementations use consumed length. Both uniquely describe this two-part split.
	if len(first)+len(last) != total || (lastOffset != len(first) && lastOffset != len(last)) {
		return nil, 0, errNetBIOSDatagram
	}
	return bytes.Join([][]byte{first, last}, nil), 2, nil
}

func netbiosDatagramQuery(random io.Reader, local *net.UDPAddr) ([]byte, error) {
	if local == nil || local.IP.To4() == nil || local.IP.IsUnspecified() || local.Port < 1 || local.Port > 65535 {
		return nil, errNetBIOSDatagram
	}
	status, err := netbiosNodeStatusQuery(random)
	if err != nil {
		return nil, err
	}
	query := make([]byte, 44)
	query[0] = 0x14
	copy(query[2:4], status[:2])
	copy(query[4:8], local.IP.To4())
	binary.BigEndian.PutUint16(query[8:10], uint16(local.Port))
	copy(query[10:], status[12:46])
	return query, nil
}

func exchangeNetBIOSDatagram(conn net.Conn, query []byte, expires time.Time) (version, evidence string, observed bool, err error) {
	peer, ok := conn.RemoteAddr().(*net.UDPAddr)
	if !ok || peer.IP.To4() == nil || len(query) != 44 {
		return "", "", false, errNetBIOSDatagram
	}
	if err = conn.SetDeadline(expires); err != nil {
		return
	}
	n, err := conn.Write(query)
	if err != nil {
		return "", "", false, err
	}
	if n != len(query) {
		return "", "", false, io.ErrShortWrite
	}
	a := netbiosDatagramAssembly{expires: expires}
	buffer := make([]byte, maxUDPResponseBytes+1)
	for range maxNetBIOSReads {
		n, readErr := conn.Read(buffer)
		observed = observed || n > 0 || readErr == nil
		if n > 0 {
			packet := buffer[:n]
			if !time.Now().Before(expires) || n < 10 || n > maxUDPResponseBytes || packet[1]&0xf0 != 0 ||
				!bytes.Equal(packet[4:8], peer.IP.To4()) || int(binary.BigEndian.Uint16(packet[8:10])) != peer.Port {
				return "", "", observed, errNetBIOSDatagram
			}
			switch packet[0] {
			case 0x15, 0x16:
				end, valid := netbiosDatagramNameEnd(packet, 10)
				if valid && end == n && packet[1]&3 == 0 && bytes.Equal(packet[2:4], query[2:4]) && bytes.Equal(packet[10:], query[10:]) {
					label := "NetBIOS datagram query response"
					if packet[0] == 0x16 {
						label = "NetBIOS datagram negative query response"
					}
					return label, "NetBIOS datagram query ID/name matched; not authenticated", true, nil
				}
				return "", "", observed, errNetBIOSDatagram
			case 0x13:
				if n == 11 && packet[1]&3 == 0 && bytes.Equal(packet[2:4], query[2:4]) && packet[10] >= 0x82 && packet[10] <= 0x84 {
					return "NetBIOS datagram error", "NetBIOS datagram error; query ID matched; not authenticated", true, nil
				}
				return "", "", observed, errNetBIOSDatagram
			default:
				body, fragments, frameErr := a.add(packet, time.Now())
				if frameErr != nil {
					return "", "", observed, frameErr
				}
				if fragments != 0 {
					end, valid := netbiosDatagramNamesEnd(body)
					if !valid || end == len(body) {
						return "", "", observed, errNetBIOSDatagram
					}
					return "NetBIOS datagram", fmt.Sprintf("NetBIOS datagram; fragments=%d; bytes=%d; request not correlated; not authenticated", fragments, len(body)), true, nil
				}
			}
		}
		if readErr != nil {
			return "", "", observed, readErr
		}
	}
	return "", "", observed, errNetBIOSDatagram
}

func (s *Scanner) scanNetBIOSDatagram(port int) (result ScanResult) {
	start := time.Now()
	defer func() { result.Latency = time.Since(start); result.LatencyMs = max(1, result.Latency.Milliseconds()) }()
	result = ScanResult{Port: port, State: "unknown", Confidence: "low", DetectionPath: "netbios-datagram"}
	timeout := s.currentTimeout()
	if timeout <= 0 || timeout > 2*time.Second {
		timeout = 2 * time.Second
	}
	conn, err := s.dialUDP(net.JoinHostPort(s.Host, strconv.Itoa(port)), timeout)
	if err != nil {
		result.State, result.Evidence = udpErrorState(err)
		return
	}
	defer func() { _ = conn.Close() }()
	local, _ := conn.LocalAddr().(*net.UDPAddr)
	query, err := netbiosDatagramQuery(rand.Reader, local)
	if err != nil {
		result.Evidence = "NetBIOS datagram query unavailable; requires IPv4 and random identifiers"
		return
	}
	version, evidence, observed, err := exchangeNetBIOSDatagram(conn, query, time.Now().Add(timeout))
	if !observed {
		result.State, result.Evidence = udpErrorState(err)
		return
	}
	result.IsOpen, result.State, result.ServiceName = true, "open", "netbios-dgm"
	result.Evidence = "UDP reply received; NetBIOS datagram not confirmed"
	if err == nil {
		result.Version, result.Evidence, result.Confidence = version, evidence, "medium"
	}
	return
}
