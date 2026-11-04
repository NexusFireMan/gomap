package scanner

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"regexp"
	"strconv"
	"time"
)

const (
	maxMemcachedFragments = 16
	maxMemcachedResponse  = 16 * 1024
	maxMemcachedReads     = 32
)

var errMemcachedFrame = errors.New("invalid or expired Memcached UDP response")
var memcachedVersionPattern = regexp.MustCompile(`^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}([-+][A-Za-z0-9._-]{1,32})?$`)

type memcachedReassembler struct {
	id                uint16
	expires           time.Time
	total, seen, size int
	fragments         [maxMemcachedFragments][]byte
}

func (a *memcachedReassembler) add(packet []byte, now time.Time) ([]byte, bool, error) {
	if !now.Before(a.expires) || len(packet) < 8 || len(packet) > maxUDPResponseBytes {
		return nil, false, errMemcachedFrame
	}
	if binary.BigEndian.Uint16(packet) != a.id {
		return nil, false, nil
	}
	sequence := int(binary.BigEndian.Uint16(packet[2:]))
	total := int(binary.BigEndian.Uint16(packet[4:]))
	if total < 1 || total > maxMemcachedFragments || sequence >= total || binary.BigEndian.Uint16(packet[6:]) != 0 || len(packet) == 8 || (a.total != 0 && a.total != total) {
		return nil, false, errMemcachedFrame
	}
	a.total = total
	if previous := a.fragments[sequence]; previous != nil {
		if !bytes.Equal(previous, packet[8:]) {
			return nil, false, errMemcachedFrame
		}
	} else {
		if a.size+len(packet)-8 > maxMemcachedResponse {
			return nil, false, errMemcachedFrame
		}
		a.fragments[sequence] = bytes.Clone(packet[8:])
		a.size += len(packet) - 8
		a.seen++
	}
	if a.seen != a.total {
		return nil, false, nil
	}
	return bytes.Join(a.fragments[:a.total], nil), true, nil
}

func memcachedStatsQuery(random io.Reader) ([]byte, uint16, error) {
	packet := make([]byte, 8+len("stats\r\n"))
	if _, err := io.ReadFull(random, packet[:2]); err != nil {
		return nil, 0, err
	}
	packet[5] = 1
	copy(packet[8:], "stats\r\n")
	return packet, binary.BigEndian.Uint16(packet), nil
}

func memcachedStatsVersion(data []byte) (string, bool) {
	if len(data) > maxMemcachedResponse || !bytes.HasSuffix(data, []byte("END\r\n")) {
		return "", false
	}
	lines := bytes.Split(data[:len(data)-len("END\r\n")], []byte("\r\n"))
	if len(lines) < 2 || len(lines) > 513 || len(lines[len(lines)-1]) != 0 {
		return "", false
	}
	version, versionSeen := "", false
	for _, line := range lines[:len(lines)-1] {
		if !bytes.HasPrefix(line, []byte("STAT ")) {
			return "", false
		}
		parts := bytes.SplitN(line[5:], []byte{' '}, 2)
		if len(parts) != 2 || len(parts[0]) == 0 || len(parts[0]) > 64 || len(parts[1]) == 0 || len(parts[1]) > 256 {
			return "", false
		}
		for _, c := range parts[0] {
			if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' {
				continue
			}
			return "", false
		}
		for _, c := range parts[1] {
			if c < 32 || c > 126 {
				return "", false
			}
		}
		if bytes.Equal(parts[0], []byte("version")) {
			if versionSeen {
				return "", false
			}
			versionSeen = true
			if memcachedVersionPattern.Match(parts[1]) {
				version = string(parts[1])
			}
		}
	}
	return version, true
}

func exchangeMemcachedStats(conn net.Conn, query []byte, expires time.Time) (payload []byte, observed bool, fragments int, err error) {
	if len(query) != 15 {
		return nil, false, 0, errMemcachedFrame
	}
	if err := conn.SetDeadline(expires); err != nil {
		return nil, false, 0, err
	}
	n, err := conn.Write(query)
	if err != nil {
		return nil, false, 0, err
	}
	if n != len(query) {
		return nil, false, 0, io.ErrShortWrite
	}
	a := memcachedReassembler{id: binary.BigEndian.Uint16(query), expires: expires}
	buffer := make([]byte, maxUDPResponseBytes+1)
	for range maxMemcachedReads {
		n, readErr := conn.Read(buffer)
		if n > 0 || readErr == nil {
			observed = true
		}
		if n > 0 {
			joined, complete, frameErr := a.add(buffer[:n], time.Now())
			if frameErr != nil {
				return nil, observed, 0, frameErr
			}
			if complete {
				return joined, observed, a.total, nil
			}
		}
		if readErr != nil {
			return nil, observed, 0, readErr
		}
	}
	return nil, observed, 0, errMemcachedFrame
}

func (s *Scanner) scanMemcachedUDP(port int) (result ScanResult) {
	start := time.Now()
	defer func() { result.Latency = time.Since(start); result.LatencyMs = max(1, result.Latency.Milliseconds()) }()
	result = ScanResult{Port: port, State: "unknown", Confidence: "low", DetectionPath: "memcached-udp"}
	query, _, err := memcachedStatsQuery(rand.Reader)
	if err != nil {
		result.Evidence = "UDP query identifiers unavailable"
		return result
	}
	timeout := s.currentTimeout()
	if timeout <= 0 {
		timeout = 500 * time.Millisecond
	}
	if timeout > 5*time.Second {
		timeout = 5 * time.Second
	}
	conn, err := s.dialUDP(net.JoinHostPort(s.Host, strconv.Itoa(port)), timeout)
	if err != nil {
		result.State, result.Evidence = udpErrorState(err)
		return result
	}
	defer func() { _ = conn.Close() }()
	payload, observed, fragments, err := exchangeMemcachedStats(conn, query, time.Now().Add(timeout))
	if !observed {
		result.State, result.Evidence = udpErrorState(err)
		return result
	}
	result.IsOpen, result.State, result.ServiceName = true, "open", "memcached"
	result.Evidence = "UDP reply received; Memcached response not confirmed"
	if err != nil {
		return result
	}
	version, valid := memcachedStatsVersion(payload)
	if !valid {
		return result
	}
	result.Confidence, result.Version = "medium", "Memcached UDP stats"
	result.Evidence = fmt.Sprintf("Memcached UDP stats; request ID matched; fragments=%d; bytes=%d; not authenticated", fragments, len(payload))
	if version != "" {
		result.Version = "Memcached " + version
	}
	return result
}
