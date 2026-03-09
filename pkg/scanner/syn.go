package scanner

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"runtime"
	"sort"
	"strings"
	"time"
)

const (
	tcpFlagSyn = 0x02
	tcpFlagRst = 0x04
	tcpFlagAck = 0x10
)

// SYNConfig contains runtime options for SYN discovery.
type SYNConfig struct {
	Rate      int
	Retries   int
	GhostMode bool
}

type tcpResponse struct {
	srcPort int
	dstPort int
	flags   byte
}

// DiscoverOpenPortsSYN discovers open ports via native TCP SYN probes.
// Requires root/CAP_NET_RAW privileges.
func DiscoverOpenPortsSYN(host string, ports []int, cfg SYNConfig) ([]int, error) {
	if len(ports) == 0 {
		return nil, nil
	}
	if runtime.GOOS != "linux" {
		return nil, errors.New("native syn scan currently supported on linux only")
	}

	dstIP, err := resolveIPv4(host)
	if err != nil {
		return nil, err
	}
	srcIP, err := resolveSourceIPv4(dstIP)
	if err != nil {
		return nil, err
	}

	conn, err := net.ListenPacket("ip4:tcp", srcIP.String())
	if err != nil {
		msg := strings.ToLower(err.Error())
		if strings.Contains(msg, "operation not permitted") || strings.Contains(msg, "permission denied") {
			return nil, errors.New("insufficient privileges for native syn scan")
		}
		return nil, fmt.Errorf("failed to open raw tcp socket: %w", err)
	}
	defer func() { _ = conn.Close() }()

	srcPort := 40000 + rand.IntN(20000)
	timeoutPerRound := 650 * time.Millisecond
	if cfg.GhostMode {
		timeoutPerRound = 1200 * time.Millisecond
	}
	if cfg.Retries < 0 {
		cfg.Retries = 0
	}

	targetPorts := dedupeSortedPorts(append([]int(nil), ports...))
	sort.Ints(targetPorts)
	openSet := make(map[int]struct{}, 16)
	pending := make(map[int]struct{}, len(targetPorts))
	for _, p := range targetPorts {
		pending[p] = struct{}{}
	}

	for attempt := 0; attempt <= cfg.Retries && len(pending) > 0; attempt++ {
		batch := make([]int, 0, 64)
		for p := range pending {
			batch = append(batch, p)
		}
		sort.Ints(batch)

		for i, port := range batch {
			if _, stillPending := pending[port]; !stillPending {
				continue
			}
			if err := sendTCPProbe(conn, srcIP, dstIP, srcPort, port, tcpFlagSyn); err != nil {
				msg := strings.ToLower(err.Error())
				if strings.Contains(msg, "operation not permitted") || strings.Contains(msg, "permission denied") {
					return nil, errors.New("insufficient privileges for native syn scan")
				}
				return nil, fmt.Errorf("failed to send syn probe: %w", err)
			}
			if cfg.Rate > 0 {
				interval := time.Second / time.Duration(cfg.Rate)
				if interval < time.Millisecond {
					interval = time.Millisecond
				}
				time.Sleep(interval)
			}
			// Drain responses incrementally to avoid socket buffer overflows on large scans.
			if (i+1)%64 == 0 {
				if err := collectSYNResponses(conn, srcPort, pending, openSet, 220*time.Millisecond); err != nil {
					return nil, err
				}
			}
		}

		if err := collectSYNResponses(conn, srcPort, pending, openSet, timeoutPerRound); err != nil {
			return nil, err
		}
	}

	openPorts := make([]int, 0, len(openSet))
	for p := range openSet {
		openPorts = append(openPorts, p)
	}
	sort.Ints(openPorts)
	return openPorts, nil
}

func collectSYNResponses(conn net.PacketConn, srcPort int, pending map[int]struct{}, openSet map[int]struct{}, wait time.Duration) error {
	deadline := time.Now().Add(wait)
	for time.Now().Before(deadline) {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			break
		}
		if remaining > 150*time.Millisecond {
			remaining = 150 * time.Millisecond
		}
		resp, ok, readErr := readTCPResponse(conn, remaining)
		if readErr != nil {
			if ne, ok := readErr.(net.Error); ok && ne.Timeout() {
				continue
			}
			return fmt.Errorf("failed to read syn response: %w", readErr)
		}
		if !ok || resp.dstPort != srcPort {
			continue
		}
		if _, exists := pending[resp.srcPort]; !exists {
			continue
		}
		if resp.flags&tcpFlagSyn != 0 && resp.flags&tcpFlagAck != 0 {
			openSet[resp.srcPort] = struct{}{}
			delete(pending, resp.srcPort)
			continue
		}
		if resp.flags&tcpFlagRst != 0 {
			delete(pending, resp.srcPort)
		}
	}
	return nil
}

// BuildResultsFromKnownOpenPorts builds scan results from a pre-discovered open port list.
func BuildResultsFromKnownOpenPorts(s *Scanner, openPorts []int, detectServices bool) []ScanResult {
	if len(openPorts) == 0 {
		return nil
	}
	sort.Ints(openPorts)
	openPorts = dedupeSortedPorts(openPorts)

	if detectServices {
		return s.Scan(openPorts, true)
	}

	results := make([]ScanResult, 0, len(openPorts))
	for _, port := range openPorts {
		r := ScanResult{
			Port:        port,
			IsOpen:      true,
			ServiceName: s.PortManager.GetServiceName(port, ""),
		}
		if r.ServiceName != "" {
			r.Confidence = "low"
			r.Evidence = "syn+port map"
			r.DetectionPath = "syn+portmap"
		}
		results = append(results, r)
	}
	return results
}

func sendTCPProbe(conn net.PacketConn, srcIP, dstIP net.IP, srcPort, dstPort int, flags byte) error {
	seq := rand.Uint32()
	hdr := buildTCPHeader(srcIP, dstIP, srcPort, dstPort, seq, flags)
	_, err := conn.WriteTo(hdr, &net.IPAddr{IP: dstIP})
	return err
}

func buildTCPHeader(srcIP, dstIP net.IP, srcPort, dstPort int, seq uint32, flags byte) []byte {
	hdr := make([]byte, 20)
	binary.BigEndian.PutUint16(hdr[0:2], uint16(srcPort))
	binary.BigEndian.PutUint16(hdr[2:4], uint16(dstPort))
	binary.BigEndian.PutUint32(hdr[4:8], seq)
	binary.BigEndian.PutUint32(hdr[8:12], 0)
	hdr[12] = 5 << 4 // data offset
	hdr[13] = flags
	binary.BigEndian.PutUint16(hdr[14:16], 64240) // window size
	// checksum in [16:18]
	binary.BigEndian.PutUint16(hdr[18:20], 0)

	sum := tcpChecksum(srcIP.To4(), dstIP.To4(), hdr)
	binary.BigEndian.PutUint16(hdr[16:18], sum)
	return hdr
}

func tcpChecksum(srcIP, dstIP net.IP, tcpHdr []byte) uint16 {
	pseudo := make([]byte, 12+len(tcpHdr))
	copy(pseudo[0:4], srcIP)
	copy(pseudo[4:8], dstIP)
	pseudo[8] = 0
	pseudo[9] = 6 // TCP
	binary.BigEndian.PutUint16(pseudo[10:12], uint16(len(tcpHdr)))
	copy(pseudo[12:], tcpHdr)
	return checksum16(pseudo)
}

func checksum16(data []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(data); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(data[i : i+2]))
	}
	if len(data)%2 == 1 {
		sum += uint32(data[len(data)-1]) << 8
	}
	for (sum >> 16) > 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

func readTCPResponse(conn net.PacketConn, timeout time.Duration) (tcpResponse, bool, error) {
	var resp tcpResponse
	_ = conn.SetReadDeadline(time.Now().Add(timeout))
	buf := make([]byte, 4096)
	n, _, err := conn.ReadFrom(buf)
	if err != nil {
		return resp, false, err
	}
	return parseTCPResponsePacket(buf[:n])
}

func parseTCPResponsePacket(pkt []byte) (tcpResponse, bool, error) {
	var resp tcpResponse
	n := len(pkt)
	if n < 20 {
		return resp, false, nil
	}

	// Depending on the socket behavior, payload may include IPv4 header or only TCP segment.
	offset := 0
	if (pkt[0] >> 4) == 4 {
		ihl := int(pkt[0]&0x0f) * 4
		if ihl >= 20 && ihl+20 <= n {
			offset = ihl
		}
	}
	if offset+20 > n {
		return resp, false, nil
	}
	resp.srcPort = int(binary.BigEndian.Uint16(pkt[offset : offset+2]))
	resp.dstPort = int(binary.BigEndian.Uint16(pkt[offset+2 : offset+4]))
	resp.flags = pkt[offset+13]
	return resp, true, nil
}

func resolveIPv4(host string) (net.IP, error) {
	ip := net.ParseIP(host)
	if ip != nil {
		ip = ip.To4()
		if ip == nil {
			return nil, fmt.Errorf("target %s is not ipv4", host)
		}
		return ip, nil
	}

	ips, err := net.LookupIP(host)
	if err != nil {
		return nil, fmt.Errorf("cannot resolve %s: %w", host, err)
	}
	for _, candidate := range ips {
		if v4 := candidate.To4(); v4 != nil {
			return v4, nil
		}
	}
	return nil, fmt.Errorf("no ipv4 address found for %s", host)
}

func resolveSourceIPv4(dstIP net.IP) (net.IP, error) {
	dstAddr := net.JoinHostPort(dstIP.String(), "80")
	c, err := net.Dial("udp4", dstAddr)
	if err != nil {
		return nil, err
	}
	defer func() { _ = c.Close() }()

	local := c.LocalAddr()
	udpAddr, ok := local.(*net.UDPAddr)
	if !ok || udpAddr.IP == nil {
		return nil, errors.New("cannot determine local ipv4 address")
	}
	v4 := udpAddr.IP.To4()
	if v4 == nil {
		return nil, errors.New("cannot determine local ipv4 address")
	}
	return v4, nil
}

func dedupeSortedPorts(ports []int) []int {
	if len(ports) < 2 {
		return ports
	}
	out := ports[:1]
	for _, p := range ports[1:] {
		if p != out[len(out)-1] {
			out = append(out, p)
		}
	}
	return out
}
