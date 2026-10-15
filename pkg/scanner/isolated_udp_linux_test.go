//go:build linux

package scanner

import (
	"encoding/binary"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

func TestIsolatedUDPStates(t *testing.T) {
	if os.Getenv("GOMAP_RUN_ISOLATED_TESTS") != "1" {
		t.Skip("requires a disconnected, loopback-only Linux network namespace")
	}
	self, err := os.Readlink("/proc/self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	initial, err := os.Readlink("/proc/1/ns/net")
	if err != nil || self == initial {
		t.Fatal("refusing UDP fixtures in the initial network namespace")
	}
	interfaces, err := net.Interfaces()
	if err != nil || len(interfaces) != 1 || interfaces[0].Name != "lo" {
		t.Fatalf("expected a loopback-only namespace: %v, %v", interfaces, err)
	}
	loopback, err := netlink.LinkByName("lo")
	if err != nil {
		t.Fatal(err)
	}
	// This link is inside the guarded disposable namespace, never the host NIC.
	if err := netlink.LinkSetUp(loopback); err != nil {
		t.Fatal(err)
	}
	listen := func(port int) *net.UDPConn {
		t.Helper()
		conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = conn.Close() })
		return conn
	}
	// Keep the closed fixture outside the usual ephemeral client-port range.
	positive, silent, closed := listen(0), listen(0), listen(9)
	closedPort := closed.LocalAddr().(*net.UDPAddr).Port
	if err := closed.Close(); err != nil {
		t.Fatal(err)
	}
	packetConn, err := net.ListenPacket("ip4:icmp", "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = packetConn.Close() })
	response := []byte{0, 0xff, 'X', 0x1b}
	done := make(chan error, 1)
	go func() {
		if err := positive.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
			done <- err
			return
		}
		buffer := make([]byte, 2048)
		_, peer, err := positive.ReadFromUDP(buffer)
		if err == nil {
			_, err = positive.WriteToUDP(response, peer)
		}
		done <- err
	}()
	t.Cleanup(func() {
		_ = positive.Close()
		if err := <-done; err != nil {
			t.Errorf("UDP responder failed: %v", err)
		}
	})
	s := NewScanner("127.0.0.1", false)
	s.Configure(ScanConfig{Timeout: 150 * time.Millisecond, NumWorkers: 1, AdaptiveTimeout: false, CaptureUnknown: true, EvidenceBytes: 4})
	ports := []int{positive.LocalAddr().(*net.UDPAddr).Port, silent.LocalAddr().(*net.UDPAddr).Port, closedPort}
	results := s.ScanUDP(ports, true)
	states := make(map[int]ScanResult)
	for _, result := range results {
		states[result.Port] = result
	}
	if len(results) != 3 || states[ports[0]].EffectiveState() != "open" || states[ports[1]].EffectiveState() != "open|filtered" || states[closedPort].EffectiveState() != "closed" || CountOpen(results) != 1 {
		t.Fatalf("kernel UDP state classification failed: %+v", results)
	}
	if !strings.Contains(states[ports[0]].Evidence, "response_sample_hex=00ff581b") || states[ports[0]].Confidence != "low" || states[ports[0]].Version != "" {
		t.Fatalf("positive unknown UDP sample missing or overclaimed: %+v", states[ports[0]])
	}
	if strings.Contains(states[ports[1]].Evidence, "response_sample_hex") || strings.Contains(states[closedPort].Evidence, "response_sample_hex") {
		t.Fatal("invented response bytes for silent/closed ports")
	}
	if err := packetConn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 4096)
	for {
		n, _, err := packetConn.ReadFrom(buffer)
		if err != nil {
			t.Fatalf("no correlated kernel ICMP port-unreachable observed: %v", err)
		}
		message, err := icmp.ParseMessage(1, buffer[:n])
		if err != nil || message.Type != ipv4.ICMPTypeDestinationUnreachable || message.Code != 3 {
			continue
		}
		body, ok := message.Body.(*icmp.DstUnreach)
		if !ok {
			continue
		}
		header, err := ipv4.ParseHeader(body.Data)
		if err == nil && header.Protocol == 17 && header.Dst.Equal(net.IPv4(127, 0, 0, 1)) && len(body.Data) >= header.Len+8 && int(binary.BigEndian.Uint16(body.Data[header.Len+2:header.Len+4])) == closedPort {
			t.Log("validated UDP response, silence and closed state with correlated kernel ICMP type 3/code 3")
			break
		}
	}
}
