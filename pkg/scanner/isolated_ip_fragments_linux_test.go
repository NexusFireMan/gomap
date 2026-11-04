//go:build linux

package scanner

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/net/dns/dnsmessage"
	"golang.org/x/sys/unix"
)

func requireFragmentNamespace(t *testing.T) {
	t.Helper()
	if os.Getenv("GOMAP_RUN_ISOLATED_TESTS") != "1" {
		t.Skip("requires a disconnected loopback-only Linux network namespace")
	}
	self, err := os.Readlink("/proc/self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	initial, err := os.Readlink("/proc/1/ns/net")
	if err != nil || self == initial {
		t.Fatal("refusing raw IP fixtures in the initial network namespace")
	}
	interfaces, err := net.Interfaces()
	if err != nil || len(interfaces) != 1 || interfaces[0].Name != "lo" {
		t.Fatal("requires loopback as the only interface")
	}
	link, err := netlink.LinkByName("lo")
	if err != nil {
		t.Fatal(err)
	}
	if err := netlink.LinkSetUp(link); err != nil {
		t.Fatal(err)
	}
}

func ipFragmentUDPPayload(ipv6 bool, sourcePort, destPort int, data []byte) []byte {
	udp := make([]byte, 8+len(data))
	binary.BigEndian.PutUint16(udp, uint16(sourcePort))
	binary.BigEndian.PutUint16(udp[2:], uint16(destPort))
	binary.BigEndian.PutUint16(udp[4:], uint16(len(udp)))
	copy(udp[8:], data)
	pseudo := make([]byte, 12)
	copy(pseudo[:4], net.IPv4(127, 0, 0, 1).To4())
	copy(pseudo[4:8], net.IPv4(127, 0, 0, 1).To4())
	pseudo[9] = 17
	binary.BigEndian.PutUint16(pseudo[10:], uint16(len(udp)))
	if ipv6 {
		pseudo = make([]byte, 40)
		copy(pseudo[:16], net.IPv6loopback)
		copy(pseudo[16:32], net.IPv6loopback)
		binary.BigEndian.PutUint32(pseudo[32:], uint32(len(udp)))
		pseudo[39] = 17
	}
	sum := checksum16(append(pseudo, udp...))
	if sum == 0 {
		sum = 0xffff
	}
	binary.BigEndian.PutUint16(udp[6:], sum)
	return udp
}

func ipFragmentPacket(ipv6 bool, id uint32, offset int, more bool, data []byte) []byte {
	if ipv6 {
		packet := make([]byte, 48+len(data))
		packet[0], packet[6], packet[7] = 0x60, 44, 64
		binary.BigEndian.PutUint16(packet[4:], uint16(8+len(data)))
		copy(packet[8:24], net.IPv6loopback)
		copy(packet[24:40], net.IPv6loopback)
		packet[40] = 17
		flags := uint16(offset)
		if more {
			flags |= 1
		}
		binary.BigEndian.PutUint16(packet[42:], flags)
		binary.BigEndian.PutUint32(packet[44:], id)
		copy(packet[48:], data)
		return packet
	}
	packet := make([]byte, 20+len(data))
	packet[0], packet[8], packet[9] = 0x45, 64, 17
	binary.BigEndian.PutUint16(packet[2:], uint16(len(packet)))
	binary.BigEndian.PutUint16(packet[4:], uint16(id))
	flags := uint16(offset / 8)
	if more {
		flags |= 0x2000
	}
	binary.BigEndian.PutUint16(packet[6:], flags)
	copy(packet[12:16], net.IPv4(127, 0, 0, 1).To4())
	copy(packet[16:20], net.IPv4(127, 0, 0, 1).To4())
	binary.BigEndian.PutUint16(packet[10:], checksum16(packet[:20]))
	copy(packet[20:], data)
	return packet
}

func TestIsolatedUDPIPFragments(t *testing.T) {
	requireFragmentNamespace(t)
	for _, family := range []string{"udp4", "udp6"} {
		for index, mode := range []string{"ordered", "reversed", "missing-first", "missing-last", "mixed-id", "bad-checksum"} {
			t.Run(family+"/"+mode, func(t *testing.T) {
				ipv6 := family == "udp6"
				ip, domain := net.IPv4(127, 0, 0, 1), unix.AF_INET
				if ipv6 {
					ip, domain = net.IPv6loopback, unix.AF_INET6
				}
				fd, err := unix.Socket(domain, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.IPPROTO_RAW)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = unix.Close(fd) })
				if err := unix.SetsockoptString(fd, unix.SOL_SOCKET, unix.SO_BINDTODEVICE, "lo"); err != nil {
					t.Fatal(err)
				}
				listener, err := net.ListenUDP(family, &net.UDPAddr{IP: ip})
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = listener.Close() })
				if err := listener.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
					_ = listener.Close()
					t.Fatal(err)
				}
				query := udpProbePayload(53)
				var reply dnsmessage.Message
				if err := reply.Unpack(query); err != nil {
					t.Fatal(err)
				}
				reply.Response = true
				question := reply.Questions[0]
				reply.Answers = []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: question.Name, Class: question.Class}, Body: &dnsmessage.TXTResource{TXT: []string{strings.Repeat("private-fixture-", 8)}}}}
				payload, err := reply.Pack()
				if err != nil {
					t.Fatal(err)
				}
				done := make(chan error, 1)
				go func() {
					buffer := make([]byte, 512)
					n, peer, err := listener.ReadFromUDP(buffer)
					if err != nil {
						done <- err
						return
					}
					if !peer.IP.IsLoopback() || !bytes.Equal(buffer[:n], query) {
						done <- errors.New("unexpected fixture peer/query")
						return
					}
					udp := ipFragmentUDPPayload(ipv6, listener.LocalAddr().(*net.UDPAddr).Port, peer.Port, payload)
					if mode == "bad-checksum" {
						bad := binary.BigEndian.Uint16(udp[6:]) ^ 1
						if bad == 0 {
							bad = 2 // Zero would disable UDP checksumming in IPv4.
						}
						binary.BigEndian.PutUint16(udp[6:], bad)
					}
					id := uint32(1000 + index)
					first := ipFragmentPacket(ipv6, id, 0, true, udp[:32])
					lastID := id
					if mode == "mixed-id" {
						lastID += 100
					}
					last := ipFragmentPacket(ipv6, lastID, 32, false, udp[32:])
					packets := [][]byte{first, last}
					switch mode {
					case "reversed":
						packets = [][]byte{last, first}
					case "missing-first":
						packets = [][]byte{last}
					case "missing-last":
						packets = [][]byte{first}
					}
					for _, packet := range packets {
						var dest unix.Sockaddr = &unix.SockaddrInet4{Addr: [4]byte{127, 0, 0, 1}}
						if ipv6 {
							addr := [16]byte{}
							addr[15] = 1
							dest = &unix.SockaddrInet6{Addr: addr}
						}
						if err := unix.Sendto(fd, packet, 0, dest); err != nil {
							done <- err
							return
						}
					}
					done <- nil
				}()
				t.Cleanup(func() {
					_ = listener.Close()
					if err := <-done; err != nil {
						t.Error(err)
					}
				})
				s := NewScanner(ip.String(), false)
				s.Configure(ScanConfig{Timeout: 350 * time.Millisecond, NumWorkers: 1})
				response, err := s.exchangeUDP(listener.LocalAddr().String(), query)
				positive := mode == "ordered" || mode == "reversed"
				if !positive {
					state, _ := udpErrorState(err)
					if state != "open|filtered" || len(response) != 0 {
						t.Fatalf("invalid/incomplete IP fragments produced an application response: state=%s err=%v", state, err)
					}
					return
				}
				if err != nil || !bytes.Equal(response, payload) {
					t.Fatalf("IP fragments not reassembled intact: %v", err)
				}
				_, version, confidence, evidence := s.classifyUDPResponseForProbe(53, response, query, true)
				if version != "DNS response" || confidence != "medium" || !strings.Contains(evidence, "sent probe fields matched") || strings.Contains(evidence, "private-fixture") {
					t.Fatal("reassembled DNS response misclassified or disclosed")
				}
			})
		}
	}
}
