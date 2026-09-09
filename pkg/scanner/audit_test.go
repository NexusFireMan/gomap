package scanner

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"testing/iotest"
	"time"
)

func mysqlFixture() []byte {
	payload := append([]byte{10}, []byte("8.0.27\x00")...)
	return append([]byte{byte(len(payload)), 0, 0, 0}, payload...)
}

func TestFramedReadersHandleFragmentedAndTruncatedInput(t *testing.T) {
	rpc := make([]byte, 28)
	binary.BigEndian.PutUint32(rpc, 0x80000018)
	binary.BigEndian.PutUint32(rpc[4:], 123)
	binary.BigEndian.PutUint32(rpc[8:], 1)
	dns := append([]byte{0, 12}, make([]byte, 12)...)
	for _, tc := range []struct {
		name  string
		frame []byte
		read  func(io.Reader) ([]byte, error)
	}{
		{"mysql", mysqlFixture(), readMySQLPacket},
		{"dns", dns, readDNSMessage},
		{"rpc", rpc, readRPCRecord},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.read(iotest.OneByteReader(bytes.NewReader(tc.frame)))
			if err != nil || !bytes.Equal(got, tc.frame) {
				t.Fatalf("fragmented frame: %x, %v", got, err)
			}
			for end := 0; end < len(tc.frame); end++ {
				if _, err := tc.read(bytes.NewReader(tc.frame[:end])); err == nil {
					t.Fatalf("accepted truncated frame of %d bytes", end)
				}
			}
		})
	}
	if _, err := readMySQLPacket(bytes.NewReader([]byte{255, 255, 255, 0})); err == nil {
		t.Fatal("accepted oversized MySQL packet")
	}
	if _, err := readRPCRecord(bytes.NewReader([]byte{255, 255, 255, 255})); err == nil {
		t.Fatal("accepted oversized RPC record")
	}
	fragmented := append([]byte{0, 0, 0, 12}, rpc[4:16]...)
	fragmented = append(fragmented, 0x80, 0, 0, 12)
	fragmented = append(fragmented, rpc[16:]...)
	record, err := readRPCRecord(bytes.NewReader(fragmented))
	if err != nil || !bytes.Equal(record, rpc) {
		t.Fatalf("RPC record fragments: %x, %v", record, err)
	}
	if accepted, valid := parseONCRPCReply(record, 123); !accepted || !valid {
		t.Fatal("valid RPC response rejected")
	}
	binary.BigEndian.PutUint32(record[20:], ^uint32(0))
	if accepted, valid := parseONCRPCReply(record, 123); accepted || valid {
		t.Fatal("invalid verifier accepted")
	}
}

func TestMySQLHandshakeRejectsIncompleteFrames(t *testing.T) {
	packet := mysqlFixture()
	if got := parseMySQLHandshakePacket(packet); got != "MySQL 8.0.27" {
		t.Fatal(got)
	}
	for end := 0; end < len(packet); end++ {
		if got := parseMySQLHandshakePacket(packet[:end]); got != "" {
			t.Fatalf("accepted incomplete handshake: %q", got)
		}
	}
	packet[3] = 1
	if got := parseMySQLHandshakePacket(packet); got != "" {
		t.Fatal("accepted non-greeting sequence")
	}
}

func TestTargetAndPortDeduplication(t *testing.T) {
	targets, err := ParseTargets("127.0.0.1,127.0.0.0/30,127.0.0.2")
	if err != nil || !reflect.DeepEqual(targets, []string{"127.0.0.1", "127.0.0.2"}) {
		t.Fatalf("targets: %v, %v", targets, err)
	}
	ports, err := NewPortManager().ParsePorts("22,80-82,80,443")
	if err != nil || !reflect.DeepEqual(ports, []int{22, 80, 81, 82, 443}) {
		t.Fatalf("ports: %v, %v", ports, err)
	}
}

func TestDiscoveryBoundedAndOrdered(t *testing.T) {
	hosts := make([]string, 1000)
	for i := range hosts {
		hosts[i] = fmt.Sprint(i)
	}
	var running, peak atomic.Int32
	got := discoverHosts(hosts, 4, func(string) bool {
		current := running.Add(1)
		defer running.Add(-1)
		for old := peak.Load(); current > old; old = peak.Load() {
			if peak.CompareAndSwap(old, current) {
				break
			}
		}
		return true
	})
	if peak.Load() > 4 || !reflect.DeepEqual(got, hosts) {
		t.Fatalf("discovery order or concurrency changed: peak=%d", peak.Load())
	}
}

func TestHTTPBannerBoundedAndCaseInsensitive(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Server", "fixture/1.0")
		_, _ = io.WriteString(w, strings.Repeat("x", 128*1024))
	}))
	defer server.Close()
	addr := server.Listener.Addr().(*net.TCPAddr)
	s := NewScanner(addr.IP.String(), false)
	banner := s.grabHTTPBanner(addr.Port)
	if len(banner) > 64*1024 || !strings.Contains(banner, "fixture/1.0") {
		t.Fatalf("unexpected banner size/content: %d", len(banner))
	}
	for _, header := range []string{"Server", "server", "SERVER", "sErVeR"} {
		_, version := parseHTTP("HTTP/1.1 200 OK\r\n" + header + ": fixture/1.0\r\n\r\n")
		if version != "fixture/1.0" {
			t.Fatalf("%s: %q", header, version)
		}
	}
	_, version := parseHTTP("HTTP/1.1 200 OK\r\n\r\nServer: forged/1.0")
	if version != "" {
		t.Fatalf("interpreted body text as a server header: %q", version)
	}
}

func TestAJPResponseUsesContainerMagic(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
		request := make([]byte, 5)
		if _, err := io.ReadFull(conn, request); err == nil {
			_, _ = conn.Write([]byte("AB\x00\x01\x09"))
		}
	}()
	s := NewScanner("127.0.0.1", false)
	if !s.detectAJP(listener.Addr().(*net.TCPAddr).Port) {
		t.Error("CPONG not recognized")
	}
	<-done
}

func TestSMBNegotiateWireFormat(t *testing.T) {
	request := buildSMBNegotiate()
	if int(binary.BigEndian.Uint32(request)) != len(request)-4 || string(request[4:8]) != "\xfeSMB" || binary.LittleEndian.Uint16(request[68:70]) != 36 {
		t.Fatal("invalid SMB negotiate request")
	}
	response := make([]byte, 128)
	copy(response, "\xfeSMB")
	binary.LittleEndian.PutUint16(response[4:], 64)
	binary.LittleEndian.PutUint32(response[16:], 1)
	binary.LittleEndian.PutUint16(response[64:], 65)
	binary.LittleEndian.PutUint16(response[68:], 0x0302)
	s := NewScanner("fixture.invalid", false)
	if got := s.analyzeSMBResponse(response); got != "SMB 3.0.2" {
		t.Fatal(got)
	}
	for size := 0; size < len(response); size++ {
		if got := s.analyzeSMBResponse(response[:size]); got != "" {
			t.Fatalf("accepted short SMB response: %d %q", size, got)
		}
	}
	response[8] = 1
	if got := s.analyzeSMBResponse(response); got != "" {
		t.Fatal("accepted failed negotiation")
	}
	if got := s.analyzeSMBResponse([]byte("not an SMB frame: Samba smbd 4.0")); got != "" {
		t.Fatal("accepted unframed text as binary SMB evidence")
	}
}

func BenchmarkParseSSH(b *testing.B) {
	for i := 0; i < b.N; i++ {
		parseSSH("SSH-2.0-OpenSSH_9.6p1 Debian-4")
	}
}

func BenchmarkDiscoveryWorkers(b *testing.B) {
	hosts := make([]string, 1024)
	for i := range hosts {
		hosts[i] = fmt.Sprint(i)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		discoverHosts(hosts, 8, func(string) bool { return true })
	}
}

func FuzzBinaryParsers(f *testing.F) {
	f.Add(mysqlFixture())
	f.Add([]byte{0xff, 0xff, 0xff, 0xff})
	f.Fuzz(func(t *testing.T, data []byte) {
		_ = parseMySQLHandshakePacket(data)
		_, _ = parseONCRPCReply(data, 123)
		_ = parseDNSVersionBindResponse(data)
		_, _, _ = parseTCPResponsePacket(data)
		_, _ = parseRDPNegotiationProtocol(data)
	})
}
