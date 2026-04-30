package scanner

import (
	"encoding/binary"
	"net"
	"testing"
	"time"
)

func TestProtocolFingerprintDetectsDynamicMountd(t *testing.T) {
	listener := startONCRPCTestServer(t, 100005, 3)

	port := listener.Addr().(*net.TCPAddr).Port
	s := NewScanner("127.0.0.1", false)
	s.Configure(ScanConfig{Timeout: 150 * time.Millisecond, NumWorkers: 1})

	results := s.Scan([]int{port}, true)
	if len(results) != 1 {
		t.Fatalf("expected one result, got %d (%v)", len(results), results)
	}
	if results[0].ServiceName != "mountd" {
		t.Fatalf("expected mountd, got %+v", results[0])
	}
	if results[0].Version != "mountd v3" {
		t.Fatalf("expected mountd v3, got %q", results[0].Version)
	}
	if results[0].DetectionPath != "protocol-fingerprint" {
		t.Fatalf("expected protocol-fingerprint, got %q", results[0].DetectionPath)
	}
}

func TestProtocolFingerprintDetectsNFSPort(t *testing.T) {
	listener := startONCRPCTestServer(t, 100003, 4)

	port := listener.Addr().(*net.TCPAddr).Port
	s := NewScanner("127.0.0.1", false)
	s.Configure(ScanConfig{Timeout: 150 * time.Millisecond, NumWorkers: 1})

	version, ok := s.detectONCRPCProgram(port, 100003, []uint32{4, 3, 2})
	if !ok {
		t.Fatal("expected NFS RPC program detection")
	}
	if version != 4 {
		t.Fatalf("expected NFS v4, got v%d", version)
	}
}

func startONCRPCTestServer(t *testing.T, program, version uint32) net.Listener {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go handleONCRPCTestConn(conn, program, version)
		}
	}()

	return listener
}

func handleONCRPCTestConn(conn net.Conn, program, version uint32) {
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))

	buf := make([]byte, 128)
	n, err := conn.Read(buf)
	if err != nil || n < 44 {
		return
	}
	payload := buf[4:n]
	xid := binary.BigEndian.Uint32(payload[0:4])
	gotProgram := binary.BigEndian.Uint32(payload[12:16])
	gotVersion := binary.BigEndian.Uint32(payload[16:20])
	if gotProgram != program || gotVersion != version {
		return
	}

	resp := make([]byte, 28)
	binary.BigEndian.PutUint32(resp[0:4], uint32(24)|0x80000000)
	binary.BigEndian.PutUint32(resp[4:8], xid)
	binary.BigEndian.PutUint32(resp[8:12], 1)  // REPLY
	binary.BigEndian.PutUint32(resp[12:16], 0) // MSG_ACCEPTED
	binary.BigEndian.PutUint32(resp[16:20], 0) // AUTH_NULL verifier
	binary.BigEndian.PutUint32(resp[20:24], 0)
	binary.BigEndian.PutUint32(resp[24:28], 0) // SUCCESS
	_, _ = conn.Write(resp)
}
