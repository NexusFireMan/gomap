package scanner

import (
	"net"
	"testing"
	"time"
)

func TestGenericProbeDetectsFTPOnNonStandardPort(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = listener.Close() }()

	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 16; i++ {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer func() { _ = c.Close() }()
				_ = c.SetDeadline(time.Now().Add(2 * time.Second))
				buf := make([]byte, 512)
				n, _ := c.Read(buf)
				if n > 0 {
					_, _ = c.Write([]byte("220 HTB{pr0F7pDv3r510nb4nn3r}\r\n"))
				}
			}(conn)
		}
	}()

	port := listener.Addr().(*net.TCPAddr).Port
	s := NewScanner("127.0.0.1", false)
	s.Configure(ScanConfig{Timeout: 150 * time.Millisecond, NumWorkers: 1})

	results := s.Scan([]int{port}, true)
	if len(results) != 1 {
		t.Fatalf("expected one result, got %d (%v)", len(results), results)
	}
	if results[0].ServiceName != "ftp" {
		t.Fatalf("expected ftp on non-standard port, got %+v", results[0])
	}
	if results[0].DetectionPath != "banner-parser" {
		t.Fatalf("expected banner-parser path, got %q", results[0].DetectionPath)
	}

	_ = listener.Close()
}

func TestFTPProbeEnrichesGenericGreetingWithSYST(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = listener.Close() }()

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer func() { _ = c.Close() }()
				_ = c.SetDeadline(time.Now().Add(2 * time.Second))
				_, _ = c.Write([]byte("220\r\n"))

				buf := make([]byte, 512)
				for {
					n, err := c.Read(buf)
					if err != nil || n == 0 {
						return
					}
					switch string(buf[:n]) {
					case "SYST\r\n":
						_, _ = c.Write([]byte("215 UNIX Type: L8\r\n"))
					case "FEAT\r\n":
						_, _ = c.Write([]byte("211 no-features\r\n"))
					case "HELP\r\n":
						_, _ = c.Write([]byte("214 help ok\r\n"))
					}
				}
			}(conn)
		}
	}()

	port := listener.Addr().(*net.TCPAddr).Port
	s := NewScanner("127.0.0.1", false)
	s.Configure(ScanConfig{Timeout: 150 * time.Millisecond, NumWorkers: 1})

	results := s.Scan([]int{port}, true)
	if len(results) != 1 {
		t.Fatalf("expected one result, got %d (%v)", len(results), results)
	}
	if results[0].ServiceName != "ftp" {
		t.Fatalf("expected ftp, got %+v", results[0])
	}
	if results[0].Version != "SYST UNIX Type: L8" {
		t.Fatalf("expected SYST UNIX Type: L8, got %+v", results[0])
	}
}
