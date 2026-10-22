package scanner

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

func TestWriteFirstTextTransactionsOverLoopback(t *testing.T) {
	for _, tc := range transactionFixtures() {
		t.Run(tc.name, func(t *testing.T) {
			port, done := serveStreamFixture(t, func(conn net.Conn) error {
				request := make([]byte, len(tc.payload))
				if _, err := io.ReadFull(conn, request); err != nil {
					return err
				}
				if string(request) != tc.payload {
					return fmt.Errorf("request changed: %q", request)
				}
				if _, err := io.WriteString(conn, tc.response); err != nil {
					return err
				}
				var extra [1]byte
				if n, err := conn.Read(extra[:]); n != 0 || err != io.EOF {
					return fmt.Errorf("unexpected follow-up or unclosed connection: n=%d err=%v", n, err)
				}
				return nil
			})
			s := NewScanner("127.0.0.1", false)
			s.Configure(ScanConfig{Timeout: 3 * time.Second, NumWorkers: 1})
			var got string
			if strings.HasPrefix(tc.payload, "NICK ") || tc.payload == "INFO\r\n" {
				got = s.probeTextService(port, tc.payload)
			} else {
				got = s.probeTextServiceWriteFirstWithTimeout(port, tc.payload, time.Second, 3*time.Second)
			}
			if got != tc.response {
				t.Fatalf("response lost: got=%q want=%q", got, tc.response)
			}
			waitStreamFixture(t, done)
		})
	}
}

func TestGenericProbeKeepsHTTPHeadersTogether(t *testing.T) {
	response := "HTTP/1.1 400 Bad Request\r\nServer: fixture/1.0\r\nContent-Length: 0\r\n\r\n"
	port, done := serveStreamFixture(t, func(conn net.Conn) error {
		r := bufio.NewReader(conn)
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				return err
			}
			if line == "\r\n" {
				break
			}
		}
		_, err := io.WriteString(conn, response)
		return err
	})
	s := NewScanner("127.0.0.1", false)
	s.Configure(ScanConfig{Timeout: time.Second, NumWorkers: 1})
	got := s.tryGenericServiceProbes(port)
	if service, version := parseObservedBanner(got); got != response || service != "http" || version != "fixture/1.0" {
		t.Fatalf("generic response fragmented into partial header: %q", got)
	}
	waitStreamFixture(t, done)
}

func BenchmarkTextTransactions(b *testing.B) {
	for _, index := range []int{0, 3, 12} {
		tc := transactionFixtures()[index]
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				if _, err := readTextTransaction(bufio.NewReaderSize(strings.NewReader(tc.response), 512), tc.payload); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
