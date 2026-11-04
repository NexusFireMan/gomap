package scanner

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"
	"testing/iotest"
	"time"
)

func redisTransactionFixture() string {
	body := "# Server\r\nredis_version:7.2.4\r\nredis_mode:standalone\r\n"
	return fmt.Sprintf("$%d\r\n%s\r\n", len(body), body)
}

func transactionFixtures() []struct{ name, payload, response string } {
	return []struct{ name, payload, response string }{
		{"RESP INFO", "INFO\r\n", redisTransactionFixture()},
		{"RESP array", "INFO\r\n", "*3\r\n$3\r\na\x00b\r\n:42\r\n*-1\r\n"},
		{"RESP error", "INFO\r\n", "-NOAUTH Authentication required.\r\n"},
		{"IRC", "NICK gomap\r\nUSER gomap 0 * :GoMap\r\n", ":irc.fixture NOTICE AUTH :Checking hostname\r\n:irc.fixture 001 gomap :Welcome\r\n:irc.fixture 004 gomap irc.fixture UnrealIRCd-6.1.0 oi oi\r\n"},
		{"IRC denial", "NICK gomap\r\nUSER gomap 0 * :GoMap\r\n", ":irc.fixture 433 * gomap :Nickname in use\r\n"},
		{"generic line", "HELP\r\n", "SSH-2.0-OpenSSH_9.6p1\r\n"},
		{"numeric multiline", "HELP\r\n", "211-Features\r\n UTF8\r\n211 End\r\n"},
		{"SMTP EHLO", "EHLO gomap.local\r\n", "220 fixture ESMTP\r\n250-fixture\r\n250-SIZE 1000\r\n250 HELP\r\n"},
		{"SMTP denial", "EHLO gomap.local\r\n", "500-bad command\r\n500 No EHLO\r\n"},
		{"POP3 CAPA", "CAPA\r\n", "+OK capability list follows\r\nUSER\r\n..escaped\r\n.\r\n"},
		{"POP3 denial", "CAPA\r\n", "-ERR unavailable\r\n"},
		{"IMAP tagged", "a001 CAPABILITY\r\n", "* OK fixture\r\n* CAPABILITY IMAP4rev1\r\nA001 oK Done\r\n"},
		{"HTTP body", "GET / HTTP/1.0\r\n\r\n", "HTTP/1.1 200 OK\r\nServer: fixture/1.0\r\nContent-Length: 5\r\n\r\nhello"},
		{"HTTP chunks", "GET / HTTP/1.0\r\n\r\n", "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nhe\r\n3\r\nllo\r\n0\r\nX-Fixture: yes\r\n\r\n"},
		{"HTTP HEAD", "HEAD / HTTP/1.0\r\n\r\n", "HTTP/1.1 200 OK\r\nContent-Length: 9000000\r\n\r\n"},
		{"RTSP", "OPTIONS rtsp://gomap.local/ RTSP/1.0\r\nCSeq: 1\r\n\r\n", "RTSP/1.0 200 OK\r\nCSeq: 1\r\nServer: fixture/1.0\r\nContent-Length: 4\r\n\r\nbody"},
		{"SIP", "OPTIONS sip:gomap.local SIP/2.0\r\n\r\n", "SIP/2.0 401 Unauthorized\r\nServer: fixture/1.0\r\nContent-Length: 0\r\n\r\n"},
	}
}

func TestTextTransactionsEverySplitAndMessageBoundary(t *testing.T) {
	for _, tc := range transactionFixtures() {
		t.Run(tc.name, func(t *testing.T) {
			for cut := 0; cut <= len(tc.response); cut++ {
				r := bufio.NewReader(io.MultiReader(strings.NewReader(tc.response[:cut]), iotest.OneByteReader(strings.NewReader(tc.response[cut:]))))
				got, err := readTextTransaction(r, tc.payload)
				if err != nil || got != tc.response {
					t.Fatalf("cut=%d got=%q err=%v", cut, got, err)
				}
			}
			r := bufio.NewReader(strings.NewReader(tc.response + "NEXT-MESSAGE"))
			if got, err := readTextTransaction(r, tc.payload); err != nil || got != tc.response {
				t.Fatalf("got=%q err=%v", got, err)
			}
			if rest, _ := io.ReadAll(r); string(rest) != "NEXT-MESSAGE" {
				t.Fatal("next buffered message consumed")
			}
			r = bufio.NewReader(iotest.DataErrReader(strings.NewReader(tc.response)))
			if got, err := readTextTransaction(r, tc.payload); err != nil || got != tc.response {
				t.Fatal("complete final EOF bytes lost")
			}
			for cut := 0; cut < len(tc.response); cut++ {
				for _, failure := range []error{io.EOF, os.ErrDeadlineExceeded, io.ErrClosedPipe} {
					r := bufio.NewReader(io.MultiReader(strings.NewReader(tc.response[:cut]), framingErrorReader{failure}))
					got, err := readTextTransaction(r, tc.payload)
					if err == nil || !strings.HasPrefix(tc.response, got) {
						t.Fatalf("cut=%d failure=%v err=%v got=%q", cut, failure, err, got)
					}
				}
			}
		})
	}
}

func TestRESPMalformedFramesAndBudgets(t *testing.T) {
	for _, frame := range []string{
		"$-2\r\n", "$+1\r\nx\r\n", "$1\nx\r\n", "$1\r\nx!!", "$4294967295\r\n", "$65536\r\n", "*65\r\n", "*2\r\n+OK\r\n", ":9223372036854775808\r\n", ": 1\r\n", ":1\r2\r\n", strings.Repeat("*1\r\n", 10) + "+OK\r\n", "_\r\n", "%0\r\n",
	} {
		if _, err := readTextTransaction(bufio.NewReader(strings.NewReader(frame)), "INFO\r\n"); err == nil {
			t.Fatalf("malformed/unsupported RESP accepted: %q", frame)
		}
	}
	for _, frame := range []string{"$0\r\n\r\n", "$-1\r\n", "*-1\r\n", "*0\r\n", ":+1\r\n", ":-9223372036854775808\r\n", "+OK\r\n"} {
		if got, err := readTextTransaction(bufio.NewReader(strings.NewReader(frame)), "INFO\r\n"); err != nil || got != frame {
			t.Fatalf("legal RESP rejected: %q %v", frame, err)
		}
	}
	frame := "*64\r\n" + strings.Repeat("*1\r\n+OK\r\n", 64)
	if _, err := readTextTransaction(bufio.NewReader(strings.NewReader(frame)), "INFO\r\n"); err == nil {
		t.Fatal("RESP total-node budget exceeded")
	}
	stream := bufio.NewReader(strings.NewReader("$65536\r\nUNREAD"))
	if _, err := readTextTransaction(stream, "INFO\r\n"); err == nil {
		t.Fatal("oversized bulk accepted")
	}
	if rest, _ := io.ReadAll(stream); string(rest) != "UNREAD" {
		t.Fatal("oversized body consumed")
	}
	frame = strings.Repeat("x", 5000)
	if got, err := readTextTransaction(bufio.NewReader(strings.NewReader(frame)), "HELP\r\n"); err == nil || len(got) != textTransactionLimit {
		t.Fatal("generic byte bound lost")
	}
}

func TestTransactionRejectsMalformedHeadersAndTerminators(t *testing.T) {
	for _, tc := range []struct{ payload, response string }{
		{"GET / HTTP/1.0\r\n\r\n", "HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\nxx"},
		{"GET / HTTP/1.0\r\n\r\n", "HTTP/1.1 200 OK\r\nContent-Length: 9223372036854775807\r\n\r\n"},
		{"GET / HTTP/1.0\r\n\r\n", "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1\r\nx!!"},
		{"GET / HTTP/1.0\r\n\r\n", "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n10000\r\n"},
		{"CAPA\r\n", "+OK list\r\nUSER\r\n"},
		{"a001 CAPABILITY\r\n", "* CAPABILITY IMAP4rev1\r\na002 OK wrong tag\r\n"},
		{"EHLO gomap.local\r\n", "250-fixture\r\n251 wrong end\r\n"},
		{"NICK gomap\r\n", strings.Repeat("x", 512) + "\r\n"},
		{"NICK gomap\r\n", ":server NOTICE AUTH :bad\x00line\r\n"},
	} {
		if _, err := readTextTransaction(bufio.NewReader(strings.NewReader(tc.response)), tc.payload); err == nil {
			t.Fatalf("malformed transaction accepted: %q", tc.response)
		}
	}
	response := strings.Repeat(":s NOTICE AUTH :waiting\r\n", 33)
	if _, err := readTextTransaction(bufio.NewReader(strings.NewReader(response)), "NICK gomap\r\n"); err == nil {
		t.Fatal("IRC line-count cap lost")
	}
}

func TestTransactionWriteFirstFixedDeadlineAndFailures(t *testing.T) {
	response := redisTransactionFixture()
	conn := &textFragmentConn{transportFixtureConn: transportFixtureConn{r: iotest.OneByteReader(strings.NewReader(response))}}
	if got := exchangeTextTransaction(conn, "INFO\r\n", time.Second); got != response || conn.deadlines != 1 || conn.w.String() != "INFO\r\n" {
		t.Fatal("transaction lost bytes, changed request or renewed deadline")
	}
	for _, failure := range []string{"deadline", "write", "short"} {
		trap := &greetingReadTrap{}
		conn := &negotiationWriteConn{textFragmentConn: textFragmentConn{transportFixtureConn: transportFixtureConn{r: trap}}, writeErr: io.ErrClosedPipe, short: failure == "short"}
		if failure == "deadline" {
			conn.deadlineErr = os.ErrDeadlineExceeded
		}
		if got := exchangeTextTransaction(conn, "INFO\r\n", time.Second); got != "" || trap.calls != 0 || conn.deadlines != 1 {
			t.Fatal("IO continued after deadline/write failure")
		}
	}
}

func TestCloseDelimitedHTTPAndCompleteReplyEarlyStop(t *testing.T) {
	response := "HTTP/1.0 200 OK\r\nServer: fixture/1.0\r\n\r\nbody"
	for _, failure := range []error{io.EOF, os.ErrDeadlineExceeded} {
		r := bufio.NewReader(io.MultiReader(strings.NewReader(response), framingErrorReader{failure}))
		got, err := readTextTransaction(r, "GET / HTTP/1.0\r\n\r\n")
		if got != response || (err == nil) != (failure == io.EOF) {
			t.Fatalf("close-delimited collection: got=%q err=%v", got, err)
		}
	}
	for _, tc := range transactionFixtures() {
		trap := &greetingReadTrap{}
		r := bufio.NewReaderSize(io.MultiReader(strings.NewReader(tc.response), trap), 512)
		if got, err := readTextTransaction(r, tc.payload); err != nil || got != tc.response || trap.calls != 0 {
			t.Fatalf("%s: complete reply waited for close: %v calls=%d", tc.name, err, trap.calls)
		}
	}
}

func FuzzTextTransactionFragmentation(f *testing.F) {
	for i, tc := range transactionFixtures() {
		f.Add(byte(i), []byte(tc.response))
	}
	f.Fuzz(func(t *testing.T, mode byte, data []byte) {
		if len(data) > respTransactionLimit+1 {
			return
		}
		fixtures := transactionFixtures()
		payload := fixtures[int(mode)%len(fixtures)].payload
		original := bytes.Clone(data)
		a, errA := readTextTransaction(bufio.NewReader(bytes.NewReader(data)), payload)
		b, errB := readTextTransaction(bufio.NewReader(iotest.OneByteReader(bytes.NewReader(data))), payload)
		if a != b || (errA == nil) != (errB == nil) || len(a) > respTransactionLimit || !bytes.Equal(data, original) {
			t.Fatal("transaction depends on read boundaries or exceeds bounds")
		}
	})
}
