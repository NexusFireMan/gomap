package scanner

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"
	"testing/iotest"
	"time"
)

type textFragmentConn struct {
	transportFixtureConn
	deadlines   int
	deadlineErr error
}

type greetingReadTrap struct{ calls int }

func (r *greetingReadTrap) Read([]byte) (int, error) {
	r.calls++
	return 0, os.ErrDeadlineExceeded
}

func TestTextGreetingBoundsAndEarlyStop(t *testing.T) {
	line := "220 fixture ESMTP Postfix\r\n"
	trap := &greetingReadTrap{}
	if got := readTextGreeting(io.MultiReader(strings.NewReader(line), trap)); got != line || trap.calls != 0 {
		t.Fatal("complete line waited for another read")
	}
	trap = &greetingReadTrap{}
	partial := "220 fixture ESMTP partial"
	if got := readTextGreeting(io.MultiReader(strings.NewReader(partial), trap)); got != partial || trap.calls != 1 {
		t.Fatal("final partial bytes lost or retried after timeout")
	}
	stream := strings.NewReader(strings.Repeat("x", 4096) + "UNREAD")
	if got := readTextGreeting(stream); len(got) != 4096 || stream.Len() != len("UNREAD") {
		t.Fatal("greeting exceeded its allocation/read bound")
	}
	if got := readTextGreeting(iotest.DataErrReader(strings.NewReader(line))); got != line {
		t.Fatal("complete greeting with final EOF lost")
	}
}

func (c *textFragmentConn) SetDeadline(time.Time) error     { c.deadlines++; return c.deadlineErr }
func (c *textFragmentConn) SetReadDeadline(time.Time) error { c.deadlines++; return c.deadlineErr }

func TestTextGreetingDeadlineFailurePreventsIO(t *testing.T) {
	for _, active := range []bool{false, true} {
		trap := &greetingReadTrap{}
		conn := &textFragmentConn{transportFixtureConn: transportFixtureConn{r: trap}, deadlineErr: os.ErrDeadlineExceeded}
		s := NewScanner("fixture.invalid", false)
		var banner string
		if active {
			banner = s.probeTextServiceOnConn(conn, "EHLO fixture.invalid\r\n")
		} else {
			banner = s.tryPassiveBanner(conn)
		}
		if banner != "" || trap.calls != 0 || conn.w.Len() != 0 || conn.deadlines != 1 {
			t.Fatal("greeting attempted IO without a working deadline")
		}
	}
}

func BenchmarkTextGreetingCompleteLine(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		readTextGreeting(strings.NewReader("SSH-2.0-OpenSSH_9.6p1 fixture\r\n"))
	}
}

func TestTextGreetingFragmentation(t *testing.T) {
	for _, banner := range []string{
		"SSH-2.0-OpenSSH_9.6p1 fixture\r\n",
		"220 fixture ESMTP Postfix\r\n",
		"220 ProFTPD 1.3.5 Server\r\n",
		"+OK fixture POP3 v1.2\r\n",
		"* OK [CAPABILITY IMAP4rev1] fixture\r\n",
		"220-fixture ESMTP\r\n220 fixture ESMTP Postfix\r\n",
		"211-Features\r\n UTF8\r\n211 End\r\n",
	} {
		for cut := 0; cut <= len(banner); cut++ {
			reader := io.MultiReader(bytes.NewReader([]byte(banner[:cut])), iotest.OneByteReader(bytes.NewReader([]byte(banner[cut:]))))
			conn := &textFragmentConn{transportFixtureConn: transportFixtureConn{r: reader}}
			if got := NewScanner("fixture.invalid", false).tryPassiveBanner(conn); got != banner {
				t.Fatalf("split %d: got=%q want=%q", cut, got, banner)
			}
			if conn.deadlines != 1 {
				t.Fatal("passive read renewed its deadline per chunk")
			}
		}
		conn := &textFragmentConn{transportFixtureConn: transportFixtureConn{r: iotest.OneByteReader(bytes.NewReader([]byte(banner)))}}
		if got := NewScanner("fixture.invalid", false).probeTextServiceOnConn(conn, "EHLO fixture.invalid\r\n"); got != banner || conn.w.String() != "EHLO fixture.invalid\r\n" || conn.deadlines != 1 {
			t.Fatal("active probe failed to collect fragmented greeting under one deadline")
		}
	}
}

func TestTextGreetingCompleteLineDoesNotWaitForClose(t *testing.T) {
	for _, failure := range []error{io.EOF, os.ErrDeadlineExceeded} {
		banner := "220 fixture ESMTP Postfix\r\n"
		reader := io.MultiReader(bytes.NewReader([]byte(banner)), framingErrorReader{failure})
		conn := &textFragmentConn{transportFixtureConn: transportFixtureConn{r: reader}}
		if got := NewScanner("fixture.invalid", false).tryPassiveBanner(conn); got != banner {
			t.Fatal("complete line lost at terminal error")
		}
	}
}
