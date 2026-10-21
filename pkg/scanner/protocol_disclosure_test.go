package scanner

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"testing/iotest"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

func dnsDisclosureFixture(t testing.TB, mutate func(*dnsmessage.Message)) []byte {
	t.Helper()
	name := dnsmessage.MustNewName("version.bind.")
	msg := dnsmessage.Message{
		Header:    dnsmessage.Header{ID: 0x1337, Response: true},
		Questions: []dnsmessage.Question{{Name: name, Type: dnsmessage.TypeTXT, Class: dnsmessage.ClassCHAOS}},
		Answers:   []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: name, Type: dnsmessage.TypeTXT, Class: dnsmessage.ClassCHAOS}, Body: &dnsmessage.TXTResource{TXT: []string{"fixture-dns/1.0"}}}},
	}
	if mutate != nil {
		mutate(&msg)
	}
	wire, err := msg.Pack()
	if err != nil {
		t.Fatal(err)
	}
	frame := make([]byte, 2, len(wire)+2)
	binary.BigEndian.PutUint16(frame, uint16(len(wire)))
	return append(frame, wire...)
}

func TestDNSDisclosureRequiresCorrelatedCompleteAnswer(t *testing.T) {
	valid := dnsDisclosureFixture(t, nil)
	if got := parseDNSVersionBindResponse(valid); got != "DNS version.bind: fixture-dns/1.0" {
		t.Fatal(got)
	}
	for cut := 0; cut < len(valid); cut++ {
		if got := parseDNSVersionBindResponse(valid[:cut]); got != "" {
			t.Fatalf("truncation at %d accepted: %q", cut, got)
		}
	}
	for _, mutate := range []func(*dnsmessage.Message){
		func(m *dnsmessage.Message) { m.ID++ },
		func(m *dnsmessage.Message) { m.Response = false },
		func(m *dnsmessage.Message) { m.Truncated = true },
		func(m *dnsmessage.Message) { m.OpCode = 1 },
		func(m *dnsmessage.Message) { m.RCode = dnsmessage.RCodeNameError },
		func(m *dnsmessage.Message) { m.Questions = nil },
		func(m *dnsmessage.Message) { m.Questions = append(m.Questions, m.Questions[0]) },
		func(m *dnsmessage.Message) { m.Questions[0].Name = dnsmessage.MustNewName("other.invalid.") },
		func(m *dnsmessage.Message) { m.Questions[0].Class = dnsmessage.ClassINET },
		func(m *dnsmessage.Message) { m.Questions[0].Type = dnsmessage.TypeA },
		func(m *dnsmessage.Message) { m.Answers[0].Header.Name = dnsmessage.MustNewName("other.invalid.") },
		func(m *dnsmessage.Message) { m.Answers[0].Header.Class = dnsmessage.ClassINET },
		func(m *dnsmessage.Message) { m.Answers = append(m.Answers, m.Answers[0]) },
		func(m *dnsmessage.Message) { m.Answers[0].Body = &dnsmessage.TXTResource{TXT: []string{"one", "two"}} },
		func(m *dnsmessage.Message) { m.Answers[0].Body = &dnsmessage.TXTResource{TXT: []string{""}} },
		func(m *dnsmessage.Message) {
			m.Answers[0].Body = &dnsmessage.TXTResource{TXT: []string{"fixture\x00version"}}
		},
		func(m *dnsmessage.Message) {
			m.Answers[0].Body = &dnsmessage.TXTResource{TXT: []string{"fixture\r\nforged"}}
		},
	} {
		if got := parseDNSVersionBindResponse(dnsDisclosureFixture(t, mutate)); got != "" {
			t.Fatalf("uncorrelated or ambiguous disclosure accepted: %q", got)
		}
	}
	for _, adjustedLength := range []bool{false, true} {
		frame := append(bytes.Clone(valid), 0)
		if adjustedLength {
			binary.BigEndian.PutUint16(frame, uint16(len(frame)-2))
		}
		if parseDNSVersionBindResponse(frame) != "" {
			t.Fatal("trailing bytes accepted")
		}
	}
}

func TestWSManHTTPDisclosureDoesNotConfirmWinRM(t *testing.T) {
	for _, tc := range []struct{ raw, version string }{
		{"HTTP/1.1 404 Not Found\r\nServer: Microsoft-HTTPAPI/2.0\r\nContent-Length: 0\r\n\r\n", "Microsoft-HTTPAPI/2.0"},
		{"HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Negotiate private-token\r\nContent-Length: 0\r\n\r\n", ""},
		{"HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\nContent-Length: 100\r\n\r\nshort body", "Nginx 1.24.0"},
		{"HTTP/1.1 200 OK\r\nContent-Length: 80\r\n\r\nwsman\r\nServer: Microsoft-HTTPAPI/9.9\r\n<title>WinRM</title>", ""},
		{"HTTP/1.1 200 OK\r\nServer: one/1\r\nServer: two/2\r\n\r\n", ""},
	} {
		version, evidence := wsmanHTTPDisclosure(tc.raw)
		if version != tc.version || !strings.Contains(evidence, "WinRM not confirmed") || strings.Contains(evidence, "private-token") || strings.Contains(evidence, "HTTPAPI/9.9") {
			t.Fatalf("unsupported identity or sensitive evidence: %q %q", version, evidence)
		}
	}
	for _, raw := range []string{
		"wsman Microsoft-HTTPAPI/2.0\r\n",
		"HTTP/1.1 200 OK\r\nServer: Microsoft-HTTPAPI/2.",
		"HTTP/1.1 200 OK\r\nServer: Microsoft-HTTPAPI/2.0\r\ninvalid\r\n\r\n",
		"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\nxx",
		"HTTP/1.1 200 OK\r\nServer: " + strings.Repeat("x", textTransactionLimit) + "\r\n\r\n",
	} {
		if version, evidence := wsmanHTTPDisclosure(raw); version != "" || evidence != "" {
			t.Fatalf("invalid/incomplete headers promoted: %q %q", version, evidence)
		}
	}
}

func TestDNSDisclosureStreamAndUnchangedQuery(t *testing.T) {
	for _, valid := range []bool{true, false} {
		response := dnsDisclosureFixture(t, func(m *dnsmessage.Message) {
			if !valid {
				m.ID++
			}
		})
		port, done := serveStreamFixture(t, func(conn net.Conn) error {
			request, err := readDNSMessage(conn)
			if err != nil {
				return err
			}
			if !bytes.Equal(request, buildDNSVersionBindQuery()) {
				t.Error("DNS probe changed")
			}
			for _, b := range response {
				if _, err := conn.Write([]byte{b}); err != nil {
					return err
				}
			}
			return nil
		})
		s := NewScanner("127.0.0.1", false)
		got := s.detectDNSVersionTCP(port)
		waitStreamFixture(t, done)
		if (got != "") != valid {
			t.Fatalf("valid=%t: disclosure=%q", valid, got)
		}
	}
}

func TestWSManHTTPStreamAndRequest(t *testing.T) {
	response := "HTTP/1.1 404 Not Found\r\nServer: Microsoft-HTTPAPI/2.0\r\nContent-Length: 0\r\n\r\n"
	for cut := 0; cut <= len(response); cut++ {
		conn := &textFragmentConn{transportFixtureConn: transportFixtureConn{r: io.MultiReader(strings.NewReader(response[:cut]), iotest.OneByteReader(strings.NewReader(response[cut:])))}}
		version, _ := probeWSManHTTP(conn, "OPTIONS /wsman HTTP/1.1\r\n\r\n", time.Second)
		if version != "Microsoft-HTTPAPI/2.0" || conn.deadlines != 1 || conn.w.String() != "OPTIONS /wsman HTTP/1.1\r\n\r\n" {
			t.Fatalf("split=%d: lost complete header or renewed deadline", cut)
		}
	}
	port, done := serveStreamFixture(t, func(conn net.Conn) error {
		req, err := http.ReadRequest(bufio.NewReader(conn))
		if err != nil {
			return err
		}
		defer func() { _ = req.Body.Close() }()
		if req.Method != "OPTIONS" || req.URL.Path != "/wsman" {
			t.Error("WSMan request changed")
		}
		for _, b := range []byte(response) {
			if _, err := conn.Write([]byte{b}); err != nil {
				return err
			}
		}
		return nil
	})
	s := NewScanner("127.0.0.1", false)
	version, evidence := s.detectWSManHTTP(port)
	waitStreamFixture(t, done)
	if version != "Microsoft-HTTPAPI/2.0" || !strings.Contains(evidence, "WinRM not confirmed") {
		t.Fatalf("specialized path lost disclosure: %q %q", version, evidence)
	}
}

func TestWSManHTTPStopsAtHeadersAndRejectsIOFailures(t *testing.T) {
	headers := "HTTP/1.1 200 OK\r\nServer: fixture/1.0\r\n\r\n"
	trap := &greetingReadTrap{}
	conn := &textFragmentConn{transportFixtureConn: transportFixtureConn{r: io.MultiReader(strings.NewReader(headers), trap)}}
	if version, _ := probeWSManHTTP(conn, "OPTIONS /wsman HTTP/1.1\r\n\r\n", time.Second); version != "fixture/1.0" || trap.calls != 0 {
		t.Fatal("complete headers waited for an unspecified body or close")
	}
	for cut := 0; cut < len(headers); cut++ {
		conn := &textFragmentConn{transportFixtureConn: transportFixtureConn{r: strings.NewReader(headers[:cut])}}
		if version, evidence := probeWSManHTTP(conn, "OPTIONS /wsman HTTP/1.1\r\n\r\n", time.Second); version != "" || evidence != "" {
			t.Fatalf("truncated header promoted at %d", cut)
		}
	}
	for _, failure := range []string{"deadline", "write", "short"} {
		trap := &greetingReadTrap{}
		conn := &negotiationWriteConn{textFragmentConn: textFragmentConn{transportFixtureConn: transportFixtureConn{r: trap}}, writeErr: io.ErrClosedPipe, short: failure == "short"}
		if failure == "deadline" {
			conn.deadlineErr = io.ErrClosedPipe
		}
		if version, evidence := probeWSManHTTP(conn, "OPTIONS /wsman HTTP/1.1\r\n\r\n", time.Second); version != "" || evidence != "" || trap.calls != 0 || conn.deadlines != 1 {
			t.Fatal("I/O continued after deadline/write failure")
		}
	}
	for _, response := range []string{
		"HTTP/1.1 200 OK\r\n" + strings.Repeat("X-Fixture: yes\r\n", 33) + "\r\n",
		"HTTP/1.1 200 OK\r\nServer: " + strings.Repeat("x", textTransactionLimit) + "\r\n\r\n",
	} {
		conn := &textFragmentConn{transportFixtureConn: transportFixtureConn{r: strings.NewReader(response)}}
		if version, evidence := probeWSManHTTP(conn, "OPTIONS /wsman HTTP/1.1\r\n\r\n", time.Second); version != "" || evidence != "" {
			t.Fatal("header count or byte budget exceeded")
		}
	}
}

func FuzzProtocolDisclosures(f *testing.F) {
	f.Add([]byte("HTTP/1.1 404 Not Found\r\nServer: Microsoft-HTTPAPI/2.0\r\n\r\n"))
	f.Add(buildDNSVersionBindQuery())
	f.Add(dnsDisclosureFixture(f, nil))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 64*1024 {
			return
		}
		if version, evidence := wsmanHTTPDisclosure(string(data)); (version != "" || evidence != "") && !strings.Contains(evidence, "WinRM not confirmed") {
			t.Fatal("HTTP metadata asserted WinRM identity")
		}
		if got := parseDNSVersionBindResponse(data); got != "" && !strings.HasPrefix(got, "DNS version.bind: ") {
			t.Fatal("DNS text asserted an implementation")
		}
	})
}
