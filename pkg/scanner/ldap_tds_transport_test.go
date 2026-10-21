package scanner

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"strconv"
	"testing"
	"testing/iotest"
	"time"
)

type negotiationWriteConn struct {
	textFragmentConn
	writeErr error
	short    bool
	writes   int
}

func (c *negotiationWriteConn) Write(p []byte) (int, error) {
	c.writes++
	if c.short {
		return len(p) - 1, nil
	}
	return 0, c.writeErr
}

func TestLDAPAndTDSProbeIOFailures(t *testing.T) {
	for name, probe := range map[string]func(net.Conn, time.Duration) bool{"ldap": probeLDAPBind, "tds": probeTDSPrelogin} {
		t.Run(name, func(t *testing.T) {
			for _, failure := range []string{"deadline", "write", "short-write"} {
				trap := &greetingReadTrap{}
				conn := &negotiationWriteConn{textFragmentConn: textFragmentConn{transportFixtureConn: transportFixtureConn{r: trap}}, writeErr: io.ErrClosedPipe}
				if failure == "deadline" {
					conn.deadlineErr = os.ErrDeadlineExceeded
				}
				conn.short = failure == "short-write"
				if probe(conn, time.Second) || trap.calls != 0 || conn.deadlines != 1 {
					t.Fatalf("%s: IO continued after failure", failure)
				}
				wantWrites := 1
				if failure == "deadline" {
					wantWrites = 0
				}
				if conn.writes != wantWrites {
					t.Fatalf("%s: writes=%d", failure, conn.writes)
				}
			}
		})
	}
}

func TestTDSProbeFragmentedRequestAndFixedDeadline(t *testing.T) {
	frame := tdsPacketFixture(tdsPayloadFixture(false), 1, 1)
	for cut := 0; cut <= len(frame); cut++ {
		r := io.MultiReader(bytes.NewReader(frame[:cut]), iotest.OneByteReader(bytes.NewReader(frame[cut:])))
		conn := &textFragmentConn{transportFixtureConn: transportFixtureConn{r: r}}
		if !probeTDSPrelogin(conn, time.Second) || conn.deadlines != 1 {
			t.Fatalf("split=%d: response lost or deadline renewed", cut)
		}
		request := conn.w.Bytes()
		if len(request) != 52 || !bytes.Equal(request[:8], []byte{0x12, 1, 0, 52, 0, 0, 0, 0}) || !validTDSPrelogin(request[8:]) {
			t.Fatalf("PRELOGIN request changed: %x", request)
		}
	}
}

func TestLDAPAndLDAPSFragmentedExchange(t *testing.T) {
	cfg := streamFixtureTLSConfig(t)
	for _, useTLS := range []bool{false, true} {
		for _, mode := range []string{"success", "denied", "wrong-id", "echo", "truncated", "malformed"} {
			t.Run(strconv.FormatBool(useTLS)+"/"+mode, func(t *testing.T) {
				want := mode == "success" || mode == "denied"
				port, done := serveStreamFixture(t, func(conn net.Conn) error {
					if useTLS {
						secure := tls.Server(conn, cfg)
						if err := secure.Handshake(); err != nil {
							return err
						}
						conn = secure
					}
					request := make([]byte, len(ldapAnonymousBindRequest))
					if _, err := io.ReadFull(conn, request); err != nil {
						return err
					}
					if string(request) != ldapAnonymousBindRequest {
						return errors.New("unexpected LDAP request")
					}
					response := ldapBindFixture(1, 0, nil, true)
					switch mode {
					case "denied":
						response = ldapBindFixture(1, 49, []byte("private diagnostic"), true)
					case "wrong-id":
						response = ldapBindFixture(2, 0, nil, false)
					case "echo":
						response = request
					case "truncated":
						response = response[:len(response)-1]
					case "malformed":
						response = ldapFixtureElement(0x30, []byte("arbitrary LDAP text"), false)
					}
					if _, err := conn.Write(response); err != nil {
						if want {
							return err
						}
						return nil // Rejected frames may cause an early client close.
					}
					if want {
						var extra [1]byte
						if n, err := conn.Read(extra[:]); n != 0 || err != io.EOF {
							return errors.New("LDAP probe sent follow-up traffic or did not close")
						}
					}
					return nil
				})
				s := NewScanner("127.0.0.1", false)
				s.Configure(ScanConfig{Timeout: 3 * time.Second, NumWorkers: 1})
				if got := s.detectLDAPBind(port, useTLS); got != want {
					t.Fatalf("detected=%v want=%v", got, want)
				}
				waitStreamFixture(t, done)
			})
		}
	}
}

func TestTDSFragmentedExchange(t *testing.T) {
	for _, mode := range []string{"success", "multi-packet", "echo", "header-only", "malformed", "truncated"} {
		t.Run(mode, func(t *testing.T) {
			want := mode == "success" || mode == "multi-packet"
			port, done := serveStreamFixture(t, func(conn net.Conn) error {
				request := make([]byte, 52)
				if _, err := io.ReadFull(conn, request); err != nil {
					return err
				}
				if !bytes.Equal(request[:8], []byte{0x12, 1, 0, 52, 0, 0, 0, 0}) || !validTDSPrelogin(request[8:]) {
					return errors.New("unexpected PRELOGIN request")
				}
				payload := tdsPayloadFixture(true)
				response := tdsPacketFixture(payload, 1, 1)
				switch mode {
				case "multi-packet":
					response = append(tdsPacketFixture(payload[:3], 0, 1), tdsPacketFixture(payload[3:], 1, 2)...)
				case "echo":
					response = request
				case "header-only":
					response = []byte{4, 1, 0, 8, 0, 0, 1, 0}
				case "malformed":
					response = tdsPacketFixture([]byte("not a PRELOGIN"), 1, 1)
				case "truncated":
					response = response[:len(response)-1]
				}
				if binary.BigEndian.Uint16(response[2:4]) < 8 {
					return errors.New("invalid test header")
				}
				if _, err := conn.Write(response); err != nil {
					if want {
						return err
					}
					return nil
				}
				if want {
					var extra [1]byte
					if n, err := conn.Read(extra[:]); n != 0 || err != io.EOF {
						return errors.New("TDS probe sent login/query traffic or did not close")
					}
				}
				return nil
			})
			s := NewScanner("127.0.0.1", false)
			s.Configure(ScanConfig{Timeout: 3 * time.Second, NumWorkers: 1})
			if got := s.detectMSSQLTDS(port); got != want {
				t.Fatalf("detected=%v want=%v", got, want)
			}
			waitStreamFixture(t, done)
		})
	}
}
