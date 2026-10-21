package scanner

import (
	"bufio"
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type smallChunkConn struct{ net.Conn }

func (c smallChunkConn) Read(p []byte) (int, error) { return c.Conn.Read(p[:min(len(p), 7)]) }
func (c smallChunkConn) Write(p []byte) (int, error) {
	total := 0
	for len(p) > 0 {
		n, err := c.Conn.Write(p[:min(len(p), 7)])
		total += n
		p = p[n:]
		if err != nil {
			return total, err
		}
		if n == 0 {
			return total, io.ErrNoProgress
		}
	}
	return total, nil
}

func serveStreamFixture(t *testing.T, handler func(net.Conn) error) (int, <-chan error) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		defer close(done)
		conn, err := listener.Accept()
		if err != nil {
			done <- err
			return
		}
		defer func() { _ = conn.Close() }()
		if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
			done <- err
			return
		}
		done <- handler(smallChunkConn{conn})
	}()
	t.Cleanup(func() {
		_ = listener.Close()
		select {
		case err := <-done:
			if err != nil && !errors.Is(err, net.ErrClosed) {
				t.Error(err)
			}
		case <-time.After(6 * time.Second):
			t.Error("loopback fixture cleanup did not stop")
		}
	})
	return listener.Addr().(*net.TCPAddr).Port, done
}

func waitStreamFixture(t *testing.T, done <-chan error) {
	t.Helper()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(6 * time.Second):
		t.Fatal("loopback fixture did not stop")
	}
}

func streamFixtureTLSConfig(t *testing.T) *tls.Config {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "rdp.fixture.invalid"},
		NotBefore: time.Unix(0, 0), NotAfter: time.Unix(4102444800, 0),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}, MinVersion: tls.VersionTLS12}
}

func TestRDPStreamConfirmationAndTLSUpgrade(t *testing.T) {
	cfg := streamFixtureTLSConfig(t)
	for _, mode := range []string{"standard", "legacy", "failure", "tls", "tls-failed", "request-echo", "truncated"} {
		t.Run(mode, func(t *testing.T) {
			response := rdpConfirmFixture()
			response[15] = 0
			switch mode {
			case "legacy":
				response = response[:11]
				response[3], response[4] = 11, 6
			case "failure":
				response[11], response[15] = 3, 1
			case "tls", "tls-failed":
				response[15] = 1
			case "request-echo":
				response[5] = 0xe0
			case "truncated":
				response = response[:10]
			}
			port, done := serveStreamFixture(t, func(conn net.Conn) error {
				request := make([]byte, 19)
				if _, err := io.ReadFull(conn, request); err != nil {
					return err
				}
				if request[5] != 0xe0 || binary.LittleEndian.Uint32(request[15:]) != 3 {
					return errors.New("RDP probe changed its requested protocols")
				}
				if _, err := conn.Write(response); err != nil {
					return err
				}
				if mode == "tls" {
					return tls.Server(conn, cfg).Handshake()
				}
				return nil
			})
			s := NewScanner("127.0.0.1", false)
			version, confidence, evidence, ok := s.detectRDPInfo(port)
			waitStreamFixture(t, done)
			valid := mode != "request-echo" && mode != "truncated"
			if ok != valid || (version != "") != valid || (evidence != "") != valid {
				t.Fatalf("mode %s: ok=%t version=%q evidence=%q", mode, ok, version, evidence)
			}
			if mode == "tls" && (!strings.Contains(evidence, "cert CN=rdp.fixture.invalid") || !strings.Contains(evidence, "certificate not verified")) {
				t.Fatal("fragmented confirmation consumed or lost the subsequent TLS handshake")
			}
			if mode == "failure" && (!strings.Contains(evidence, "RDP negotiation failure: code=1") || version != "RDP service (negotiation rejected)") {
				t.Fatal("negotiation failure confused with a successful selection")
			}
			if mode == "tls-failed" && !strings.Contains(evidence, "TLS handshake not completed") {
				t.Fatal("selected TLS incorrectly reported as an established handshake")
			}
			if valid {
				wantConfidence := "medium"
				if mode == "legacy" {
					wantConfidence = "low"
				}
				if confidence != wantConfidence || strings.Contains(version, "Microsoft") || !strings.Contains(evidence, "product/OS not established") {
					t.Fatalf("unsupported product confidence: %q %q %q", version, confidence, evidence)
				}
			}
		})
	}
}

func TestSMBAndAJPStreamProbes(t *testing.T) {
	for _, protocol := range []string{"smb", "ajp"} {
		for _, valid := range []bool{false, true} {
			t.Run(protocol+"/"+strconv.FormatBool(valid), func(t *testing.T) {
				port, done := serveStreamFixture(t, func(conn net.Conn) error {
					if protocol == "ajp" {
						request := make([]byte, 5)
						if _, err := io.ReadFull(conn, request); err != nil {
							return err
						}
						if !bytes.Equal(request, []byte{0x12, 0x34, 0, 1, 10}) {
							return errors.New("unexpected AJP operation")
						}
						response := []byte{'A', 'B', 0, 1, 9}
						if !valid {
							response[4] = 10
						}
						_, err := conn.Write(response)
						return err
					}
					header := make([]byte, 4)
					if _, err := io.ReadFull(conn, header); err != nil {
						return err
					}
					size := int(binary.BigEndian.Uint32(header))
					if size != len(buildSMBNegotiate())-4 {
						return errors.New("unexpected SMB request size")
					}
					request := make([]byte, size)
					if _, err := io.ReadFull(conn, request); err != nil {
						return err
					}
					if string(request[:4]) != "\xfeSMB" {
						return errors.New("unexpected SMB request signature")
					}
					response := smbFramingFixture()
					if !valid {
						response[12] = 1 // Nonzero server status, not a negotiated dialect.
					}
					_, err := conn.Write(response)
					return err
				})
				s := NewScanner("127.0.0.1", false)
				if protocol == "smb" {
					version := s.attemptRawSMBDetection(net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
					if (version == "SMB 3.0.2") != valid || (!valid && version != "") {
						t.Fatalf("wrong SMB identification: %q", version)
					}
				} else if s.detectAJP(port) != valid {
					t.Fatal("AJP response validation failed")
				}
				waitStreamFixture(t, done)
			})
		}
	}
}

func TestHTTPAndTLSFragmentedResponseCollection(t *testing.T) {
	cfg := streamFixtureTLSConfig(t)
	var redirects atomic.Int32
	destination := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { redirects.Add(1) }))
	t.Cleanup(destination.Close)
	for _, useTLS := range []bool{false, true} {
		for _, mode := range []string{"headers", "forged-body", "malformed-status"} {
			t.Run(strconv.FormatBool(useTLS)+"/"+mode, func(t *testing.T) {
				port, done := serveStreamFixture(t, func(conn net.Conn) error {
					if useTLS {
						secure := tls.Server(conn, cfg)
						if err := secure.Handshake(); err != nil {
							return err
						}
						conn = secure
					}
					request, err := http.ReadRequest(bufio.NewReader(conn))
					if err != nil {
						return err
					}
					defer func() { _ = request.Body.Close() }()
					if request.Method != "GET" || request.URL.Path != "/" {
						return errors.New("unexpected HTTP request")
					}
					response := "HTTP/1.1 302 Found\r\nServer: fixture/1.2\r\nLocation: " + destination.URL + "/never-fetch\r\nContent-Length: 0\r\n\r\n"
					switch mode {
					case "forged-body":
						body := "Server: forged/9.9\r\n"
						response = "HTTP/1.1 200 OK\r\nContent-Length: " + strconv.Itoa(len(body)) + "\r\n\r\n" + body
					case "malformed-status":
						response = "HTTP/1.1 broken\r\nServer: forged/9.9\r\n\r\n"
					}
					_, err = io.WriteString(conn, response)
					return err
				})
				s := NewScanner("127.0.0.1", false)
				s.Configure(ScanConfig{Timeout: 3 * time.Second, NumWorkers: 1})
				banner, fingerprint := s.grabHTTPBannerTransport(port, useTLS)
				waitStreamFixture(t, done)
				if (fingerprint != nil) != useTLS || (useTLS && (fingerprint.Version == "" || fingerprint.Cipher == "")) {
					t.Fatal("TLS metadata lost or invented")
				}
				service, version := parseHTTP(banner)
				if mode == "headers" && (service != "http" || version != "fixture/1.2") {
					t.Fatalf("fragmented headers lost: service=%q version=%q", service, version)
				}
				if mode == "forged-body" && (service != "http" || version != "") {
					t.Fatal("body text mistaken for a Server header")
				}
				if mode == "malformed-status" && (service != "" || version != "") {
					t.Fatal("invalid HTTP status promoted to identification")
				}
			})
		}
	}
	if redirects.Load() != 0 {
		t.Fatal("banner collector followed a redirect")
	}
}

func TestFragmentedMailAndFTPConversations(t *testing.T) {
	cfg := streamFixtureTLSConfig(t)
	for _, mode := range []string{"ftp", "smtp", "smtps", "pop3s", "imaps"} {
		t.Run(mode, func(t *testing.T) {
			greeting, command, reply := "220 fixture ESMTP v1.2\r\n", "EHLO gomap.local\r\n", "250-fixture\r\n250 HELP\r\n"
			switch mode {
			case "ftp":
				greeting = "220-ProFTPD 1.3.5 Server\r\n220 ready\r\n"
			case "pop3s":
				greeting, command, reply = "+OK fixture POP3 v1.2\r\n", "CAPA\r\n", "+OK capabilities\r\n"
			case "imaps":
				greeting, command, reply = "* OK fixture IMAP4rev1\r\n", "a001 CAPABILITY\r\n", "a001 OK CAPABILITY completed\r\n"
			}
			useTLS := strings.HasSuffix(mode, "s")
			port, done := serveStreamFixture(t, func(conn net.Conn) error {
				if useTLS {
					secure := tls.Server(conn, cfg)
					if err := secure.Handshake(); err != nil {
						return err
					}
					conn = secure
				}
				if _, err := io.WriteString(conn, greeting); err != nil {
					return err
				}
				reader := bufio.NewReader(conn)
				commands := []string{command}
				if mode == "ftp" {
					commands = []string{"SYST\r\n", "FEAT\r\n", "HELP\r\n"}
				}
				for _, expected := range commands {
					line, err := reader.ReadString('\n')
					if err != nil {
						return err
					}
					if line != expected {
						return errors.New("mail/FTP probe changed its command sequence")
					}
					response := reply
					if mode == "ftp" {
						response = "211-Features\r\n UTF8\r\n211 End\r\n"
					}
					if _, err := io.WriteString(conn, response); err != nil {
						return err
					}
				}
				return nil
			})
			s := NewScanner("127.0.0.1", false)
			var banner string
			if mode == "ftp" {
				banner = s.probeFTP(port)
			} else {
				banner = s.probeMailService(port, command, useTLS)
			}
			waitStreamFixture(t, done)
			if !strings.Contains(banner, greeting) || (mode != "ftp" && !strings.Contains(banner, reply)) {
				t.Fatal("split greeting/reply lost or mixed with the next command")
			}
			if mode == "ftp" && strings.Count(banner, "211 End\r\n") != 3 {
				t.Fatal("FTP multiline replies were not fully collected")
			}
		})
	}
}

func TestFTPGenericLinesCaptureBound(t *testing.T) {
	port, done := serveStreamFixture(t, func(conn net.Conn) error {
		request := make([]byte, 4)
		if _, err := io.ReadFull(conn, request); err != nil {
			return err
		}
		if string(request) != "\r\n\r\n" {
			return errors.New("unexpected FTP generic-lines probe")
		}
		// The client may close the socket once it has reached its capture limit.
		_, _ = io.WriteString(conn, strings.Repeat("x", 8192))
		return nil
	})
	if got := NewScanner("127.0.0.1", false).probeFTPGenericLines(port); len(got) != 4096 {
		t.Fatalf("FTP capture size=%d, want 4096", len(got))
	}
	waitStreamFixture(t, done)
}

func TestOversizedGreetingDoesNotStartNextCommand(t *testing.T) {
	for _, ftp := range []bool{false, true} {
		t.Run(strconv.FormatBool(ftp), func(t *testing.T) {
			greeting := "220-" + strings.Repeat("x", 4090) + "\r\n"
			port, done := serveStreamFixture(t, func(conn net.Conn) error {
				if _, err := io.WriteString(conn, greeting); err != nil {
					return err
				}
				var request [1]byte
				n, err := conn.Read(request[:])
				if n != 0 || !errors.Is(err, io.EOF) {
					return errors.New("probe sent a command before its greeting was complete")
				}
				return nil
			})
			s := NewScanner("127.0.0.1", false)
			var banner string
			if ftp {
				banner = s.probeFTP(port)
			} else {
				banner = s.probeMailService(port, "EHLO gomap.local\r\n", false)
			}
			waitStreamFixture(t, done)
			if !strings.HasPrefix(banner, greeting) || len(banner) > 4097 {
				t.Fatal("partial greeting was lost or grew without bound")
			}
		})
	}
}
