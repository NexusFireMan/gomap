package scanner

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"strconv"
	"strings"
	"testing"
	"testing/iotest"
	"time"
)

func TestRDPDisclosureSeparatesNegotiationFromProduct(t *testing.T) {
	for _, mode := range []string{"legacy", "standard", "tls", "credssp", "failure"} {
		frame := rdpConfirmFixture()
		wantConfidence, wantVersion := "medium", "RDP service"
		switch mode {
		case "legacy":
			frame = frame[:11]
			frame[3], frame[4] = 11, 6
			wantConfidence, wantVersion = "low", "RDP service (unconfirmed)"
		case "standard":
			frame[15] = 0
		case "credssp":
			frame[15] = 2
		case "failure":
			frame[11], frame[15] = 3, 5
			wantVersion = "RDP service (negotiation rejected)"
		}
		version, confidence, evidence, ok := rdpDisclosure(frame)
		if !ok || confidence != wantConfidence || version != wantVersion || !strings.Contains(evidence, "product/OS not established") || strings.Contains(version, "Microsoft") {
			t.Fatalf("%s: %q %q %q %t", mode, version, confidence, evidence, ok)
		}
		for end := 0; end < len(frame); end++ {
			if version, confidence, evidence, ok := rdpDisclosure(frame[:end]); ok || version != "" || confidence != "" || evidence != "" {
				t.Fatalf("%s: partial confirmation promoted at %d", mode, end)
			}
		}
	}
}

func TestRDPProbeFixedDeadlineAndWriteFailures(t *testing.T) {
	s := NewScanner("127.0.0.1", false)
	frame := rdpConfirmFixture()
	frame[15] = 0 // No TLS selection: the fake stream contains only the confirmation.
	for cut := 0; cut <= len(frame); cut++ {
		conn := &textFragmentConn{transportFixtureConn: transportFixtureConn{r: io.MultiReader(bytes.NewReader(frame[:cut]), iotest.OneByteReader(bytes.NewReader(frame[cut:])))}}
		version, confidence, _, ok := s.probeRDPInfo(conn, time.Second)
		if !ok || version != "RDP service" || confidence != "medium" || conn.deadlines != 1 {
			t.Fatalf("split=%d: invalid RDP metadata or deadline renewal", cut)
		}
		request := conn.w.Bytes()
		if len(request) != 19 || request[5] != 0xe0 || binary.LittleEndian.Uint32(request[15:]) != 3 {
			t.Fatal("RDP request or offered protocols changed")
		}
	}
	for _, failure := range []string{"deadline", "write", "short"} {
		trap := &greetingReadTrap{}
		conn := &negotiationWriteConn{textFragmentConn: textFragmentConn{transportFixtureConn: transportFixtureConn{r: trap}}, writeErr: io.ErrClosedPipe, short: failure == "short"}
		if failure == "deadline" {
			conn.deadlineErr = io.ErrClosedPipe
		}
		version, confidence, evidence, ok := s.probeRDPInfo(conn, time.Second)
		if ok || version != "" || confidence != "" || evidence != "" || trap.calls != 0 || conn.deadlines != 1 {
			t.Fatal("RDP continued after deadline/write failure")
		}
	}
	for code := byte(1); code <= 7; code++ {
		failure := rdpConfirmFixture()
		failure[11], failure[15] = 3, code
		trap := &greetingReadTrap{}
		conn := &textFragmentConn{transportFixtureConn: transportFixtureConn{r: io.MultiReader(bytes.NewReader(failure), trap)}}
		version, confidence, evidence, ok := s.probeRDPInfo(conn, time.Second)
		if !ok || version != "RDP service (negotiation rejected)" || confidence != "medium" || trap.calls != 0 || !strings.Contains(evidence, "code="+strconv.Itoa(int(code))) {
			t.Fatal("RDP rejection advanced to TLS or lost failure evidence")
		}
	}
}

type rdpDeadlineConn struct {
	net.Conn
	deadlines int
}

func (c *rdpDeadlineConn) SetDeadline(deadline time.Time) error {
	c.deadlines++
	return c.Conn.SetDeadline(deadline)
}

func TestRDPTLSKeepsOriginalDeadlineAndUnverifiedIdentity(t *testing.T) {
	cfg := streamFixtureTLSConfig(t)
	port, done := serveStreamFixture(t, func(conn net.Conn) error {
		request := make([]byte, 19)
		if _, err := io.ReadFull(conn, request); err != nil {
			return err
		}
		if _, err := conn.Write(rdpConfirmFixture()); err != nil {
			return err
		}
		return tls.Server(conn, cfg).Handshake()
	})
	raw, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = raw.Close() }()
	conn := &rdpDeadlineConn{Conn: raw}
	s := NewScanner("127.0.0.1", false)
	version, confidence, evidence, ok := s.probeRDPInfo(conn, 2*time.Second)
	waitStreamFixture(t, done)
	if !ok || version != "RDP service" || confidence != "medium" || conn.deadlines != 1 || !strings.Contains(evidence, "TLS handshake completed; certificate not verified") || hostnameFromEvidence(evidence) != "rdp.fixture.invalid" {
		t.Fatalf("TLS renewed budget or certified identity: %q %q %q deadlines=%d", version, confidence, evidence, conn.deadlines)
	}
}

func TestTDSDisclosureUsesOnlyValidatedDeclaredFields(t *testing.T) {
	encryptionNames := [...]string{"ENCRYPT_OFF", "ENCRYPT_ON", "ENCRYPT_NOT_SUP", "ENCRYPT_REQ"}
	for encryption := byte(0); encryption <= 3; encryption++ {
		payload := tdsPayloadFixture(false)
		payload[len(payload)-1] = encryption
		original := bytes.Clone(payload)
		version, evidence := tdsPreloginDisclosure(payload)
		if version != "TDS PRELOGIN (server-declared 15.0.1234)" || !strings.Contains(evidence, "server-declared VERSION=15.0.1234") || !strings.Contains(evidence, "server ENCRYPTION="+encryptionNames[encryption]) || !strings.Contains(evidence, "no TLS/login exchange performed; product/OS not established") || !bytes.Equal(payload, original) {
			t.Fatalf("encryption=%d: %q %q", encryption, version, evidence)
		}
		for cut := 0; cut < len(payload); cut++ {
			if version, evidence := tdsPreloginDisclosure(payload[:cut]); version != "" || evidence != "" {
				t.Fatalf("partial PRELOGIN disclosed fields at %d", cut)
			}
		}
	}
	payload := tdsPayloadFixture(true)
	versionOffset := int(binary.BigEndian.Uint16(payload[1:]))
	clear(payload[versionOffset : versionOffset+6])
	version, evidence := tdsPreloginDisclosure(payload)
	if version != "TDS PRELOGIN" || strings.Contains(evidence, "VERSION=") {
		t.Fatal("zero sender version was promoted to a concrete version")
	}
	// Optional fields and padding are not identification disclosures.
	payload = append(payload, []byte("private-instance-name-and-trace-data")...)
	version, evidence = tdsPreloginDisclosure(payload)
	if version == "" || strings.Contains(evidence, "private-instance") || strings.Contains(evidence, "Microsoft") {
		t.Fatal("unrelated payload bytes became product evidence")
	}
}

func FuzzNegotiationDisclosures(f *testing.F) {
	f.Add(rdpConfirmFixture())
	f.Add(tdsPayloadFixture(false))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > tdsMessageLimit {
			return
		}
		original := bytes.Clone(data)
		version, confidence, evidence, ok := rdpDisclosure(data)
		if ok && (!validRDPConfirm(data) || confidence == "high" || strings.Contains(version, "Microsoft") || !strings.Contains(evidence, "product/OS not established")) {
			t.Fatal("unsupported RDP confidence or product assertion")
		}
		if version, evidence := tdsPreloginDisclosure(data); version != "" && (!validTDSPrelogin(data) || !strings.HasPrefix(version, "TDS PRELOGIN") || !strings.Contains(evidence, "no TLS/login exchange performed")) {
			t.Fatal("unsupported TDS disclosure")
		}
		if !bytes.Equal(data, original) {
			t.Fatal("disclosure parser mutated input")
		}
	})
}
