package scanner

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/gosnmp/gosnmp"
)

func testSNMPCredentials(t testing.TB, auth, privacy string) *SNMPCredentials {
	t.Helper()
	password := ""
	if privacy != "none" {
		password = "test-only-privacy-pass"
	}
	c, err := NewSNMPCredentials("fixture-user", auth, "test-only-auth-pass", privacy, password)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestSNMPCredentialValidationAndDisclosure(t *testing.T) {
	c := testSNMPCredentials(t, "sha256", "aes128")
	for _, value := range []any{c, *c, map[string]any{"credentials": c}} {
		encoded, err := json.Marshal(value)
		text := fmt.Sprintf("%v %+v %#v %s", value, value, value, encoded)
		if err != nil || strings.Contains(text, "test-only") || strings.Contains(text, "fixture-user") {
			t.Fatal("secret disclosure")
		}
	}
	for _, fields := range [][5]string{
		{"", "sha256", "test-only-password", "none", ""},
		{"fixture-user", "md5", "test-only-password", "none", ""},
		{"fixture-user", "sha1", "test-only-password", "none", ""},
		{"fixture-user", "sha256", "short", "none", ""},
		{"fixture-user", "sha256", "test-only-password", "des", "test-only-password"},
		{"fixture-user", "sha256", "test-only-password", "aes128", "short"},
		{"fixture-user", "sha256", "test-only-password", "none", "unexpected-password"},
	} {
		if _, err := NewSNMPCredentials(fields[0], fields[1], fields[2], fields[3], fields[4]); err == nil || strings.Contains(err.Error(), "password") {
			t.Fatal("unsafe validation")
		}
	}
}

func fakeSNMPAgentReply(query []byte, credentials *SNMPCredentials, mutate string) ([]byte, error) {
	f, valid := parseSNMPSecureFrame(query)
	if !valid {
		return nil, errors.New("bad synthetic query")
	}
	parameters := credentials.parameters()
	parameters.AuthoritativeEngineID = "synthetic-engine-only"
	parameters.AuthoritativeEngineBoots, parameters.AuthoritativeEngineTime = 7, 1000
	packet := &gosnmp.SnmpPacket{Version: gosnmp.Version3, MsgID: uint32(f.id), MsgMaxSize: maxUDPResponseBytes,
		SecurityModel: gosnmp.UserSecurityModel, SecurityParameters: parameters,
		ContextEngineID: parameters.AuthoritativeEngineID}
	if f.flags[0] == byte(gosnmp.Reportable) {
		parameters.UserName = ""
		parameters.AuthenticationProtocol, parameters.PrivacyProtocol = gosnmp.NoAuth, gosnmp.NoPriv
		packet.MsgFlags, packet.PDUType = gosnmp.NoAuthNoPriv, gosnmp.Report
		packet.Variables = []gosnmp.SnmpPDU{{Name: ".1.3.6.1.6.3.15.1.1.4.0", Type: gosnmp.Counter32, Value: uint32(1)}}
	} else {
		if mutate == "wrong-password" {
			parameters.AuthenticationPassphrase = "different-test-only-auth-pass"
		}
		if err := parameters.InitSecurityKeys(); err != nil {
			return nil, err
		}
		decoder := &gosnmp.GoSNMP{Version: gosnmp.Version3, MsgFlags: credentials.flags(), SecurityModel: gosnmp.UserSecurityModel, SecurityParameters: parameters.Copy()}
		request, err := decoder.SnmpDecodePacket(query)
		if err != nil {
			return nil, err
		}
		packet.MsgFlags, packet.PDUType, packet.RequestID = credentials.flags(), gosnmp.GetResponse, request.RequestID
		packet.Variables = []gosnmp.SnmpPDU{{Name: snmpSystemDescriptionOID, Type: gosnmp.OctetString, Value: []byte("synthetic-device-do-not-log")}}
		switch mutate {
		case "wrong-message":
			packet.MsgID++
		case "wrong-request":
			packet.RequestID++
		case "stale":
			parameters.AuthoritativeEngineTime = 1
		case "future":
			parameters.AuthoritativeEngineTime = 10000
		case "boots":
			parameters.AuthoritativeEngineBoots++
		case "engine":
			parameters.AuthoritativeEngineID = "different-engine-only"
		case "wrong-oid":
			packet.Variables[0].Name = ".1.3.6.1.2.1.1.2.0"
		case "downgrade":
			packet.MsgFlags = gosnmp.NoAuthNoPriv
		}
		if err := parameters.InitPacket(packet); err != nil {
			return nil, err
		}
	}
	data, err := packet.MarshalMsg()
	if mutate == "tampered" && f.flags[0] != byte(gosnmp.Reportable) && len(data) != 0 {
		data[len(data)-1] ^= 1
	}
	return data, err
}

func TestAuthenticatedSNMPLoopback(t *testing.T) {
	for _, auth := range []string{"sha256", "sha512"} {
		for _, privacy := range []string{"none", "aes128"} {
			for _, mutate := range []string{"", "tampered", "wrong-password", "wrong-message", "wrong-request", "stale", "future", "boots", "engine", "wrong-oid", "downgrade"} {
				t.Run(auth+"/"+privacy+"/"+mutate, func(t *testing.T) {
					credentials := testSNMPCredentials(t, auth, privacy)
					conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
					if err != nil {
						t.Fatal(err)
					}
					done := make(chan error, 1)
					go func() {
						buffer := make([]byte, maxUDPResponseBytes+1)
						for attempt := 0; attempt < 2; attempt++ {
							n, addr, err := conn.ReadFromUDP(buffer)
							if err != nil {
								done <- err
								return
							}
							reply, err := fakeSNMPAgentReply(buffer[:n], credentials, mutate)
							if err != nil {
								done <- err
								return
							}
							if _, err := conn.WriteToUDP(reply, addr); err != nil {
								done <- err
								return
							}
						}
						done <- nil
					}()
					t.Cleanup(func() {
						_ = conn.Close()
						if err := <-done; err != nil && !errors.Is(err, net.ErrClosed) {
							t.Error(err)
						}
					})
					s := NewScanner("127.0.0.1", false)
					s.Timeout, s.AdaptiveTimeout, s.SNMPCredentials = time.Second, false, credentials
					result := s.scanAuthenticatedSNMP(conn.LocalAddr().(*net.UDPAddr).Port)
					if !result.IsOpen || result.State != "open" {
						t.Fatalf("responsive agent lost: %+v", result)
					}
					if (mutate == "") != (result.Confidence == "high") {
						t.Fatalf("unexpected confirmation: %+v", result)
					}
					if strings.Contains(result.Version+result.Evidence, "synthetic") || strings.Contains(result.Version+result.Evidence, "fixture-user") || strings.Contains(result.Version+result.Evidence, "test-only") {
						t.Fatal("sensitive response disclosed")
					}
				})
			}
		}
	}
}

func snmpSecureQueryFixture(t testing.TB, seed uint32) []byte {
	t.Helper()
	packet := &gosnmp.SnmpPacket{Version: gosnmp.Version3, MsgID: snmpSessionIdentifier(seed), MsgMaxSize: maxUDPResponseBytes,
		MsgFlags: gosnmp.Reportable, SecurityModel: gosnmp.UserSecurityModel, PDUType: gosnmp.GetRequest,
		SecurityParameters: &gosnmp.UsmSecurityParameters{AuthenticationProtocol: gosnmp.NoAuth, PrivacyProtocol: gosnmp.NoPriv}}
	data, err := packet.MarshalMsg()
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestSNMPSessionIdentifierAndBounds(t *testing.T) {
	for _, seed := range []uint32{0, 1, 127, 255, 65535, 1<<23 - 1, 1<<24 - 1, 1 << 31, 1<<32 - 1} {
		frame, valid := parseSNMPSecureFrame(snmpSecureQueryFixture(t, seed))
		if !valid || uint32(frame.id) != snmpSessionIdentifier(seed) || frame.id < 1<<24 {
			t.Fatal("nonminimal identifier generated")
		}
	}
	clock := time.Unix(1, 0)
	var delays []time.Duration
	limiter := NewAttemptLimiter(10)
	limiter.now = func() time.Time { return clock }
	limiter.sleep = func(delay time.Duration) { delays = append(delays, delay); clock = clock.Add(delay) }
	s := NewScanner("fixture.invalid", false)
	s.AttemptLimiter = limiter
	conn := &transportFixtureConn{r: bytes.NewReader(nil)}
	guard := &snmpSessionConn{Conn: conn, scanner: s, ctx: context.Background()}
	query := snmpSecureQueryFixture(t, 123)
	for range 2 {
		if _, err := guard.Write(query); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := guard.Write(query); err == nil || guard.writes != 2 || conn.w.Len() != 2*len(query) || len(delays) != 1 {
		t.Fatal("attempt budget exceeded or bypassed")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	guard.ctx, guard.writes = ctx, 0
	if _, err := guard.Write(query); err == nil || guard.writes != 0 {
		t.Fatal("canceled session sent a query")
	}
}

func FuzzSNMPSecureFrame(f *testing.F) {
	f.Add(snmpSecureQueryFixture(f, 1))
	f.Add([]byte{0x30, 0x80, 0, 0})
	f.Fuzz(func(t *testing.T, data []byte) {
		frame, valid := parseSNMPSecureFrame(data)
		if valid && (len(data) > maxUDPResponseBytes || frame.id <= 0 || frame.boots < 0 || len(frame.flags) != 1 || len(frame.engine) > 32) {
			t.Fatal("invalid bounded frame accepted")
		}
	})
}
