package scanner

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

func netbiosQueryFixture(t testing.TB) []byte {
	t.Helper()
	query, err := netbiosNodeStatusQuery(bytes.NewReader([]byte{0x12, 0x34}))
	if err != nil {
		t.Fatal(err)
	}
	return query
}

func netbiosReplyFixture(t testing.TB, query []byte) []byte {
	t.Helper()
	var message dnsmessage.Message
	if err := message.Unpack(query); err != nil {
		t.Fatal(err)
	}
	question := message.Questions[0]
	message.Header = dnsmessage.Header{ID: message.ID, Response: true, Authoritative: true}
	message.Questions = nil
	message.Answers = []dnsmessage.Resource{{
		Header: dnsmessage.ResourceHeader{Name: question.Name, Class: question.Class},
		Body: &dnsmessage.UnknownResource{
			Type: question.Type, Data: netbiosStatusFixture(),
		},
	}}
	payload, err := message.Pack()
	if err != nil {
		t.Fatal(err)
	}
	return payload
}

func TestNetBIOSNodeStatusQuery(t *testing.T) {
	query := netbiosQueryFixture(t)
	if len(query) != 50 || binary.BigEndian.Uint16(query) != 0x1234 ||
		binary.BigEndian.Uint16(query[2:]) != 0 || binary.BigEndian.Uint16(query[4:]) != 1 {
		t.Fatal("invalid unicast query header")
	}
	var message dnsmessage.Message
	if err := message.Unpack(query); err != nil {
		t.Fatal(err)
	}
	question := message.Questions[0]
	if question.Name.String() != "CK"+strings.Repeat("A", 30)+"." || question.Type != netbiosStatusRecord || question.Class != dnsmessage.ClassINET {
		t.Fatal("invalid wildcard/type/class")
	}
	if _, err := netbiosNodeStatusQuery(bytes.NewReader([]byte{1})); err == nil {
		t.Fatal("entropy failure ignored")
	}
}

func TestNetBIOSNodeStatusCorrelation(t *testing.T) {
	query := netbiosQueryFixture(t)
	reply := netbiosReplyFixture(t, query)
	s := NewScanner("fixture.invalid", false)
	_, version, confidence, evidence := s.classifyUDPResponseForProbe(137, reply, query, true)
	if version != "NetBIOS node status response" || confidence != "medium" ||
		!strings.Contains(evidence, "sent probe fields matched") || strings.Contains(evidence, "fixed identifiers") ||
		strings.Contains(version+evidence, "do-not-log") || strings.Contains(version+evidence, "disclosure") {
		t.Fatalf("incorrect or disclosing metadata: %q %q %q", version, confidence, evidence)
	}
	for _, mutate := range []func([]byte){
		func(p []byte) { p[0] ^= 1 },
		func(p []byte) { p[13] = 'A' },
		func(p []byte) { p[47] = byte(netbiosNameRecord) },
	} {
		bad := bytes.Clone(reply)
		mutate(bad)
		if checked, matched := netbiosNodeStatusMatches(query, bad); !checked || matched {
			t.Fatal("unrelated/malformed response correlated")
		}
		_, version, confidence, _ = s.classifyUDPResponseForProbe(137, bad, query, true)
		if version != "" || confidence != "low" {
			t.Fatal("unmatched response promoted")
		}
	}
	for n := range len(reply) {
		if checked, matched := netbiosNodeStatusMatches(query, reply[:n]); !checked || matched {
			t.Fatalf("truncation correlated at %d", n)
		}
	}
	if checked, _ := netbiosNodeStatusMatches(udpProbePayload(137), reply); checked {
		t.Fatal("generic query treated as NBSTAT")
	}
	for n := range len(query) {
		if checked, _ := netbiosNodeStatusMatches(query[:n], reply); checked {
			t.Fatal("truncated query treated as valid")
		}
	}
	_, version, confidence, _ = s.classifyUDPResponseForProbe(137, reply, query, false)
	if version != "" || confidence != "low" {
		t.Fatal("disabled detection parsed reply")
	}
}

func TestNetBIOSNodeStatusExchangePolicy(t *testing.T) {
	for _, tc := range []struct {
		name                string
		deep, ghost, detect bool
	}{
		{"deep", true, false, true}, {"default", false, false, true},
		{"ghost", true, true, true}, {"disabled", true, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := NewScanner("fixture.invalid", tc.ghost)
			s.DeepVersion = tc.deep
			s.Retries = 0
			calls := 0
			_, _, err := s.exchangeUDPPort(137, tc.detect, func(query []byte) ([]byte, error) {
				calls++
				if tc.deep && tc.detect && !tc.ghost {
					if len(query) != 50 {
						t.Fatal("no NBSTAT request sent")
					}
				} else if !bytes.Equal(query, udpProbePayload(137)) {
					t.Fatal("default/ghost probe changed")
				}
				return nil, os.ErrDeadlineExceeded
			})
			if !errors.Is(err, os.ErrDeadlineExceeded) || calls != 1 {
				t.Fatal("unexpected query count/outcome")
			}
		})
	}
	for _, outcome := range []error{nil, os.ErrDeadlineExceeded, syscall.ECONNREFUSED} {
		s := NewScanner("fixture.invalid", false)
		s.DeepVersion, s.Retries = true, 5
		calls := 0
		reply, query, err := s.exchangeUDPPort(137, true, func(query []byte) ([]byte, error) {
			calls++
			if outcome != nil {
				return nil, outcome
			}
			return netbiosReplyFixture(t, query), nil
		})
		if calls != 1 || !errors.Is(err, outcome) {
			t.Fatal("NBSTAT repeated or transport outcome changed")
		}
		if outcome == nil {
			if _, matched := netbiosNodeStatusMatches(query, reply); !matched {
				t.Fatal("exchange did not retain sent identifier")
			}
		}
	}
}

func FuzzNetBIOSNodeStatusCorrelation(f *testing.F) {
	query := netbiosQueryFixture(f)
	f.Add(query, netbiosReplyFixture(f, query))
	f.Add([]byte{0}, []byte{0})
	f.Fuzz(func(t *testing.T, probe, reply []byte) {
		originalProbe, originalReply := bytes.Clone(probe), bytes.Clone(reply)
		checked, matched := netbiosNodeStatusMatches(probe, reply)
		if matched && (!checked || len(probe) != 50 || udpNetBIOSVersion(reply) != "NetBIOS node status response") {
			t.Fatal("unvalidated match")
		}
		if !bytes.Equal(originalProbe, probe) || !bytes.Equal(originalReply, reply) {
			t.Fatal("input mutated")
		}
	})
}

func TestNetBIOSNodeStatusLoopback(t *testing.T) {
	for _, mode := range []string{"matching", "wrong-id", "truncated", "oversized"} {
		t.Run(mode, func(t *testing.T) {
			conn, err := net.ListenPacket("udp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = conn.Close() }()
			if err := conn.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
				t.Fatal(err)
			}
			reply := netbiosReplyFixture(t, netbiosQueryFixture(t))
			done := make(chan error, 1)
			go func() {
				query := make([]byte, 64)
				n, peer, err := conn.ReadFrom(query)
				if err != nil {
					done <- err
					return
				}
				if n != 50 {
					done <- errors.New("unexpected NBSTAT request")
					return
				}
				copy(reply[:2], query[:2])
				switch mode {
				case "wrong-id":
					reply[0] ^= 1
				case "truncated":
					reply = reply[:len(reply)-1]
				case "oversized":
					reply = append(reply, make([]byte, maxUDPResponseBytes+50-len(reply))...)
				}
				_, err = conn.WriteTo(reply, peer)
				done <- err
			}()
			s := NewScanner("127.0.0.1", false)
			s.Configure(ScanConfig{Timeout: time.Second, NumWorkers: 1, DeepVersion: true})
			response, query, err := s.exchangeUDPPort(137, true, func(query []byte) ([]byte, error) {
				return s.exchangeUDP(conn.LocalAddr().String(), query)
			})
			if err != nil {
				t.Fatal(err)
			}
			if err := <-done; err != nil {
				t.Fatal(err)
			}
			_, version, confidence, _ := s.classifyUDPResponseForProbe(137, response, query, true)
			if mode == "matching" {
				if version != "NetBIOS node status response" || confidence != "medium" {
					t.Fatal("loopback response not correlated")
				}
			} else if version != "" || confidence != "low" {
				t.Fatal("unvalidated response promoted")
			}
			if mode == "oversized" && len(response) != maxUDPResponseBytes+1 {
				t.Fatal("datagram overflow was hidden")
			}
		})
	}
}
