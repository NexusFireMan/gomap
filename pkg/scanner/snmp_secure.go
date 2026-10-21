package scanner

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"net"
	"time"

	"github.com/gosnmp/gosnmp"
)

const snmpSystemDescriptionOID = ".1.3.6.1.2.1.1.1.0"

var errSNMPSession = errors.New("SNMP session validation failed")

func snmpSessionIdentifier(seed uint32) uint32 {
	return (seed & 0x3effffff) | 0x01000000
}

type snmpSecureFrame struct {
	id, boots, clock int32
	flags            []byte
	engine, user     []byte
	scoped           asn1.RawValue
}

func parseSNMPSecureFrame(data []byte) (f snmpSecureFrame, valid bool) {
	if len(data) == 0 || len(data) > maxUDPResponseBytes {
		return f, false
	}
	var version, size, model int
	var header asn1.RawValue
	var security, auth, privacy []byte
	if !snmpSequenceFields(data, &version, &header, &security, &f.scoped) || version != 3 || !snmpSequence(header) ||
		!snmpFields(header.Bytes, &f.id, &size, &f.flags, &model) || f.id <= 0 || size < 484 || model != 3 || len(f.flags) != 1 ||
		!snmpSequenceFields(security, &f.engine, &f.boots, &f.clock, &f.user, &auth, &privacy) ||
		f.boots < 0 || f.boots == 1<<31-1 || f.clock < 0 || len(f.engine) > 32 || len(f.user) > 32 {
		return f, false
	}
	return f, true
}

// The library handles cryptography; this transport adds bounded framing, correlation,
// engine pinning and timeliness checks before permitting a response to reach it.
type snmpSessionConn struct {
	net.Conn
	scanner     *Scanner
	credentials *SNMPCredentials
	ctx         context.Context
	timeout     time.Duration
	writes      int
	reads       int
	failure     error
	requestBase uint32
	messageID   int32
	baseline    snmpSecureFrame
	baselineAt  time.Time
	observed    bool
}

func (c *snmpSessionConn) Write(packet []byte) (int, error) {
	if c.writes >= 2 || c.ctx.Err() != nil {
		return 0, errSNMPSession
	}
	f, valid := parseSNMPSecureFrame(packet)
	if !valid {
		return 0, errSNMPSession
	}
	c.scanner.AttemptLimiter.Wait()
	if c.ctx.Err() != nil {
		return 0, c.ctx.Err()
	}
	if c.timeout > 0 {
		deadline := time.Now().Add(c.timeout)
		if overall, ok := c.ctx.Deadline(); ok && overall.Before(deadline) {
			deadline = overall
		}
		if err := c.SetDeadline(deadline); err != nil {
			c.failure = err
			return 0, err
		}
	}
	c.messageID = f.id
	c.writes++
	n, err := c.Conn.Write(packet)
	if err != nil {
		c.failure = err
	}
	return n, err
}

func (c *snmpSessionConn) Read(buffer []byte) (int, error) {
	if c.reads >= c.writes {
		return 0, errSNMPSession
	}
	c.reads++
	n, err := c.Conn.Read(buffer[:min(len(buffer), maxUDPResponseBytes+1)])
	if err != nil {
		c.failure = err
		return n, err
	}
	c.observed = true
	f, valid := parseSNMPSecureFrame(buffer[:n])
	if !valid || f.id != c.messageID {
		return 0, errSNMPSession
	}
	if c.writes == 1 {
		if f.flags[0] != 0 || len(f.engine) < 5 || udpSNMPVersion(buffer[:n]) != "SNMPv3 report (unauthenticated)" {
			return 0, errSNMPSession
		}
		c.baseline, c.baselineAt = f, time.Now()
	} else {
		expectedTime := int64(c.baseline.clock) + int64(time.Since(c.baselineAt)/time.Second)
		if f.flags[0] != byte(c.credentials.flags()) || !bytes.Equal(f.engine, c.baseline.engine) || string(f.user) != c.credentials.username ||
			f.boots != c.baseline.boots || int64(f.clock) < expectedTime-150 || int64(f.clock) > expectedTime+150 {
			return 0, errSNMPSession
		}
	}
	return n, nil
}

func (s *Scanner) scanAuthenticatedSNMP(port int) ScanResult {
	start := time.Now()
	result := ScanResult{Port: port, State: "unknown", Confidence: "low", DetectionPath: "snmpv3-session"}
	timeout := s.currentTimeout()
	if timeout <= 0 || timeout > 30*time.Second {
		timeout = 30 * time.Second
	}
	budget := 2 * timeout
	if s.AttemptLimiter != nil {
		budget += 2 * s.AttemptLimiter.interval
	}
	ctx, cancel := context.WithTimeout(context.Background(), budget)
	defer cancel()
	client := &gosnmp.GoSNMP{Target: s.Host, Port: uint16(port), Transport: "udp", Version: gosnmp.Version3,
		Context: ctx, Timeout: timeout, Retries: 0, MaxOids: 1,
		MsgFlags: s.SNMPCredentials.flags(), SecurityModel: gosnmp.UserSecurityModel, SecurityParameters: s.SNMPCredentials.parameters()}
	if err := client.Connect(); err != nil {
		result.Evidence = "SNMP session could not connect"
		return result
	}
	defer func() { _ = client.Close() }()
	var entropy [8]byte
	if _, err := rand.Read(entropy[:]); err != nil {
		result.Evidence = "SNMP session could not initialize identifiers"
		return result
	}
	// GoSNMP encodes msgID in four octets. Keep its first octet nonzero so
	// the wire integer is minimal and remains accepted by our strict parser.
	base := snmpSessionIdentifier(binary.BigEndian.Uint32(entropy[:4]))
	client.SetRequestID(base)
	client.SetMsgID(snmpSessionIdentifier(binary.BigEndian.Uint32(entropy[4:])))
	guard := &snmpSessionConn{Conn: client.Conn, scanner: s, credentials: s.SNMPCredentials, ctx: ctx, timeout: timeout, requestBase: base}
	client.Conn = guard
	packet, err := client.Get([]string{snmpSystemDescriptionOID})
	result.Latency = time.Since(start)
	result.LatencyMs = max(1, result.Latency.Milliseconds())
	if guard.observed {
		result.IsOpen, result.State, result.ServiceName = true, "open", "snmp"
		result.Evidence = "UDP reply received; authenticated SNMP session not confirmed"
	} else {
		result.State, result.Evidence = udpErrorState(guard.failure)
	}
	if err != nil || packet == nil || guard.writes != 2 || packet.Version != gosnmp.Version3 || packet.PDUType != gosnmp.GetResponse ||
		packet.RequestID != guard.requestBase+2 || packet.MsgID != uint32(guard.messageID) || packet.Error != gosnmp.NoError ||
		packet.ContextEngineID != string(guard.baseline.engine) || packet.ContextName != "" || len(packet.Variables) != 1 ||
		packet.Variables[0].Name != snmpSystemDescriptionOID || packet.Variables[0].Type != gosnmp.OctetString {
		return result
	}
	result.Version, result.Confidence = "SNMPv3 (authenticated)", "high"
	result.Evidence = "SNMPv3 authenticated GET response; identifiers, engine and time window matched; product version not inferred"
	if s.SNMPCredentials.privProtocol == gosnmp.AES {
		result.Version = "SNMPv3 (authenticated, AES-128)"
	}
	return result
}
