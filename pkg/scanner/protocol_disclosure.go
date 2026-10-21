package scanner

import (
	"bufio"
	"encoding/binary"
	"net"
	"net/http"
	"strings"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// version.bind is configurable text, not proof that the server runs BIND.
func parseDNSVersionBindResponse(frame []byte) string {
	if len(frame) < 2 || int(binary.BigEndian.Uint16(frame)) != len(frame)-2 {
		return ""
	}
	wire := frame[2:]
	if !udpDNSFrameValid(wire) || wire[3]&0x40 != 0 {
		return ""
	}
	var msg dnsmessage.Message
	if msg.Unpack(wire) != nil || msg.ID != 0x1337 || !msg.Response || msg.OpCode != 0 || msg.Truncated || msg.RCode != dnsmessage.RCodeSuccess || len(msg.Questions) != 1 || len(msg.Answers) != 1 {
		return ""
	}
	q, a := msg.Questions[0], msg.Answers[0]
	if !strings.EqualFold(q.Name.String(), "version.bind.") || q.Type != dnsmessage.TypeTXT || q.Class != dnsmessage.ClassCHAOS || !strings.EqualFold(a.Header.Name.String(), q.Name.String()) || a.Header.Type != dnsmessage.TypeTXT || a.Header.Class != dnsmessage.ClassCHAOS {
		return ""
	}
	txt, ok := a.Body.(*dnsmessage.TXTResource)
	if !ok || len(txt.TXT) != 1 || txt.TXT[0] == "" || binaryTextObservation(txt.TXT[0]) || strings.ContainsAny(txt.TXT[0], "\r\n\t") {
		return ""
	}
	value := sanitizeVersionString(txt.TXT[0])
	if value == "" {
		return ""
	}
	return "DNS version.bind: " + value
}

// OPTIONS /wsman can establish HTTP, but HTTPAPI/Negotiate are not unique to WinRM.
func wsmanHTTPDisclosure(raw string) (version, evidence string) {
	if len(raw) > textTransactionLimit || !validHTTPResponseLine(raw) || !strings.Contains(raw, "\r\n\r\n") && !strings.Contains(raw, "\n\n") {
		return "", ""
	}
	resp, err := http.ReadResponse(bufio.NewReader(strings.NewReader(raw)), nil)
	if err != nil {
		return "", ""
	}
	defer func() { _ = resp.Body.Close() }()
	evidence = "OPTIONS /wsman; " + resp.Proto + " " + resp.Status
	servers := resp.Header.Values("Server")
	if len(servers) == 1 {
		// Parse only the independently complete Server disclosure, never a body title.
		_, version = parseHTTP(resp.Proto + " " + resp.Status + "\r\nServer: " + servers[0] + "\r\n\r\n")
		if version != "" {
			evidence += "; Server: " + servers[0]
		}
	} else if len(servers) > 1 {
		evidence += "; ambiguous Server headers; product/version withheld"
	}
	evidence += "; WinRM not confirmed"
	return version, sanitizeVersionString(evidence)
}

func probeWSManHTTP(conn net.Conn, request string, timeout time.Duration) (string, string) {
	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return "", ""
	}
	if n, err := conn.Write([]byte(request)); err != nil || n != len(request) {
		return "", ""
	}
	reader := &textTransactionReader{r: bufio.NewReaderSize(conn, 512), limit: textTransactionLimit}
	// Only headers support this disclosure; do not wait for a body or socket close.
	for lines := 0; lines < 34; lines++ {
		line, err := reader.line(textTransactionLimit)
		if err != nil {
			return "", ""
		}
		if string(line) == "\r\n" || string(line) == "\n" {
			return wsmanHTTPDisclosure(string(reader.data))
		}
	}
	return "", ""
}
