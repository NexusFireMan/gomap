package scanner

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const textTransactionLimit = 4096
const respTransactionLimit = 64 * 1024

var errTextTransaction = errors.New("incomplete, malformed or oversized text transaction")

type textTransactionReader struct {
	r     *bufio.Reader
	data  []byte
	limit int
}

func (r *textTransactionReader) take(n int) ([]byte, error) {
	if n < 0 || n > r.limit-len(r.data) {
		return nil, errTextTransaction
	}
	start := len(r.data)
	r.data = append(r.data, make([]byte, n)...)
	read, err := io.ReadFull(r.r, r.data[start:])
	r.data = r.data[:start+read]
	return r.data[start:], err
}

func (r *textTransactionReader) line(limit int) ([]byte, error) {
	start := len(r.data)
	for len(r.data)-start < limit {
		p, err := r.take(1)
		if err != nil {
			return r.data[start:], err
		}
		if p[0] == '\n' {
			return r.data[start:], nil
		}
	}
	return r.data[start:], errTextTransaction
}

func numericReplyEnd(line []byte, code string) bool {
	return len(line) >= 4 && string(line[:3]) == code && line[3] == ' '
}

func readTextTransaction(r *bufio.Reader, payload string) (string, error) {
	limit := textTransactionLimit
	if payload == "INFO\r\n" || strings.HasPrefix(payload, "GET ") || strings.HasPrefix(payload, "HEAD ") {
		limit = respTransactionLimit
	}
	t := &textTransactionReader{r: r, limit: limit}
	_, err := r.Peek(1)
	if err != nil {
		return "", err
	}
	if payload == "INFO\r\n" || respWirePrefix(r) {
		t.limit = respTransactionLimit
		_, err = t.resp(0, new(int))
		return string(t.data), err
	}
	irc := strings.HasPrefix(payload, "NICK ")
	lineLimit := textTransactionLimit
	if irc {
		lineLimit = 512
	}
	var multiline string
	for lines := 0; lines < 32; lines++ {
		line, err := t.line(lineLimit)
		if err != nil {
			return string(t.data), err
		}
		text := strings.TrimSuffix(strings.TrimSuffix(string(line), "\n"), "\r")
		if lines == 0 && (strings.HasPrefix(text, "HTTP/") || strings.HasPrefix(text, "RTSP/") || strings.HasPrefix(text, "SIP/")) {
			err = t.headersAndBody(text, payload)
			return string(t.data), err
		}
		if irc {
			if !validIRCLine(text) {
				return string(t.data), errTextTransaction
			}
			if ircRegistrationEnd(text) {
				return string(t.data), nil
			}
			continue
		}
		switch payload {
		case "CAPA\r\n":
			if strings.HasPrefix(text, "-ERR") {
				return string(t.data), nil
			}
			if lines == 0 && !strings.HasPrefix(text, "+OK") {
				return string(t.data), errTextTransaction
			}
			if lines > 0 && text == "." {
				return string(t.data), nil
			}
			continue
		case "a001 CAPABILITY\r\n":
			fields := strings.Fields(text)
			if len(fields) >= 2 && strings.EqualFold(fields[0], "a001") && (strings.EqualFold(fields[1], "OK") || strings.EqualFold(fields[1], "NO") || strings.EqualFold(fields[1], "BAD")) {
				return string(t.data), nil
			}
			if !strings.HasPrefix(text, "* ") {
				return string(t.data), errTextTransaction
			}
			continue
		case "EHLO gomap.local\r\n":
			if len(text) >= 4 && strings.HasPrefix(text, "220") && (text[3] == '-' || text[3] == ' ') {
				continue
			}
			if len(text) >= 4 && (strings.HasPrefix(text, "250") || text[0] == '4' || text[0] == '5') {
				if text[3] == '-' {
					multiline = text[:3]
					continue
				}
				if text[3] == ' ' && (multiline == "" || multiline == text[:3]) {
					return string(t.data), nil
				}
			}
			return string(t.data), errTextTransaction
		}
		if lines == 0 && len(text) >= 4 && text[0] >= '0' && text[0] <= '9' && text[1] >= '0' && text[1] <= '9' && text[2] >= '0' && text[2] <= '9' && text[3] == '-' {
			multiline = text[:3]
			continue
		}
		if multiline == "" || numericReplyEnd(line, multiline) {
			return string(t.data), nil
		}
	}
	return string(t.data), errTextTransaction
}

func (t *textTransactionReader) headersAndBody(status, payload string) error {
	for lines := 0; ; lines++ {
		line, err := t.line(textTransactionLimit)
		if err != nil {
			return err
		}
		if bytes.Equal(line, []byte("\r\n")) || bytes.Equal(line, []byte("\n")) {
			break
		}
		if lines >= 32 {
			return errTextTransaction
		}
	}
	header := string(t.data)
	if !strings.HasPrefix(status, "HTTP/") {
		// Reuse the standard HTTP header/framing parser for the shared wire shape.
		parts := strings.SplitN(status, " ", 2)
		if len(parts) != 2 {
			return errTextTransaction
		}
		header = "HTTP/1.1 " + parts[1] + header[len(status):]
	}
	response, err := http.ReadResponse(bufio.NewReader(strings.NewReader(header)), nil)
	if err != nil {
		return err
	}
	defer func() { _ = response.Body.Close() }()
	if strings.HasPrefix(payload, "HEAD ") || response.StatusCode == 204 || response.StatusCode == 304 || response.StatusCode < 200 {
		return nil
	}
	if len(response.TransferEncoding) > 0 {
		if len(response.TransferEncoding) != 1 || response.TransferEncoding[0] != "chunked" {
			return errTextTransaction
		}
		return t.chunks()
	}
	if response.ContentLength >= 0 {
		if response.ContentLength > int64(t.limit-len(t.data)) {
			return errTextTransaction
		}
		_, err = t.take(int(response.ContentLength))
		return err
	}
	if !strings.HasPrefix(status, "HTTP/") {
		return nil
	}
	for len(t.data) < t.limit {
		p, readErr := t.r.ReadByte()
		if readErr == io.EOF {
			return nil
		}
		if readErr != nil {
			return readErr
		}
		t.data = append(t.data, p)
	}
	return errTextTransaction
}

func (t *textTransactionReader) chunks() error {
	for count := 0; count < 64; count++ {
		line, err := t.line(128)
		if err != nil || !bytes.HasSuffix(line, []byte("\r\n")) {
			return errTextTransaction
		}
		sizeText := strings.SplitN(string(line[:len(line)-2]), ";", 2)[0]
		if sizeText == "" || strings.ContainsAny(sizeText, "+- \t") {
			return errTextTransaction
		}
		size, err := strconv.ParseUint(sizeText, 16, 32)
		if err != nil {
			return errTextTransaction
		}
		if size == 0 {
			for trailers := 0; trailers < 32; trailers++ {
				line, err := t.line(textTransactionLimit)
				if err != nil {
					return err
				}
				if bytes.Equal(line, []byte("\r\n")) {
					return nil
				}
				if !bytes.Contains(line, []byte(":")) {
					return errTextTransaction
				}
			}
			return errTextTransaction
		}
		if size+2 > uint64(t.limit-len(t.data)) {
			return errTextTransaction
		}
		body, err := t.take(int(size) + 2)
		if err != nil || !bytes.HasSuffix(body, []byte("\r\n")) {
			return errTextTransaction
		}
	}
	return errTextTransaction
}

func exchangeTextTransaction(conn net.Conn, payload string, timeout time.Duration) string {
	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return ""
	}
	if n, err := io.WriteString(conn, payload); err != nil || n != len(payload) {
		return ""
	}
	response, _ := readTextTransaction(bufio.NewReaderSize(conn, 512), payload)
	return response
}
