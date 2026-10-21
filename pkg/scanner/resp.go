package scanner

import (
	"bufio"
	"bytes"
	"strconv"
	"strings"
)

func respWirePrefix(r *bufio.Reader) bool {
	p, err := r.Peek(2)
	if err != nil {
		return false
	}
	return respPrefix(p[0], p[1])
}

func respPrefix(first, second byte) bool {
	return first == '$' || ((first == '*' || first == ':') && (second == '-' || second >= '0' && second <= '9')) || first == ':' && second == '+'
}

func respBannerPrefix(banner string) bool {
	return len(banner) >= 2 && respPrefix(banner[0], banner[1])
}

// RESP2 is the wire version used by the existing INFO probe. Parse complete
// bounded values, never a bulk payload as newline-delimited greeting text.
func (r *textTransactionReader) resp(depth int, nodes *int) ([]byte, error) {
	*nodes = *nodes + 1
	if depth > 8 || *nodes > 128 {
		return nil, errTextTransaction
	}
	line, err := r.line(textTransactionLimit)
	if err != nil || len(line) < 3 || !bytes.HasSuffix(line, []byte("\r\n")) {
		return nil, errTextTransaction
	}
	value := line[1 : len(line)-2]
	if bytes.ContainsAny(value, "\r\n") {
		return nil, errTextTransaction
	}
	switch line[0] {
	case '+', '-':
		return nil, nil
	case ':':
		_, err := strconv.ParseInt(string(value), 10, 64)
		if err != nil || bytes.ContainsAny(value, " \t") {
			return nil, errTextTransaction
		}
		return nil, nil
	case '$', '*':
		if bytes.Equal(value, []byte("-1")) {
			return nil, nil
		}
		if len(value) == 0 {
			return nil, errTextTransaction
		}
		for _, digit := range value {
			if digit < '0' || digit > '9' {
				return nil, errTextTransaction
			}
		}
		n, err := strconv.ParseUint(string(value), 10, 32)
		if err != nil {
			return nil, errTextTransaction
		}
		if line[0] == '$' {
			if n+2 > uint64(r.limit-len(r.data)) {
				return nil, errTextTransaction
			}
			body, err := r.take(int(n) + 2)
			if err != nil || !bytes.HasSuffix(body, []byte("\r\n")) {
				return nil, errTextTransaction
			}
			return body[:len(body)-2], nil
		}
		if n > 64 {
			return nil, errTextTransaction
		}
		for i := uint64(0); i < n; i++ {
			if _, err := r.resp(depth+1, nodes); err != nil {
				return nil, err
			}
		}
		return nil, nil
	}
	return nil, errTextTransaction
}

func respBulkPayload(banner string) ([]byte, bool) {
	if len(banner) > respTransactionLimit || !strings.HasPrefix(banner, "$") {
		return nil, false
	}
	r := &textTransactionReader{r: bufio.NewReaderSize(strings.NewReader(banner), 512), limit: respTransactionLimit}
	payload, err := r.resp(0, new(int))
	return payload, err == nil && len(r.data) == len(banner)
}
