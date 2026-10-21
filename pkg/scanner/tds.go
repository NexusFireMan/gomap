package scanner

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"time"
)

const tdsMessageLimit = 4096
const tdsPacketLimit = 32

var errInvalidTDS = errors.New("invalid TDS prelogin response")

func readTDSPrelogin(r io.Reader) ([]byte, error) {
	var message []byte
	var previousID byte
	var spid uint16
	for packet := 0; packet < tdsPacketLimit; packet++ {
		var header [8]byte
		if _, err := io.ReadFull(r, header[:]); err != nil {
			return nil, err
		}
		size := int(binary.BigEndian.Uint16(header[2:4])) - len(header)
		id := binary.BigEndian.Uint16(header[4:6])
		if header[0] != 4 || header[1]&^byte(1) != 0 || header[7] != 0 || size <= 0 || size > tdsMessageLimit-len(message) {
			return nil, errInvalidTDS
		}
		if packet > 0 && (id != spid || header[6] != previousID+1) {
			return nil, errInvalidTDS
		}
		spid, previousID = id, header[6]
		start := len(message)
		message = append(message, make([]byte, size)...)
		if _, err := io.ReadFull(r, message[start:]); err != nil {
			return nil, err
		}
		if header[1]&1 != 0 {
			if !validTDSPrelogin(message) {
				return nil, errInvalidTDS
			}
			return message, nil
		}
	}
	return nil, errInvalidTDS
}

func validTDSPrelogin(data []byte) bool {
	if len(data) == 0 || len(data) > tdsMessageLimit || data[0] != 0 {
		return false
	}
	type option struct{ token, offset, length int }
	var options []option
	var seen [8]bool
	tableEnd := 0
	for pos := 0; pos < len(data); pos += 5 {
		if data[pos] == 0xff {
			tableEnd = pos + 1
			break
		}
		token := int(data[pos])
		if token >= len(seen) || seen[token] || len(data)-pos < 5 {
			return false
		}
		seen[token] = true
		options = append(options, option{token, int(binary.BigEndian.Uint16(data[pos+1:])), int(binary.BigEndian.Uint16(data[pos+3:]))})
	}
	if tableEnd == 0 || !seen[0] || !seen[1] {
		return false
	}
	for i, opt := range options {
		if opt.offset < tableEnd || opt.offset > len(data) || opt.length > len(data)-opt.offset {
			return false
		}
		for _, previous := range options[:i] {
			if opt.length > 0 && previous.length > 0 && opt.offset < previous.offset+previous.length && previous.offset < opt.offset+opt.length {
				return false
			}
		}
		value := data[opt.offset : opt.offset+opt.length]
		switch opt.token {
		case 0:
			if len(value) != 6 {
				return false
			}
		case 1:
			if len(value) != 1 || value[0] > 3 {
				return false
			}
		case 2, 4, 6:
			if len(value) != 1 || value[0] > 1 {
				return false
			}
		case 3:
			if len(value) != 0 && len(value) != 4 {
				return false
			}
		case 5:
			if len(value) != 36 {
				return false
			}
		case 7:
			if len(value) != 32 {
				return false
			}
		}
	}
	return true
}

func probeTDSPrelogin(conn net.Conn, timeout time.Duration) bool {
	// Preserve the existing bounded PRELOGIN request; no login or query follows.
	prelogin := []byte{
		0x12, 0x01, 0x00, 0x34, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x1a, 0x00, 0x06, 0x01, 0x00, 0x20,
		0x00, 0x01, 0x02, 0x00, 0x21, 0x00, 0x01, 0x03,
		0x00, 0x22, 0x00, 0x04, 0x04, 0x00, 0x26, 0x00,
		0x01, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
	}
	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return false
	}
	if n, err := conn.Write(prelogin); err != nil || n != len(prelogin) {
		return false
	}
	_, err := readTDSPrelogin(conn)
	return err == nil
}
