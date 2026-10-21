package scanner

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
)

// Collect split greeting lines under the caller's fixed deadline. Numeric
// multiline FTP/SMTP replies end at the matching code followed by a space.
func readTextGreeting(r io.Reader) string {
	buffer := make([]byte, 4096)
	used := 0
	for used < len(buffer) {
		n, err := r.Read(buffer[used:])
		chunk := buffer[used : used+n]
		used += n
		binaryData := false
		for _, c := range chunk {
			if c < 32 && c != '\r' && c != '\n' && c != '\t' {
				binaryData = true
				break
			}
		}
		if binaryData || textGreetingComplete(buffer[:used]) || err != nil || n == 0 {
			break
		}
	}
	return string(buffer[:used])
}

func textGreetingComplete(data []byte) bool {
	end := bytes.IndexByte(data, '\n')
	if end < 0 {
		return false
	}
	if end < 4 || data[0] < '0' || data[0] > '9' || data[1] < '0' || data[1] > '9' || data[2] < '0' || data[2] > '9' || data[3] != '-' {
		return true
	}
	code := data[:3]
	for rest := data[end+1:]; len(rest) > 0; {
		end = bytes.IndexByte(rest, '\n')
		if end < 0 {
			return false
		}
		if end >= 4 && bytes.Equal(rest[:3], code) && rest[3] == ' ' {
			return true
		}
		rest = rest[end+1:]
	}
	return false
}

// Read complete frames under the connection's existing deadline, with bounded allocations.
func readDNSMessage(r io.Reader) ([]byte, error) {
	header := make([]byte, 2)
	if _, err := io.ReadFull(r, header); err != nil {
		return nil, err
	}
	return readFrameBody(r, header, int(binary.BigEndian.Uint16(header)), 65535)
}

func mysqlPayloadLength(header []byte) int {
	return int(header[0]) | int(header[1])<<8 | int(header[2])<<16
}

func readMySQLPacket(r io.Reader) ([]byte, error) {
	header := make([]byte, 4)
	if _, err := io.ReadFull(r, header); err != nil {
		return nil, err
	}
	return readFrameBody(r, header, mysqlPayloadLength(header), 4096)
}

func readRDPConfirm(r io.Reader) ([]byte, error) {
	header := make([]byte, 4)
	if _, err := io.ReadFull(r, header); err != nil {
		return nil, err
	}
	size := int(binary.BigEndian.Uint16(header[2:]))
	if header[0] != 3 || header[1] != 0 || (size != 11 && size != 19) {
		return nil, fmt.Errorf("invalid RDP confirmation header")
	}
	frame, err := readFrameBody(r, header, size-4, 15)
	if err != nil {
		return nil, err
	}
	if !validRDPConfirm(frame) {
		return nil, fmt.Errorf("invalid RDP confirmation body")
	}
	return frame, nil
}

func readSMBMessage(r io.Reader) ([]byte, error) {
	header := make([]byte, 4)
	if _, err := io.ReadFull(r, header); err != nil {
		return nil, err
	}
	if header[0] != 0 {
		return nil, fmt.Errorf("invalid SMB session message type")
	}
	return readFrameBody(r, header, int(binary.BigEndian.Uint32(header)), 64*1024)
}

func readAJPReply(r io.Reader) bool {
	var header [4]byte
	if _, err := io.ReadFull(r, header[:]); err != nil || !bytes.Equal(header[:], []byte{'A', 'B', 0, 1}) {
		return false
	}
	var body [1]byte
	_, err := io.ReadFull(r, body[:])
	return err == nil && body[0] == 9
}

func readFrameBody(r io.Reader, header []byte, size, limit int) ([]byte, error) {
	if size <= 0 || size > limit {
		return nil, fmt.Errorf("invalid frame size: %d", size)
	}
	frame := make([]byte, len(header)+size)
	copy(frame, header)
	_, err := io.ReadFull(r, frame[len(header):])
	return frame, err
}

func readRPCRecord(r io.Reader) ([]byte, error) {
	const limit = 4096
	record := make([]byte, 4)
	for fragments := 0; fragments < 64; fragments++ {
		var header [4]byte
		if _, err := io.ReadFull(r, header[:]); err != nil {
			return nil, err
		}
		marker := binary.BigEndian.Uint32(header[:])
		size := marker & 0x7fffffff
		if size > uint32(limit-(len(record)-4)) {
			return nil, fmt.Errorf("RPC record exceeds %d bytes", limit)
		}
		start := len(record)
		record = append(record, make([]byte, int(size))...)
		if _, err := io.ReadFull(r, record[start:]); err != nil {
			return nil, err
		}
		if marker&0x80000000 != 0 {
			binary.BigEndian.PutUint32(record, uint32(len(record)-4)|0x80000000)
			return record, nil
		}
	}
	return nil, fmt.Errorf("too many RPC record fragments")
}
