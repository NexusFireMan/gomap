package scanner

import (
	"encoding/binary"
	"fmt"
	"io"
)

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
