package orgtree

import (
	"bytes"
	"encoding/binary"
)

func sqlitePageSize(data []byte) int {
	if len(data) < 100 || !bytes.Equal(data[:16], []byte("SQLite format 3\x00")) {
		return 0
	}
	size := int(binary.BigEndian.Uint16(data[16:18]))
	if size == 1 {
		size = 65536
	}
	if size < 512 || size > 65536 || size&(size-1) != 0 {
		return 0
	}
	return size
}

func walChecksum(data []byte, order binary.ByteOrder, first, second uint32) (uint32, uint32) {
	for len(data) >= 8 {
		first += order.Uint32(data[:4]) + second
		second += order.Uint32(data[4:8]) + first
		data = data[8:]
	}
	return first, second
}

func validWAL(data []byte, pageSize int) bool {
	if len(data) == 0 {
		return true
	}
	if len(data) < 32 || binary.BigEndian.Uint32(data[4:8]) != 3007000 ||
		int(binary.BigEndian.Uint32(data[8:12])) != pageSize {
		return false
	}
	magic := binary.BigEndian.Uint32(data[:4])
	var order binary.ByteOrder = binary.LittleEndian
	if magic == 0x377f0683 {
		order = binary.BigEndian
	} else if magic != 0x377f0682 {
		return false
	}
	first, second := walChecksum(data[:24], order, 0, 0)
	if first != binary.BigEndian.Uint32(data[24:28]) || second != binary.BigEndian.Uint32(data[28:32]) {
		return false
	}
	frameSize := 24 + pageSize
	frames := data[32:]
	validFrames := 0
	for len(frames) >= frameSize {
		frame := frames[:frameSize]
		if binary.BigEndian.Uint32(frame[:4]) == 0 || !bytes.Equal(frame[8:16], data[16:24]) {
			break
		}
		a, b := walChecksum(frame[:8], order, first, second)
		a, b = walChecksum(frame[24:], order, a, b)
		if a != binary.BigEndian.Uint32(frame[16:20]) || b != binary.BigEndian.Uint32(frame[20:24]) {
			break
		}
		first, second = a, b
		validFrames++
		frames = frames[frameSize:]
	}
	// SQLite stops at the first stale/uncommitted tail after a valid prefix.
	// Raw-byte scanning still examines that tail, including discarded pages.
	return len(data) == 32 || validFrames > 0
}

func validSHM(data, wal []byte, pageSize int) bool {
	if len(data) == 0 {
		return true
	}
	if len(wal) < 32 || !validWAL(wal, pageSize) || len(data) < 32768 || len(data)%32768 != 0 ||
		!bytes.Equal(data[:48], data[48:96]) || data[12] != 1 || data[13] > 1 ||
		!bytes.Equal(data[32:40], wal[16:24]) {
		return false
	}
	for _, order := range []binary.ByteOrder{binary.LittleEndian, binary.BigEndian} {
		if order.Uint32(data[:4]) != 3007000 {
			continue
		}
		size := int(order.Uint16(data[14:16]))
		if size == 1 {
			size = 65536
		}
		first, second := walChecksum(data[:40], order, 0, 0)
		if size == pageSize && first == order.Uint32(data[40:44]) && second == order.Uint32(data[44:48]) {
			return true
		}
	}
	return false
}

func validJournal(data []byte, pageSize int) bool {
	if len(data) == 0 {
		return true
	}
	magic := []byte{0xd9, 0xd5, 0x05, 0xf9, 0x20, 0xa1, 0x63, 0xd7}
	offset := 0
	for offset < len(data) {
		if len(data)-offset < 28 || !bytes.Equal(data[offset:offset+8], magic) {
			return false
		}
		header := data[offset : offset+28]
		sector := int(binary.BigEndian.Uint32(header[20:24]))
		if sector < 512 || sector > 65536 || sector&(sector-1) != 0 ||
			int(binary.BigEndian.Uint32(header[24:28])) != pageSize || sector > len(data)-offset {
			return false
		}
		count := binary.BigEndian.Uint32(header[8:12])
		nonce := binary.BigEndian.Uint32(header[12:16])
		offset += sector
		if count == 0xffffffff {
			count = uint32((len(data) - offset) / (pageSize + 8))
		}
		if count == 0 || uint64(count)*uint64(pageSize+8) > uint64(len(data)-offset) {
			return false
		}
		for i := uint32(0); i < count; i++ {
			page := data[offset : offset+pageSize+8]
			if binary.BigEndian.Uint32(page[:4]) == 0 {
				return false
			}
			sum := nonce
			for j := pageSize - 200; j > 0; j -= 200 {
				sum += uint32(page[4+j])
			}
			if sum != binary.BigEndian.Uint32(page[4+pageSize:]) {
				return false
			}
			offset += pageSize + 8
		}
		if offset == len(data) {
			return true
		}
		next := (offset + sector - 1) & ^(sector - 1)
		if next >= len(data) {
			return bytes.Equal(data[offset:], make([]byte, len(data)-offset))
		}
		offset = next
	}
	return true
}

func validStoreCompanion(suffix string, data []byte, snapshot map[string]*storeFileSnapshot, pageSize int) bool {
	switch suffix {
	case "-wal":
		return validWAL(data, pageSize)
	case "-shm":
		wal := snapshot[decisionStorePath+"-wal"]
		if wal == nil {
			return len(data) == 0
		}
		return validSHM(data, wal.data, pageSize)
	case "-journal":
		return validJournal(data, pageSize)
	}
	return false
}
