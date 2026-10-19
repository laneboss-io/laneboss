package orgtree

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
)

type rawStorePage struct {
	data []byte
	mask []byte
	file string
	base int
}

type rawStoreField struct {
	kind uint64
	data []byte
}

type rawStoreScan struct {
	tree *tree
	view map[uint32]*rawStorePage
	size int
	safe int
}

func rawStoreVarint(data []byte) (uint64, int, bool) {
	var value uint64
	for i := 0; i < 9 && i < len(data); i++ {
		if i == 8 {
			return value<<8 | uint64(data[i]), 9, true
		}
		value = value<<7 | uint64(data[i]&0x7f)
		if data[i]&0x80 == 0 {
			return value, i + 1, true
		}
	}
	return 0, 0, false
}

func rawStoreRecord(payload []byte) ([]rawStoreField, error) {
	header, position, ok := rawStoreVarint(payload)
	if !ok || header > uint64(len(payload)) || header < uint64(position) {
		return nil, errors.New(decisionStoreUnreadable)
	}
	start := int(header)
	var fields []rawStoreField
	for position < int(header) {
		kind, n, ok := rawStoreVarint(payload[position:int(header)])
		if !ok {
			return nil, errors.New(decisionStoreUnreadable)
		}
		position += n
		var size uint64
		switch kind {
		case 0, 8, 9:
		case 1, 2, 3, 4:
			size = kind
		case 5:
			size = 6
		case 6, 7:
			size = 8
		case 10, 11:
			return nil, errors.New(decisionStoreUnreadable)
		default:
			size = (kind - 12) / 2
		}
		if size > uint64(len(payload)-start) {
			return nil, errors.New(decisionStoreUnreadable)
		}
		fields = append(fields, rawStoreField{kind, payload[start : start+int(size)]})
		start += int(size)
	}
	if start != len(payload) {
		return nil, errors.New(decisionStoreUnreadable)
	}
	return fields, nil
}

func rawStoreInteger(field rawStoreField) uint32 {
	if field.kind == 9 {
		return 1
	}
	if field.kind < 1 || field.kind > 6 || len(field.data) > 8 || len(field.data) == 0 || field.data[0]&0x80 != 0 {
		return 0
	}
	var value uint64
	for _, octet := range field.data {
		value = value<<8 | uint64(octet)
	}
	if value > uint64(^uint32(0)) {
		return 0
	}
	return uint32(value)
}

func rawStoreMask(data []byte) {
	for i := range data {
		data[i] = 1
	}
}

// Record serial types provide real value boundaries. Text and BLOB values are
// screened separately, including older page images; unused bytes are left for
// the raw-file pass. Numeric fields cannot join neighboring text into a shape.
func (s *rawStoreScan) record(page *rawStorePage, offset int, leaf bool) ([]rawStoreField, error) {
	position := offset
	payloadSize, n, ok := rawStoreVarint(page.data[position:s.safe])
	if !ok || payloadSize > maxFileBytes {
		return nil, errors.New(decisionStoreUnreadable)
	}
	position += n
	if leaf {
		_, n, ok = rawStoreVarint(page.data[position:s.safe])
		if !ok {
			return nil, errors.New(decisionStoreUnreadable)
		}
		position += n
	}
	minimum := ((s.safe - 12) * 32 / 255) - 23
	maximum := ((s.safe - 12) * 64 / 255) - 23
	if leaf {
		maximum = s.safe - 35
	}
	local := int(payloadSize)
	if local > maximum {
		local = minimum + (local-minimum)%(s.safe-4)
		if local > maximum {
			local = minimum
		}
	}
	if position > s.safe || local > s.safe-position {
		return nil, errors.New(decisionStoreUnreadable)
	}
	payload := append([]byte(nil), page.data[position:position+local]...)
	end := position + local
	type fragment struct {
		page *rawStorePage
		size int
	}
	var overflow []fragment
	seen := make(map[uint32]bool)
	if local < int(payloadSize) {
		if end+4 > s.safe {
			return nil, errors.New(decisionStoreUnreadable)
		}
		next := binary.BigEndian.Uint32(page.data[end : end+4])
		end += 4
		for len(payload) < int(payloadSize) {
			if !s.tree.withinTime() || next == 0 || seen[next] {
				return nil, errors.New(decisionStoreUnreadable)
			}
			seen[next] = true
			part := s.view[next]
			if part == nil || len(part.data) != s.size {
				return nil, errors.New(decisionStoreUnreadable)
			}
			count := min(s.safe-4, int(payloadSize)-len(payload))
			payload = append(payload, part.data[4:4+count]...)
			overflow = append(overflow, fragment{part, count})
			next = binary.BigEndian.Uint32(part.data[:4])
		}
	}
	fields, err := rawStoreRecord(payload)
	if err != nil {
		return nil, err
	}
	for _, field := range fields {
		if err = s.tree.scanRawStoreText(page.file, field.data, 1); err != nil {
			return nil, err
		}
	}
	rawStoreMask(page.mask[offset:end])
	for _, part := range overflow {
		rawStoreMask(part.page.mask[:4+part.size])
	}
	return fields, nil
}

func (s *rawStoreScan) walk(number uint32, schema bool, seen map[uint32]bool) ([]uint32, error) {
	if !s.tree.withinTime() || number == 0 || seen[number] {
		return nil, errors.New(decisionStoreUnreadable)
	}
	seen[number] = true
	page := s.view[number]
	if page == nil || len(page.data) != s.size {
		return nil, errors.New(decisionStoreUnreadable)
	}
	header := 0
	if number == 1 {
		header = 100
	}
	if header+12 > s.safe {
		return nil, errors.New(decisionStoreUnreadable)
	}
	kind := page.data[header]
	interior := kind == 2 || kind == 5
	if kind != 2 && kind != 5 && kind != 10 && kind != 13 {
		return nil, errors.New(decisionStoreUnreadable)
	}
	count := int(binary.BigEndian.Uint16(page.data[header+3 : header+5]))
	pointers := header + 8
	if interior {
		pointers += 4
	}
	if count > (s.safe-pointers)/2 {
		return nil, errors.New(decisionStoreUnreadable)
	}
	var roots []uint32
	if interior {
		child := binary.BigEndian.Uint32(page.data[header+8 : header+12])
		more, err := s.walk(child, schema, seen)
		if err != nil {
			return nil, err
		}
		roots = append(roots, more...)
	}
	for i := 0; i < count; i++ {
		offset := int(binary.BigEndian.Uint16(page.data[pointers+2*i : pointers+2*i+2]))
		if offset < pointers+2*count || offset >= s.safe {
			return nil, errors.New(decisionStoreUnreadable)
		}
		start := offset
		if interior {
			if offset+4 > s.safe {
				return nil, errors.New(decisionStoreUnreadable)
			}
			child := binary.BigEndian.Uint32(page.data[offset : offset+4])
			more, err := s.walk(child, schema, seen)
			if err != nil {
				return nil, err
			}
			roots = append(roots, more...)
			offset += 4
		}
		if kind == 5 {
			_, n, ok := rawStoreVarint(page.data[offset:s.safe])
			if !ok {
				return nil, errors.New(decisionStoreUnreadable)
			}
			rawStoreMask(page.mask[start : offset+n])
			continue
		}
		fields, err := s.record(page, offset, kind == 13)
		if err != nil {
			return nil, err
		}
		if interior {
			rawStoreMask(page.mask[start:offset])
		}
		if schema {
			if kind != 13 || len(fields) != 5 {
				return nil, errors.New(decisionStoreUnreadable)
			}
			if root := rawStoreInteger(fields[3]); root != 0 {
				roots = append(roots, root)
			}
		}
	}
	return roots, nil
}

func (s *rawStoreScan) image() error {
	roots, err := s.walk(1, true, make(map[uint32]bool))
	if err != nil {
		return err
	}
	seen := make(map[uint32]bool)
	for _, root := range roots {
		if seen[root] {
			continue
		}
		if _, err = s.walk(root, false, seen); err != nil {
			return err
		}
	}
	return nil
}

func (t *tree) scanRawStoreText(relative string, data []byte, line int) error {
	found, err := findCredentialUntil(strings.ToValidUTF8(string(data), "\ufffd"), t.deadline)
	if err != nil {
		return err
	}
	if found != nil {
		t.problem(relative, fmt.Sprintf("secret value detected on line %d (%s); keep secret names only", line+found.line-1, found.rule))
	}
	return nil
}

func (t *tree) scanRawStore(snapshot map[string]*storeFileSnapshot, skipCompanions bool) error {
	masks := make(map[string][]byte)
	for relative, item := range snapshot {
		if item != nil {
			masks[relative] = make([]byte, len(item.data))
		}
	}
	main := snapshot[decisionStorePath].data
	size := sqlitePageSize(main)
	scan := rawStoreScan{t, make(map[uint32]*rawStorePage), size, size - int(main[20])}
	if scan.safe < 480 {
		return errors.New(decisionStoreUnreadable)
	}
	for position := 0; position+size <= len(main); position += size {
		scan.view[uint32(position/size+1)] = &rawStorePage{
			main[position : position+size], masks[decisionStorePath][position : position+size], decisionStorePath, position,
		}
	}
	if err := scan.image(); err != nil {
		return err
	}
	if wal := snapshot[decisionStorePath+"-wal"]; wal != nil && !skipCompanions && len(wal.data) >= 32 && validWAL(wal.data, size) {
		pending := false
		for position := 32; position+24+size <= len(wal.data); position += 24 + size {
			frame := wal.data[position : position+24+size]
			if !bytesSame(frame[8:16], wal.data[16:24]) {
				break
			}
			number := binary.BigEndian.Uint32(frame[:4])
			if number == 0 {
				break
			}
			scan.view[number] = &rawStorePage{
				frame[24:], masks[decisionStorePath+"-wal"][position+24 : position+24+size], decisionStorePath + "-wal", position + 24,
			}
			pending = true
			if binary.BigEndian.Uint32(frame[4:8]) != 0 {
				if err := scan.image(); err != nil {
					return err
				}
				pending = false
			}
		}
		if pending {
			// A partial transaction is not silently masked: its original bytes
			// still receive the raw scan, while SQL reads only committed pages.
			if err := t.scanRawStoreText(decisionStorePath+"-wal", wal.data, 1); err != nil {
				return err
			}
		}
	}
	for relative, covered := range masks {
		if skipCompanions && relative != decisionStorePath {
			continue
		}
		data := snapshot[relative].data
		line := 1
		for position := 0; position < len(data); {
			start := position
			live := covered[position] != 0
			for position < len(data) && (covered[position] != 0) == live {
				position++
			}
			if !live {
				if err := t.scanRawStoreText(relative, data[start:position], line); err != nil {
					return err
				}
			}
			line += strings.Count(string(data[start:position]), "\n")
		}
	}
	return nil
}

func bytesSame(first, second []byte) bool {
	if len(first) != len(second) {
		return false
	}
	for i := range first {
		if first[i] != second[i] {
			return false
		}
	}
	return true
}
