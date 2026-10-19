package identity

import (
	"encoding/binary"
	"math"
	"unicode/utf8"
)

// Registration uses a bounded, definite-length CBOR subset. No tags, floats,
// indefinite containers, duplicate keys, private COSE keys or trailing objects
// acquire a meaning by being ignored. This parser never loads external data.
type registrationCBOR struct {
	raw   []byte
	pos   int
	nodes int
}

func (c *registrationCBOR) value(depth int) (any, error) {
	if depth > 12 || c.nodes >= 256 || c.pos >= len(c.raw) {
		return nil, registrationInvalid()
	}
	c.nodes++
	header := c.raw[c.pos]
	c.pos++
	major, extra := header>>5, header&31
	var n uint64
	switch {
	case extra < 24:
		n = uint64(extra)
	case extra <= 27:
		width := 1 << (extra - 24)
		if width > len(c.raw)-c.pos {
			return nil, registrationInvalid()
		}
		for _, b := range c.raw[c.pos : c.pos+width] {
			n = n<<8 | uint64(b)
		}
		c.pos += width
	default:
		return nil, registrationInvalid()
	}
	switch major {
	case 0, 1:
		if n > math.MaxInt64 {
			return nil, registrationInvalid()
		}
		if major == 1 {
			return -1 - int64(n), nil
		}
		return int64(n), nil
	case 2, 3:
		if n > uint64(len(c.raw)-c.pos) {
			return nil, registrationInvalid()
		}
		bytes := c.raw[c.pos : c.pos+int(n)]
		c.pos += int(n)
		if major == 2 {
			return bytes, nil
		}
		if !utf8.Valid(bytes) {
			return nil, registrationInvalid()
		}
		return string(bytes), nil
	case 4:
		if n > 64 {
			return nil, registrationInvalid()
		}
		items := make([]any, 0, int(n))
		for range n {
			value, err := c.value(depth + 1)
			if err != nil {
				return nil, err
			}
			items = append(items, value)
		}
		return items, nil
	case 5:
		if n > 32 {
			return nil, registrationInvalid()
		}
		items := make(map[any]any, int(n))
		for range n {
			key, err := c.value(depth + 1)
			if err != nil {
				return nil, err
			}
			switch key.(type) {
			case string, int64:
			default:
				return nil, registrationInvalid()
			}
			if _, exists := items[key]; exists {
				return nil, registrationInvalid()
			}
			value, err := c.value(depth + 1)
			if err != nil {
				return nil, err
			}
			items[key] = value
		}
		return items, nil
	}
	return nil, registrationInvalid()
}

func cborObject(raw []byte) (map[any]any, error) {
	decoder := registrationCBOR{raw: raw}
	value, err := decoder.value(0)
	object, ok := value.(map[any]any)
	if err != nil || !ok || decoder.pos != len(raw) {
		return nil, registrationInvalid()
	}
	return object, nil
}

func registrationInvalid() error {
	return refusal("invalid_request", "invalid or unsupported WebAuthn registration encoding")
}

func registrationCounter(auth []byte) uint32 { return binary.BigEndian.Uint32(auth[33:37]) }
