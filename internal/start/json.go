package start

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"math/big"
	"strconv"
	"strings"
	"unicode/utf8"
)

func digest(data []byte) string { sum := sha256.Sum256(data); return hex.EncodeToString(sum[:]) }

// Strict parsing is also used for markers and projections. Never let a duplicate
// field, an invalid Unicode escape, or an inexact number hide a stored fact.
func parseJSON(data []byte) (any, error) {
	if !utf8.Valid(data) || !validEscapes(data) {
		return nil, integrity("stored JSON is not valid Unicode")
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	var read func(int) (any, error)
	read = func(depth int) (any, error) {
		if depth > 512 {
			return nil, integrity("stored JSON is too deeply nested")
		}
		token, err := d.Token()
		if err != nil {
			return nil, integrity("stored JSON cannot be read")
		}
		switch t := token.(type) {
		case json.Delim:
			switch t {
			case '{':
				m := map[string]any{}
				for d.More() {
					key, err := d.Token()
					if err != nil {
						return nil, integrity("stored JSON cannot be read")
					}
					name, ok := key.(string)
					if !ok {
						return nil, integrity("stored JSON has an invalid field")
					}
					if _, ok := m[name]; ok {
						return nil, integrity("stored JSON contains a duplicate field")
					}
					value, err := read(depth + 1)
					if err != nil {
						return nil, err
					}
					m[name] = value
				}
				end, err := d.Token()
				if err != nil || end != json.Delim('}') {
					return nil, integrity("stored JSON cannot be read")
				}
				return m, nil
			case '[':
				a := []any{}
				for d.More() {
					value, err := read(depth + 1)
					if err != nil {
						return nil, err
					}
					a = append(a, value)
				}
				end, err := d.Token()
				if err != nil || end != json.Delim(']') {
					return nil, integrity("stored JSON cannot be read")
				}
				return a, nil
			}
			return nil, integrity("stored JSON has an unexpected delimiter")
		case json.Number:
			literal := string(t)
			if len(strings.TrimPrefix(literal, "-")) > 4300 {
				return nil, integrity("stored JSON integer exceeds its digit limit")
			}
			if strings.ContainsAny(literal, ".eE") {
				n, err := strconv.ParseFloat(literal, 64)
				if err != nil || math.IsNaN(n) || math.IsInf(n, 0) {
					return nil, integrity("stored JSON must contain finite numbers")
				}
				normalized := pythonFloat(n)
				first, ok1 := new(big.Rat).SetString(literal)
				second, ok2 := new(big.Rat).SetString(normalized)
				if !ok1 || !ok2 || first.Cmp(second) != 0 {
					return nil, integrity("stored JSON number cannot be stored exactly")
				}
			}
			return t, nil
		default:
			return token, nil
		}
	}
	value, err := read(0)
	if err != nil {
		return nil, err
	}
	if _, err := d.Token(); err != io.EOF {
		return nil, integrity("stored JSON contains trailing input")
	}
	return value, nil
}
func validEscapes(data []byte) bool {
	quoted := false
	for i := 0; i < len(data); i++ {
		if data[i] == '"' {
			quoted = !quoted
			continue
		}
		if !quoted || data[i] != '\\' {
			continue
		}
		i++
		if i >= len(data) {
			return false
		}
		if data[i] != 'u' {
			continue
		}
		if i+4 >= len(data) {
			return false
		}
		value, err := strconv.ParseUint(string(data[i+1:i+5]), 16, 16)
		if err != nil {
			return false
		}
		i += 4
		if value >= 0xd800 && value <= 0xdbff {
			if i+6 >= len(data) || data[i+1] != '\\' || data[i+2] != 'u' {
				return false
			}
			low, err := strconv.ParseUint(string(data[i+3:i+7]), 16, 16)
			if err != nil || low < 0xdc00 || low > 0xdfff {
				return false
			}
			i += 6
		} else if value >= 0xdc00 && value <= 0xdfff {
			return false
		}
	}
	return true
}
func pythonFloat(n float64) string {
	abs := math.Abs(n)
	format := byte('f')
	if abs != 0 && (abs < 1e-4 || abs >= 1e16) {
		format = 'e'
	}
	s := strconv.FormatFloat(n, format, -1, 64)
	if !strings.ContainsAny(s, ".eE") {
		s += ".0"
	}
	return s
}
func quoteString(s string) string {
	var out strings.Builder
	out.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			out.WriteString(`\"`)
		case '\\':
			out.WriteString(`\\`)
		case '\b':
			out.WriteString(`\b`)
		case '\f':
			out.WriteString(`\f`)
		case '\n':
			out.WriteString(`\n`)
		case '\r':
			out.WriteString(`\r`)
		case '\t':
			out.WriteString(`\t`)
		default:
			if r < 32 {
				fmt.Fprintf(&out, `\u%04x`, r)
			} else {
				out.WriteRune(r)
			}
		}
	}
	out.WriteByte('"')
	return out.String()
}
func canonical(v any) string {
	switch value := v.(type) {
	case nil:
		return "null"
	case string:
		return quoteString(value)
	case bool:
		if value {
			return "true"
		}
		return "false"
	case int:
		return strconv.Itoa(value)
	case int64:
		return strconv.FormatInt(value, 10)
	case float64:
		return pythonFloat(value)
	case json.Number:
		if strings.ContainsAny(string(value), ".eE") {
			n, _ := value.Float64()
			return pythonFloat(n)
		}
		if value == "-0" {
			return "0"
		}
		return string(value)
	case []any:
		parts := make([]string, len(value))
		for i, item := range value {
			parts[i] = canonical(item)
		}
		return "[" + strings.Join(parts, ",") + "]"
	case []string:
		parts := make([]string, len(value))
		for i, item := range value {
			parts[i] = quoteString(item)
		}
		return "[" + strings.Join(parts, ",") + "]"
	case map[string]any:
		parts := []string{}
		for _, key := range sortedKeys(value) {
			parts = append(parts, quoteString(key)+":"+canonical(value[key]))
		}
		return "{" + strings.Join(parts, ",") + "}"
	}
	panic("unsupported canonical value")
}
func same(a, b any) bool { return canonical(a) == canonical(b) }
