package brief

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

// The event store hashes Python's sorted, compact, UTF-8 JSON form. In
// particular, HTML and U+2028/U+2029 must remain literal Unicode characters.
func canonical(value any) ([]byte, error) {
	var out bytes.Buffer
	var encode func(any) error
	quote := func(s string) error {
		if !utf8.ValidString(s) {
			return refused("text must be valid Unicode")
		}
		out.WriteByte('"')
		for _, r := range s {
			switch r {
			case '"', '\\':
				out.WriteByte('\\')
				out.WriteRune(r)
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
		return nil
	}
	encode = func(value any) error {
		switch v := value.(type) {
		case nil:
			out.WriteString("null")
		case bool:
			out.WriteString(strconv.FormatBool(v))
		case string:
			return quote(v)
		case int:
			out.WriteString(strconv.Itoa(v))
		case int64:
			out.WriteString(strconv.FormatInt(v, 10))
		case json.Number:
			if !json.Valid([]byte(v)) {
				return refused("a JSON number is invalid")
			}
			out.WriteString(string(v))
		case float64:
			if math.IsNaN(v) || math.IsInf(v, 0) {
				return refused("JSON numbers must be finite")
			}
			text := strconv.FormatFloat(v, 'g', -1, 64)
			if !strings.ContainsAny(text, ".eE") {
				text += ".0"
			}
			out.WriteString(text)
		case []string:
			items := make([]any, len(v))
			for i := range v {
				items[i] = v[i]
			}
			return encode(items)
		case []any:
			out.WriteByte('[')
			for i, item := range v {
				if i > 0 {
					out.WriteByte(',')
				}
				if err := encode(item); err != nil {
					return err
				}
			}
			out.WriteByte(']')
		case map[string]any:
			keys := make([]string, 0, len(v))
			for key := range v {
				keys = append(keys, key)
			}
			sort.Strings(keys)
			out.WriteByte('{')
			for i, key := range keys {
				if i > 0 {
					out.WriteByte(',')
				}
				if err := quote(key); err != nil {
					return err
				}
				out.WriteByte(':')
				if err := encode(v[key]); err != nil {
					return err
				}
			}
			out.WriteByte('}')
		default:
			return fmt.Errorf("unsupported JSON type")
		}
		return nil
	}
	if err := encode(value); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

func decodeJSON(data []byte) (any, error) {
	if !utf8.Valid(data) {
		return nil, fmt.Errorf("invalid Unicode")
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	var read func(int) (any, error)
	read = func(depth int) (any, error) {
		if depth > 128 {
			return nil, fmt.Errorf("JSON nesting exceeds limit")
		}
		token, err := d.Token()
		if err != nil {
			return nil, err
		}
		if delimiter, ok := token.(json.Delim); ok {
			switch delimiter {
			case '{':
				value := map[string]any{}
				for d.More() {
					key, err := d.Token()
					if err != nil {
						return nil, err
					}
					name, ok := key.(string)
					if !ok {
						return nil, fmt.Errorf("invalid field")
					}
					if _, exists := value[name]; exists {
						return nil, fmt.Errorf("duplicate field")
					}
					item, err := read(depth + 1)
					if err != nil {
						return nil, err
					}
					value[name] = item
				}
				end, err := d.Token()
				if err != nil || end != json.Delim('}') {
					return nil, fmt.Errorf("invalid object")
				}
				return value, nil
			case '[':
				value := []any{}
				for d.More() {
					item, err := read(depth + 1)
					if err != nil {
						return nil, err
					}
					value = append(value, item)
				}
				end, err := d.Token()
				if err != nil || end != json.Delim(']') {
					return nil, fmt.Errorf("invalid array")
				}
				return value, nil
			default:
				return nil, fmt.Errorf("invalid delimiter")
			}
		}
		return token, nil
	}
	value, err := read(0)
	if err != nil {
		return nil, err
	}
	if _, err = d.Token(); err != io.EOF {
		return nil, fmt.Errorf("trailing JSON content")
	}
	return value, nil
}
