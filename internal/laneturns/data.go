package laneturns

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"
)

type object = map[string]any

func isStringValue(v any) bool { _, ok := v.(string); return ok }

func obj(v any) object { m, _ := v.(map[string]any); return m }
func str(v any) string { s, _ := v.(string); return s }
func flag(v any) bool  { b, _ := v.(bool); return b }
func number(v any) float64 {
	switch n := v.(type) {
	case int:
		return float64(n)
	case int64:
		return float64(n)
	case uint64:
		return float64(n)
	case float64:
		return n
	case json.Number:
		f, _ := n.Float64()
		return f
	}
	return 0
}
func integer(v any) int { return int(number(v)) }
func array(v any) []any {
	if v == nil {
		return []any{}
	}
	if a, ok := v.([]any); ok {
		return a
	}
	r := reflect.ValueOf(v)
	if r.Kind() != reflect.Slice && r.Kind() != reflect.Array {
		return []any{}
	}
	a := make([]any, r.Len())
	for i := range a {
		a[i] = r.Index(i).Interface()
	}
	return a
}
func texts(v any) []string {
	a := array(v)
	r := make([]string, len(a))
	for i, x := range a {
		r[i] = str(x)
	}
	return r
}
func contains(v any, s string) bool {
	for _, x := range texts(v) {
		if x == s {
			return true
		}
	}
	return false
}
func copyObject(v object) object {
	r := object{}
	for k, x := range v {
		r[k] = x
	}
	return r
}
func digest(data []byte) string { sum := sha256.Sum256(data); return hex.EncodeToString(sum[:]) }
func randomID() (string, error) {
	data := make([]byte, 16)
	if _, err := rand.Read(data); err != nil {
		return "", err
	}
	return hex.EncodeToString(data), nil
}
func nowStamp() string         { return stamp(time.Now()) }
func stamp(t time.Time) string { return t.UTC().Format("2006-01-02T15:04:05.000000Z") }
func moment(v any) (time.Time, error) {
	t, err := time.Parse(time.RFC3339Nano, str(v))
	if err != nil {
		return t, integrity("a stored timestamp is not valid")
	}
	return t, nil
}
func eventTime(e object) any {
	if e["occurred_at"] != nil {
		return e["occurred_at"]
	}
	return e["recorded_at"]
}
func decodeJSON(data []byte) (object, error) {
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	v, err := decodeValue(d, 0)
	if err != nil {
		return nil, integrity("stored JSON is not valid")
	}
	if _, err = d.Token(); err != io.EOF {
		return nil, integrity("stored JSON has trailing data")
	}
	m, ok := v.(map[string]any)
	if !ok {
		return nil, integrity("stored JSON must be an object")
	}
	return m, nil
}
func decodeValue(d *json.Decoder, depth int) (any, error) {
	if depth > 128 {
		return nil, fmt.Errorf("JSON nesting limit")
	}
	t, err := d.Token()
	if err != nil {
		return nil, err
	}
	if delim, ok := t.(json.Delim); ok {
		switch delim {
		case '{':
			m := object{}
			for d.More() {
				key, err := d.Token()
				if err != nil {
					return nil, err
				}
				k, ok := key.(string)
				if !ok {
					return nil, fmt.Errorf("field")
				}
				if _, exists := m[k]; exists {
					return nil, fmt.Errorf("duplicate field")
				}
				v, err := decodeValue(d, depth+1)
				if err != nil {
					return nil, err
				}
				m[k] = v
			}
			end, err := d.Token()
			if end != json.Delim('}') || err != nil {
				return nil, fmt.Errorf("object end")
			}
			return m, nil
		case '[':
			a := []any{}
			for d.More() {
				v, err := decodeValue(d, depth+1)
				if err != nil {
					return nil, err
				}
				a = append(a, v)
			}
			end, err := d.Token()
			if end != json.Delim(']') || err != nil {
				return nil, fmt.Errorf("array end")
			}
			return a, nil
		}
		return nil, fmt.Errorf("delimiter")
	}
	return t, nil
}

// canonical matches the Python store's sorted-key UTF-8 JSON, including float spellings.
func canonical(v any) ([]byte, error) {
	var b bytes.Buffer
	err := writeCanonical(&b, v, 0)
	return b.Bytes(), err
}
func quoteJSON(b *bytes.Buffer, s string) {
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"', '\\':
			b.WriteByte('\\')
			b.WriteRune(r)
		case '\b':
			b.WriteString("\\b")
		case '\f':
			b.WriteString("\\f")
		case '\n':
			b.WriteString("\\n")
		case '\r':
			b.WriteString("\\r")
		case '\t':
			b.WriteString("\\t")
		default:
			if r < 32 {
				fmt.Fprintf(b, "\\u%04x", r)
			} else {
				b.WriteRune(r)
			}
		}
	}
	b.WriteByte('"')
}
func pythonFloat(f float64) (string, error) {
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return "", fmt.Errorf("nonfinite number")
	}
	format := byte('f')
	a := math.Abs(f)
	if a != 0 && (a < 0.0001 || a >= 1e16) {
		format = 'e'
	}
	s := strconv.FormatFloat(f, format, -1, 64)
	if !strings.ContainsAny(s, ".e") {
		s += ".0"
	}
	return s, nil
}
func writeCanonical(b *bytes.Buffer, v any, depth int) error {
	if depth > 128 {
		return integrity("JSON exceeds the nesting limit")
	}
	switch x := v.(type) {
	case nil:
		b.WriteString("null")
	case string:
		quoteJSON(b, x)
	case bool:
		if x {
			b.WriteString("true")
		} else {
			b.WriteString("false")
		}
	case json.Number:
		s := string(x)
		if strings.ContainsAny(s, ".eE") {
			f, err := x.Float64()
			if err != nil {
				return err
			}
			s, err = pythonFloat(f)
			if err != nil {
				return err
			}
		}
		b.WriteString(s)
	case float64:
		s, err := pythonFloat(x)
		if err != nil {
			return err
		}
		b.WriteString(s)
	case int:
		b.WriteString(strconv.Itoa(x))
	case int64:
		b.WriteString(strconv.FormatInt(x, 10))
	case uint64:
		b.WriteString(strconv.FormatUint(x, 10))
	case map[string]any:
		if x == nil {
			b.WriteString("null")
			break
		}
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		b.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				b.WriteByte(',')
			}
			quoteJSON(b, k)
			b.WriteByte(':')
			if err := writeCanonical(b, x[k], depth+1); err != nil {
				return err
			}
		}
		b.WriteByte('}')
	default:
		r := reflect.ValueOf(v)
		if r.Kind() != reflect.Slice && r.Kind() != reflect.Array {
			return fmt.Errorf("unsupported JSON value")
		}
		if r.Kind() == reflect.Slice && r.IsNil() {
			b.WriteString("null")
			break
		}
		b.WriteByte('[')
		for i := 0; i < r.Len(); i++ {
			if i > 0 {
				b.WriteByte(',')
			}
			if err := writeCanonical(b, r.Index(i).Interface(), depth+1); err != nil {
				return err
			}
		}
		b.WriteByte(']')
	}
	return nil
}
func printJSON(w io.Writer, v any) error {
	data, err := canonical(v)
	if err != nil {
		return err
	}
	var out bytes.Buffer
	quoted, escaped := false, false
	for _, r := range string(data) {
		if quoted {
			out.WriteRune(r)
			if escaped {
				escaped = false
			} else if r == '\\' {
				escaped = true
			} else if r == '"' {
				quoted = false
			}
			continue
		}
		out.WriteRune(r)
		if r == '"' {
			quoted = true
		}
		if r == ',' || r == ':' {
			out.WriteByte(' ')
		}
	}
	_, err = fmt.Fprintln(w, out.String())
	return err
}
