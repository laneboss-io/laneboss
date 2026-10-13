// Package eventstore implements the event store's shared, versioned disk format.
package eventstore

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode/utf16"
	"unicode/utf8"
)

type Problem struct {
	Code    int
	Message string
}

func (e *Problem) Error() string                 { return e.Message }
func Refuse(format string, args ...any) error    { return &Problem{2, fmt.Sprintf(format, args...)} }
func Integrity(format string, args ...any) error { return &Problem{3, fmt.Sprintf(format, args...)} }
func Failure(err error, stderr io.Writer) int {
	if errors.Is(err, io.ErrClosedPipe) || errors.Is(err, syscall.EPIPE) {
		return 0
	}
	var p *Problem
	if errors.As(err, &p) {
		prefix := "refused"
		if p.Code == 3 {
			prefix = "integrity problem"
		}
		fmt.Fprintln(stderr, prefix+": "+p.Message)
		return p.Code
	}
	fmt.Fprintln(stderr, "integrity problem: operation failed")
	return 3
}

// Floats are kept separately from integers: Python canonical JSON preserves .0.
type floatValue float64
type Object = map[string]any

func Parse(data []byte, what string) (any, error) {
	if !utf8.Valid(data) {
		return nil, Refuse("%s must be UTF-8 JSON", what)
	}
	if err := checkSurrogates(data); err != nil {
		return nil, err
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	v, err := readJSON(d, 0)
	if err != nil {
		var p *Problem
		if errors.As(err, &p) {
			return nil, err
		}
		return nil, Refuse("%s is not valid JSON", what)
	}
	if _, err = d.Token(); err != io.EOF {
		return nil, Refuse("%s is not valid JSON", what)
	}
	return v, nil
}

func checkSurrogates(b []byte) error {
	inString := false
	for i := 0; i < len(b); i++ {
		if b[i] == '"' {
			inString = !inString
			continue
		}
		if !inString || b[i] != '\\' {
			continue
		}
		i++
		if i >= len(b) || b[i] != 'u' {
			continue
		}
		if i+4 >= len(b) {
			return Refuse("text must be valid Unicode without unpaired surrogates")
		}
		n, err := strconv.ParseUint(string(b[i+1:i+5]), 16, 16)
		if err != nil {
			continue
		}
		i += 4
		if n >= 0xd800 && n <= 0xdbff {
			if i+6 >= len(b) || b[i+1] != '\\' || b[i+2] != 'u' {
				return Refuse("text must be valid Unicode without unpaired surrogates")
			}
			low, e := strconv.ParseUint(string(b[i+3:i+7]), 16, 16)
			if e != nil || low < 0xdc00 || low > 0xdfff {
				return Refuse("text must be valid Unicode without unpaired surrogates")
			}
			i += 6
		} else if n >= 0xdc00 && n <= 0xdfff {
			return Refuse("text must be valid Unicode without unpaired surrogates")
		}
	}
	return nil
}

func readJSON(d *json.Decoder, depth int) (any, error) {
	if depth > 512 {
		return nil, Refuse("JSON nesting is too deep")
	}
	t, err := d.Token()
	if err != nil {
		return nil, err
	}
	switch x := t.(type) {
	case json.Delim:
		if x == '{' {
			m := Object{}
			for d.More() {
				k, e := d.Token()
				if e != nil {
					return nil, e
				}
				key, ok := k.(string)
				if !ok {
					return nil, Refuse("JSON is not valid")
				}
				if _, ok = m[key]; ok {
					return nil, Refuse("JSON contains a duplicate field")
				}
				v, e := readJSON(d, depth+1)
				if e != nil {
					return nil, e
				}
				m[key] = v
			}
			end, e := d.Token()
			if e != nil || end != json.Delim('}') {
				return nil, Refuse("JSON is not valid")
			}
			return m, nil
		}
		if x == '[' {
			v := []any{}
			for d.More() {
				item, e := readJSON(d, depth+1)
				if e != nil {
					return nil, e
				}
				v = append(v, item)
			}
			end, e := d.Token()
			if e != nil || end != json.Delim(']') {
				return nil, Refuse("JSON is not valid")
			}
			return v, nil
		}
		return nil, Refuse("JSON is not valid")
	case json.Number:
		literal := string(x)
		if !strings.ContainsAny(literal, ".eE") {
			if len(strings.TrimPrefix(literal, "-")) > 4300 {
				return nil, Refuse("a JSON integer has more than 4300 digits; write it as a string")
			}
			if literal == "-0" {
				literal = "0"
			}
			return json.Number(literal), nil
		}
		f, e := strconv.ParseFloat(literal, 64)
		if e != nil || math.IsNaN(f) || math.IsInf(f, 0) {
			return nil, Refuse("JSON must contain finite numbers")
		}
		a, aok := decimalForm(literal)
		b, bok := decimalForm(strconv.FormatFloat(f, 'g', -1, 64))
		if !aok || !bok || a != b {
			return nil, Refuse("a JSON number with a fraction or an exponent cannot be stored exactly; write it as an integer or a string")
		}
		return floatValue(f), nil
	default:
		return t, nil
	}
}

// Compare decimal values without constructing a power of ten from an untrusted exponent.
func decimalForm(s string) (string, bool) {
	negative := strings.HasPrefix(s, "-")
	s = strings.TrimPrefix(s, "-")
	mantissa, expText, hasExponent := strings.Cut(strings.ToLower(s), "e")
	frac := 0
	if dot := strings.IndexByte(mantissa, '.'); dot >= 0 {
		frac = len(mantissa) - dot - 1
		mantissa = mantissa[:dot] + mantissa[dot+1:]
	}
	digits := strings.TrimLeft(mantissa, "0")
	if digits == "" {
		return "0", true
	}
	exponent := int64(0)
	if hasExponent {
		var err error
		exponent, err = strconv.ParseInt(expText, 10, 64)
		if err != nil {
			return "", false
		}
	}
	trimmed := strings.TrimRight(digits, "0")
	adjustment := int64(len(digits) - len(trimmed) - frac)
	const maximumExponent int64 = 1<<63 - 1
	const minimumExponent int64 = -1 << 63
	if adjustment > 0 && exponent > maximumExponent-adjustment || adjustment < 0 && exponent < minimumExponent-adjustment {
		return "", false
	}
	exponent += adjustment
	prefix := ""
	if negative {
		prefix = "-"
	}
	return prefix + trimmed + "e" + strconv.FormatInt(exponent, 10), true
}

func Canonical(value any) string {
	var b strings.Builder
	encodeJSON(&b, value, false)
	return b.String()
}
func Output(value any, w io.Writer) error {
	var b strings.Builder
	encodeJSON(&b, value, true)
	b.WriteByte('\n')
	_, err := io.WriteString(w, b.String())
	return err
}
func encodeJSON(b *strings.Builder, v any, ascii bool) {
	switch x := v.(type) {
	case nil:
		b.WriteString("null")
	case string:
		quoteString(b, x, ascii)
	case bool:
		if x {
			b.WriteString("true")
		} else {
			b.WriteString("false")
		}
	case json.Number:
		b.WriteString(string(x))
	case floatValue:
		b.WriteString(pythonFloat(float64(x)))
	case float64:
		b.WriteString(pythonFloat(x))
	case int:
		b.WriteString(strconv.Itoa(x))
	case int64:
		b.WriteString(strconv.FormatInt(x, 10))
	case Object:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		b.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				b.WriteByte(',')
				if ascii {
					b.WriteByte(' ')
				}
			}
			quoteString(b, k, ascii)
			b.WriteByte(':')
			if ascii {
				b.WriteByte(' ')
			}
			encodeJSON(b, x[k], ascii)
		}
		b.WriteByte('}')
	case []any:
		b.WriteByte('[')
		for i, item := range x {
			if i > 0 {
				b.WriteByte(',')
				if ascii {
					b.WriteByte(' ')
				}
			}
			encodeJSON(b, item, ascii)
		}
		b.WriteByte(']')
	case []Object:
		b.WriteByte('[')
		for i, item := range x {
			if i > 0 {
				b.WriteByte(',')
				if ascii {
					b.WriteByte(' ')
				}
			}
			encodeJSON(b, item, ascii)
		}
		b.WriteByte(']')
	default:
		panic("unsupported event JSON type")
	}
}
func quoteString(b *strings.Builder, s string, ascii bool) {
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"', '\\':
			b.WriteByte('\\')
			b.WriteRune(r)
		case '\b':
			b.WriteString(`\b`)
		case '\f':
			b.WriteString(`\f`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			if r < 32 || (ascii && r >= 127) {
				if r > 0xffff {
					hi, lo := utf16.EncodeRune(r)
					fmt.Fprintf(b, `\u%04x\u%04x`, hi, lo)
				} else {
					fmt.Fprintf(b, `\u%04x`, r)
				}
			} else {
				b.WriteRune(r)
			}
		}
	}
	b.WriteByte('"')
}
func pythonFloat(f float64) string {
	s := strconv.FormatFloat(f, 'e', -1, 64)
	parts := strings.Split(s, "e")
	exponent, _ := strconv.Atoi(parts[1])
	if exponent >= -4 && exponent < 16 {
		s = strconv.FormatFloat(f, 'f', -1, 64)
		if !strings.Contains(s, ".") {
			s += ".0"
		}
		return s
	}
	return s
}
func digest(data []byte) string { h := sha256.Sum256(data); return hex.EncodeToString(h[:]) }
func randomID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return hex.EncodeToString(b), nil
}
func now() string         { return time.Now().UTC().Format("2006-01-02T15:04:05.000000Z") }
func object(v any) Object { m, _ := v.(Object); return m }
func text(v any) string   { s, _ := v.(string); return s }
func list(v any) []any    { a, _ := v.([]any); return a }
func integerValue(v any) (int64, bool) {
	switch n := v.(type) {
	case int:
		return int64(n), true
	case int64:
		return n, true
	case json.Number:
		i, e := strconv.ParseInt(string(n), 10, 64)
		return i, e == nil
	}
	return 0, false
}
func num(v any) int64     { n, _ := integerValue(v); return n }
func equal(a, b any) bool { return Canonical(a) == Canonical(b) }
