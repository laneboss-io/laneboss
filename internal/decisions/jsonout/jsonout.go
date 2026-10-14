// Package jsonout preserves the Python decision store's JSON representations.
// Results use json.dumps with sorted keys, ASCII escaping and default separators;
// stored metadata uses sorted keys, UTF-8 and compact separators for its hashes.
package jsonout

import (
	"encoding/json"
	"fmt"
	"math"
	"math/big"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

// Line returns one complete result line, including its trailing newline.
func Line(value any) ([]byte, error) {
	var b strings.Builder
	if err := encode(&b, value, true); err != nil {
		return nil, err
	}
	b.WriteByte('\n')
	return []byte(b.String()), nil
}

// Canonical returns the compact UTF-8 representation used for stored hashes.
func Canonical(value any) (string, error) {
	var b strings.Builder
	if err := encode(&b, value, false); err != nil {
		return "", err
	}
	return b.String(), nil
}

func encodeString(b *strings.Builder, value string, ascii bool) error {
	if !utf8.ValidString(value) {
		return fmt.Errorf("JSON text must be valid UTF-8")
	}
	b.WriteByte('"')
	for _, r := range value {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
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
	return nil
}

func encodeFloat(b *strings.Builder, value float64) error {
	if math.IsNaN(value) || math.IsInf(value, 0) {
		return fmt.Errorf("JSON must contain finite numbers")
	}
	// Python's repr uses the shortest round-trippable digits, fixed notation for
	// exponents -4 through 15, and a decimal point for integral floats.
	s := strconv.FormatFloat(value, 'g', -1, 64)
	if mantissa, exponent, ok := strings.Cut(s, "e"); ok {
		exp, err := strconv.Atoi(exponent)
		if err != nil {
			return err
		}
		if exp >= -4 && exp < 16 {
			s = strconv.FormatFloat(value, 'f', -1, 64)
		} else {
			sign := "+"
			if exp < 0 {
				sign, exp = "-", -exp
			}
			s = mantissa + "e" + sign + fmt.Sprintf("%02d", exp)
		}
	}
	if !strings.ContainsAny(s, ".e") {
		s += ".0"
	}
	b.WriteString(s)
	return nil
}

func encodeNumber(b *strings.Builder, value json.Number) error {
	s := string(value)
	if len(s) == 0 || strings.TrimSpace(s) != s || (s[0] != '-' && (s[0] < '0' || s[0] > '9')) || !json.Valid([]byte(s)) {
		return fmt.Errorf("unsupported JSON number")
	}
	if strings.ContainsAny(s, ".eE") {
		f, err := value.Float64()
		// Underflow is a finite zero, just as Python's JSON decoder produces.
		if err != nil || math.IsInf(f, 0) || math.IsNaN(f) {
			return fmt.Errorf("JSON must contain finite numbers")
		}
		return encodeFloat(b, f)
	}
	n, ok := new(big.Int).SetString(s, 10)
	if !ok {
		return fmt.Errorf("unsupported JSON number")
	}
	b.WriteString(n.String())
	return nil
}

func encode(b *strings.Builder, value any, result bool) error {
	sep, colon := ",", ":"
	if result {
		sep, colon = ", ", ": "
	}
	switch v := value.(type) {
	case nil:
		b.WriteString("null")
		return nil
	case string:
		return encodeString(b, v, result)
	case bool:
		b.WriteString(strconv.FormatBool(v))
		return nil
	case json.Number:
		return encodeNumber(b, v)
	case []byte:
		return fmt.Errorf("JSON cannot contain a binary value")
	}
	rv := reflect.ValueOf(value)
	switch rv.Kind() {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		b.WriteString(strconv.FormatInt(rv.Int(), 10))
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		b.WriteString(strconv.FormatUint(rv.Uint(), 10))
	case reflect.Float32, reflect.Float64:
		return encodeFloat(b, rv.Float())
	case reflect.Map:
		if rv.Type().Key().Kind() != reflect.String {
			return fmt.Errorf("JSON fields must be strings")
		}
		keys := rv.MapKeys()
		// UTF-8 byte order is Unicode code point order, as used by Python.
		sort.Slice(keys, func(i, j int) bool { return keys[i].String() < keys[j].String() })
		b.WriteByte('{')
		for i, key := range keys {
			if i > 0 {
				b.WriteString(sep)
			}
			if err := encodeString(b, key.String(), result); err != nil {
				return err
			}
			b.WriteString(colon)
			if err := encode(b, rv.MapIndex(key).Interface(), result); err != nil {
				return err
			}
		}
		b.WriteByte('}')
	case reflect.Slice, reflect.Array:
		b.WriteByte('[')
		for i := 0; i < rv.Len(); i++ {
			if i > 0 {
				b.WriteString(sep)
			}
			if err := encode(b, rv.Index(i).Interface(), result); err != nil {
				return err
			}
		}
		b.WriteByte(']')
	default:
		return fmt.Errorf("unsupported JSON value")
	}
	return nil
}
