// Package manifest validates inert grant and object inputs. It opens no paths
// and executes no repository content.
package manifest

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"

	"laneboss.io/laneboss/internal/v2/api"
)

const MaxInteger = uint64(1<<53 - 1)

func Invalid(message string) *api.Error {
	return &api.Error{Code: api.CodeInvalid, Message: message,
		Instead: "Correct the retained grant or object input and submit it again.",
		Owner:   "lb-v2-grants"}
}

// Decode rejects duplicate/unknown keys, missing required fields, explicit
// null, invalid Unicode, fractional/unsafe integers and trailing JSON. All
// types accepted here are the frozen grant/manifest types, not arbitrary maps.
func Decode(data []byte, target any) error {
	if len(data) == 0 || len(data) > api.MaxObjectBytes || !utf8.Valid(data) {
		return Invalid("invalid or oversized JSON input")
	}
	if err := unicodeEscapes(data); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	value, err := readValue(decoder, 0)
	if err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return Invalid("trailing JSON input")
	}
	typeOf := reflect.TypeOf(target)
	if typeOf == nil || typeOf.Kind() != reflect.Pointer || reflect.ValueOf(target).IsNil() {
		return Invalid("JSON target must be a nonnil typed pointer")
	}
	if err := shape(value, typeOf.Elem()); err != nil {
		return err
	}
	if err := json.Unmarshal(data, target); err != nil {
		return Invalid("invalid typed JSON input")
	}
	return nil
}

func readValue(decoder *json.Decoder, depth int) (any, error) {
	if depth > 64 {
		return nil, Invalid("JSON nesting exceeds the limit")
	}
	token, err := decoder.Token()
	if err != nil {
		return nil, Invalid("malformed JSON input")
	}
	switch value := token.(type) {
	case json.Delim:
		switch value {
		case '{':
			object := make(map[string]any)
			for decoder.More() {
				key, err := decoder.Token()
				if err != nil {
					return nil, Invalid("malformed JSON object")
				}
				name, ok := key.(string)
				if !ok {
					return nil, Invalid("invalid JSON object key")
				}
				if _, found := object[name]; found {
					return nil, Invalid("duplicate JSON object key")
				}
				item, err := readValue(decoder, depth+1)
				if err != nil {
					return nil, err
				}
				object[name] = item
			}
			if end, err := decoder.Token(); err != nil || end != json.Delim('}') {
				return nil, Invalid("unterminated JSON object")
			}
			return object, nil
		case '[':
			array := []any{}
			for decoder.More() {
				item, err := readValue(decoder, depth+1)
				if err != nil {
					return nil, err
				}
				array = append(array, item)
			}
			if end, err := decoder.Token(); err != nil || end != json.Delim(']') {
				return nil, Invalid("unterminated JSON array")
			}
			return array, nil
		default:
			return nil, Invalid("unexpected JSON delimiter")
		}
	case json.Number:
		// Grant, manifest and request envelopes contain integer numbers only.
		number, err := strconv.ParseUint(string(value), 10, 64)
		if err != nil || number > MaxInteger {
			return nil, Invalid("JSON integer is negative, fractional or unsafe")
		}
		return value, nil
	case string, bool, nil:
		return value, nil
	default:
		return nil, Invalid("unsupported JSON value")
	}
}

func shape(value any, t reflect.Type) error {
	if value == nil {
		return Invalid("explicit null is not permitted")
	}
	if t.Kind() == reflect.Pointer {
		return shape(value, t.Elem())
	}
	if t == reflect.TypeFor[json.RawMessage]() {
		return nil
	}
	switch t.Kind() {
	case reflect.Struct:
		object, ok := value.(map[string]any)
		if !ok {
			return Invalid("expected a JSON object")
		}
		known := make(map[string]bool)
		for i := 0; i < t.NumField(); i++ {
			field := t.Field(i)
			tag := strings.Split(field.Tag.Get("json"), ",")
			if tag[0] == "-" || field.PkgPath != "" {
				continue
			}
			name := tag[0]
			if name == "" {
				name = field.Name
			}
			known[name] = true
			item, found := object[name]
			optional := len(tag) > 1 && tag[1] == "omitempty"
			if !found {
				if !optional {
					return Invalid("required JSON field is missing")
				}
				continue
			}
			if err := shape(item, field.Type); err != nil {
				return err
			}
		}
		for name := range object {
			if !known[name] {
				return Invalid("unknown JSON field")
			}
		}
	case reflect.Slice:
		if t.Elem().Kind() == reflect.Uint8 {
			if _, ok := value.(string); !ok {
				return Invalid("expected encoded bytes")
			}
			break
		}
		array, ok := value.([]any)
		if !ok {
			return Invalid("expected a nonnull JSON array")
		}
		for _, item := range array {
			if err := shape(item, t.Elem()); err != nil {
				return err
			}
		}
	case reflect.String:
		if _, ok := value.(string); !ok {
			return Invalid("expected a JSON string")
		}
	case reflect.Bool:
		if _, ok := value.(bool); !ok {
			return Invalid("expected a JSON boolean")
		}
	case reflect.Int, reflect.Int32, reflect.Int64, reflect.Uint, reflect.Uint32, reflect.Uint64:
		if _, ok := value.(json.Number); !ok {
			return Invalid("expected a JSON integer")
		}
	default:
		return Invalid("unsupported JSON target type")
	}
	return nil
}

// unicodeEscapes prevents encoding/json from repairing lone surrogate escapes.
func unicodeEscapes(data []byte) error {
	for i := 0; i < len(data); i++ {
		if data[i] != '\\' {
			continue
		}
		i++
		if i >= len(data) || data[i] != 'u' {
			continue
		}
		if i+4 >= len(data) {
			return Invalid("invalid Unicode escape")
		}
		first, err := strconv.ParseUint(string(data[i+1:i+5]), 16, 16)
		if err != nil {
			return Invalid("invalid Unicode escape")
		}
		i += 4
		if first >= 0xdc00 && first <= 0xdfff {
			return Invalid("unpaired Unicode surrogate")
		}
		if first < 0xd800 || first > 0xdbff {
			continue
		}
		if i+6 >= len(data) || data[i+1] != '\\' || data[i+2] != 'u' {
			return Invalid("unpaired Unicode surrogate")
		}
		second, err := strconv.ParseUint(string(data[i+3:i+7]), 16, 16)
		if err != nil || second < 0xdc00 || second > 0xdfff {
			return Invalid("unpaired Unicode surrogate")
		}
		i += 6
	}
	return nil
}

// Canonical applies RFC8785 to the integer-only JSON subset used by this lane.
// Arrays keep their order. Object keys are ordered by UTF-16 code units.
func Canonical(data []byte) ([]byte, error) {
	if len(data) == 0 || len(data) > api.MaxObjectBytes || !utf8.Valid(data) {
		return nil, Invalid("invalid canonical JSON input")
	}
	if err := unicodeEscapes(data); err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	value, err := readValue(decoder, 0)
	if err != nil {
		return nil, err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return nil, Invalid("trailing canonical JSON input")
	}
	var result bytes.Buffer
	writeCanonical(&result, value)
	return result.Bytes(), nil
}

func writeCanonical(output *bytes.Buffer, value any) {
	switch v := value.(type) {
	case map[string]any:
		keys := make([]string, 0, len(v))
		for key := range v {
			keys = append(keys, key)
		}
		sort.Slice(keys, func(i, j int) bool {
			a, b := utf16.Encode([]rune(keys[i])), utf16.Encode([]rune(keys[j]))
			for n := 0; n < len(a) && n < len(b); n++ {
				if a[n] != b[n] {
					return a[n] < b[n]
				}
			}
			return len(a) < len(b)
		})
		output.WriteByte('{')
		for i, key := range keys {
			if i > 0 {
				output.WriteByte(',')
			}
			writeString(output, key)
			output.WriteByte(':')
			writeCanonical(output, v[key])
		}
		output.WriteByte('}')
	case []any:
		output.WriteByte('[')
		for i, item := range v {
			if i > 0 {
				output.WriteByte(',')
			}
			writeCanonical(output, item)
		}
		output.WriteByte(']')
	case string:
		writeString(output, v)
	case json.Number:
		output.WriteString(string(v))
	case bool:
		output.WriteString(strconv.FormatBool(v))
	case nil:
		output.WriteString("null")
	}
}

func writeString(output *bytes.Buffer, value string) {
	const digits = "0123456789abcdef"
	output.WriteByte('"')
	for _, r := range value {
		switch r {
		case '"', '\\':
			output.WriteByte('\\')
			output.WriteRune(r)
		case '\b':
			output.WriteString(`\b`)
		case '\t':
			output.WriteString(`\t`)
		case '\n':
			output.WriteString(`\n`)
		case '\f':
			output.WriteString(`\f`)
		case '\r':
			output.WriteString(`\r`)
		default:
			if r < 0x20 {
				output.WriteString(`\u00`)
				output.WriteByte(digits[byte(r)>>4])
				output.WriteByte(digits[byte(r)&15])
			} else {
				output.WriteRune(r)
			}
		}
	}
	output.WriteByte('"')
}

func Hash(data []byte) api.Digest {
	sum := sha256.Sum256(data)
	return api.Digest(hex.EncodeToString(sum[:]))
}

func HashValue(value any) (api.Digest, error) {
	data, err := json.Marshal(value)
	if err != nil {
		return "", Invalid("cannot encode typed grant data")
	}
	canonical, err := Canonical(data)
	if err != nil {
		return "", err
	}
	return Hash(canonical), nil
}
