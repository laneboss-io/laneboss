// Package wire implements the closed v2 JSON and framing rules. It has no
// filesystem, identity or state authority.
package wire

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"math"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"
	"unicode/utf8"

	"laneboss.io/laneboss/internal/v2/api"
)

const maxInteger = uint64(1<<53 - 1)

func Invalid(message string) *api.Error {
	return &api.Error{Code: api.CodeInvalid, Message: message,
		Instead: "Correct the bounded schema-2 file input and retry."}
}

// Parse rejects duplicate members at every depth, malformed Unicode (including
// isolated escaped surrogates), and multiple top-level values before decoding.
func Parse(data []byte) (any, error) {
	if len(data) == 0 || len(data) > api.MaxFrameBytes || !utf8.Valid(data) || !validSurrogates(data) {
		return nil, Invalid("invalid JSON bytes or size")
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	v, err := parseValue(d, 0)
	if err != nil {
		return nil, err
	}
	if _, err := d.Token(); err != io.EOF {
		return nil, Invalid("trailing JSON data")
	}
	return v, nil
}

func parseValue(d *json.Decoder, depth int) (any, error) {
	if depth > 64 {
		return nil, Invalid("JSON nesting exceeds limit")
	}
	token, err := d.Token()
	if err != nil {
		return nil, Invalid("malformed JSON")
	}
	switch t := token.(type) {
	case json.Delim:
		switch t {
		case '{':
			object := make(map[string]any)
			for d.More() {
				key, err := d.Token()
				if err != nil {
					return nil, Invalid("malformed JSON member")
				}
				name, ok := key.(string)
				if !ok {
					return nil, Invalid("invalid JSON member")
				}
				if _, exists := object[name]; exists {
					return nil, Invalid("duplicate JSON member")
				}
				value, err := parseValue(d, depth+1)
				if err != nil {
					return nil, err
				}
				object[name] = value
			}
			end, err := d.Token()
			if err != nil || end != json.Delim('}') {
				return nil, Invalid("unterminated JSON object")
			}
			return object, nil
		case '[':
			array := make([]any, 0)
			for d.More() {
				value, err := parseValue(d, depth+1)
				if err != nil {
					return nil, err
				}
				array = append(array, value)
			}
			end, err := d.Token()
			if err != nil || end != json.Delim(']') {
				return nil, Invalid("unterminated JSON array")
			}
			return array, nil
		}
		return nil, Invalid("unexpected JSON delimiter")
	case json.Number:
		f, err := strconv.ParseFloat(string(t), 64)
		if err != nil || math.IsInf(f, 0) || math.IsNaN(f) {
			return nil, Invalid("nonfinite JSON number")
		}
	}
	return token, nil
}

// encoding/json replaces unpaired surrogates with U+FFFD; JCS must refuse them.
func validSurrogates(data []byte) bool {
	inString := false
	for i := 0; i < len(data); i++ {
		if data[i] == '"' {
			inString = !inString
			continue
		}
		if !inString || data[i] != '\\' {
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
		u, err := strconv.ParseUint(string(data[i+1:i+5]), 16, 16)
		if err != nil {
			return false
		}
		i += 4
		if u >= 0xdc00 && u <= 0xdfff {
			return false
		}
		if u >= 0xd800 && u <= 0xdbff {
			if i+6 >= len(data) || data[i+1] != '\\' || data[i+2] != 'u' {
				return false
			}
			low, err := strconv.ParseUint(string(data[i+3:i+7]), 16, 16)
			if err != nil || low < 0xdc00 || low > 0xdfff {
				return false
			}
			i += 6
		}
	}
	return !inString
}

// Decode validates exact member names and required fields recursively; the Go
// decoder alone accepts case-insensitive field aliases and missing zero fields.
func Decode(data []byte, out any) error {
	v, err := Parse(data)
	if err != nil {
		return err
	}
	t := reflect.TypeOf(out)
	if t == nil || t.Kind() != reflect.Pointer || reflect.ValueOf(out).IsNil() {
		return Invalid("decoder requires a typed destination")
	}
	if err := shape(v, t.Elem(), ""); err != nil {
		return err
	}
	if err := json.Unmarshal(data, out); err != nil {
		return Invalid("JSON value outside field bounds")
	}
	return nil
}

var rawType = reflect.TypeFor[json.RawMessage]()

// operationEventSchema keeps the public request digest optional for internal
// operations. An explicitly present digest still receives normal SHA checks.
// The shared API DTO remains readable through Decode with the same field names.
type operationEventSchema struct {
	Operation     api.Operation `json:"operation"`
	RequestSHA256 api.Digest    `json:"request_sha256,omitempty"`
}

func EncodeOperationEvent(event api.OperationEvent) ([]byte, error) {
	return json.Marshal(operationEventSchema(event))
}

func shape(value any, t reflect.Type, field string) error {
	if value == nil {
		return Invalid("explicit null is not supported")
	}
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if t == reflect.TypeFor[api.OperationEvent]() {
		t = reflect.TypeFor[operationEventSchema]()
	}
	if t == rawType {
		return nil // The closed discriminant is checked by the envelope validator.
	}
	switch t.Kind() {
	case reflect.Struct:
		object, ok := value.(map[string]any)
		if !ok {
			return Invalid("expected a JSON object")
		}
		known := make(map[string]bool)
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			tag := strings.Split(f.Tag.Get("json"), ",")
			if tag[0] == "-" || !f.IsExported() {
				continue
			}
			name := tag[0]
			if name == "" {
				name = f.Name
			}
			known[name] = true
			v, present := object[name]
			if !present {
				if len(tag) > 1 && tag[1] == "omitempty" {
					continue
				}
				return Invalid("missing required JSON field")
			}
			if t == reflect.TypeFor[api.ResolvedRuntime]() && name == "Network" {
				if empty, err := shapeOfflineNetwork(v); err != nil {
					return err
				} else if empty {
					continue
				}
			}
			if t == reflect.TypeFor[api.MarkRequest]() && name == "review" {
				if handled, err := shapeAbandonedMark(value); err != nil {
					return err
				} else if handled {
					continue
				}
			}
			if err := shape(v, f.Type, name); err != nil {
				return err
			}
			if err := enum(t.Name(), name, v); err != nil {
				return err
			}
		}
		for key := range object {
			if !known[key] {
				return Invalid("unknown JSON field")
			}
		}
		if err := objectRules(t.Name(), object); err != nil {
			return err
		}
	case reflect.Array:
		array, ok := value.([]any)
		if !ok || len(array) != t.Len() {
			return Invalid("expected exact-length JSON array")
		}
		for _, member := range array {
			if err := shape(member, t.Elem(), field); err != nil {
				return err
			}
		}
	case reflect.Slice:
		if t.Elem().Kind() == reflect.Uint8 {
			s, ok := value.(string)
			if !ok {
				return Invalid("expected canonical base64 bytes")
			}
			decoded, err := base64.StdEncoding.Strict().DecodeString(s)
			if err != nil || base64.StdEncoding.EncodeToString(decoded) != s {
				return Invalid("invalid canonical base64")
			}
			return nil
		}
		array, ok := value.([]any)
		if !ok {
			return Invalid("expected a non-null JSON array")
		}
		for _, v := range array {
			if err := shape(v, t.Elem(), field); err != nil {
				return err
			}
		}
	case reflect.String:
		s, ok := value.(string)
		if !ok {
			return Invalid("expected JSON string")
		}
		switch t {
		case reflect.TypeFor[api.ID]():
			if !ValidID(s) {
				return Invalid("invalid object ID")
			}
		case reflect.TypeFor[api.Digest]():
			if !ValidDigest(s) {
				return Invalid("invalid SHA-256 digest")
			}
		case reflect.TypeFor[api.Timestamp]():
			if _, err := time.Parse(time.RFC3339Nano, s); err != nil || !strings.HasSuffix(s, "Z") {
				return Invalid("invalid UTC timestamp")
			}
		case reflect.TypeFor[api.Driver]():
			if s != string(api.DriverClaudock) && s != string(api.DriverCodex) {
				return Invalid("unknown driver")
			}
		case reflect.TypeFor[api.ErrorCode]():
			if !validError(api.ErrorCode(s)) {
				return Invalid("unknown error code")
			}
		case reflect.TypeFor[api.Method]():
			if _, ok := api.Methods[api.Method(s)]; !ok {
				return Invalid("unknown RPC method")
			}
		case reflect.TypeFor[api.EventKind]():
			if s == "" && field == "until" {
				return nil
			}
			if _, ok := api.EventSchemas[api.EventKind(s)]; !ok {
				return Invalid("unknown event kind")
			}
		}
	case reflect.Bool:
		if _, ok := value.(bool); !ok {
			return Invalid("expected JSON boolean")
		}
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		n, ok := value.(json.Number)
		if !ok || strings.ContainsAny(string(n), ".eE+") {
			return Invalid("expected exact JSON integer")
		}
		if field == "exit_code" || field == "signal" {
			if _, err := strconv.ParseInt(string(n), 10, 32); err != nil {
				return Invalid("signed value exceeds int32")
			}
		} else if u, err := strconv.ParseUint(string(n), 10, 64); err != nil || u > maxInteger {
			return Invalid("integer exceeds safe range")
		}
	case reflect.Float32, reflect.Float64:
		if _, ok := value.(json.Number); !ok {
			return Invalid("expected finite JSON number")
		}
	default:
		return Invalid("unsupported JSON schema type")
	}
	return nil
}

func ValidID(s string) bool {
	if len(s) < 1 || len(s) > 128 {
		return false
	}
	for _, c := range []byte(s) {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

func ValidDigest(s string) bool {
	if len(s) != sha256.Size*2 {
		return false
	}
	for _, c := range []byte(s) {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

func NewID() (api.ID, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", &api.Error{Code: api.CodeUnavailable, Message: "random ID generation unavailable",
			Instead: "Repair the host random source before retrying."}
	}
	return api.ID(hex.EncodeToString(b[:])), nil
}

// Canonical implements JCS: UTF-16 member order, ECMAScript number formatting,
// and minimal JSON escaping, without Go's HTML or U+2028 escaping.
func Canonical(data []byte) ([]byte, error) {
	v, err := Parse(data)
	if err != nil {
		return nil, err
	}
	return appendCanonical(nil, v), nil
}

func appendCanonical(out []byte, v any) []byte {
	switch value := v.(type) {
	case nil:
		return append(out, "null"...)
	case bool:
		return strconv.AppendBool(out, value)
	case string:
		out = append(out, '"')
		for _, c := range value {
			switch c {
			case '"', '\\':
				out = append(out, '\\', byte(c))
			case '\b':
				out = append(out, `\b`...)
			case '\t':
				out = append(out, `\t`...)
			case '\n':
				out = append(out, `\n`...)
			case '\f':
				out = append(out, `\f`...)
			case '\r':
				out = append(out, `\r`...)
			default:
				if c < 32 {
					const hexDigits = "0123456789abcdef"
					out = append(out, '\\', 'u', '0', '0', hexDigits[c>>4], hexDigits[c&15])
				} else {
					out = utf8.AppendRune(out, c)
				}
			}
		}
		return append(out, '"')
	case json.Number:
		f, _ := strconv.ParseFloat(string(value), 64) // Parse already validated it.
		if f == 0 {
			return append(out, '0')
		}
		format := byte('f')
		if math.Abs(f) < 1e-6 || math.Abs(f) >= 1e21 {
			format = 'e'
		}
		s := strconv.FormatFloat(f, format, -1, 64)
		if i := strings.IndexByte(s, 'e'); i >= 0 {
			prefix, exponent := s[:i+2], s[i+2:]
			exponent = strings.TrimLeft(exponent, "0")
			if exponent == "" {
				exponent = "0"
			}
			s = prefix + exponent
		}
		return append(out, s...)
	case []any:
		out = append(out, '[')
		for i, item := range value {
			if i != 0 {
				out = append(out, ',')
			}
			out = appendCanonical(out, item)
		}
		return append(out, ']')
	case map[string]any:
		keys := make([]string, 0, len(value))
		for key := range value {
			keys = append(keys, key)
		}
		sort.Slice(keys, func(i, j int) bool {
			a, b := utf16.Encode([]rune(keys[i])), utf16.Encode([]rune(keys[j]))
			for k := 0; k < len(a) && k < len(b); k++ {
				if a[k] != b[k] {
					return a[k] < b[k]
				}
			}
			return len(a) < len(b)
		})
		out = append(out, '{')
		for i, key := range keys {
			if i != 0 {
				out = append(out, ',')
			}
			out = appendCanonical(out, key)
			out = append(out, ':')
			out = appendCanonical(out, value[key])
		}
		return append(out, '}')
	}
	panic("wire: unparsed JSON value")
}
