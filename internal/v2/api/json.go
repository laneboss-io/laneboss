package api

import (
	"bytes"
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
	"unicode/utf16"
	"unicode/utf8"
)

// DecodeObject enforces the frozen field map before Go's decoder can discard
// duplicate/unknown keys, absent required fields or explicit nulls. Diagnostics
// deliberately contain no input bytes. Semantic authorization stays in modules.
// A fixed Go array requires exactly its declared number of recursively typed
// elements; encoding/json's padding/truncation is never a schema decision.
func DecodeObject(data []byte, target any) error {
	return DecodeObjectFrame(data, target, JSONFrameObject)
}

// DecodeObjectFrame adds only a closed diagnostic label, never authority or a
// different validation policy. All successful bytes use the same strict path.
func DecodeObjectFrame(data []byte, target any, frame JSONFrameKind) error {
	typeOf := reflect.TypeOf(target)
	value, err := jsonValue(data)
	if err != nil {
		return describeJSONShape(typeOf, locateJSONSyntax(data, typeOf, err), frame)
	}
	if _, ok := value.(map[string]any); !ok {
		return describeJSONShape(typeOf, shapeProblem("$", "type"), frame)
	}
	if typeOf == nil || typeOf.Kind() != reflect.Pointer || reflect.ValueOf(target).IsNil() {
		return &Error{Code: CodeIntegrity, Message: "JSON destination is not a pointer", Instead: "Repair the typed handler."}
	}
	if err := checkShape(value, typeOf.Elem()); err != nil {
		return describeJSONShape(typeOf, err, frame)
	}
	if err := json.Unmarshal(data, target); err != nil {
		return describeJSONShape(typeOf, shapeProblem("$", "bounds"), frame)
	}
	return nil
}

// DecodeValueFrame is DecodeObjectFrame for a typed non-object root (a private helper result that is a
// list or a boolean): the same strict bytes, shape and bounds checks, without the object-root rule.
func DecodeValueFrame(data []byte, target any, frame JSONFrameKind) error {
	typeOf := reflect.TypeOf(target)
	value, err := jsonValue(data)
	if err != nil {
		return describeJSONShape(typeOf, locateJSONSyntax(data, typeOf, err), frame)
	}
	if typeOf == nil || typeOf.Kind() != reflect.Pointer || reflect.ValueOf(target).IsNil() {
		return &Error{Code: CodeIntegrity, Message: "JSON destination is not a pointer", Instead: "Repair the typed handler."}
	}
	if err := checkShape(value, typeOf.Elem()); err != nil {
		return describeJSONShape(typeOf, err, frame)
	}
	if err := json.Unmarshal(data, target); err != nil {
		return describeJSONShape(typeOf, shapeProblem("$", "bounds"), frame)
	}
	return nil
}

func invalidJSON() *Error {
	return &Error{Code: CodeInvalid, Message: "invalid JSON object or field shape", Instead: "Use the exact documented request fields and bounded UTF-8 JSON."}
}

func jsonValue(data []byte) (any, error) {
	return jsonValueBound(data, MaxFrameBytes)
}

func jsonValueBound(data []byte, limit int) (any, error) {
	if len(data) == 0 {
		return nil, shapeProblem("$", "empty")
	}
	if len(data) > limit {
		return nil, shapeProblem("$", "frame_limit")
	}
	if !utf8.Valid(data) {
		return nil, shapeProblem("$", "utf8")
	}
	if !validSurrogates(data) {
		return nil, shapeProblem("$", "surrogate")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	value, err := readJSONValue(decoder, 0)
	if err != nil {
		return nil, err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return nil, shapeProblem("$", "trailing")
	}
	return value, nil
}

func readJSONValue(decoder *json.Decoder, depth int) (any, error) {
	if depth > 64 {
		return nil, shapeProblem("$", "depth")
	}
	token, err := decoder.Token()
	if err != nil {
		return nil, shapeProblem("$", "syntax")
	}
	delim, compound := token.(json.Delim)
	if !compound {
		if number, ok := token.(json.Number); ok {
			f, err := strconv.ParseFloat(string(number), 64)
			if err != nil || math.IsInf(f, 0) || math.IsNaN(f) {
				return nil, shapeProblem("$", "nonfinite")
			}
		}
		return token, nil
	}
	switch delim {
	case '{':
		object := make(map[string]any)
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return nil, shapeProblem("$", "syntax")
			}
			key, ok := keyToken.(string)
			if !ok {
				return nil, shapeProblem("$", "syntax")
			}
			if _, exists := object[key]; exists {
				return nil, shapeProblem("$", "duplicate")
			}
			value, err := readJSONValue(decoder, depth+1)
			if err != nil {
				return nil, err
			}
			object[key] = value
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim('}') {
			return nil, shapeProblem("$", "syntax")
		}
		return object, nil
	case '[':
		array := make([]any, 0)
		for decoder.More() {
			value, err := readJSONValue(decoder, depth+1)
			if err != nil {
				return nil, err
			}
			array = append(array, value)
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim(']') {
			return nil, shapeProblem("$", "syntax")
		}
		return array, nil
	default:
		return nil, shapeProblem("$", "syntax")
	}
}

// encoding/json replaces unpaired UTF-16 escapes. Reject them before decoding
// so a hash or stored source never silently describes different scalar values.
func validSurrogates(data []byte) bool {
	for i := 0; i < len(data); i++ {
		if data[i] != '\\' {
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
		code, err := strconv.ParseUint(string(data[i+1:i+5]), 16, 16)
		if err != nil {
			return false
		}
		i += 4
		if code >= 0xdc00 && code <= 0xdfff {
			return false
		}
		if code < 0xd800 || code > 0xdbff {
			continue
		}
		if i+6 >= len(data) || data[i+1] != '\\' || data[i+2] != 'u' {
			return false
		}
		low, err := strconv.ParseUint(string(data[i+3:i+7]), 16, 16)
		if err != nil || low < 0xdc00 || low > 0xdfff {
			return false
		}
		i += 6
	}
	return true
}

func checkShape(value any, target reflect.Type) error {
	return checkShapeAt(value, target, "$")
}

func checkShapeAt(value any, target reflect.Type, path string) error {
	if value == nil {
		return shapeProblem(path, "null")
	}
	if target == reflect.TypeFor[json.RawMessage]() {
		return nil
	}
	if target.Kind() == reflect.Pointer {
		return checkShapeAt(value, target.Elem(), path)
	}
	switch target.Kind() {
	case reflect.Struct:
		object, ok := value.(map[string]any)
		if !ok {
			return shapeProblem(path, "type")
		}
		known := make(map[string]bool)
		for i := 0; i < target.NumField(); i++ {
			field := target.Field(i)
			tag := strings.Split(field.Tag.Get("json"), ",")
			if !field.IsExported() || tag[0] == "-" {
				continue
			}
			name := tag[0]
			if name == "" {
				name = field.Name
			}
			known[name] = true
			member, exists := object[name]
			optional := false
			for _, option := range tag[1:] {
				optional = optional || option == "omitempty"
			}
			if !exists && optional {
				continue
			}
			child := jsonFieldPath(path, name)
			if !exists {
				return shapeProblem(child, "missing")
			}
			if err := checkShapeAt(member, field.Type, child); err != nil {
				return err
			}
		}
		for name := range object {
			if !known[name] {
				return shapeProblem(path+".*", "unknown")
			}
		}
	case reflect.Array:
		array, ok := value.([]any)
		if !ok {
			return shapeProblem(path, "type")
		}
		if len(array) != target.Len() {
			return shapeProblem(path, "length")
		}
		for _, member := range array {
			if err := checkShapeAt(member, target.Elem(), path+"[]"); err != nil {
				return err
			}
		}
	case reflect.Slice:
		if target.Elem().Kind() == reflect.Uint8 {
			text, ok := value.(string)
			if !ok {
				return shapeProblem(path, "type")
			}
			decoded, err := base64.StdEncoding.Strict().DecodeString(text)
			if err != nil || base64.StdEncoding.EncodeToString(decoded) != text {
				return shapeProblem(path, "base64")
			}
			return nil
		}
		array, ok := value.([]any)
		if !ok {
			return shapeProblem(path, "type")
		}
		for _, member := range array {
			if err := checkShapeAt(member, target.Elem(), path+"[]"); err != nil {
				return err
			}
		}
	case reflect.String:
		if _, ok := value.(string); !ok {
			return shapeProblem(path, "type")
		}
	case reflect.Bool:
		if _, ok := value.(bool); !ok {
			return shapeProblem(path, "type")
		}
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		number, ok := value.(json.Number)
		if !ok {
			return shapeProblem(path, "type")
		}
		integer, err := strconv.ParseInt(string(number), 10, 64)
		if err != nil || integer > 1<<53-1 || integer < -(1<<53-1) {
			return shapeProblem(path, "range")
		}
		if target.Kind() >= reflect.Uint {
			if _, err := strconv.ParseUint(string(number), 10, target.Bits()); err != nil {
				return shapeProblem(path, "range")
			}
		} else if _, err := strconv.ParseInt(string(number), 10, target.Bits()); err != nil {
			return shapeProblem(path, "range")
		}
	case reflect.Float32, reflect.Float64:
		number, ok := value.(json.Number)
		if !ok {
			return shapeProblem(path, "type")
		}
		if _, err := strconv.ParseFloat(string(number), target.Bits()); err != nil {
			return shapeProblem(path, "range")
		}
	default:
		return shapeProblem(path, "unsupported")
	}
	return nil
}

// CanonicalJSON implements RFC 8785's scalar encoding and UTF-16 member order.
// The original bytes remain the caller's evidence; this is for digests only.
func CanonicalJSON(data []byte) ([]byte, error) {
	return canonicalJSONFrame(data, JSONFrameCanonical)
}

func canonicalJSONFrame(data []byte, frame JSONFrameKind) ([]byte, error) {
	value, err := jsonValue(data)
	if err != nil {
		return nil, describeJSONShape(nil, err, frame)
	}
	return appendCanonical(nil, value), nil
}

// ValidateObjectJSON checks retained object/state bytes with the same duplicate,
// Unicode and nesting rules as RPC JSON. RPC frames retain MaxFrameBytes.
func ValidateObjectJSON(data []byte) error {
	if len(data) > MaxObjectBytes {
		return &Error{Code: CodeBudget, Message: "retained JSON exceeds its immutable object budget", Instead: "Retain complete objects within the approved storage bounds."}
	}
	_, err := jsonValueBound(data, MaxObjectBytes)
	if err != nil {
		return describeJSONShape(nil, err, JSONFrameStoredObject)
	}
	return nil
}

// CanonicalObjectJSON is JCS for retained objects, inventories and evidence.
// It does not increase the size accepted by CanonicalJSON or DecodeObject.
func CanonicalObjectJSON(data []byte) ([]byte, error) {
	if len(data) > MaxObjectBytes {
		return nil, &Error{Code: CodeBudget, Message: "retained JSON exceeds its immutable object budget", Instead: "Retain complete objects within the approved storage bounds."}
	}
	value, err := jsonValueBound(data, MaxObjectBytes)
	if err != nil {
		return nil, describeJSONShape(nil, err, JSONFrameCanonicalObject)
	}
	canonical := appendCanonical(nil, value)
	if len(canonical) > MaxObjectBytes {
		return nil, &Error{Code: CodeBudget, Message: "canonical JSON exceeds its immutable object budget", Instead: "Retain complete objects within the approved storage bounds."}
	}
	return canonical, nil
}

func appendCanonical(dst []byte, value any) []byte {
	switch value := value.(type) {
	case nil:
		return append(dst, "null"...)
	case bool:
		return strconv.AppendBool(dst, value)
	case string:
		return appendJSONString(dst, value)
	case json.Number:
		number, _ := strconv.ParseFloat(string(value), 64) // proved finite by jsonValue
		if number == 0 {
			return append(dst, '0')
		}
		format := byte('e')
		if math.Abs(number) >= 1e-6 && math.Abs(number) < 1e21 {
			format = 'f'
		}
		text := strconv.FormatFloat(number, format, -1, 64)
		if index := strings.IndexByte(text, 'e'); index >= 0 {
			exponent, _ := strconv.Atoi(text[index+1:])
			text = text[:index+1]
			if exponent >= 0 {
				text += "+"
			}
			text += strconv.Itoa(exponent)
		}
		return append(dst, text...)
	case []any:
		dst = append(dst, '[')
		for index, member := range value {
			if index > 0 {
				dst = append(dst, ',')
			}
			dst = appendCanonical(dst, member)
		}
		return append(dst, ']')
	case map[string]any:
		keys := make([]string, 0, len(value))
		for key := range value {
			keys = append(keys, key)
		}
		sort.Slice(keys, func(i, j int) bool {
			left, right := utf16.Encode([]rune(keys[i])), utf16.Encode([]rune(keys[j]))
			for k := 0; k < len(left) && k < len(right); k++ {
				if left[k] != right[k] {
					return left[k] < right[k]
				}
			}
			return len(left) < len(right)
		})
		dst = append(dst, '{')
		for index, key := range keys {
			if index > 0 {
				dst = append(dst, ',')
			}
			dst = appendJSONString(dst, key)
			dst = append(dst, ':')
			dst = appendCanonical(dst, value[key])
		}
		return append(dst, '}')
	}
	panic("unreachable JSON type")
}

func appendJSONString(dst []byte, value string) []byte {
	const digits = "0123456789abcdef"
	dst = append(dst, '"')
	for _, r := range value {
		switch r {
		case '"', '\\':
			dst = append(dst, '\\', byte(r))
		case '\b':
			dst = append(dst, '\\', 'b')
		case '\f':
			dst = append(dst, '\\', 'f')
		case '\n':
			dst = append(dst, '\\', 'n')
		case '\r':
			dst = append(dst, '\\', 'r')
		case '\t':
			dst = append(dst, '\\', 't')
		default:
			if r < 0x20 {
				dst = append(dst, '\\', 'u', '0', '0', digits[r>>4], digits[r&15])
			} else {
				dst = utf8.AppendRune(dst, r)
			}
		}
	}
	return append(dst, '"')
}

// RequestDigest excludes proof and request IDs and hashes the exact supplied
// intent fields without applying defaults, as required by the wire contract.
// Proof producers must set the final wire protocol/schema first;
// client.PrepareRequest applies its defaults before checking this digest.
func RequestDigest(request Request) (Digest, error) {
	body, err := json.Marshal(struct {
		Protocol string          `json:"protocol"`
		Schema   uint32          `json:"schema"`
		Config   string          `json:"config"`
		Method   Method          `json:"method"`
		Params   json.RawMessage `json:"params"`
	}{request.Protocol, request.Schema, request.Config, request.Method, request.Params})
	if err != nil {
		return "", describeJSONShape(nil, shapeProblem("$", "encoding"), JSONFrameRequestDigest)
	}
	canonical, err := canonicalJSONFrame(body, JSONFrameRequestDigest)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(canonical)
	return Digest(hex.EncodeToString(sum[:])), nil
}
