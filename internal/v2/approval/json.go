package approval

import (
	"bytes"
	"encoding/json"
	"io"
	"reflect"
	"strconv"
	"unicode/utf8"

	"laneboss.io/laneboss/internal/v2/api"
)

// DecodeJSON applies the strict wire rules to an approval object. The transport
// also enforces them; keeping them here prevents alternate module entry points
// and file clients from silently discarding fields or duplicate keys.
func DecodeJSON(data []byte, target any) error {
	if len(data) == 0 || len(data) > api.MaxFrameBytes || !utf8.Valid(data) {
		return invalid("approval JSON is empty, oversized or not UTF-8")
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
	if _, ok := value.(map[string]any); !ok {
		return invalid("approval JSON must be an object")
	}
	if _, err = decoder.Token(); err != io.EOF {
		return invalid("approval JSON has trailing data")
	}
	typeOf := reflect.TypeOf(target)
	if typeOf == nil || typeOf.Kind() != reflect.Pointer || reflect.ValueOf(target).IsNil() {
		return integrity("approval decoder requires a destination")
	}
	if err = requiredFields(value, typeOf.Elem()); err != nil {
		return err
	}
	decoder = json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(target); err != nil {
		return invalid("approval JSON has an unknown field or wrong type")
	}
	return nil
}

func readValue(decoder *json.Decoder, depth int) (any, error) {
	if depth > 32 {
		return nil, invalid("approval JSON nesting exceeds its bound")
	}
	token, err := decoder.Token()
	if err != nil {
		return nil, invalid("approval JSON is malformed")
	}
	switch token {
	case json.Delim('{'):
		object := make(map[string]any)
		for decoder.More() {
			key, err := decoder.Token()
			if err != nil {
				return nil, invalid("approval JSON key is malformed")
			}
			name, ok := key.(string)
			if !ok {
				return nil, invalid("approval JSON key must be a string")
			}
			if _, exists := object[name]; exists {
				return nil, invalid("approval JSON contains a duplicate key")
			}
			value, err := readValue(decoder, depth+1)
			if err != nil {
				return nil, err
			}
			object[name] = value
		}
		if end, err := decoder.Token(); err != nil || end != json.Delim('}') {
			return nil, invalid("approval JSON object is incomplete")
		}
		return object, nil
	case json.Delim('['):
		array := make([]any, 0)
		for decoder.More() {
			value, err := readValue(decoder, depth+1)
			if err != nil {
				return nil, err
			}
			array = append(array, value)
		}
		if end, err := decoder.Token(); err != nil || end != json.Delim(']') {
			return nil, invalid("approval JSON array is incomplete")
		}
		return array, nil
	case nil:
		return nil, invalid("approval JSON must omit optional fields instead of null")
	default:
		switch token.(type) {
		case string, bool, json.Number:
			return token, nil
		default:
			return nil, invalid("approval JSON contains an unexpected token")
		}
	}
}

func requiredFields(value any, kind reflect.Type) error {
	for kind.Kind() == reflect.Pointer {
		kind = kind.Elem()
	}
	switch kind.Kind() {
	case reflect.Struct:
		object, ok := value.(map[string]any)
		if !ok {
			return invalid("approval JSON field must be an object")
		}
		known := make(map[string]bool, kind.NumField())
		for i := 0; i < kind.NumField(); i++ {
			field := kind.Field(i)
			name, optional := jsonField(field)
			if name == "" {
				continue
			}
			known[name] = true
			child, present := object[name]
			if !present {
				if !optional {
					return invalid("approval JSON is missing a required field")
				}
				continue
			}
			if err := requiredFields(child, field.Type); err != nil {
				return err
			}
		}
		for name := range object {
			if !known[name] {
				return invalid("approval JSON contains an unknown or differently cased field")
			}
		}
	case reflect.Slice:
		array, ok := value.([]any)
		if !ok {
			return invalid("approval JSON field must be an array")
		}
		for _, child := range array {
			if err := requiredFields(child, kind.Elem()); err != nil {
				return err
			}
		}
	}
	return nil
}

// encoding/json replaces lone UTF-16 surrogates with U+FFFD. A signed intent
// cannot silently change text this way, so reject them before decoding.
func unicodeEscapes(data []byte) error {
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
			return invalid("approval JSON string escape is incomplete")
		}
		if data[i] != 'u' {
			continue
		}
		if len(data)-i < 5 {
			return invalid("approval JSON Unicode escape is incomplete")
		}
		code, err := strconv.ParseUint(string(data[i+1:i+5]), 16, 16)
		if err != nil {
			return invalid("approval JSON Unicode escape is invalid")
		}
		i += 4
		if code >= 0xdc00 && code <= 0xdfff {
			return invalid("approval JSON contains an unpaired Unicode surrogate")
		}
		if code < 0xd800 || code > 0xdbff {
			continue
		}
		if len(data)-i < 7 || data[i+1] != '\\' || data[i+2] != 'u' {
			return invalid("approval JSON contains an unpaired Unicode surrogate")
		}
		low, err := strconv.ParseUint(string(data[i+3:i+7]), 16, 16)
		if err != nil || low < 0xdc00 || low > 0xdfff {
			return invalid("approval JSON contains an invalid Unicode surrogate pair")
		}
		i += 6
	}
	return nil
}

func jsonField(field reflect.StructField) (string, bool) {
	if field.PkgPath != "" {
		return "", false
	}
	tag := field.Tag.Get("json")
	if tag == "-" {
		return "", false
	}
	name, optional := tag, false
	for i, c := range tag {
		if c == ',' {
			name, optional = tag[:i], tag[i:] == ",omitempty"
			break
		}
	}
	if name == "" {
		name = field.Name
	}
	return name, optional
}
