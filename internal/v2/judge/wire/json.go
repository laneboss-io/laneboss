package wire

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"

	"laneboss.io/laneboss/internal/typesafe"
	"laneboss.io/laneboss/internal/v2/api"
)

// DecodeStrict checks the frozen required/optional/null/array rules in addition
// to rejecting duplicate keys, unknown fields, bad Unicode and trailing JSON.
func DecodeStrict(raw []byte, destination any) error {
	root, err := typesafe.Decode(raw)
	if err != nil {
		return failure(api.CodeInvalid, "request must be one strict UTF-8 JSON object")
	}
	target := reflect.ValueOf(destination)
	if target.Kind() != reflect.Pointer || target.IsNil() {
		return failure(api.CodeIntegrity, "invalid typed JSON destination")
	}
	if !shapeMatches(root, target.Elem().Type()) {
		return failure(api.CodeInvalid, "missing, null or unknown JSON field")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil || !integerBounds(target.Elem()) {
		return failure(api.CodeInvalid, "JSON value does not match the frozen type")
	}
	return nil
}

func shapeMatches(value any, t reflect.Type) bool {
	if value == nil {
		return false
	}
	if t.Kind() == reflect.Pointer {
		return shapeMatches(value, t.Elem())
	}
	if t.Kind() == reflect.Struct {
		object, ok := value.(map[string]any)
		if !ok {
			return false
		}
		known := make(map[string]bool, t.NumField())
		for i := 0; i < t.NumField(); i++ {
			field := t.Field(i)
			name, options, _ := strings.Cut(field.Tag.Get("json"), ",")
			if name == "-" {
				continue
			}
			if name == "" {
				name = field.Name
			}
			known[name] = true
			child, exists := object[name]
			if !exists && options == "omitempty" {
				continue
			}
			if !exists || !shapeMatches(child, field.Type) {
				return false
			}
		}
		for name := range object {
			if !known[name] {
				return false
			}
		}
	}
	if t.Kind() == reflect.Slice && t.Elem().Kind() == reflect.Uint8 {
		_, ok := value.(string)
		return ok
	}
	if t.Kind() == reflect.Slice {
		array, ok := value.([]any)
		if !ok {
			return false
		}
		for _, child := range array {
			if !shapeMatches(child, t.Elem()) {
				return false
			}
		}
	}
	return true
}

func integerBounds(v reflect.Value) bool {
	switch v.Kind() {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return v.Int() >= 0 && v.Int() <= maxInteger
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return v.Uint() <= maxInteger
	case reflect.Struct:
		for i := 0; i < v.NumField(); i++ {
			if !integerBounds(v.Field(i)) {
				return false
			}
		}
	case reflect.Slice, reflect.Array:
		for i := 0; i < v.Len(); i++ {
			if !integerBounds(v.Index(i)) {
				return false
			}
		}
	case reflect.Pointer:
		return v.IsNil() || integerBounds(v.Elem())
	}
	return true
}
