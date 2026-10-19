package templates

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"reflect"
	"strconv"
	"strings"

	"laneboss.io/laneboss/internal/jsontext"
	"laneboss.io/laneboss/internal/v2/api"
)

// DecodeJSON validates this feature's file/RPC body. It does not replace the
// transport's envelope checks. Required fields, case, duplicate keys, null,
// Unicode and exact integers are checked before decoding into the frozen type.
func DecodeJSON(data []byte, destination any) error {
	target := reflect.ValueOf(destination)
	if !target.IsValid() || target.Kind() != reflect.Pointer || target.IsNil() || target.Elem().Kind() != reflect.Struct {
		return invalid("JSON destination must be a typed object")
	}
	if len(data) == 0 || len(data) > api.MaxFrameBytes || !jsontext.ValidUnicode(data) {
		return invalid("JSON input exceeds the frame bound or has invalid Unicode")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := walkJSON(decoder, 0); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return invalid("JSON input must contain exactly one object")
	}
	if err := checkShape(data, target.Elem().Type()); err != nil {
		return err
	}
	if err := json.Unmarshal(data, destination); err != nil {
		return invalid("JSON input does not match the frozen request or response type")
	}
	return nil
}

func walkJSON(decoder *json.Decoder, depth int) error {
	if depth > 32 {
		return invalid("JSON input exceeds the nesting bound")
	}
	token, err := decoder.Token()
	if err != nil {
		return invalid("malformed JSON input")
	}
	if token == nil {
		return invalid("explicit null is not a frozen field value")
	}
	delimiter, compound := token.(json.Delim)
	if !compound {
		return nil
	}
	switch delimiter {
	case '{':
		seen := map[string]bool{}
		for decoder.More() {
			key, err := decoder.Token()
			if err != nil {
				return invalid("malformed JSON object")
			}
			name, ok := key.(string)
			if !ok || seen[name] {
				return invalid("JSON object has a duplicate or invalid field")
			}
			seen[name] = true
			if err := walkJSON(decoder, depth+1); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim('}') {
			return invalid("malformed JSON object ending")
		}
	case '[':
		for decoder.More() {
			if err := walkJSON(decoder, depth+1); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim(']') {
			return invalid("malformed JSON array ending")
		}
	default:
		return invalid("unexpected JSON delimiter")
	}
	return nil
}

func checkShape(data json.RawMessage, target reflect.Type) error {
	if target.Kind() == reflect.Pointer {
		return checkShape(data, target.Elem())
	}
	switch target.Kind() {
	case reflect.Struct:
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(data, &fields); err != nil || fields == nil {
			return invalid("a typed JSON object is required")
		}
		known := map[string]bool{}
		for index := 0; index < target.NumField(); index++ {
			field := target.Field(index)
			tag := strings.Split(field.Tag.Get("json"), ",")
			if field.PkgPath != "" || tag[0] == "-" {
				continue
			}
			name := tag[0]
			if name == "" {
				name = field.Name
			}
			known[name] = true
			value, present := fields[name]
			optional := len(tag) > 1 && tag[1] == "omitempty"
			if !present {
				if optional {
					continue
				}
				return invalid("JSON input is missing a required field")
			}
			if err := checkShape(value, field.Type); err != nil {
				return err
			}
		}
		for name := range fields {
			if !known[name] {
				return invalid("JSON input has an unknown or wrongly cased field")
			}
		}
	case reflect.Slice:
		if target.Elem().Kind() == reflect.Uint8 {
			var encoded string
			if err := json.Unmarshal(data, &encoded); err != nil {
				return invalid("bytes must be canonical base64")
			}
			decoded, err := base64.StdEncoding.Strict().DecodeString(encoded)
			if err != nil || base64.StdEncoding.EncodeToString(decoded) != encoded {
				return invalid("bytes must be canonical base64")
			}
			return nil
		}
		var rows []json.RawMessage
		if err := json.Unmarshal(data, &rows); err != nil || rows == nil {
			return invalid("array fields must be arrays")
		}
		for _, row := range rows {
			if err := checkShape(row, target.Elem()); err != nil {
				return err
			}
		}
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		value, err := strconv.ParseInt(string(data), 10, 64)
		if err != nil || value < 0 || value > maxGeneration {
			return invalid("integer is outside the exact JSON range")
		}
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		value, err := strconv.ParseUint(string(data), 10, 64)
		if err != nil || value > maxGeneration {
			return invalid("integer is outside the exact JSON range")
		}
	}
	return nil
}
