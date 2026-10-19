package claudock

import (
	"bytes"
	"encoding/json"
	"io"
	"unicode/utf8"

	"laneboss.io/laneboss/internal/v2/api"
)

const maxRecordBytes = 1024 * 1024

// Check duplicate keys before decoding into structs/maps: encoding/json's
// last-key-wins behavior must not turn a quoted/successful event into an error.
func decodeRecord(data []byte) (map[string]any, error) {
	if len(data) == 0 || len(data) > maxRecordBytes || !utf8.Valid(data) {
		return nil, failure(api.CodeIntegrity, "structured adapter input is oversized or invalid UTF-8")
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	value, err := jsonValue(d, 0)
	if err != nil {
		return nil, err
	}
	if _, err := d.Token(); err != io.EOF {
		return nil, failure(api.CodeIntegrity, "structured adapter input has trailing or malformed bytes")
	}
	document, ok := value.(map[string]any)
	if !ok {
		return nil, failure(api.CodeIntegrity, "structured adapter input must be an object")
	}
	return document, nil
}

func jsonValue(d *json.Decoder, depth int) (any, error) {
	if depth > 64 {
		return nil, failure(api.CodeIntegrity, "structured adapter input exceeds the nesting bound")
	}
	token, err := d.Token()
	if err != nil {
		return nil, failure(api.CodeIntegrity, "structured adapter input is incomplete")
	}
	delim, container := token.(json.Delim)
	if !container {
		return token, nil
	}
	switch delim {
	case '{':
		document := map[string]any{}
		for d.More() {
			key, err := d.Token()
			name, ok := key.(string)
			if err != nil || !ok {
				return nil, failure(api.CodeIntegrity, "structured adapter input has an invalid key")
			}
			if _, exists := document[name]; exists {
				return nil, failure(api.CodeIntegrity, "structured adapter input has a duplicate key")
			}
			value, err := jsonValue(d, depth+1)
			if err != nil {
				return nil, err
			}
			document[name] = value
		}
		if token, err := d.Token(); err != nil || token != json.Delim('}') {
			return nil, failure(api.CodeIntegrity, "structured adapter object is incomplete")
		}
		return document, nil
	case '[':
		array := []any{}
		for d.More() {
			value, err := jsonValue(d, depth+1)
			if err != nil {
				return nil, err
			}
			array = append(array, value)
		}
		if token, err := d.Token(); err != nil || token != json.Delim(']') {
			return nil, failure(api.CodeIntegrity, "structured adapter array is incomplete")
		}
		return array, nil
	default:
		return nil, failure(api.CodeIntegrity, "structured adapter input has an unexpected delimiter")
	}
}

func decodeExact(data []byte, destination any) error {
	if _, err := decodeRecord(data); err != nil {
		return err
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err := d.Decode(destination); err != nil {
		return failure(api.CodeIntegrity, "adapter input differs from its versioned schema")
	}
	return nil
}

func object(value any) map[string]any { result, _ := value.(map[string]any); return result }
func textValue(value any) string      { result, _ := value.(string); return result }
