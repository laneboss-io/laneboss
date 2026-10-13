package orgtree

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"strconv"
	"strings"

	"github.com/BurntSushi/toml"
)

func decodeTOML(text string) (map[string]any, error) {
	var value map[string]any
	_, err := toml.Decode(text, &value)
	return value, err
}

// Decode objects token by token so duplicate fields cannot silently replace
// policy. Keep numbers as literals, including manifest versions, without rounding.
func decodeJSON(text string) (any, error) {
	decoder := json.NewDecoder(strings.NewReader(text))
	decoder.UseNumber()
	value, err := jsonValue(decoder, 0)
	if err != nil {
		return nil, err
	}
	if _, err = decoder.Token(); err != io.EOF {
		return nil, errors.New("invalid JSON trailing data")
	}
	return value, nil
}

func jsonValue(decoder *json.Decoder, depth int) (any, error) {
	if depth > 256 {
		return nil, errors.New("JSON nesting limit exceeded")
	}
	token, err := decoder.Token()
	if err != nil {
		return nil, err
	}
	switch value := token.(type) {
	case json.Delim:
		switch value {
		case '{':
			result := make(map[string]any)
			for decoder.More() {
				keyToken, err := decoder.Token()
				if err != nil {
					return nil, err
				}
				key, ok := keyToken.(string)
				if !ok {
					return nil, errors.New("invalid JSON field")
				}
				if _, exists := result[key]; exists {
					return nil, errors.New("duplicate JSON field")
				}
				result[key], err = jsonValue(decoder, depth+1)
				if err != nil {
					return nil, err
				}
			}
			end, err := decoder.Token()
			if err != nil || end != json.Delim('}') {
				return nil, errors.New("invalid JSON object")
			}
			return result, nil
		case '[':
			result := []any{}
			for decoder.More() {
				item, err := jsonValue(decoder, depth+1)
				if err != nil {
					return nil, err
				}
				result = append(result, item)
			}
			end, err := decoder.Token()
			if err != nil || end != json.Delim(']') {
				return nil, errors.New("invalid JSON array")
			}
			return result, nil
		default:
			return nil, errors.New("invalid JSON delimiter")
		}
	case json.Number:
		literal := string(value)
		if !strings.ContainsAny(literal, ".eE") {
			if len(strings.TrimPrefix(literal, "-")) > 4300 {
				return nil, errors.New("JSON integer digit limit exceeded")
			}
		} else {
			floating, err := strconv.ParseFloat(literal, 64)
			if err != nil {
				return nil, errors.New("JSON number must be finite and exact")
			}
			// Zero with a large exponent needs no enormous power-of-ten
			// allocation. Nonzero literals that underflow are inexact.
			if floating == 0 {
				mantissa := strings.SplitN(strings.ToLower(literal), "e", 2)[0]
				if strings.Trim(mantissa, "-+.0") != "" {
					return nil, errors.New("JSON number must be finite and exact")
				}
				return value, nil
			}
			exact, ok := new(big.Rat).SetString(literal)
			roundtrip, roundOK := new(big.Rat).SetString(strconv.FormatFloat(floating, 'g', -1, 64))
			if !ok || !roundOK || exact.Cmp(roundtrip) != 0 {
				return nil, errors.New("JSON number must be finite and exact")
			}
		}
		return value, nil
	default:
		return value, nil
	}
}

func jsonText(value any, indent bool) (string, error) {
	var data bytes.Buffer
	encoder := json.NewEncoder(&data)
	encoder.SetEscapeHTML(false)
	if indent {
		encoder.SetIndent("", "  ")
	}
	if err := encoder.Encode(value); err != nil {
		return "", err
	}
	return data.String(), nil
}

// The schemas have scalar/array fields and one level of tables. Explicit field
// order keeps defaults last, so TOML additions stay in their intended table.
func encodeTOML(value map[string]any, order []string) (string, error) {
	var result strings.Builder
	write := func(key string, item any) error {
		encoded, err := jsonText(item, false)
		if err != nil {
			return errors.New("cannot encode org data")
		}
		encoded = strings.TrimSuffix(encoded, "\n")
		if items, ok := array(item); ok {
			parts := make([]string, len(items))
			for i, item := range items {
				part, err := jsonText(item, false)
				if err != nil {
					return err
				}
				parts[i] = strings.TrimSuffix(part, "\n")
			}
			encoded = "[" + strings.Join(parts, ", ") + "]"
		}
		result.WriteString(key + " = " + encoded + "\n")
		return nil
	}
	for _, key := range order {
		if item, exists := value[key]; exists {
			if _, table := item.(map[string]any); !table {
				if err := write(key, item); err != nil {
					return "", err
				}
			}
		}
	}
	for _, key := range order {
		if table, ok := value[key].(map[string]any); ok {
			result.WriteString("\n[" + key + "]\n")
			var fields []string
			if key == "secret_store" {
				fields = []string{"kind", "path"}
			} else {
				fields = instanceOrder
			}
			for _, field := range fields {
				if item, exists := table[field]; exists {
					if err := write(field, item); err != nil {
						return "", err
					}
				}
			}
		}
	}
	return result.String(), nil
}
