package orgdiscord

import (
	"bytes"
	"encoding/json"
	"io"
	"math"
	"math/big"
	"os"
	"strconv"
	"strings"
	"syscall"
	"unicode/utf8"
)

func writeJSON(writer io.Writer, value any) error {
	encoder := json.NewEncoder(writer)
	encoder.SetEscapeHTML(false)
	return encoder.Encode(value)
}

// Go's default JSON decoder accepts duplicate fields and repairs malformed
// Unicode. Neither is safe for Discord authority or binding documents.
func parseJSON(data []byte, label string) (any, error) {
	if !utf8.Valid(data) || !validSurrogates(data) {
		return nil, refused(label + " must be valid UTF-8 JSON")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var read func(int) (any, error)
	read = func(depth int) (any, error) {
		if depth > 128 {
			return nil, refused(label + " JSON nesting exceeds the supported limit")
		}
		token, err := decoder.Token()
		if err != nil {
			return nil, refused(label + " is not valid JSON")
		}
		if delimiter, ok := token.(json.Delim); ok {
			switch delimiter {
			case '{':
				value := map[string]any{}
				for decoder.More() {
					keyToken, err := decoder.Token()
					if err != nil {
						return nil, refused(label + " is not valid JSON")
					}
					key, ok := keyToken.(string)
					if !ok {
						return nil, refused(label + " is not valid JSON")
					}
					if _, exists := value[key]; exists {
						return nil, refused(label + " JSON contains a duplicate field")
					}
					item, err := read(depth + 1)
					if err != nil {
						return nil, err
					}
					value[key] = item
				}
				end, err := decoder.Token()
				if err != nil || end != json.Delim('}') {
					return nil, refused(label + " is not valid JSON")
				}
				return value, nil
			case '[':
				value := []any{}
				for decoder.More() {
					item, err := read(depth + 1)
					if err != nil {
						return nil, err
					}
					value = append(value, item)
				}
				end, err := decoder.Token()
				if err != nil || end != json.Delim(']') {
					return nil, refused(label + " is not valid JSON")
				}
				return value, nil
			default:
				return nil, refused(label + " is not valid JSON")
			}
		}
		if number, ok := token.(json.Number); ok {
			literal := string(number)
			if len(strings.TrimPrefix(literal, "-")) > 4300 {
				return nil, refused(label + " JSON number exceeds the digit limit")
			}
			if strings.ContainsAny(literal, ".eE") {
				if _, exponent, found := strings.Cut(strings.ToLower(literal), "e"); found {
					power, err := strconv.Atoi(exponent)
					if err != nil || power < -10000 || power > 10000 {
						return nil, refused(label + " JSON number exponent exceeds the supported limit")
					}
				}
				floating, err := strconv.ParseFloat(literal, 64)
				if err != nil || math.IsInf(floating, 0) || math.IsNaN(floating) {
					return nil, refused(label + " JSON must contain finite numbers")
				}
				original, originalOK := new(big.Rat).SetString(literal)
				roundTrip, roundTripOK := new(big.Rat).SetString(strconv.FormatFloat(floating, 'g', -1, 64))
				if !originalOK || !roundTripOK || original.Cmp(roundTrip) != 0 {
					return nil, refused(label + " JSON number cannot be stored exactly; write it as an integer or a string")
				}
			}
		}
		return token, nil
	}
	value, err := read(0)
	if err != nil {
		return nil, err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return nil, refused(label + " is not valid JSON")
	}
	return value, nil
}

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
		code, err := strconv.ParseUint(string(data[i+1:i+5]), 16, 16)
		if err != nil {
			return false
		}
		i += 4
		if code >= 0xdc00 && code <= 0xdfff {
			return false
		}
		if code >= 0xd800 && code <= 0xdbff {
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

func readProbeJSON(path, label string) (any, error) {
	handle, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, refused("cannot read " + label)
	}
	defer handle.Close()
	data, err := readHandle(handle, label, false)
	if err != nil {
		return nil, err
	}
	return parseJSON(data, label)
}
