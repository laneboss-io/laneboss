package orgdiscord

import (
	"bytes"
	"encoding/json"
	"fmt"
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

func runProbe(args []string, stdout, stderr io.Writer) int {
	result, err := probe(args, stderr)
	if err != nil {
		fmt.Fprintln(stderr, "laneboss org channel: "+err.Error())
		return 2
	}
	if err := writeJSON(stdout, result); err != nil {
		fmt.Fprintln(stderr, "cannot write Discord probe result")
		return 2
	}
	return 0
}

func probe(args []string, stderr io.Writer) (any, error) {
	if len(args) < 2 {
		return nil, refused("probe requires an operation and ORG")
	}
	operation, org := args[0], args[1]
	if operation != "validate" && operation != "read" && operation != "event" && operation != "line" {
		return nil, refused("unknown Discord probe operation")
	}
	messagePath, namesPath := "", ""
	for i := 2; i < len(args); i += 2 {
		if i+1 >= len(args) {
			return nil, refused("Discord probe option requires a file")
		}
		switch args[i] {
		case "--message":
			messagePath = args[i+1]
		case "--channel-names":
			namesPath = args[i+1]
		default:
			return nil, refused("unrecognized Discord probe option")
		}
	}
	if operation == "validate" {
		failures := ValidateOrgChannels(org)
		return map[string]any{"valid": len(failures) == 0, "failures": failures}, nil
	}
	roles, err := ReadRoles(org, false)
	if err != nil {
		return nil, err
	}
	if operation == "read" {
		result := map[string]any{}
		for name, role := range roles {
			result[name] = role.document()
		}
		return result, nil
	}
	if messagePath == "" {
		return nil, refused("Discord event probe requires --message")
	}
	message, err := readProbeJSON(messagePath, "Discord message file")
	if err != nil {
		return nil, err
	}
	var names map[string]any
	if namesPath != "" {
		value, err := readProbeJSON(namesPath, "Discord channel names file")
		if err != nil {
			return nil, err
		}
		var ok bool
		names, ok = value.(map[string]any)
		if !ok {
			return nil, refused("Discord channel names file must contain an object")
		}
	}
	if operation == "line" {
		return EventJSONLine(message, roles, names, stderr)
	}
	return MessageToEvent(message, roles, names, stderr), nil
}
