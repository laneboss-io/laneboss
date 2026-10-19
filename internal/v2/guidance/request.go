package guidance

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"

	"laneboss.io/laneboss/internal/jsontext"
	"laneboss.io/laneboss/internal/v2/api"
)

const maxInteger = 1<<53 - 1

func invalid(message string) *api.Error {
	return &api.Error{
		Code: api.CodeInvalid, Owner: "lb-v2-guidance", Message: message,
		Instead: "Supply the complete frozen guidance request as a JSON file.",
	}
}

func validID(id api.ID) bool {
	if len(id) == 0 || len(id) > 128 {
		return false
	}
	for _, char := range id {
		if !((char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') ||
			(char >= '0' && char <= '9') || char == '-' || char == '_') {
			return false
		}
	}
	return true
}

func validDigest(digest api.Digest) bool {
	if len(digest) != 64 {
		return false
	}
	return strings.IndexFunc(string(digest), func(char rune) bool {
		return !(char >= '0' && char <= '9' || char >= 'a' && char <= 'f')
	}) == -1
}

func validateRequest(request api.GuidanceRequest) error {
	if !validID(request.Target.LifeID) || !validID(request.LogicalTurnID) ||
		request.Target.Run == 0 || request.Target.Run > maxInteger {
		return invalid("guidance requires valid life, run and logical turn IDs")
	}
	if !validID(request.Task.ID) || !validDigest(request.Task.SHA256) ||
		request.Task.Bytes < 0 || request.Task.Bytes > api.MaxObjectBytes ||
		request.Task.Class != "task" {
		return invalid("guidance requires a bounded, committed task reference")
	}
	return nil
}

func decodeRequest(raw []byte) (api.GuidanceRequest, error) {
	var request api.GuidanceRequest
	if len(raw) > api.MaxFrameBytes || !jsontext.ValidUnicode(raw) {
		return request, invalid("guidance request is oversized or invalid UTF-8")
	}
	outer, err := object(raw, "target", "logical_turn_id", "task")
	if err != nil {
		return request, err
	}
	if _, err := object(outer["target"], "life_id", "run"); err != nil {
		return request, err
	}
	if _, err := object(outer["task"], "id", "sha256", "bytes", "class"); err != nil {
		return request, err
	}
	if err := json.Unmarshal(raw, &request); err != nil {
		return api.GuidanceRequest{}, invalid("guidance request has invalid field types")
	}
	return request, validateRequest(request)
}

// object validates the exact object shape before encoding/json can discard
// duplicate keys, nulls or missing required fields. It never echoes input.
func object(raw []byte, fields ...string) (map[string]json.RawMessage, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	start, err := decoder.Token()
	if err != nil || start != json.Delim('{') {
		return nil, invalid("guidance request requires JSON objects")
	}
	values := make(map[string]json.RawMessage, len(fields))
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return nil, invalid("malformed guidance request")
		}
		name, ok := token.(string)
		if !ok {
			return nil, invalid("malformed guidance field")
		}
		if _, duplicate := values[name]; duplicate {
			return nil, invalid("duplicate guidance field")
		}
		known := false
		for _, field := range fields {
			known = known || name == field
		}
		if !known {
			return nil, invalid("unknown guidance field")
		}
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return nil, invalid("missing or invalid guidance value")
		}
		values[name] = value
	}
	if end, err := decoder.Token(); err != nil || end != json.Delim('}') {
		return nil, invalid("malformed guidance object")
	}
	if _, err := decoder.Token(); err != io.EOF || len(values) != len(fields) {
		return nil, invalid("incomplete guidance object or trailing JSON")
	}
	return values, nil
}
