package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"strings"

	"laneboss.io/laneboss/internal/jsontext"
	"laneboss.io/laneboss/internal/v2/api"
)

func init() {
	if err := RegisterInputValidator("guidance.select", "lb-v2-guidance", lbV2GuidanceValidateInput); err != nil {
		panic(err)
	}
}

func lbV2GuidanceValidateInput(raw json.RawMessage) error {
	_, err := lbV2GuidanceFileRequest(raw)
	return err
}

// runGuidanceSelect maps file/flag inputs to api.GuidanceRequest, then calls guidance.select.
func runGuidanceSelect(ctx context.Context, call Invocation) error {
	file := ""
	for index := 0; index < len(call.Args); index++ {
		argument := call.Args[index]
		if file != "" {
			return lbV2GuidanceInputError("duplicate or unexpected guidance argument")
		}
		switch {
		case argument == "--request":
			index++
			if index == len(call.Args) || strings.HasPrefix(call.Args[index], "-") {
				return lbV2GuidanceInputError("guidance requires a request file")
			}
			file = call.Args[index]
		case strings.HasPrefix(argument, "--request="):
			file = strings.TrimPrefix(argument, "--request=")
		default:
			return lbV2GuidanceInputError("unknown guidance argument")
		}
		if file == "" || file == "-" {
			return lbV2GuidanceInputError("guidance requires a request file")
		}
	}
	if file == "" {
		return lbV2GuidanceInputError("guidance requires --request FILE")
	}
	raw, err := ReadInput(file, api.MaxFrameBytes)
	if err != nil {
		return err
	}
	if _, err := lbV2GuidanceFileRequest(raw); err != nil {
		return err
	}
	if call.Method != "guidance.select" {
		return lbV2GuidanceInputError("guidance requires its exact RPC method")
	}
	// InvokeRaw owns retained keys, proof preparation and the invocation's
	// shared socket. An explicit Client is borrowed and is already open.
	return call.InvokeRaw(ctx, raw)
}

func lbV2GuidanceInputError(message string) *api.Error {
	return &api.Error{
		Code: api.CodeInvalid, Owner: "lb-v2-guidance", Message: message,
		Instead: "Use guidance select --config NAME --request FILE with a committed task reference.",
	}
}

func lbV2GuidanceID(value string) bool {
	if len(value) == 0 || len(value) > 128 {
		return false
	}
	for _, char := range value {
		if !(char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' ||
			char >= '0' && char <= '9' || char == '-' || char == '_') {
			return false
		}
	}
	return true
}

func lbV2GuidanceFileRequest(raw []byte) (api.GuidanceRequest, error) {
	var result api.GuidanceRequest
	if len(raw) > api.MaxFrameBytes || !jsontext.ValidUnicode(raw) {
		return result, lbV2GuidanceInputError("invalid or oversized guidance JSON")
	}
	outer, err := lbV2GuidanceObject(raw, "target", "logical_turn_id", "task")
	if err != nil {
		return result, err
	}
	if _, err := lbV2GuidanceObject(outer["target"], "life_id", "run"); err != nil {
		return result, err
	}
	if _, err := lbV2GuidanceObject(outer["task"], "id", "sha256", "bytes", "class"); err != nil {
		return result, err
	}
	if err := json.Unmarshal(raw, &result); err != nil {
		return result, lbV2GuidanceInputError("invalid guidance JSON field types")
	}
	if !lbV2GuidanceID(string(result.Target.LifeID)) || !lbV2GuidanceID(string(result.LogicalTurnID)) ||
		result.Target.Run == 0 || result.Target.Run > 1<<53-1 ||
		!lbV2GuidanceID(string(result.Task.ID)) || result.Task.Class != "task" ||
		result.Task.Bytes < 0 || result.Task.Bytes > api.MaxObjectBytes ||
		len(result.Task.SHA256) != 64 || strings.IndexFunc(string(result.Task.SHA256), func(char rune) bool {
		return !(char >= '0' && char <= '9' || char >= 'a' && char <= 'f')
	}) != -1 {
		return result, lbV2GuidanceInputError("invalid guidance target or task reference")
	}
	return result, nil
}

func lbV2GuidanceObject(raw []byte, fields ...string) (map[string]json.RawMessage, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	if token, err := decoder.Token(); err != nil || token != json.Delim('{') {
		return nil, lbV2GuidanceInputError("guidance request requires JSON objects")
	}
	values := make(map[string]json.RawMessage, len(fields))
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return nil, lbV2GuidanceInputError("malformed guidance request")
		}
		name, ok := token.(string)
		if !ok {
			return nil, lbV2GuidanceInputError("malformed guidance JSON field")
		}
		if _, duplicate := values[name]; duplicate {
			return nil, lbV2GuidanceInputError("duplicate guidance JSON field")
		}
		known := false
		for _, field := range fields {
			known = known || name == field
		}
		if !known {
			return nil, lbV2GuidanceInputError("unknown guidance JSON field")
		}
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return nil, lbV2GuidanceInputError("invalid or null guidance JSON field")
		}
		values[name] = value
	}
	if token, err := decoder.Token(); err != nil || token != json.Delim('}') {
		return nil, lbV2GuidanceInputError("malformed guidance JSON object")
	}
	if _, err := decoder.Token(); err != io.EOF || len(values) != len(fields) {
		return nil, lbV2GuidanceInputError("missing guidance JSON field or trailing data")
	}
	return values, nil
}
