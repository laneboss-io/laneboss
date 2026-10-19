package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"unicode/utf8"
)

// Diagnostics contain only compiled schema names and closed reason words.
// Unknown member names and array indexes are replaced by fixed wildcards.
type jsonShapeProblem struct{ path, reason string }

type JSONFrameKind string

const (
	JSONFrameObject          JSONFrameKind = "object"
	JSONFrameHelperRequest   JSONFrameKind = "helper_request"
	JSONFrameHelperResponse  JSONFrameKind = "helper_response"
	JSONFrameHelperResult    JSONFrameKind = "helper_result"
	JSONFrameIsolationProof  JSONFrameKind = "isolation_proof"
	JSONFrameIsolationCanary JSONFrameKind = "isolation_canary"
	JSONFrameGateInput       JSONFrameKind = "gate_input"
	JSONFrameCanonical       JSONFrameKind = "canonical_json"
	JSONFrameCanonicalObject JSONFrameKind = "canonical_object"
	JSONFrameStoredObject    JSONFrameKind = "stored_object"
	JSONFrameRequestDigest   JSONFrameKind = "request_digest"
)

func jsonFrameWord(frame JSONFrameKind) string {
	switch frame {
	case JSONFrameObject, JSONFrameHelperRequest, JSONFrameHelperResponse, JSONFrameHelperResult,
		JSONFrameIsolationProof, JSONFrameIsolationCanary, JSONFrameGateInput, JSONFrameCanonical,
		JSONFrameCanonicalObject, JSONFrameStoredObject, JSONFrameRequestDigest:
		return string(frame)
	default:
		return string(JSONFrameObject)
	}
}

func (p *jsonShapeProblem) Error() string { return "JSON schema refusal" }

func shapeProblem(path, reason string) error {
	return &jsonShapeProblem{path: path, reason: reason}
}

func jsonSchemaWord(word string) string {
	if word == "" {
		return "object"
	}
	for _, value := range word {
		if value != '_' && (value < 'a' || value > 'z') && (value < 'A' || value > 'Z') && (value < '0' || value > '9') {
			return "object"
		}
	}
	return word
}

func jsonFieldPath(parent, field string) string {
	return parent + "." + jsonSchemaWord(field)
}

func describeJSONShape(target reflect.Type, err error, frame JSONFrameKind) *Error {
	object := "object"
	for target != nil && target.Kind() == reflect.Pointer {
		target = target.Elem()
	}
	if target != nil {
		object = jsonSchemaWord(target.Name())
	}
	path, reason := "$", "syntax"
	var problem *jsonShapeProblem
	if errors.As(err, &problem) {
		path, reason = problem.path, problem.reason
	}
	return &Error{Code: CodeInvalid,
		Message: "invalid JSON object or field shape (frame=" + jsonFrameWord(frame) + "; object=" + object + "; field=" + path + "; reason=" + reason + ")",
		Instead: "Use the exact documented request fields and bounded UTF-8 JSON."}
}

func locateJSONSyntax(data []byte, target reflect.Type, err error) error {
	var primary *jsonShapeProblem
	if !errors.As(err, &primary) {
		return shapeProblem("$", "syntax")
	}
	path := "$"
	if primary.reason == "duplicate" || primary.reason == "syntax" || primary.reason == "depth" {
		var location *jsonShapeProblem
		if errors.As(diagnoseJSONSyntax(data, target), &location) && location.reason == primary.reason {
			path = location.path
		}
	}
	return shapeProblem(path, primary.reason)
}

// ValidateJSONFrame checks the complete encoded producer frame before any
// transport byte is written. It does not replace typed consumer validation.
func ValidateJSONFrame(data []byte, frame JSONFrameKind) error {
	value, err := jsonValue(data)
	if err != nil {
		return describeJSONShape(nil, err, frame)
	}
	if _, ok := value.(map[string]any); !ok {
		return describeJSONShape(nil, shapeProblem("$", "type"), frame)
	}
	return nil
}

func JSONEncodingError(frame JSONFrameKind) error {
	err := describeJSONShape(nil, shapeProblem("$", "encoding"), frame)
	err.Code = CodeIntegrity
	return err
}

// JSONFailureFacts may be used by private journals that must never log an
// error message. Only allowlisted frame/reason tokens can leave this helper.
func JSONFailureFacts(err error) (JSONFrameKind, string) {
	var typed *Error
	if !errors.As(err, &typed) || typed.Code != CodeInvalid && typed.Code != CodeIntegrity {
		return "", ""
	}
	const prefix = "invalid JSON object or field shape (frame="
	if !strings.HasPrefix(typed.Message, prefix) || !strings.HasSuffix(typed.Message, ")") {
		return "", ""
	}
	message := strings.TrimPrefix(typed.Message, prefix)
	frame, _, ok := strings.Cut(message, "; object=")
	if !ok || jsonFrameWord(JSONFrameKind(frame)) != frame {
		return "", ""
	}
	index := strings.LastIndex(message, "; reason=")
	if index < 0 {
		return "", ""
	}
	reason := strings.TrimSuffix(message[index+len("; reason="):], ")")
	switch reason {
	case "empty", "frame_limit", "utf8", "surrogate", "duplicate", "depth", "syntax", "trailing", "nonfinite", "encoding",
		"null", "type", "missing", "unknown", "length", "base64", "range", "unsupported", "bounds":
		return JSONFrameKind(frame), reason
	default:
		return "", ""
	}
}

func jsonMemberType(target reflect.Type, name string) reflect.Type {
	for target != nil && target.Kind() == reflect.Pointer {
		target = target.Elem()
	}
	if target == nil || target.Kind() != reflect.Struct || target == reflect.TypeFor[json.RawMessage]() {
		return nil
	}
	for index := 0; index < target.NumField(); index++ {
		field := target.Field(index)
		tag := strings.Split(field.Tag.Get("json"), ",")[0]
		if !field.IsExported() || tag == "-" {
			continue
		}
		if tag == "" {
			tag = field.Name
		}
		if tag == name {
			return field.Type
		}
	}
	return nil
}

// The strict parser already refused this input. This bounded second walk only
// locates a duplicate/syntax refusal using compiled field names; it cannot
// accept bytes, write a destination or replace any validation decision.
func diagnoseJSONSyntax(data []byte, target reflect.Type) error {
	if len(data) == 0 || len(data) > MaxFrameBytes || !utf8.Valid(data) || !validSurrogates(data) {
		return shapeProblem("$", "syntax")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := diagnoseJSONValue(decoder, target, "$", 0); err != nil {
		return err
	}
	return shapeProblem("$", "syntax")
}

func diagnoseJSONValue(decoder *json.Decoder, target reflect.Type, path string, depth int) error {
	if depth > 64 {
		return shapeProblem(path, "depth")
	}
	token, err := decoder.Token()
	if err != nil {
		return shapeProblem(path, "syntax")
	}
	for target != nil && target.Kind() == reflect.Pointer {
		target = target.Elem()
	}
	switch token {
	case json.Delim('{'):
		seen := make(map[string]bool)
		for decoder.More() {
			key, err := decoder.Token()
			name, ok := key.(string)
			if err != nil || !ok {
				return shapeProblem(path, "syntax")
			}
			member, child := jsonMemberType(target, name), path+".*"
			if member != nil {
				child = jsonFieldPath(path, name)
			}
			if seen[name] {
				return shapeProblem(child, "duplicate")
			}
			seen[name] = true
			if err := diagnoseJSONValue(decoder, member, child, depth+1); err != nil {
				return err
			}
		}
		if end, err := decoder.Token(); err != nil || end != json.Delim('}') {
			return shapeProblem(path, "syntax")
		}
	case json.Delim('['):
		var element reflect.Type
		if target != nil && (target.Kind() == reflect.Array || target.Kind() == reflect.Slice) {
			element = target.Elem()
		}
		for decoder.More() {
			if err := diagnoseJSONValue(decoder, element, path+"[]", depth+1); err != nil {
				return err
			}
		}
		if end, err := decoder.Token(); err != nil || end != json.Delim(']') {
			return shapeProblem(path, "syntax")
		}
	}
	return nil
}
