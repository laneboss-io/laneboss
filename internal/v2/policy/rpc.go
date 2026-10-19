package policy

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"reflect"
	"strconv"
	"unicode/utf8"

	"laneboss.io/laneboss/internal/v2/api"
)

func (s *Service) Register(registry api.Registrar) error {
	if registry == nil {
		return invalid("policy registrar is missing")
	}
	for _, route := range []struct {
		method api.Method
		handle api.Handler
	}{
		{"policy.get", handler(s.PolicyGet)},
		{"policy.evaluate", handler(s.PolicyEvaluate)},
		{"config.read", handler(s.ConfigRead)},
		{"config.validate", handler(s.ConfigValidate)},
	} {
		if err := registry.Register(route.method, route.handle); err != nil {
			return err
		}
	}
	return nil
}

func handler[Request, Response any](call func(context.Context, api.Scope, Request) (Response, error)) api.Handler {
	return func(ctx context.Context, scope api.Scope, raw json.RawMessage) (json.RawMessage, error) {
		var request Request
		if err := decode(raw, &request); err != nil {
			return nil, err
		}
		result, err := call(ctx, scope, request)
		if err != nil {
			return nil, err
		}
		data, err := json.Marshal(result)
		if err != nil {
			return nil, integrity("policy response cannot be encoded")
		}
		return data, nil
	}
}

// decode enforces the exact frozen shape, including required zero/false fields,
// duplicates and explicit null. It does not use a permissive map as the API.
func decode(raw []byte, target any) error {
	if _, empty := target.(*api.Empty); empty {
		return ValidateConfigValidateInput(raw)
	}
	// The common decoder also rejects unpaired surrogates and noncanonical
	// base64; the local range walk retains the policy's nonnegative integers.
	if err := api.DecodeObject(raw, target); err != nil {
		return err
	}
	if len(raw) == 0 || len(raw) > api.MaxFrameBytes || !utf8.Valid(raw) {
		return invalid("invalid policy request bytes")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := jsonValue(decoder, reflect.TypeOf(target).Elem()); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return invalid("trailing policy JSON")
	}
	decoder = json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return invalid("invalid typed policy request")
	}
	return nil
}

func jsonValue(decoder *json.Decoder, typ reflect.Type) error {
	if typ.Kind() == reflect.Pointer {
		typ = typ.Elem()
	}
	token, err := decoder.Token()
	if err != nil || token == nil {
		return invalid("invalid or null policy JSON value")
	}
	switch typ.Kind() {
	case reflect.Struct:
		if token != json.Delim('{') {
			return invalid("policy JSON object required")
		}
		fields, required := map[string]reflect.Type{}, map[string]bool{}
		for i := 0; i < typ.NumField(); i++ {
			field := typ.Field(i)
			tag := field.Tag.Get("json")
			name := tag
			optional := false
			for j, c := range tag {
				if c == ',' {
					name, optional = tag[:j], tag[j+1:] == "omitempty"
					break
				}
			}
			if name == "-" {
				continue
			}
			fields[name] = field.Type
			if !optional {
				required[name] = true
			}
		}
		seen := map[string]bool{}
		for decoder.More() {
			key, err := decoder.Token()
			if err != nil {
				return invalid("invalid policy JSON key")
			}
			name, ok := key.(string)
			fieldType, found := fields[name]
			if !ok || !found || seen[name] {
				return invalid("unknown or duplicate policy JSON field")
			}
			seen[name] = true
			if err := jsonValue(decoder, fieldType); err != nil {
				return err
			}
		}
		for name := range required {
			if !seen[name] {
				return invalid("missing required policy JSON field")
			}
		}
		if end, err := decoder.Token(); err != nil || end != json.Delim('}') {
			return invalid("unterminated policy JSON object")
		}
	case reflect.Slice:
		// encoding/json represents []byte with base64, all other slices as arrays.
		if typ.Elem().Kind() == reflect.Uint8 {
			if _, ok := token.(string); !ok {
				return invalid("base64 command bytes required")
			}
			return nil
		}
		if token != json.Delim('[') {
			return invalid("policy JSON array required")
		}
		for decoder.More() {
			if err := jsonValue(decoder, typ.Elem()); err != nil {
				return err
			}
		}
		if end, err := decoder.Token(); err != nil || end != json.Delim(']') {
			return invalid("unterminated policy JSON array")
		}
	default:
		if _, nested := token.(json.Delim); nested {
			return invalid("scalar policy JSON value required")
		}
		if typ.Kind() >= reflect.Int && typ.Kind() <= reflect.Uint64 {
			number, ok := token.(json.Number)
			if !ok {
				return invalid("integer policy JSON value required")
			}
			value, err := strconv.ParseInt(string(number), 10, 64)
			if err != nil || value < 0 || value > 1<<53-1 {
				return invalid("policy JSON integer outside exact range")
			}
		}
	}
	return nil
}
