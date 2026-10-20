package lifecycle

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"reflect"
	"strconv"
	"strings"
	"unicode/utf8"

	"laneboss.io/laneboss/internal/v2/api"
)

func bind[Q, R any](registry api.Registrar, method api.Method,
	fn func(context.Context, api.Scope, Q) (R, error)) error {
	return registry.Register(method, func(ctx context.Context, scope api.Scope,
		raw json.RawMessage) (json.RawMessage, error) {
		var request Q
		if err := decode(raw, &request); err != nil {
			return nil, err
		}
		result, err := fn(ctx, scope, request)
		if err != nil {
			return nil, failure(err)
		}
		encoded, err := json.Marshal(result)
		if err != nil {
			return nil, integrity("cannot encode lifecycle response")
		}
		return encoded, nil
	})
}

func (s *Service) Register(registry api.Registrar) error {
	if err := s.ready(); err != nil {
		return err
	}
	if absent(registry) {
		return invalid("lifecycle registrar required")
	}
	routes := []func() error{
		func() error { return bind(registry, "lane.start", s.LaneStart) },
		func() error { return bind(registry, "lane.adopt", s.LaneAdopt) },
		func() error { return bind(registry, "lane.resume", s.LaneResume) },
		func() error { return bind(registry, "lane.turn", s.LaneTurn) },
		func() error { return bind(registry, "lane.stop", s.LaneStop) },
		func() error { return bind(registry, "lane.mark", s.LaneMark) },
		func() error { return bind(registry, "lane.review", s.LaneReview) },
		func() error { return bind(registry, "lane.clean", s.LaneClean) },
		func() error { return bind(registry, "lane.archive", s.LaneArchive) },
		func() error { return bind(registry, "lane.restore", s.LaneRestore) },
		func() error { return bind(registry, "lane.status", s.LaneStatus) },
		func() error { return bind(registry, "lane.list", s.LaneList) },
		func() error { return bind(registry, "lane.check", s.LaneCheck) },
		func() error { return bind(registry, "lane.loop", s.LaneLoop) },
		func() error { return bind(registry, "lane.attach", s.LaneAttach) },
		func() error { return bind(registry, "lane.input", s.LaneInput) },
		func() error { return bind(registry, "event.tail", s.EventTail) },
	}
	for _, route := range routes {
		if err := route(); err != nil {
			return failure(err)
		}
	}
	if err := registry.RegisterStream("event.tail", func(ctx context.Context,
		scope api.Scope, raw json.RawMessage) (api.EventStream, error) {
		var request api.EventTailRequest
		if err := decode(raw, &request); err != nil {
			return nil, err
		}
		return s.OpenEvents(ctx, scope, request)
	}); err != nil {
		return failure(err)
	}
	return failure(registry.RegisterStream("lane.attach", func(ctx context.Context,
		scope api.Scope, raw json.RawMessage) (api.EventStream, error) {
		var request api.AttachRequest
		if err := decode(raw, &request); err != nil {
			return nil, err
		}
		return s.OpenAttach(ctx, scope, request)
	}))
}

// The transport validates the envelope too. This decoder also protects direct
// module use from duplicate keys, nulls, omitted fields and trailing documents.
// DecodeRequest is also used by this lane's file-backed CLI adapter. It performs
// structural validation only; authentication and provenance remain service work.
func DecodeRequest(raw []byte, destination any) error {
	return decode(raw, destination)
}

func decode(raw []byte, destination any) error {
	if len(raw) == 0 || len(raw) > api.MaxFrameBytes || !utf8.Valid(raw) || !unicodeEscapes(raw) {
		return invalid("invalid lifecycle request bytes")
	}
	tokens := json.NewDecoder(bytes.NewReader(raw))
	tokens.UseNumber()
	if err := tokensValue(tokens, 0); err != nil {
		return err
	}
	if _, err := tokens.Token(); err != io.EOF {
		return invalid("trailing lifecycle request data")
	}
	var shape any
	if err := json.Unmarshal(raw, &shape); err != nil {
		return invalid("malformed lifecycle request")
	}
	target := reflect.TypeOf(destination)
	if target == nil || target.Kind() != reflect.Pointer ||
		reflect.ValueOf(destination).IsNil() || !requiredShape(shape, target.Elem()) {
		return invalid("missing or null lifecycle request field")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return invalid("invalid lifecycle request fields")
	}
	return nil
}

func tokensValue(decoder *json.Decoder, depth int) error {
	if depth > 64 {
		return invalid("lifecycle request nesting exceeded")
	}
	token, err := decoder.Token()
	if err != nil || token == nil {
		return invalid("malformed or null lifecycle request")
	}
	switch value := token.(type) {
	case json.Delim:
		if value != '{' && value != '[' {
			return invalid("malformed lifecycle structure")
		}
		seen := make(map[string]bool)
		for decoder.More() {
			if value == '{' {
				key, err := decoder.Token()
				name, ok := key.(string)
				if err != nil || !ok || seen[name] {
					return invalid("duplicate lifecycle request field")
				}
				seen[name] = true
			}
			if err := tokensValue(decoder, depth+1); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil || value == '{' && end != json.Delim('}') ||
			value == '[' && end != json.Delim(']') {
			return invalid("unclosed lifecycle request structure")
		}
	case json.Number:
		number, err := strconv.ParseInt(string(value), 10, 64)
		if err != nil || number < -2147483648 || number > int64(maxInteger) {
			return invalid("lifecycle integer outside exact range")
		}
	}
	return nil
}

func requiredShape(value any, target reflect.Type) bool {
	if target == reflect.TypeFor[json.RawMessage]() {
		return value != nil
	}
	if target.Kind() == reflect.Pointer {
		return value != nil && requiredShape(value, target.Elem())
	}
	switch target.Kind() {
	case reflect.Struct:
		fields, ok := value.(map[string]any)
		if !ok {
			return false
		}
		allowed := make(map[string]bool, target.NumField())
		for i := 0; i < target.NumField(); i++ {
			field := target.Field(i)
			tag := field.Tag.Get("json")
			if tag == "-" || field.PkgPath != "" {
				continue
			}
			parts := strings.Split(tag, ",")
			name := parts[0]
			if name == "" {
				name = field.Name
			}
			allowed[name] = true
			child, exists := fields[name]
			optional := len(parts) > 1 && parts[1] == "omitempty"
			if !exists && optional {
				continue
			}
			if !exists || child == nil || !requiredShape(child, field.Type) {
				return false
			}
		}
		for name := range fields {
			if !allowed[name] {
				return false
			}
		}
	case reflect.Slice:
		if target.Elem().Kind() == reflect.Uint8 {
			text, ok := value.(string)
			if !ok {
				return false
			}
			decoded, err := base64.StdEncoding.Strict().DecodeString(text)
			return err == nil && base64.StdEncoding.EncodeToString(decoded) == text
		}
		items, ok := value.([]any)
		if !ok {
			return false
		}
		for _, item := range items {
			if item == nil || !requiredShape(item, target.Elem()) {
				return false
			}
		}
	}
	return value != nil
}

// encoding/json replaces unpaired UTF-16 escapes with a replacement rune.
// Such replacement would change the retained input and its canonical digest.
func unicodeEscapes(raw []byte) bool {
	quoted := false
	for i := 0; i < len(raw); i++ {
		if raw[i] == '"' {
			quoted = !quoted
			continue
		}
		if !quoted || raw[i] != '\\' {
			continue
		}
		i++
		if i >= len(raw) {
			return false
		}
		if raw[i] != 'u' {
			continue
		}
		if i+4 >= len(raw) {
			return false
		}
		code, err := strconv.ParseUint(string(raw[i+1:i+5]), 16, 16)
		if err != nil {
			return false
		}
		i += 4
		if code >= 0xdc00 && code <= 0xdfff {
			return false
		}
		if code >= 0xd800 && code <= 0xdbff {
			if i+6 >= len(raw) || raw[i+1] != '\\' || raw[i+2] != 'u' {
				return false
			}
			low, err := strconv.ParseUint(string(raw[i+3:i+7]), 16, 16)
			if err != nil || low < 0xdc00 || low > 0xdfff {
				return false
			}
			i += 6
		}
	}
	return !quoted
}
