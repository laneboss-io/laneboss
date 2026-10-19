package wire

import (
	"reflect"
	"strings"

	"laneboss.io/laneboss/internal/v2/api"
)

// The normal strict decoder remains the acceptance gate. Only its refusal is
// annotated with a fixed known field; untrusted unknown keys are never logged.
func DecodeAdminEnrollmentFrame(data []byte, out *api.AdminEnrollmentFrame) error {
	err := Decode(data, out)
	if err == nil {
		return nil
	}
	value, parseErr := Parse(data)
	object, ok := value.(map[string]any)
	if parseErr == nil && ok {
		schema := reflect.TypeFor[api.AdminEnrollmentFrame]()
		for index := 0; index < schema.NumField(); index++ {
			field := schema.Field(index)
			name := strings.Split(field.Tag.Get("json"), ",")[0]
			value, present := object[name]
			if !present || shape(value, field.Type, name) != nil {
				return api.AdminEnrollmentFailure(name, err)
			}
		}
	}
	return api.AdminEnrollmentFailure("frame", err)
}

// Correlation is diagnostic only until the whole frame and native peer pass.
// Malformed/duplicate JSON has no safely recoverable nonce.
func AdminEnrollmentNonce(data []byte) api.ID {
	value, err := Parse(data)
	if err != nil {
		return ""
	}
	object, ok := value.(map[string]any)
	if !ok {
		return ""
	}
	nonce, ok := object["nonce"].(string)
	if !ok || !ValidID(nonce) {
		return ""
	}
	return api.ID(nonce)
}
