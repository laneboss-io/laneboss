package claudock

import (
	"bytes"

	"laneboss.io/laneboss/internal/v2/api"
)

// APIKeyValidator checks only the bounded wire shape, without copying or
// formatting material. Provider authentication remains a separate operation.
type APIKeyValidator struct{}

const MaxAPIKeyBytes = 65536

func (APIKeyValidator) ValidateAPIKeyCredential(profile, canonicalLogin string, key []byte) error {
	if !label(profile) || !label(canonicalLogin) || len(key) <= len("sk-ant-") || len(key) > MaxAPIKeyBytes || !bytes.HasPrefix(key, []byte("sk-ant-")) {
		return failure(api.CodeInvalid, "API key handles and bounded sk-ant- material are required")
	}
	for _, value := range key {
		if value < 33 || value > 126 {
			return failure(api.CodeInvalid, "API key must be one line of printable ASCII without whitespace")
		}
	}
	return nil
}
