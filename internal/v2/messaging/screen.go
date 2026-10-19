package messaging

import (
	"strings"
	"unicode"
	"unicode/utf8"

	"laneboss.io/laneboss/internal/credentialtext"
	"laneboss.io/laneboss/internal/v2/api"
)

// CheckContent screens the original bytes with the shared credential detector.
// It never rewrites, executes or includes matched values in diagnostics.
func CheckContent(data []byte) error {
	if len(data) < 1 || len(data) > MaxMailBytes || !utf8.Valid(data) || strings.TrimSpace(string(data)) == "" {
		return problem(api.CodeInvalid, "mail must be nonempty UTF-8 text of at most 262144 bytes")
	}
	text := string(data)
	if strings.Contains(text, "<!-- laneboss launcher block: begin") {
		return problem(api.CodeInvalid, "mail must contain original text without an appended launcher block")
	}
	for _, c := range text {
		if unicode.IsControl(c) && c != '\n' && c != '\r' && c != '\t' {
			return problem(api.CodeInvalid, "mail contains a terminal control character")
		}
	}
	if credentialtext.HasCredential(text) {
		return problem(api.CodeInvalid, "mail contains a credential-shaped value; nothing was queued")
	}
	return nil
}
