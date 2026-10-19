package boxcore

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

// PlainName accepts a short ASCII name with a letter or digit first.
func PlainName(s string) bool {
	if len(s) == 0 || len(s) > 63 || !asciiLetter(s[0]) && !asciiDigit(s[0]) {
		return false
	}
	for i := 1; i < len(s); i++ {
		c := s[i]
		if !asciiLetter(c) && !asciiDigit(c) && c != '.' && c != '_' && c != '-' {
			return false
		}
	}
	return true
}

// TagSafe rejects characters that break the provider's shorthand tag syntax.
func TagSafe(s string) bool {
	if s == "" || utf8.RuneCountInString(s) > 255 {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) || strings.ContainsRune(",{}[]\"\\", r) {
			return false
		}
	}
	return true
}

// GCPLabelValue makes a lower-case ASCII label of at most 63 bytes.
func GCPLabelValue(s string) string {
	value := cloudName(s, true)
	if len(value) > 63 {
		value = value[:63]
	}
	if value == "" {
		return "none"
	}
	return value
}

// GCPInstanceName keeps the run tail while shortening the purpose to fit.
func GCPInstanceName(prefix, purpose, runID string) string {
	prefix = cloudName(prefix, false)
	purpose = cloudName(purpose, false)
	suffix := "-" + cloudName(RunIDTail(runID, 10), false)
	name := prefix + purpose + suffix
	if name[0] < 'a' || name[0] > 'z' {
		prefix = "lb" + prefix
	}
	room := 63 - len(prefix) - len(suffix)
	if room < 0 {
		// An oversized prefix leaves no purpose; still reserve the run tail.
		prefix = prefix[:63-len(suffix)]
		room = 0
	}
	if len(purpose) > room {
		purpose = purpose[:room]
	}
	return strings.TrimRight(prefix+purpose+suffix, "-")
}

func cloudName(s string, underscore bool) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' || underscore && r == '_' {
			b.WriteRune(r)
		} else {
			b.WriteByte('-')
		}
	}
	return b.String()
}

func asciiLetter(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}

func asciiDigit(c byte) bool {
	return c >= '0' && c <= '9'
}
