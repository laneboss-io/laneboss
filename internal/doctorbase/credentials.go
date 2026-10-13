package doctorbase

import (
	"regexp"
	"strings"
)

// Findings contain labels only. A matched credential is never returned to a caller.
var credentialShapes = []*regexp.Regexp{
	regexp.MustCompile(`-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----`),
	regexp.MustCompile(`(?i)\b(?:proxy-)?authorization["']?\s*[:=]\s*["']?(?:bearer|basic|token|digest)\s+[A-Za-z0-9._~+/=-]{8,}`),
	regexp.MustCompile(`(?i)\bbearer\s+[A-Za-z0-9._~+/-]{16,}`),
	regexp.MustCompile(`\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,}|glpat-[A-Za-z0-9_-]{20,})`),
	regexp.MustCompile(`\bxox[abposr]-[A-Za-z0-9-]{10,}`),
	regexp.MustCompile(`\b[MNO][A-Za-z0-9_-]{23,27}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,40}`),
	regexp.MustCompile(`\b[0-9]{8,10}:AA[A-Za-z0-9_-]{33}`),
	regexp.MustCompile(`(?:^|[^A-Z0-9])(?:AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}(?:$|[^A-Z0-9])`),
	regexp.MustCompile(`\bAIza[0-9A-Za-z_-]{35}`),
	regexp.MustCompile(`\bya29\.[0-9A-Za-z_-]{20,}`),
	regexp.MustCompile(`(?:^|[^A-Za-z0-9])(?:sk|pa)-[A-Za-z0-9_-]{20,}`),
	regexp.MustCompile(`\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}`),
	regexp.MustCompile(`\b(?:npm_[A-Za-z0-9]{36}|pypi-[A-Za-z0-9_-]{50,}|hf_[A-Za-z0-9]{30,})`),
	regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}`),
	regexp.MustCompile(`\b[A-Za-z][A-Za-z0-9+.-]*://[^\s/:@]+:[^\s/@]+@`),
	regexp.MustCompile(`(?i)discord(?:app)?\.com(?:\\?/|%2f)api(?:\\?/|%2f)(?:v[0-9]+(?:\\?/|%2f))?webhooks(?:\\?/|%2f)[0-9]{5,}(?:\\?/|%2f)[A-Za-z0-9_-]{6,}`),
	regexp.MustCompile(`(?i)hooks\.slack\.com(?:\\?/|%2f)(?:services(?:\\?/|%2f)T[A-Z0-9]{5,}(?:\\?/|%2f)B[A-Z0-9]{5,}|workflows(?:\\?/|%2f)T[A-Z0-9]{5,}(?:\\?/|%2f)A[A-Z0-9]{5,}(?:\\?/|%2f)[0-9]{5,}|triggers(?:\\?/|%2f)T[A-Z0-9]{5,}(?:\\?/|%2f)[0-9]{5,})(?:\\?/|%2f)[A-Za-z0-9_-]{6,}`),
	regexp.MustCompile(`(?i)script\.google\.com(?:\\?/|%2f)(?:a(?:\\?/|%2f)(?:macros(?:\\?/|%2f))?[A-Za-z0-9.-]+(?:\\?/|%2f))?(?:macros(?:\\?/|%2f))?(?:u(?:\\?/|%2f)[0-9]+(?:\\?/|%2f))?s(?:\\?/|%2f)[A-Za-z0-9_-]{10,}`),
	regexp.MustCompile(`(?:^|[^A-Za-z0-9_-])AKfycb[A-Za-z0-9_-]{40,}`),
}

const sensitiveWords = `(?:api[ _-]?key|apikey|access[ _-]?key|secret[ _-]?key|private[ _-]?key|client[ _-]?secret|auth[ _-]?token|secret|token|passw(?:or)?d|passphrase|credentials?)`

var sensitiveName = regexp.MustCompile(`(?i)^(?:[A-Za-z0-9]+[_.-])*?` + sensitiveWords + `$`)
var assignment = regexp.MustCompile(`(?i)(?:^|[^A-Za-z0-9_])(?:[A-Za-z0-9]+[_.-])*?` + sensitiveWords + `["'*_]*[ \t]*(?::=|=>|=|:)`)
var reference = regexp.MustCompile(`^(?:\$[A-Z_][A-Z0-9_]*|\$\{[A-Za-z_][A-Za-z0-9_]*\}|<[A-Za-z_][A-Za-z0-9_ .-]*>|\{\{?[ ]*[A-Za-z_][A-Za-z0-9_. -]*[ ]*\}?\})$`)
var secretReference = regexp.MustCompile(`^[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+$`)
var codeReference = regexp.MustCompile(`^(?:[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*\(.*|[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)+|[A-Za-z_][A-Za-z0-9_.]*\[.*|[a-z][a-z0-9]*(?:_[a-z0-9]+)+|[a-z]+(?:[A-Z][a-z]+)+)$`)
var masks = regexp.MustCompile(`^[xX*.-]+$`)
var proseWord = regexp.MustCompile(`^[A-Za-z][a-z]*$`)
var placeholders = strings.Fields("none null nil empty required optional provided redacted omitted unset unchanged unknown missing hidden masked rotated revoked expired n/a tbd true false yes no str string bytes int integer bool boolean number float any object dict list")

func literalToken(s string, more bool) bool {
	s = strings.TrimRight(strings.Trim(s, "*_"), ",;.")
	if s == "" || reference.MatchString(s) || secretReference.MatchString(s) || codeReference.MatchString(s) || masks.MatchString(s) {
		return false
	}
	for _, p := range placeholders {
		if strings.EqualFold(p, s) {
			return false
		}
	}
	return !(more && proseWord.MatchString(s))
}
func literalQuoted(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" || reference.MatchString(s) {
		return false
	}
	return len(strings.Fields(s)) > 1 || literalToken(s, false)
}
func literalAfter(s string) bool {
	s = strings.TrimSpace(strings.SplitN(s, "\n", 2)[0])
	if s == "" {
		return false
	}
	if strings.ContainsRune("\"'`", rune(s[0])) {
		end := strings.IndexByte(s[1:], s[0])
		if end >= 0 {
			return literalQuoted(s[1 : 1+end])
		}
		return literalQuoted(s[1:])
	}
	if s[0] == '<' || s[0] == '{' {
		end := strings.IndexAny(s, ">}")
		if end >= 0 {
			candidate := s[:end+1]
			if len(s) > end+1 && s[end+1] == '}' {
				candidate += "}"
			}
			if reference.MatchString(candidate) {
				return false
			}
		}
	}
	words := strings.Fields(s)
	return literalToken(words[0], len(words) > 1)
}
func CredentialText(s string) bool {
	for _, p := range credentialShapes {
		if p.MatchString(s) {
			return true
		}
	}
	for _, match := range assignment.FindAllStringIndex(s, -1) {
		if match[1] < len(s) && strings.ContainsRune("=: ", rune(s[match[1]])) && (s[match[1]] == '=' || s[match[1]] == ':') {
			continue
		}
		if literalAfter(s[match[1]:]) {
			return true
		}
	}
	return false
}
func CredentialValue(v any) bool {
	switch x := v.(type) {
	case string:
		return CredentialText(x)
	case map[string]any:
		for k, item := range x {
			if CredentialText(k) {
				return true
			}
			if s, ok := item.(string); ok && sensitiveName.MatchString(k) && literalQuoted(s) {
				return true
			}
			if CredentialValue(item) {
				return true
			}
		}
	case []any:
		for _, item := range x {
			if CredentialValue(item) {
				return true
			}
		}
	}
	return false
}
