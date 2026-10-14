package laneturns

import (
	"regexp"
	"strings"
	"unicode/utf8"
)

type credentialShape struct {
	name    string
	pattern *regexp.Regexp
}

func shape(name, pattern string) credentialShape {
	return credentialShape{name, regexp.MustCompile(pattern)}
}

var credentialShapes = []credentialShape{
	shape("private-key", `-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----`),
	shape("authorization-header", `(?i)\b(?:proxy-)?authorization["']?[\s\v\p{Z}\x{0085}\x{001c}-\x{001f}]*[:=][\s\v\p{Z}\x{0085}\x{001c}-\x{001f}]*["']?(?:bearer|basic|token|digest)[\s\v\p{Z}\x{0085}\x{001c}-\x{001f}]+[A-Za-z0-9._~+/=-]{8,}`),
	shape("bearer-token", `(?i)\bbearer[\s\v\p{Z}\x{0085}\x{001c}-\x{001f}]+[A-Za-z0-9._~+/-]{16,}`),
	shape("code-host-token", `\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,}|glpat-[A-Za-z0-9_-]{20,})`),
	shape("chat-token", `\bxox[abposr]-[A-Za-z0-9-]{10,}`),
	shape("chat-bot-token", `\b[MNO][A-Za-z0-9_-]{23,27}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,40}(?:$|[^A-Za-z0-9_-])`),
	shape("messenger-bot-token", `\b[0-9]{8,10}:AA[A-Za-z0-9_-]{33}(?:$|[^A-Za-z0-9_-])`),
	shape("cloud-access-key-id", `(?:^|[^A-Z0-9])(?:AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}(?:$|[^A-Z0-9])`),
	shape("cloud-api-key", `\bAIza[0-9A-Za-z_-]{35}`),
	shape("oauth-access-token", `\bya29\.[0-9A-Za-z_-]{20,}`),
	shape("prefixed-secret-key", `(?:^|[^A-Za-z0-9])sk-[A-Za-z0-9_-]{20,}`),
	shape("payment-secret-key", `\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}`),
	shape("package-registry-token", `\b(?:npm_[A-Za-z0-9]{36}|pypi-[A-Za-z0-9_-]{50,})`),
	shape("model-hub-token", `\bhf_[A-Za-z0-9]{30,}`),
	shape("embedding-api-key", `(?:^|[^A-Za-z0-9])pa-[A-Za-z0-9_-]{40,}`),
	shape("json-web-token", `\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}`),
	shape("url-credentials", `\b[A-Za-z][A-Za-z0-9+.-]*://[^\s/:@]+:[^\s/@]+@`),
	shape("chat-webhook-url", `(?i)discord(?:app)?\.com(?:\\?/|%2f)api(?:\\?/|%2f)(?:v[0-9]+(?:\\?/|%2f))?webhooks(?:\\?/|%2f)[0-9]{5,}(?:\\?/|%2f)[A-Za-z0-9_-]{6,}`),
	shape("chat-webhook-url", `(?i)hooks\.slack\.com(?:\\?/|%2f)(?:services(?:\\?/|%2f)T[A-Z0-9]{5,}(?:\\?/|%2f)B[A-Z0-9]{5,}|workflows(?:\\?/|%2f)T[A-Z0-9]{5,}(?:\\?/|%2f)A[A-Z0-9]{5,}(?:\\?/|%2f)[0-9]{5,}|triggers(?:\\?/|%2f)T[A-Z0-9]{5,}(?:\\?/|%2f)[0-9]{5,})(?:\\?/|%2f)[A-Za-z0-9_-]{6,}`),
	shape("script-web-app-url", `(?i)script\.google\.com(?:\\?/|%2f)(?:a(?:\\?/|%2f)(?:macros(?:\\?/|%2f))?[A-Za-z0-9.-]+(?:\\?/|%2f))?(?:macros(?:\\?/|%2f))?(?:u(?:\\?/|%2f)[0-9]+(?:\\?/|%2f))?s(?:\\?/|%2f)[A-Za-z0-9_-]{10,}`),
	shape("script-web-app-url", `(?:^|[^A-Za-z0-9_-])AKfycb[A-Za-z0-9_-]{40,}`),
}

const sensitiveWords = `(?:api[ _-]?key|apikey|access[ _-]?key|secret[ _-]?key|private[ _-]?key|client[ _-]?secret|auth[ _-]?token|secret|token|passw(?:or)?d|passphrase|credentials?)`

var sensitiveName = regexp.MustCompile(`(?i)^(?:[A-Za-z0-9]+[_.-])*?` + sensitiveWords + `$`)
var assignment = regexp.MustCompile(`(?i)(?:^|[^A-Za-z0-9_])(?:[A-Za-z0-9]+[_.-])*?` + sensitiveWords + `["'*_]*[ \t]*(?::=|=>|=|:)`)
var reference = regexp.MustCompile(`^(?:\$[A-Z_][A-Z0-9_]*|\$\{[A-Za-z_][A-Za-z0-9_]*\}|<[A-Za-z_][A-Za-z0-9_ .-]*>|\{\{?[ ]*[A-Za-z_][A-Za-z0-9_. -]*[ ]*\}?\})$`)
var secretName = regexp.MustCompile(`^[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+$`)
var codeValue = regexp.MustCompile(`^(?:[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*\(.*|[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)+|[A-Za-z_][A-Za-z0-9_.]*\[.*|[a-z][a-z0-9]*(?:_[a-z0-9]+)+|[a-z]+(?:[A-Z][a-z]+)+)$`)
var maskValue = regexp.MustCompile(`^[xX*.-]+$`)
var proseWord = regexp.MustCompile(`^[A-Za-z][a-z]*$`)
var hasDigit = regexp.MustCompile(`[0-9]`)
var placeholders = " none null nil empty required optional provided redacted omitted unset unchanged unknown missing hidden masked rotated revoked expired n/a tbd true false yes no str string bytes int integer bool boolean number float any object dict list "

func literalToken(v string, more bool) bool {
	v = strings.TrimRight(strings.Trim(v, "*_"), ",;.")
	return v != "" && !reference.MatchString(v) && !secretName.MatchString(v) && !codeValue.MatchString(v) && !maskValue.MatchString(v) && !strings.Contains(placeholders, " "+strings.ToLower(v)+" ") && !(more && proseWord.MatchString(v))
}
func literalQuoted(v string) bool {
	v = strings.TrimSpace(v)
	if v == "" || reference.MatchString(v) {
		return false
	}
	return len(strings.Fields(v)) > 1 || literalToken(v, false)
}
func literalValue(v string) bool {
	v = strings.TrimSpace(v)
	if v == "" {
		return false
	}
	if strings.ContainsRune("\"'`", rune(v[0])) {
		end := strings.IndexByte(v[1:], v[0])
		if end < 0 {
			return literalQuoted(v[1:])
		}
		return literalQuoted(v[1 : end+1])
	}
	if v[0] == '<' || v[0] == '{' {
		endChar := byte('}')
		if v[0] == '<' {
			endChar = '>'
		}
		if end := strings.IndexByte(v, endChar); end >= 0 {
			if end+1 < len(v) && v[end+1] == '}' {
				end++
			}
			if reference.MatchString(v[:end+1]) {
				return false
			}
		}
	}
	parts := strings.Fields(v)
	return len(parts) > 0 && literalToken(parts[0], len(parts) > 1)
}
func findCredential(text string) (string, int) {
	for _, s := range credentialShapes {
		if m := s.pattern.FindStringIndex(text); m != nil {
			if (s.name == "prefixed-secret-key" || s.name == "embedding-api-key") && !hasDigit.MatchString(text[m[0]:m[1]]) {
				continue
			}
			start := m[0]
			if start < len(text) && text[start] == '\n' {
				start++
			}
			return s.name, strings.Count(text[:start], "\n") + 1
		}
	}
	for _, m := range assignment.FindAllStringIndex(text, -1) {
		if m[1] < len(text) && (text[m[1]] == '=' || text[m[1]] == ':') {
			continue
		}
		rest := text[m[1]:]
		if end := strings.IndexByte(rest, '\n'); end >= 0 {
			rest = rest[:end]
		}
		if literalValue(rest) {
			start := m[0]
			if start < len(text) && text[start] == '\n' {
				start++
			}
			return "secret-assignment", strings.Count(text[:start], "\n") + 1
		}
	}
	return "", 0
}
func checkValueCredentials(v any, field string, depth int) error {
	switch x := v.(type) {
	case string:
		if rule, _ := findCredential(x); rule != "" {
			return refused("%s: looks like a credential (%s); nothing was stored", field, rule)
		}
	case map[string]any:
		for k, item := range x {
			if rule, _ := findCredential(k); rule != "" {
				return refused("a field name: looks like a credential (%s); nothing was stored", rule)
			}
			where := field
			if depth == 0 {
				where = k
			}
			if sensitiveName.MatchString(k) {
				if s, ok := item.(string); ok && literalQuoted(s) {
					return refused("%s: looks like a credential (secret-assignment); nothing was stored", field)
				}
			}
			if err := checkValueCredentials(item, where, depth+1); err != nil {
				return err
			}
		}
	default:
		for _, item := range array(v) {
			if err := checkValueCredentials(item, field, depth+1); err != nil {
				return err
			}
		}
	}
	return nil
}
func checkText(data []byte, label, noun string) error {
	if !utf8.Valid(data) {
		return refused("%s: the %s must be UTF-8 text", label, noun)
	}
	text := string(data)
	if strings.Contains(text, "<!-- laneboss launcher block: begin") {
		return refused("%s: the %s already contains a launcher block; give the original %s", label, noun, noun)
	}
	if rule, line := findCredential(text); rule != "" {
		return refused("%s line %d: looks like a credential (%s); nothing was written", label, line, rule)
	}
	return nil
}
func screened(s string) string {
	if rule, _ := findCredential(s); rule != "" {
		return "(withheld)"
	}
	return s
}
func shown(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 32 || r == 127 || (r >= 128 && r <= 159) {
			return ' '
		}
		return r
	}, s)
}
func safeDetail(err error) string {
	s := screened(strings.TrimSpace(shown(strings.SplitN(err.Error(), "\n", 2)[0])))
	r := []rune(s)
	if len(r) > 200 {
		s = string(r[:200])
	}
	if s == "" {
		return "refused"
	}
	return s
}
func checkPathCredential(path, option string) error {
	for _, candidate := range []string{path, absolute(path), realPath(path)} {
		for _, part := range append([]string{candidate}, strings.Split(candidate, "/")...) {
			if rule, _ := findCredential(part); rule != "" {
				return refused("%s: the path looks like a credential (%s); nothing was read", option, rule)
			}
		}
	}
	return nil
}
func credentialError(label string, data []byte) error {
	if rule, line := findCredential(string(data)); rule != "" {
		return invalid("%s line %d: looks like a credential (%s)", label, line, rule)
	}
	return nil
}
