package lane

import (
	"regexp"
	"strings"
)

type secretShape struct {
	name    string
	pattern *regexp.Regexp
	digits  bool
}

var secretShapes = []secretShape{
	{"private-key", regexp.MustCompile(`-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----`), false},
	{"authorization-header", regexp.MustCompile(`(?i)\b(?:proxy-)?authorization["']?[\s\v\p{Z}\x{0085}\x{001c}-\x{001f}]*[:=][\s\v\p{Z}\x{0085}\x{001c}-\x{001f}]*["']?(?:bearer|basic|token|digest)[\s\v\p{Z}\x{0085}\x{001c}-\x{001f}]+[A-Za-z0-9._~+/=-]{8,}`), false},
	{"bearer-token", regexp.MustCompile(`(?i)\bbearer[\s\v\p{Z}\x{0085}\x{001c}-\x{001f}]+[A-Za-z0-9._~+/-]{16,}`), false},
	{"code-host-token", regexp.MustCompile(`\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,}|glpat-[A-Za-z0-9_-]{20,})`), false},
	{"chat-token", regexp.MustCompile(`\bxox[abposr]-[A-Za-z0-9-]{10,}`), false},
	{"chat-bot-token", regexp.MustCompile(`\b[MNO][A-Za-z0-9_-]{23,27}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,40}`), false},
	{"messenger-bot-token", regexp.MustCompile(`\b[0-9]{8,10}:AA[A-Za-z0-9_-]{33}`), false},
	{"cloud-access-key-id", regexp.MustCompile(`(?:AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}`), false},
	{"cloud-api-key", regexp.MustCompile(`\bAIza[0-9A-Za-z_-]{35}`), false},
	{"oauth-access-token", regexp.MustCompile(`\bya29\.[0-9A-Za-z_-]{20,}`), false},
	{"prefixed-secret-key", regexp.MustCompile(`sk-[A-Za-z0-9_-]{20,}`), true},
	{"payment-secret-key", regexp.MustCompile(`\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}`), false},
	{"package-registry-token", regexp.MustCompile(`\b(?:npm_[A-Za-z0-9]{36}|pypi-[A-Za-z0-9_-]{50,})`), false},
	{"model-hub-token", regexp.MustCompile(`\bhf_[A-Za-z0-9]{30,}`), false},
	{"embedding-api-key", regexp.MustCompile(`pa-[A-Za-z0-9_-]{40,}`), true},
	{"json-web-token", regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}`), false},
	{"url-credentials", regexp.MustCompile(`\b[A-Za-z][A-Za-z0-9+.-]*://[^\s/:@]+:[^\s/@]+@`), false},
	{"chat-webhook-url", regexp.MustCompile(`(?i)discord(?:app)?\.com(?:\\?/|%2f)api(?:\\?/|%2f)(?:v[0-9]+(?:\\?/|%2f))?webhooks(?:\\?/|%2f)[0-9]{5,}(?:\\?/|%2f)[A-Za-z0-9_-]{6,}`), false},
	{"chat-webhook-url", regexp.MustCompile(`(?i)hooks\.slack\.com(?:\\?/|%2f)(?:services(?:\\?/|%2f)T[A-Z0-9]{5,}(?:\\?/|%2f)B[A-Z0-9]{5,}|workflows(?:\\?/|%2f)T[A-Z0-9]{5,}(?:\\?/|%2f)A[A-Z0-9]{5,}(?:\\?/|%2f)[0-9]{5,}|triggers(?:\\?/|%2f)T[A-Z0-9]{5,}(?:\\?/|%2f)[0-9]{5,})(?:\\?/|%2f)[A-Za-z0-9_-]{6,}`), false},
	{"script-web-app-url", regexp.MustCompile(`(?i)script\.google\.com(?:\\?/|%2f)(?:a(?:\\?/|%2f)(?:macros(?:\\?/|%2f))?[A-Za-z0-9.-]+(?:\\?/|%2f))?(?:macros(?:\\?/|%2f))?(?:u(?:\\?/|%2f)[0-9]+(?:\\?/|%2f))?s(?:\\?/|%2f)[A-Za-z0-9_-]{10,}`), false},
	{"script-web-app-url", regexp.MustCompile(`AKfycb[A-Za-z0-9_-]{40,}`), false},
}

const sensitiveWords = `(?:api[ _-]?key|apikey|access[ _-]?key|secret[ _-]?key|private[ _-]?key|client[ _-]?secret|auth[ _-]?token|secret|token|passw(?:or)?d|passphrase|credentials?)`

const referencePattern = `\$[A-Z_][A-Z0-9_]*|\$\{[A-Za-z_][A-Za-z0-9_]*\}|<[A-Za-z_][A-Za-z0-9_ .-]*>|\{\{?[ ]*[A-Za-z_][A-Za-z0-9_. -]*[ ]*\}?\}`

var assignment = regexp.MustCompile(`(?i)(?:[A-Za-z0-9]+[_.-])*?` + sensitiveWords + `["'*_]*[ \t]*(?::=|=>|=|:)`)

func literalSecret(s string, quoted bool) bool {
	s = strings.TrimSpace(s)
	if s == "" {
		return false
	}
	if match(referencePattern, s) {
		return false
	}
	if !quoted && (s[0] == '<' || s[0] == '{') {
		closing := byte('}')
		if s[0] == '<' {
			closing = '>'
		}
		if end := strings.IndexByte(s, closing); end >= 0 {
			end++
			if end < len(s) && s[end] == '}' {
				end++
			}
			if match(referencePattern, s[:end]) {
				return false
			}
		}
	}
	words := strings.Fields(s)
	if quoted && len(words) > 1 {
		return true
	}
	s = strings.TrimRight(strings.Trim(words[0], "*_"), ",;.")
	if match(referencePattern, s) {
		return false
	}
	if match(`[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+|[xX*.-]+`, s) {
		return false
	}
	if contains(strings.Fields("none null nil empty required optional provided redacted omitted unset unchanged unknown missing hidden masked rotated revoked expired n/a tbd true false yes no str string bytes int integer bool boolean number float any object dict list"), strings.ToLower(s)) {
		return false
	}
	if regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*\(`).MatchString(s) || match(`[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)+|[a-z][a-z0-9]*(?:_[a-z0-9]+)+|[a-z]+(?:[A-Z][a-z]+)+`, s) || regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.]*\[`).MatchString(s) {
		return false
	}
	if !quoted && len(words) > 1 && match(`[A-Za-z][a-z]*`, s) {
		return false
	}
	return s != ""
}
func credential(text string) (string, int) {
	for _, s := range secretShapes {
		for _, p := range s.pattern.FindAllStringIndex(text, -1) {
			if !secretBoundary(s, text, p[0], p[1]) {
				continue
			}
			if s.digits && !regexp.MustCompile(`[0-9]`).MatchString(text[p[0]:p[1]]) {
				continue
			}
			return s.name, strings.Count(text[:p[0]], "\n") + 1
		}
	}
	for _, p := range assignment.FindAllStringIndex(text, -1) {
		if p[0] > 0 && regexp.MustCompile(`[A-Za-z0-9_]`).MatchString(text[p[0]-1:p[0]]) {
			continue
		}
		if p[1] < len(text) && contains([]string{"=", ":"}, text[p[1]:p[1]+1]) {
			continue
		}
		s := text[p[1]:]
		if end := strings.IndexByte(s, '\n'); end >= 0 {
			s = s[:end]
		}
		s = strings.TrimSpace(s)
		quoted := false
		if len(s) > 0 && strings.ContainsRune("\"'`", rune(s[0])) {
			quoted = true
			q := s[0]
			s = s[1:]
			if end := strings.IndexByte(s, q); end >= 0 {
				s = s[:end]
			}
		}
		if literalSecret(s, quoted) {
			return "secret-assignment", strings.Count(text[:p[0]], "\n") + 1
		}
	}
	return "", 0
}

func secretBoundary(shape secretShape, text string, start, end int) bool {
	left, right := "", ""
	switch shape.name {
	case "cloud-access-key-id":
		left = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
		right = left
	case "prefixed-secret-key", "embedding-api-key":
		left = "ABCDEFGHIJKLMNOPQRSTUVWXYZ" + "abcdefghijklmnopqrstuvwxyz" + "0123456789"
	case "script-web-app-url":
		if strings.HasPrefix(text[start:end], "AKfycb") {
			left = "ABCDEFGHIJKLMNOPQRSTUVWXYZ" + "abcdefghijklmnopqrstuvwxyz" + "0123456789" + "_-"
		}
	}
	if start > 0 && strings.ContainsRune(left, rune(text[start-1])) {
		return false
	}
	return end == len(text) || !strings.ContainsRune(right, rune(text[end]))
}
func checkSecrets(v any) error {
	switch x := v.(type) {
	case string:
		if rule, _ := credential(x); rule != "" {
			return refuse("a field looks like a credential (%s); nothing was stored", rule)
		}
	case map[string]any:
		for key, value := range x {
			if rule, _ := credential(key); rule != "" {
				return refuse("a field name looks like a credential (%s)", rule)
			}
			if text, ok := value.(string); ok && match(`(?i)(?:[A-Za-z0-9]+[_.-])*?`+sensitiveWords, key) && literalSecret(text, true) {
				return refuse("a field looks like a credential (secret-assignment)")
			}
			if err := checkSecrets(value); err != nil {
				return err
			}
		}
	case []map[string]any:
		return checkSecrets(list(x))
	case []any:
		for _, value := range x {
			if err := checkSecrets(value); err != nil {
				return err
			}
		}
	case []string:
		for _, value := range x {
			if err := checkSecrets(value); err != nil {
				return err
			}
		}
	}
	return nil
}
