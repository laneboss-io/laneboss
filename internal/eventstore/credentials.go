package eventstore

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

type credentialRule struct {
	name     string
	re       *regexp.Regexp
	boundary bool
	digit    bool
}

var credentialRules = []credentialRule{
	{"private-key", regexp.MustCompile(`-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----`), false, false},
	{"authorization-header", regexp.MustCompile(`(?i)\b(?:proxy-)?authorization["']?[\s\v\p{Z}\x{0085}\x{001c}-\x{001f}]*[:=][\s\v\p{Z}\x{0085}\x{001c}-\x{001f}]*["']?(?:bearer|basic|token|digest)[\s\v\p{Z}\x{0085}\x{001c}-\x{001f}]+[A-Za-z0-9._~+/=-]{8,}`), false, false},
	{"bearer-token", regexp.MustCompile(`(?i)\bbearer[\s\v\p{Z}\x{0085}\x{001c}-\x{001f}]+[A-Za-z0-9._~+/-]{16,}`), false, false},
	{"code-host-token", regexp.MustCompile(`\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,}|glpat-[A-Za-z0-9_-]{20,})`), false, false},
	{"chat-token", regexp.MustCompile(`\bxox[abposr]-[A-Za-z0-9-]{10,}`), false, false},
	{"chat-bot-token", regexp.MustCompile(`\b[MNO][A-Za-z0-9_-]{23,27}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,40}`), true, false},
	{"messenger-bot-token", regexp.MustCompile(`\b[0-9]{8,10}:AA[A-Za-z0-9_-]{33}`), true, false},
	{"cloud-access-key-id", regexp.MustCompile(`(?:AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}`), true, false},
	{"cloud-api-key", regexp.MustCompile(`\bAIza[0-9A-Za-z_-]{35}`), false, false},
	{"oauth-access-token", regexp.MustCompile(`\bya29\.[0-9A-Za-z_-]{20,}`), false, false},
	{"prefixed-secret-key", regexp.MustCompile(`sk-[A-Za-z0-9_-]{20,}`), true, true},
	{"payment-secret-key", regexp.MustCompile(`\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}`), false, false},
	{"package-registry-token", regexp.MustCompile(`\b(?:npm_[A-Za-z0-9]{36}|pypi-[A-Za-z0-9_-]{50,})`), false, false},
	{"model-hub-token", regexp.MustCompile(`\bhf_[A-Za-z0-9]{30,}`), false, false},
	{"embedding-api-key", regexp.MustCompile(`pa-[A-Za-z0-9_-]{40,}`), true, true},
	{"json-web-token", regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}`), false, false},
	{"url-credentials", regexp.MustCompile(`\b[A-Za-z][A-Za-z0-9+.-]*://[^\s/:@]+:[^\s/@]+@`), false, false},
	{"chat-webhook-url", regexp.MustCompile(`(?i:discord(?:app)?\.com)(?:\\?/|%2[Ff])api(?:\\?/|%2[Ff])(?:v[0-9]+(?:\\?/|%2[Ff]))?webhooks(?:\\?/|%2[Ff])[0-9]{5,}(?:\\?/|%2[Ff])[A-Za-z0-9_-]{6,}`), false, false},
	{"chat-webhook-url", regexp.MustCompile(`(?i:hooks\.slack\.com)(?:\\?/|%2[Ff])(?:services(?:\\?/|%2[Ff])T[A-Z0-9]{5,}(?:\\?/|%2[Ff])B[A-Z0-9]{5,}|workflows(?:\\?/|%2[Ff])T[A-Z0-9]{5,}(?:\\?/|%2[Ff])A[A-Z0-9]{5,}(?:\\?/|%2[Ff])[0-9]{5,}|triggers(?:\\?/|%2[Ff])T[A-Z0-9]{5,}(?:\\?/|%2[Ff])[0-9]{5,})(?:\\?/|%2[Ff])[A-Za-z0-9_-]{6,}`), false, false},
	{"script-web-app-url", regexp.MustCompile(`(?i:script\.google\.com)(?:\\?/|%2[Ff])(?:a(?:\\?/|%2[Ff])(?:macros(?:\\?/|%2[Ff]))?[A-Za-z0-9.-]+(?:\\?/|%2[Ff]))?(?:macros(?:\\?/|%2[Ff]))?(?:u(?:\\?/|%2[Ff])[0-9]+(?:\\?/|%2[Ff]))?s(?:\\?/|%2[Ff])[A-Za-z0-9_-]{10,}`), false, false},
	{"script-web-app-url", regexp.MustCompile(`AKfycb[A-Za-z0-9_-]{40,}`), true, false},
}

const sensitiveWords = `(?:api[ _-]?key|apikey|access[ _-]?key|secret[ _-]?key|private[ _-]?key|client[ _-]?secret|auth[ _-]?token|secret|token|passw(?:or)?d|passphrase|credentials?)`

var sensitiveName = regexp.MustCompile(`(?i)^(?:[A-Za-z0-9]+[_.-])*?` + sensitiveWords + `$`)
var assignment = regexp.MustCompile(`(?i)(?:[A-Za-z0-9]+[_.-])*?` + sensitiveWords + `["'*_]*[ \t]*(?::=|=>|=|:)`)
var reference = regexp.MustCompile(`^(?:\$[A-Z_][A-Z0-9_]*|\$\{[A-Za-z_][A-Za-z0-9_]*\}|<[A-Za-z_][A-Za-z0-9_ .-]*>|\{\{?[ ]*[A-Za-z_][A-Za-z0-9_. -]*[ ]*\}?\})$`)
var secretName = regexp.MustCompile(`^[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+$`)
var codeReference = regexp.MustCompile(`^(?:[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*\(.*|[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)+|[A-Za-z_][A-Za-z0-9_.]*\[.*|[a-z][a-z0-9]*(?:_[a-z0-9]+)+|[a-z]+(?:[A-Z][a-z]+)+)$`)
var proseWord = regexp.MustCompile(`^[A-Za-z][a-z]*$`)
var mask = regexp.MustCompile(`^[xX*.-]+$`)
var placeholders = strings.Fields("none null nil empty required optional provided redacted omitted unset unchanged unknown missing hidden masked rotated revoked expired n/a tbd true false yes no str string bytes int integer bool boolean number float any object dict list")

func alphaNum(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
}
func literalToken(v string, more bool) bool {
	v = strings.TrimRight(strings.Trim(v, "*_"), ",;.")
	if v == "" || reference.MatchString(v) || secretName.MatchString(v) || codeReference.MatchString(v) || mask.MatchString(v) {
		return false
	}
	for _, p := range placeholders {
		if strings.EqualFold(v, p) {
			return false
		}
	}
	return !(more && proseWord.MatchString(v))
}
func literalQuoted(v string) bool {
	v = strings.TrimSpace(v)
	if v == "" || reference.MatchString(v) {
		return false
	}
	return len(strings.Fields(v)) > 1 || literalToken(v, false)
}
func literalAssignment(v string) bool {
	v = strings.TrimSpace(v)
	if v == "" {
		return false
	}
	if strings.ContainsRune("\"'`", rune(v[0])) {
		end := strings.IndexByte(v[1:], v[0])
		if end >= 0 {
			return literalQuoted(v[1 : 1+end])
		}
		return literalQuoted(v[1:])
	}
	if v[0] == '<' || v[0] == '{' {
		closing := byte('}')
		if v[0] == '<' {
			closing = '>'
		}
		end := strings.IndexByte(v, closing)
		if end >= 0 {
			candidate := v[:end+1]
			if end+1 < len(v) && v[end+1] == '}' {
				candidate = v[:end+2]
			}
			if reference.MatchString(candidate) {
				return false
			}
		}
	}
	words := strings.Fields(v)
	return literalToken(words[0], len(words) > 1)
}
func credentialText(s string) string {
	rule, _ := credentialFinding(s)
	return rule
}
func credentialFinding(s string) (string, string) {
	for _, rule := range credentialRules {
		for _, loc := range rule.re.FindAllStringIndex(s, -1) {
			left := loc[0] > 0 && alphaNum(s[loc[0]-1])
			right := loc[1] < len(s) && (alphaNum(s[loc[1]]) || s[loc[1]] == '_' || s[loc[1]] == '-')
			if rule.name == "cloud-access-key-id" {
				upper := func(c byte) bool { return c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' }
				left = loc[0] > 0 && upper(s[loc[0]-1])
				right = loc[1] < len(s) && upper(s[loc[1]])
			}
			if rule.boundary && (left || right) {
				continue
			}
			if rule.digit && !regexp.MustCompile(`[0-9]`).MatchString(s[loc[0]+3:loc[1]]) {
				continue
			}
			return rule.name, s[loc[0]:loc[1]]
		}
	}
	for _, loc := range assignment.FindAllStringIndex(s, -1) {
		if loc[0] > 0 && (alphaNum(s[loc[0]-1]) || s[loc[0]-1] == '_') {
			continue
		}
		if loc[1] < len(s) && (s[loc[1]] == '=' || s[loc[1]-1] == ':' && s[loc[1]] == ':') {
			continue
		}
		tail := s[loc[1]:]
		if end := strings.IndexByte(tail, '\n'); end >= 0 {
			tail = tail[:end]
		}
		if literalAssignment(tail) {
			return "secret-assignment", strings.TrimSpace(tail)
		}
	}
	return "", ""
}

func overlapsCredential(key, value string) bool {
	key, value = strings.ToLower(key), strings.ToLower(value)
	return value != "" && (strings.Contains(key, value) || len(key) >= 3 && strings.Contains(value, key))
}

// Findings never include a nested key or a matching credential.
func credentialValue(v any) (string, string) {
	var walk func(any, string, int) (string, string)
	walk = func(v any, top string, depth int) (string, string) {
		label := top
		if label == "" {
			label = "a top-level field"
		}
		switch x := v.(type) {
		case string:
			if rule, secret := credentialFinding(x); rule != "" {
				if credentialText(top) != "" || overlapsCredential(top, secret) {
					label = "a top-level field"
				}
				if depth > 0 {
					label = fmt.Sprintf("%s (a value at depth %d)", label, depth)
				}
				return label, rule
			}
		case Object:
			keys := make([]string, 0, len(x))
			for k := range x {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				here, d := top, depth+1
				if top == "" {
					here, d = k, 0
				}
				if rule := credentialText(k); rule != "" {
					if top == "" {
						return "a top-level field name", rule
					}
					label := top
					if overlapsCredential(top, k) {
						label = "a top-level field"
					}
					return fmt.Sprintf("%s (a field name at depth %d)", label, d), rule
				}
				if s, ok := x[k].(string); ok && sensitiveName.MatchString(k) && literalQuoted(s) {
					name := here
					if overlapsCredential(here, s) {
						name = "a top-level field"
					}
					if d > 0 {
						name = fmt.Sprintf("%s (a value at depth %d)", name, d)
					}
					return name, "secret-assignment"
				}
				if name, rule := walk(x[k], here, d); rule != "" {
					return name, rule
				}
			}
		case []any:
			for _, item := range x {
				if name, rule := walk(item, top, depth+1); rule != "" {
					return name, rule
				}
			}
		}
		return "", ""
	}
	return walk(v, "", 0)
}
func shown(s string) string {
	if credentialText(s) != "" {
		return "[withheld]"
	}
	return s
}
