package plugin

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
	"unicode"
)

type credential struct {
	rule, value string
	line        int
}
type shape struct {
	name               string
	pattern            *regexp.Regexp
	digit, left, right bool
}

func rx(s string) *regexp.Regexp { return regexp.MustCompile(s) }

var shapes = []shape{
	{"private-key", rx(`-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----`), false, false, false},
	{"authorization-header", rx(`(?i)\b(?:proxy-)?authorization["']?[\s\v\p{Z}\x{0085}\x{001c}-\x{001f}]*[:=][\s\v\p{Z}\x{0085}\x{001c}-\x{001f}]*["']?(?:bearer|basic|token|digest)[\s\v\p{Z}\x{0085}\x{001c}-\x{001f}]+[A-Za-z0-9._~+/=-]{8,}`), false, false, false},
	{"bearer-token", rx(`(?i)\bbearer[\s\v\p{Z}\x{0085}\x{001c}-\x{001f}]+[A-Za-z0-9._~+/-]{16,}`), false, false, false},
	{"code-host-token", rx(`\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,}|glpat-[A-Za-z0-9_-]{20,})`), false, false, false},
	{"chat-token", rx(`\bxox[abposr]-[A-Za-z0-9-]{10,}`), false, false, false},
	{"chat-bot-token", rx(`\b[MNO][A-Za-z0-9_-]{23,27}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,40}`), false, false, true},
	{"messenger-bot-token", rx(`\b[0-9]{8,10}:AA[A-Za-z0-9_-]{33}`), false, false, true},
	{"cloud-access-key-id", rx(`(?:AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}`), false, true, true},
	{"cloud-api-key", rx(`\bAIza[0-9A-Za-z_-]{35}`), false, false, false},
	{"oauth-access-token", rx(`\bya29\.[0-9A-Za-z_-]{20,}`), false, false, false},
	{"prefixed-secret-key", rx(`sk-[A-Za-z0-9_-]{20,}`), true, true, false},
	{"payment-secret-key", rx(`\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}`), false, false, false},
	{"package-registry-token", rx(`\b(?:npm_[A-Za-z0-9]{36}|pypi-[A-Za-z0-9_-]{50,})`), false, false, false},
	{"model-hub-token", rx(`\bhf_[A-Za-z0-9]{30,}`), false, false, false},
	{"embedding-api-key", rx(`pa-[A-Za-z0-9_-]{40,}`), true, true, false},
	{"json-web-token", rx(`\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}`), false, false, false},
	{"url-credentials", rx(`\b[A-Za-z][A-Za-z0-9+.-]*://[^\s/:@]+:[^\s/@]+@`), false, false, false},
	{"chat-webhook-url", rx(`(?i:discord(?:app)?\.com)(?:\\?/|%2[Ff])api(?:\\?/|%2[Ff])(?:v[0-9]+(?:\\?/|%2[Ff]))?webhooks(?:\\?/|%2[Ff])[0-9]{5,}(?:\\?/|%2[Ff])[A-Za-z0-9_-]{6,}`), false, false, false},
	{"chat-webhook-url", rx(`(?i:hooks\.slack\.com)(?:\\?/|%2[Ff])(?:services(?:\\?/|%2[Ff])T[A-Z0-9]{5,}(?:\\?/|%2[Ff])B[A-Z0-9]{5,}|workflows(?:\\?/|%2[Ff])T[A-Z0-9]{5,}(?:\\?/|%2[Ff])A[A-Z0-9]{5,}(?:\\?/|%2[Ff])[0-9]{5,}|triggers(?:\\?/|%2[Ff])T[A-Z0-9]{5,}(?:\\?/|%2[Ff])[0-9]{5,})(?:\\?/|%2[Ff])[A-Za-z0-9_-]{6,}`), false, false, false},
	{"script-web-app-url", rx(`(?i:script\.google\.com)(?:\\?/|%2[Ff])(?:a(?:\\?/|%2[Ff])(?:macros(?:\\?/|%2[Ff]))?[A-Za-z0-9.-]+(?:\\?/|%2[Ff]))?(?:macros(?:\\?/|%2[Ff]))?(?:u(?:\\?/|%2[Ff])[0-9]+(?:\\?/|%2[Ff]))?s(?:\\?/|%2[Ff])[A-Za-z0-9_-]{10,}`), false, false, false},
	{"script-web-app-url", rx(`AKfycb[A-Za-z0-9_-]{40,}`), false, true, false},
}

const sensitiveWords = `(?:api[ _-]?key|apikey|access[ _-]?key|secret[ _-]?key|private[ _-]?key|client[ _-]?secret|auth[ _-]?token|secret|token|passw(?:or)?d|passphrase|credentials?)`

var sensitiveName = rx(`(?i)^(?:[A-Za-z0-9]+[_.-])*?` + sensitiveWords + `$`)
var assignment = rx(`(?i)(?:[A-Za-z0-9]+[_.-])*?` + sensitiveWords + `["'*_]*[ \t]*(?::=|=>|=|:)`)
var reference = rx(`^(?:\$[A-Z_][A-Z0-9_]*|\$\{[A-Za-z_][A-Za-z0-9_]*\}|<[A-Za-z_][A-Za-z0-9_ .-]*>|\{\{?[ ]*[A-Za-z_][A-Za-z0-9_. -]*[ ]*\}?\})$`)
var secretName = rx(`^[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+$`)
var codeValue = rx(`^(?:[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*\(.*|[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)+|[A-Za-z_][A-Za-z0-9_.]*\[.*|[a-z][a-z0-9]*(?:_[a-z0-9]+)+|[a-z]+(?:[A-Z][a-z]+)+)$`)
var proseWord = rx(`^[A-Za-z][a-z]*$`)
var mask = rx(`^[xX*.-]+$`)
var digit = rx(`[0-9]`)
var placeholderWords = strings.Fields("none null nil empty required optional provided redacted omitted unset unchanged unknown missing hidden masked rotated revoked expired empty n/a tbd true false yes no str string bytes int integer bool boolean number float any object dict list")

func contains(list []string, value string) bool {
	for _, s := range list {
		if s == value {
			return true
		}
	}
	return false
}
func alnum(b byte) bool { return b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9' }
func shapeBoundary(s shape, b byte) bool {
	if s.name == "cloud-access-key-id" {
		return b >= 'A' && b <= 'Z' || b >= '0' && b <= '9'
	}
	return alnum(b) || (s.right || s.name == "script-web-app-url") && strings.ContainsRune("_-", rune(b))
}
func literalToken(value string, more bool) bool {
	value = strings.TrimRight(strings.Trim(value, "*_"), ",;.")
	return value != "" && !reference.MatchString(value) && !secretName.MatchString(value) && !codeValue.MatchString(value) && !contains(placeholderWords, strings.ToLower(value)) && !mask.MatchString(value) && !(more && proseWord.MatchString(value))
}
func literalQuoted(value string) bool {
	value = strings.TrimSpace(value)
	return value != "" && !reference.MatchString(value) && (len(strings.Fields(value)) > 1 || literalToken(value, false))
}
func literalValue(text string) (bool, string) {
	text = strings.TrimSpace(text)
	if text == "" {
		return false, ""
	}
	if strings.ContainsRune("\"'`", rune(text[0])) {
		value := text[1:]
		if at := strings.IndexByte(value, text[0]); at >= 0 {
			value = value[:at]
		}
		return literalQuoted(value), strings.TrimSpace(value)
	}
	if text[0] == '<' || text[0] == '{' {
		end := byte('}')
		if text[0] == '<' {
			end = '>'
		}
		if at := strings.IndexByte(text, end); at >= 0 {
			at++
			if at < len(text) && text[at] == '}' {
				at++
			}
			if reference.MatchString(text[:at]) {
				return false, text[:at]
			}
		}
	}
	words := strings.Fields(text)
	return literalToken(words[0], len(words) > 1), words[0]
}
func findCredential(text string) *credential {
	for _, s := range shapes {
		for _, at := range s.pattern.FindAllStringIndex(text, -1) {
			if s.left && at[0] > 0 && shapeBoundary(s, text[at[0]-1]) {
				continue
			}
			if s.right && at[1] < len(text) && shapeBoundary(s, text[at[1]]) {
				continue
			}
			value := text[at[0]:at[1]]
			if s.digit && !digit.MatchString(value) {
				continue
			}
			return &credential{s.name, value, strings.Count(text[:at[0]], "\n") + 1}
		}
	}
	for _, at := range assignment.FindAllStringIndex(text, -1) {
		if at[0] > 0 && (alnum(text[at[0]-1]) || text[at[0]-1] == '_') {
			continue
		}
		if at[1] < len(text) && (text[at[1]] == '=' || text[at[1]-1] == ':' && text[at[1]] == ':') {
			continue
		}
		if at[0] > 0 && strings.ContainsRune("!<>=", rune(text[at[0]-1])) {
			continue
		}
		tail := text[at[1]:]
		if end := strings.IndexByte(tail, '\n'); end >= 0 {
			tail = tail[:end]
		}
		if yes, value := literalValue(tail); yes {
			return &credential{"secret-assignment", value, strings.Count(text[:at[0]], "\n") + 1}
		}
	}
	return nil
}
func scrub(text string) string {
	for i := 0; i < 8; i++ {
		found := findCredential(text)
		if found == nil {
			return text
		}
		next := strings.ReplaceAll(text, found.value, withheld)
		if next == text {
			break
		}
		text = next
	}
	return withheld
}
func shown(text string) string {
	if findCredential(text) != nil {
		return withheld
	}
	runes := []rune(text)
	if len(runes) > 1000 {
		runes = runes[:1000]
	}
	for i, r := range runes {
		if !unicode.IsPrint(r) {
			runes[i] = ' '
		}
	}
	return string(runes)
}
func shownValue(v any) any {
	if v == nil {
		return nil
	}
	return shown(str(v))
}
func credentialInValue(v any) (string, string) {
	var walk func(any, string, int) (string, string)
	walk = func(v any, top string, depth int) (string, string) {
		switch value := v.(type) {
		case string:
			if found := findCredential(value); found != nil {
				label := top
				if label == "" || overlapsCredential(label, found.value) {
					label = "a top-level field"
				}
				if depth > 0 {
					label += fmt.Sprintf(" (a value at depth %d)", depth)
				}
				return label, found.rule
			}
		case map[string]any:
			for _, key := range sortedKeys(value) {
				childTop, childDepth := top, depth+1
				if top == "" {
					childTop, childDepth = key, 0
				}
				if found := findCredential(key); found != nil {
					return "a top-level field name", found.rule
				}
				if text, ok := value[key].(string); ok && sensitiveName.MatchString(key) && literalQuoted(text) {
					label := childTop
					if overlapsCredential(label, text) {
						label = "a top-level field"
					}
					return scrub(label), "secret-assignment"
				}
				if where, rule := walk(value[key], childTop, childDepth); rule != "" {
					return where, rule
				}
			}
		case []any:
			for _, item := range value {
				if where, rule := walk(item, top, depth+1); rule != "" {
					return where, rule
				}
			}
		}
		return "", ""
	}
	return walk(v, "", 0)
}
func overlapsCredential(key, value string) bool {
	key, value = strings.ToLower(key), strings.ToLower(value)
	return value != "" && (strings.Contains(key, value) || len([]rune(key)) >= 3 && strings.Contains(value, key))
}
func sortedKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
func str(v any) string {
	if v == nil {
		return ""
	}
	if s, ok := v.(string); ok {
		return s
	}
	return fmt.Sprint(v)
}
func object(v any) map[string]any {
	if m, ok := v.(map[string]any); ok {
		return m
	}
	return map[string]any{}
}
func array(v any) []any {
	if a, ok := v.([]any); ok {
		return a
	}
	return []any{}
}
func stringsOf(v any) []string {
	out := []string{}
	for _, item := range array(v) {
		out = append(out, str(item))
	}
	return out
}
