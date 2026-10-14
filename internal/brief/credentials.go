package brief

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"
)

type credential struct {
	rule   string
	line   int
	secret string
}
type credentialShape struct {
	rule          string
	pattern       *regexp.Regexp
	before, after string
	digit         bool
}

const sensitiveWords = `(?:api[ _-]?key|apikey|access[ _-]?key|secret[ _-]?key|private[ _-]?key|client[ _-]?secret|auth[ _-]?token|secret|token|passw(?:or)?d|passphrase|credentials?)`
const sensitivePrefix = `(?:[A-Za-z0-9]+[_.-])*?`
const addressSeparator = `(?:\\?/|%2[Ff])`

func shape(rule, pattern string) credentialShape {
	return credentialShape{rule: rule, pattern: regexp.MustCompile(pattern)}
}
func boundedShape(rule, pattern, before, after string, digit bool) credentialShape {
	s := shape(rule, pattern)
	s.before, s.after, s.digit = before, after, digit
	return s
}

var credentialShapes = []credentialShape{
	shape("private-key", `-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----`),
	shape("authorization-header", `(?i)\b(?:proxy-)?authorization["']?`+space+`*[:=]`+space+`*["']?(?:bearer|basic|token|digest)`+space+`+[A-Za-z0-9._~+/=-]{8,}`),
	shape("bearer-token", `(?i)\bbearer`+space+`+[A-Za-z0-9._~+/-]{16,}`),
	shape("code-host-token", `\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,}|glpat-[A-Za-z0-9_-]{20,})`),
	shape("chat-token", `\bxox[abposr]-[A-Za-z0-9-]{10,}`),
	boundedShape("chat-bot-token", `\b[MNO][A-Za-z0-9_-]{23,27}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,40}`, "", "token", false),
	boundedShape("messenger-bot-token", `\b[0-9]{8,10}:AA[A-Za-z0-9_-]{33}`, "", "token", false),
	boundedShape("cloud-access-key-id", `(?:AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}`, "upper", "upper", false),
	shape("cloud-api-key", `\bAIza[0-9A-Za-z_-]{35}`),
	shape("oauth-access-token", `\bya29\.[0-9A-Za-z_-]{20,}`),
	boundedShape("prefixed-secret-key", `sk-[A-Za-z0-9_-]{20,}`, "alnum", "", true),
	shape("payment-secret-key", `\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}`),
	shape("package-registry-token", `\b(?:npm_[A-Za-z0-9]{36}|pypi-[A-Za-z0-9_-]{50,})`),
	shape("model-hub-token", `\bhf_[A-Za-z0-9]{30,}`),
	boundedShape("embedding-api-key", `pa-[A-Za-z0-9_-]{40,}`, "alnum", "", true),
	shape("json-web-token", `\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}`),
	shape("url-credentials", `\b[A-Za-z][A-Za-z0-9+.-]*://[^\s/:@]+:[^\s/@]+@`),
	shape("chat-webhook-url", `(?i:discord(?:app)?\.com)`+addressSeparator+`api`+addressSeparator+`(?:v[0-9]+`+addressSeparator+`)?webhooks`+addressSeparator+`[0-9]{5,}`+addressSeparator+`[A-Za-z0-9_-]{6,}`),
	shape("chat-webhook-url", `(?i:hooks\.slack\.com)`+addressSeparator+`(?:services`+addressSeparator+`T[A-Z0-9]{5,}`+addressSeparator+`B[A-Z0-9]{5,}|workflows`+addressSeparator+`T[A-Z0-9]{5,}`+addressSeparator+`A[A-Z0-9]{5,}`+addressSeparator+`[0-9]{5,}|triggers`+addressSeparator+`T[A-Z0-9]{5,}`+addressSeparator+`[0-9]{5,})`+addressSeparator+`[A-Za-z0-9_-]{6,}`),
	shape("script-web-app-url", `(?i:script\.google\.com)`+addressSeparator+`(?:a`+addressSeparator+`(?:macros`+addressSeparator+`)?[A-Za-z0-9.-]+`+addressSeparator+`)?(?:macros`+addressSeparator+`)?(?:u`+addressSeparator+`[0-9]+`+addressSeparator+`)?s`+addressSeparator+`[A-Za-z0-9_-]{10,}`),
	boundedShape("script-web-app-url", `AKfycb[A-Za-z0-9_-]{40,}`, "token", "", false),
}

var (
	sensitiveName     = regexp.MustCompile(`(?i)^` + sensitivePrefix + sensitiveWords + `$`)
	assignmentPattern = regexp.MustCompile(`(?i)` + sensitivePrefix + sensitiveWords + `["'*_]*[ \t]*(?::=|=>|=|:)`)
	referencePattern  = regexp.MustCompile(`^(?:\$[A-Z_][A-Z0-9_]*|\$\{[A-Za-z_][A-Za-z0-9_]*\}|<[A-Za-z_][A-Za-z0-9_ .-]*>|\{\{?[ ]*[A-Za-z_][A-Za-z0-9_. -]*[ ]*\}?\})$`)
	secretReference   = regexp.MustCompile(`^[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+$`)
	codePattern       = regexp.MustCompile(`^(?:[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*\(.*|[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)+|[A-Za-z_][A-Za-z0-9_.]*\[.*|[a-z][a-z0-9]*(?:_[a-z0-9]+)+|[a-z]+(?:[A-Z][a-z]+)+)$`)
	proseWord         = regexp.MustCompile(`^[A-Za-z][a-z]*$`)
	maskPattern       = regexp.MustCompile(`^[xX*.-]+$`)
	placeholderWords  = strings.Fields("none null nil empty required optional provided redacted omitted unset unchanged unknown missing hidden masked rotated revoked expired n/a tbd true false yes no str string bytes int integer bool boolean number float any object dict list")
)

func literalToken(value string, more bool) bool {
	value = strings.TrimRight(strings.Trim(value, "*_"), ",;.")
	if value == "" || referencePattern.MatchString(value) || secretReference.MatchString(value) || codePattern.MatchString(value) || maskPattern.MatchString(value) {
		return false
	}
	for _, word := range placeholderWords {
		if strings.EqualFold(value, word) {
			return false
		}
	}
	return !(more && proseWord.MatchString(value))
}

func literalQuoted(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" || referencePattern.MatchString(value) {
		return false
	}
	return len(strings.Fields(value)) > 1 || literalToken(value, false)
}

func literalValue(text string) (bool, string) {
	text = strings.TrimSpace(text)
	if text == "" {
		return false, ""
	}
	if strings.ContainsRune("\"'`", rune(text[0])) {
		end := strings.IndexByte(text[1:], text[0])
		value := text[1:]
		if end >= 0 {
			value = text[1 : 1+end]
		}
		return literalQuoted(value), value
	}
	if text[0] == '<' || text[0] == '{' {
		closing := byte('}')
		if text[0] == '<' {
			closing = '>'
		}
		if end := strings.IndexByte(text, closing); end >= 0 {
			end++
			if end < len(text) && text[end] == '}' {
				end++
			}
			if referencePattern.MatchString(text[:end]) {
				return false, text[:end]
			}
		}
	}
	words := strings.Fields(text)
	return literalToken(words[0], len(words) > 1), words[0]
}

func wordRune(r rune) bool { return unicode.IsLetter(r) || unicode.IsNumber(r) || r == '_' }

func classContains(class string, b byte) bool {
	upper := b >= 'A' && b <= 'Z'
	lower := b >= 'a' && b <= 'z'
	digit := b >= '0' && b <= '9'
	switch class {
	case "upper":
		return upper || digit
	case "alnum":
		return upper || lower || digit
	case "token":
		return upper || lower || digit || b == '_' || b == '-'
	}
	return false
}

func findCredential(text string) *credential {
	for _, s := range credentialShapes {
		for search := 0; search < len(text); {
			match := s.pattern.FindStringIndex(text[search:])
			if match == nil {
				break
			}
			start, end := search+match[0], search+match[1]
			// Recheck overlapping candidates when a lookaround condition fails.
			search = start + 1
			if start > 0 && classContains(s.before, text[start-1]) {
				continue
			}
			if end < len(text) && classContains(s.after, text[end]) {
				continue
			}
			// Python's word boundary also regards Unicode letters as word characters.
			if strings.Contains(s.pattern.String(), `\b`) && start > 0 {
				r, _ := utf8.DecodeLastRuneInString(text[:start])
				if wordRune(r) {
					continue
				}
			}
			if s.digit && !strings.ContainsAny(text[start:end], "0123456789") {
				continue
			}
			return &credential{s.rule, strings.Count(text[:start], "\n") + 1, text[start:end]}
		}
	}
	for _, match := range assignmentPattern.FindAllStringIndex(text, -1) {
		start, end := match[0], match[1]
		if start > 0 && (classContains("alnum", text[start-1]) || text[start-1] == '_') {
			continue
		}
		last := text[end-1]
		if end < len(text) && (last == '=' && text[end] == '=' || last == ':' && (text[end] == ':' || text[end] == '=')) {
			continue
		}
		remaining := text[end:]
		if endLine := strings.IndexByte(remaining, '\n'); endLine >= 0 {
			remaining = remaining[:endLine]
		}
		if literal, value := literalValue(remaining); literal {
			return &credential{"secret-assignment", strings.Count(text[:start], "\n") + 1, value}
		}
	}
	return nil
}

func shownName(name string) string {
	if findCredential(name) != nil {
		return "[withheld]"
	}
	return name
}

// Only a safe top-level field and its depth enter an error; nested keys and
// literal credential values remain private, including when they overlap a key.
func credentialInValue(value any) (string, string) {
	type finding struct {
		top, kind string
		depth     int
		found     *credential
	}
	var walk func(any, string, int) *finding
	walk = func(value any, top string, depth int) *finding {
		switch v := value.(type) {
		case string:
			if f := findCredential(v); f != nil {
				return &finding{top, "value", depth, f}
			}
		case map[string]any:
			keys := make([]string, 0, len(v))
			for key := range v {
				keys = append(keys, key)
			}
			sort.Strings(keys)
			for _, key := range keys {
				here, child := top, depth+1
				if top == "" {
					here, child = key, 0
				}
				if f := findCredential(key); f != nil {
					kind := "field name"
					if top == "" {
						kind = "top-level field name"
					}
					f.secret = key
					return &finding{here, kind, child, f}
				}
				if s, ok := v[key].(string); ok && sensitiveName.MatchString(key) && literalQuoted(s) {
					return &finding{here, "value", child, &credential{rule: "secret-assignment", secret: s}}
				}
				if f := walk(v[key], here, child); f != nil {
					return f
				}
			}
		case []any:
			for _, item := range v {
				if f := walk(item, top, depth+1); f != nil {
					return f
				}
			}
		}
		return nil
	}
	f := walk(value, "", 0)
	if f == nil {
		return "", ""
	}
	name := f.top
	key, secret := strings.ToLower(name), strings.ToLower(f.found.secret)
	if name == "" || f.kind == "top-level field name" || secret != "" && (strings.Contains(key, secret) || len(key) >= 3 && strings.Contains(secret, key)) {
		name = "a top-level field"
	}
	if f.kind == "top-level field name" {
		return "a top-level field name", f.found.rule
	}
	if f.depth == 0 && f.kind == "value" {
		return name, f.found.rule
	}
	return fmt.Sprintf("%s (a %s at depth %d)", name, f.kind, f.depth), f.found.rule
}
