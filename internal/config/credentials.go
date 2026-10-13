package config

import (
	"fmt"
	"regexp"
	"strings"
)

// Findings keep the matched text private: only rule, line and a screened field
// label may be used in diagnostics. Never format a finding itself.
type finding struct {
	rule   string
	line   int
	secret string
}

type shape struct {
	rule     string
	pattern  *regexp.Regexp
	boundary string
	digit    bool
}

func credentialShape(rule, pattern, boundary string, digit bool) shape {
	return shape{rule, regexp.MustCompile(pattern), boundary, digit}
}

const sensitiveWords = `(?:api[ _-]?key|apikey|access[ _-]?key|secret[ _-]?key|private[ _-]?key|client[ _-]?secret|auth[ _-]?token|secret|token|passw(?:or)?d|passphrase|credentials?)`
const sensitivePrefix = `(?:[A-Za-z0-9]+[_.-])*?`
const addressSeparator = `(?:\\?/|%2[Ff])`

var sensitiveName = regexp.MustCompile(`(?i)^` + sensitivePrefix + sensitiveWords + `$`)
var assignments = regexp.MustCompile(`(?i)` + sensitivePrefix + sensitiveWords + `["'*_]*[ \t]*(?::=|=>|=|:)`)
var reference = regexp.MustCompile(`^(?:\$[A-Z_][A-Z0-9_]*|\$\{[A-Za-z_][A-Za-z0-9_]*\}|<[A-Za-z_][A-Za-z0-9_ .-]*>|\{\{?[ ]*[A-Za-z_][A-Za-z0-9_. -]*[ ]*\}?\})$`)
var secretReference = regexp.MustCompile(`^[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+$`)
var codeReference = regexp.MustCompile(`^(?:[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*\(.*|[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)+|[A-Za-z_][A-Za-z0-9_.]*\[.*|[a-z][a-z0-9]*(?:_[a-z0-9]+)+|[a-z]+(?:[A-Z][a-z]+)+)$`)
var proseWord = regexp.MustCompile(`^[A-Za-z][a-z]*$`)
var mask = regexp.MustCompile(`^[xX*.-]+$`)
var placeholderWords = map[string]bool{}

func init() {
	for _, word := range strings.Fields("none null nil empty required optional provided redacted omitted unset unchanged unknown missing hidden masked rotated revoked expired n/a tbd true false yes no str string bytes int integer bool boolean number float any object dict list") {
		placeholderWords[word] = true
	}
}

var credentialShapes = []shape{
	credentialShape("private-key", `-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----`, "", false),
	credentialShape("authorization-header", `(?i)\b(?:proxy-)?authorization["']?\s*[:=]\s*["']?(?:bearer|basic|token|digest)\s+[A-Za-z0-9._~+/=-]{8,}`, "", false),
	credentialShape("bearer-token", `(?i)\bbearer\s+[A-Za-z0-9._~+/-]{16,}`, "", false),
	credentialShape("code-host-token", `\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,}|glpat-[A-Za-z0-9_-]{20,})`, "", false),
	credentialShape("chat-token", `\bxox[abposr]-[A-Za-z0-9-]{10,}`, "", false),
	credentialShape("chat-bot-token", `\b[MNO][A-Za-z0-9_-]{23,27}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,40}`, "after-token", false),
	credentialShape("messenger-bot-token", `\b[0-9]{8,10}:AA[A-Za-z0-9_-]{33}`, "after-token", false),
	credentialShape("cloud-access-key-id", `(?:AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}`, "upper", false),
	credentialShape("cloud-api-key", `\bAIza[0-9A-Za-z_-]{35}`, "", false),
	credentialShape("oauth-access-token", `\bya29\.[0-9A-Za-z_-]{20,}`, "", false),
	credentialShape("prefixed-secret-key", `sk-[A-Za-z0-9_-]{20,}`, "before-alnum", true),
	credentialShape("payment-secret-key", `\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}`, "", false),
	credentialShape("package-registry-token", `\b(?:npm_[A-Za-z0-9]{36}|pypi-[A-Za-z0-9_-]{50,})`, "", false),
	credentialShape("model-hub-token", `\bhf_[A-Za-z0-9]{30,}`, "", false),
	credentialShape("embedding-api-key", `pa-[A-Za-z0-9_-]{40,}`, "before-alnum", true),
	credentialShape("json-web-token", `\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}`, "", false),
	credentialShape("url-credentials", `\b[A-Za-z][A-Za-z0-9+.-]*://[^\s/:@]+:[^\s/@]+@`, "", false),
	credentialShape("chat-webhook-url", `(?i:discord(?:app)?\.com)`+addressSeparator+`api`+addressSeparator+`(?:v[0-9]+`+addressSeparator+`)?webhooks`+addressSeparator+`[0-9]{5,}`+addressSeparator+`[A-Za-z0-9_-]{6,}`, "", false),
	credentialShape("chat-webhook-url", `(?i:hooks\.slack\.com)`+addressSeparator+`(?:services`+addressSeparator+`T[A-Z0-9]{5,}`+addressSeparator+`B[A-Z0-9]{5,}|workflows`+addressSeparator+`T[A-Z0-9]{5,}`+addressSeparator+`A[A-Z0-9]{5,}`+addressSeparator+`[0-9]{5,}|triggers`+addressSeparator+`T[A-Z0-9]{5,}`+addressSeparator+`[0-9]{5,})`+addressSeparator+`[A-Za-z0-9_-]{6,}`, "", false),
	credentialShape("script-web-app-url", `(?i:script\.google\.com)`+addressSeparator+`(?:a`+addressSeparator+`(?:macros`+addressSeparator+`)?[A-Za-z0-9.-]+`+addressSeparator+`)?(?:macros`+addressSeparator+`)?(?:u`+addressSeparator+`[0-9]+`+addressSeparator+`)?s`+addressSeparator+`[A-Za-z0-9_-]{10,}`, "", false),
	credentialShape("script-web-app-url", `AKfycb[A-Za-z0-9_-]{40,}`, "before-token", false),
}

func alnum(character byte) bool {
	return character >= 'A' && character <= 'Z' || character >= 'a' && character <= 'z' || character >= '0' && character <= '9'
}
func upperAlnum(character byte) bool {
	return character >= 'A' && character <= 'Z' || character >= '0' && character <= '9'
}
func tokenByte(character byte) bool { return alnum(character) || character == '_' || character == '-' }

func validBoundary(rule shape, text string, start, end int) bool {
	switch rule.boundary {
	case "upper":
		if start > 0 && upperAlnum(text[start-1]) || end < len(text) && upperAlnum(text[end]) {
			return false
		}
	case "before-alnum":
		if start > 0 && alnum(text[start-1]) {
			return false
		}
	case "before-token":
		if start > 0 && tokenByte(text[start-1]) {
			return false
		}
	case "after-token":
		if end < len(text) && tokenByte(text[end]) {
			return false
		}
	}
	return !rule.digit || versionDigit.MatchString(text[start:end])
}

func literalToken(value string, moreWords bool) bool {
	value = strings.TrimRight(strings.Trim(value, "*_"), ",;.")
	if value == "" || reference.MatchString(value) || secretReference.MatchString(value) || codeReference.MatchString(value) || placeholderWords[strings.ToLower(value)] || mask.MatchString(value) {
		return false
	}
	return !moreWords || !proseWord.MatchString(value)
}

func literalQuoted(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" || reference.MatchString(value) {
		return false
	}
	if len(strings.Fields(value)) > 1 {
		return true
	}
	return literalToken(value, false)
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
			value = text[1 : end+1]
		}
		return literalQuoted(value), value
	}
	if text[0] == '<' || text[0] == '{' {
		closing := byte('}')
		if text[0] == '<' {
			closing = '>'
		}
		end := strings.IndexByte(text, closing)
		if end >= 0 {
			end++
			if end < len(text) && text[end] == '}' {
				end++
			}
			candidate := text[:end]
			if reference.MatchString(candidate) {
				return false, candidate
			}
		}
	}
	words := strings.Fields(text)
	return literalToken(words[0], len(words) > 1), words[0]
}

func detectText(text string) *finding {
	for _, rule := range credentialShapes {
		for _, match := range rule.pattern.FindAllStringIndex(text, -1) {
			if validBoundary(rule, text, match[0], match[1]) {
				return &finding{rule.rule, strings.Count(text[:match[0]], "\n") + 1, text[match[0]:match[1]]}
			}
		}
	}
	for _, match := range assignments.FindAllStringIndex(text, -1) {
		start, end := match[0], match[1]
		if start > 0 && (alnum(text[start-1]) || text[start-1] == '_') {
			continue
		}
		if end < len(text) && ((text[end-1] == '=' && text[end] == '=') || (text[end-1] == ':' && (text[end] == ':' || text[end] == '='))) {
			continue
		}
		tail := text[end:]
		if newline := strings.IndexByte(tail, '\n'); newline >= 0 {
			tail = tail[:newline]
		}
		if literal, secret := literalValue(tail); literal {
			return &finding{"secret-assignment", strings.Count(text[:start], "\n") + 1, secret}
		}
	}
	return nil
}

type valueFinding struct {
	top   string
	depth int
	kind  string
	match *finding
}

func walkCredentials(value any, top string, depth int) *valueFinding {
	switch value := value.(type) {
	case map[string]string:
		values := make(map[string]any, len(value))
		for key, item := range value {
			values[key] = item
		}
		return walkCredentials(values, top, depth)
	case map[string]map[string]any:
		values := make(map[string]any, len(value))
		for key, item := range value {
			values[key] = item
		}
		return walkCredentials(values, top, depth)
	case []string:
		for _, item := range value {
			if found := walkCredentials(item, top, depth+1); found != nil {
				return found
			}
		}
	case string:
		if found := detectText(value); found != nil {
			return &valueFinding{top, depth, "value", found}
		}
	case map[string]any:
		child := depth
		if top != "" {
			child++
		}
		for _, key := range keys(value) {
			item, here := value[key], top
			if here == "" {
				here = key
			}
			if found := detectText(key); found != nil {
				kind := "field name"
				if top == "" {
					kind = "top-level field name"
				}
				found.secret = key
				return &valueFinding{here, child, kind, found}
			}
			if word, ok := item.(string); ok && sensitiveName.MatchString(key) && literalQuoted(word) {
				return &valueFinding{here, child, "value", &finding{rule: "secret-assignment", secret: word}}
			}
			if found := walkCredentials(item, here, child); found != nil {
				return found
			}
		}
	case []any:
		for _, item := range value {
			if found := walkCredentials(item, top, depth+1); found != nil {
				return found
			}
		}
	}
	return nil
}

func detectValue(value any) (where, rule string) {
	found := walkCredentials(value, "", 0)
	if found == nil {
		return "", ""
	}
	if found.kind == "top-level field name" {
		return "a top-level field name", found.match.rule
	}
	name := found.top
	key, secret := strings.ToLower(name), strings.ToLower(found.match.secret)
	if name == "" || secret != "" && (strings.Contains(key, secret) || len(key) >= 3 && strings.Contains(secret, key)) {
		name = "a top-level field"
	}
	if found.depth == 0 && found.kind == "value" {
		return name, found.match.rule
	}
	return fmt.Sprintf("%s (a %s at depth %d)", name, found.kind, found.depth), found.match.rule
}
