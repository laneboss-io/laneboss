package decisionsrv

import (
	"reflect"
	"regexp"
	"strings"
)

// This private detector mirrors the launcher's screening before an owner message
// reaches a configured judge. Findings are booleans: secret bytes never enter errors.
var credentialShapes = []*regexp.Regexp{
	regexp.MustCompile(`-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----`),
	regexp.MustCompile(`(?i)\b(?:proxy-)?authorization["']?\s*[:=]\s*["']?(?:bearer|basic|token|digest)\s+[A-Za-z0-9._~+/=-]{8,}`),
	regexp.MustCompile(`(?i)\bbearer\s+[A-Za-z0-9._~+/-]{16,}`),
	regexp.MustCompile(`\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,}|glpat-[A-Za-z0-9_-]{20,})`),
	regexp.MustCompile(`\bxox[abposr]-[A-Za-z0-9-]{10,}`),
	regexp.MustCompile(`\b[MNO][A-Za-z0-9_-]{23,27}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,40}`),
	regexp.MustCompile(`\b[0-9]{8,10}:AA[A-Za-z0-9_-]{33}`),
	regexp.MustCompile(`(?:AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}`),
	regexp.MustCompile(`\bAIza[0-9A-Za-z_-]{35}`),
	regexp.MustCompile(`\bya29\.[0-9A-Za-z_-]{20,}`),
	regexp.MustCompile(`\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}`),
	regexp.MustCompile(`\b(?:npm_[A-Za-z0-9]{36}|pypi-[A-Za-z0-9_-]{50,})`),
	regexp.MustCompile(`\bhf_[A-Za-z0-9]{30,}`),
	regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}`),
	regexp.MustCompile(`\b[A-Za-z][A-Za-z0-9+.-]*://[^\s/:@]+:[^\s/@]+@`),
	regexp.MustCompile(`(?i:discord(?:app)?\.com)(?:\\?/|%2[Ff])api(?:\\?/|%2[Ff])(?:v[0-9]+(?:\\?/|%2[Ff]))?webhooks(?:\\?/|%2[Ff])[0-9]{5,}(?:\\?/|%2[Ff])[A-Za-z0-9_-]{6,}`),
	regexp.MustCompile(`(?i:hooks\.slack\.com)(?:\\?/|%2[Ff])(?:services(?:\\?/|%2[Ff])T[A-Z0-9]{5,}(?:\\?/|%2[Ff])B[A-Z0-9]{5,}|workflows(?:\\?/|%2[Ff])T[A-Z0-9]{5,}(?:\\?/|%2[Ff])A[A-Z0-9]{5,}(?:\\?/|%2[Ff])[0-9]{5,}|triggers(?:\\?/|%2[Ff])T[A-Z0-9]{5,}(?:\\?/|%2[Ff])[0-9]{5,})(?:\\?/|%2[Ff])[A-Za-z0-9_-]{6,}`),
	regexp.MustCompile(`(?i:script\.google\.com)(?:\\?/|%2[Ff])(?:a(?:\\?/|%2[Ff])(?:macros(?:\\?/|%2[Ff]))?[A-Za-z0-9.-]+(?:\\?/|%2[Ff]))?(?:macros(?:\\?/|%2[Ff]))?(?:u(?:\\?/|%2[Ff])[0-9]+(?:\\?/|%2[Ff]))?s(?:\\?/|%2[Ff])[A-Za-z0-9_-]{10,}`),
	regexp.MustCompile(`AKfycb[A-Za-z0-9_-]{40,}`),
}
var prefixedKeys = regexp.MustCompile(`(?:sk-[A-Za-z0-9_-]{20,}|pa-[A-Za-z0-9_-]{40,})`)

const sensitiveWords = `(?:api[ _-]?key|apikey|access[ _-]?key|secret[ _-]?key|private[ _-]?key|client[ _-]?secret|auth[ _-]?token|secret|token|passw(?:or)?d|passphrase|credentials?)`
const sensitivePrefix = `(?:[A-Za-z0-9]+[_.-])*?`

var sensitiveName = regexp.MustCompile(`(?i)^` + sensitivePrefix + sensitiveWords + `$`)
var secretAssignment = regexp.MustCompile(`(?i)(?:^|[^A-Za-z0-9_])` + sensitivePrefix + sensitiveWords + `["'*_]*[ \t]*(?::=|=>|=|:)`)
var referenceValue = regexp.MustCompile(`^(?:\$[A-Z_][A-Z0-9_]*|\$\{[A-Za-z_][A-Za-z0-9_]*\}|<[A-Za-z_][A-Za-z0-9_ .-]*>|\{\{?[ ]*[A-Za-z_][A-Za-z0-9_. -]*[ ]*\}?\})$`)
var secretNameValue = regexp.MustCompile(`^[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+$`)
var codeValue = regexp.MustCompile(`^(?:[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*\(.*|[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)+|[A-Za-z_][A-Za-z0-9_.]*\[.*|[a-z][a-z0-9]*(?:_[a-z0-9]+)+|[a-z]+(?:[A-Z][a-z]+)+)$`)
var proseWord = regexp.MustCompile(`^[A-Za-z][a-z]*$`)
var maskValue = regexp.MustCompile(`^[xX*.-]+$`)
var placeholderValues = wordsSet("none null nil empty required optional provided redacted omitted unset unchanged unknown missing hidden masked rotated revoked expired n/a tbd true false yes no str string bytes int integer bool boolean number float any object dict list")

func literalToken(value string, moreWords bool) bool {
	value = strings.TrimRight(strings.Trim(value, "*_"), ",;.")
	if value == "" || referenceValue.MatchString(value) || secretNameValue.MatchString(value) || codeValue.MatchString(value) || placeholderValues[strings.ToLower(value)] || maskValue.MatchString(value) || (moreWords && proseWord.MatchString(value)) {
		return false
	}
	return true
}
func literalQuoted(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" || referenceValue.MatchString(value) {
		return false
	}
	if len(strings.Fields(value)) > 1 {
		return true
	}
	return literalToken(value, false)
}
func literalValue(text string) bool {
	text = strings.TrimSpace(text)
	if text == "" {
		return false
	}
	if strings.ContainsRune("\"'`", rune(text[0])) {
		end := strings.IndexByte(text[1:], text[0])
		if end >= 0 {
			return literalQuoted(text[1 : 1+end])
		}
		return literalQuoted(text[1:])
	}
	if text[0] == '<' || text[0] == '{' {
		closing := byte('}')
		if text[0] == '<' {
			closing = '>'
		}
		end := strings.IndexByte(text, closing)
		if end >= 0 {
			if end+1 < len(text) && text[end+1] == '}' {
				end++
			}
			if referenceValue.MatchString(text[:end+1]) {
				return false
			}
		}
	}
	words := strings.Fields(text)
	return literalToken(words[0], len(words) > 1)
}
func credentialsInText(text string) bool {
	for _, shape := range credentialShapes {
		if shape.MatchString(text) {
			return true
		}
	}
	for _, match := range prefixedKeys.FindAllString(text, -1) {
		if strings.ContainsAny(match, "0123456789") {
			return true
		}
	}
	for _, position := range secretAssignment.FindAllStringIndex(text, -1) {
		end := position[1]
		prefix := text[position[0]:end]
		if end < len(text) && ((strings.HasSuffix(prefix, "=") && text[end] == '=') || (strings.HasSuffix(prefix, ":") && (text[end] == ':' || text[end] == '='))) {
			continue
		}
		rest := text[end:]
		if next := strings.IndexByte(rest, '\n'); next >= 0 {
			rest = rest[:next]
		}
		if literalValue(rest) {
			return true
		}
	}
	return false
}
func credentialsInValue(v any) bool {
	switch x := v.(type) {
	case string:
		return credentialsInText(x)
	case object:
		for k, item := range x {
			if credentialsInText(k) {
				return true
			}
			if text, ok := item.(string); ok && sensitiveName.MatchString(k) && literalQuoted(text) {
				return true
			}
			if credentialsInValue(item) {
				return true
			}
		}
	case []any:
		for _, item := range x {
			if credentialsInValue(item) {
				return true
			}
		}
	case []string:
		for _, item := range x {
			if credentialsInText(item) {
				return true
			}
		}
	default:
		value := reflect.ValueOf(v)
		if value.IsValid() && (value.Kind() == reflect.Slice || value.Kind() == reflect.Array) {
			for i := 0; i < value.Len(); i++ {
				if credentialsInValue(value.Index(i).Interface()) {
					return true
				}
			}
		}
	}
	return false
}
