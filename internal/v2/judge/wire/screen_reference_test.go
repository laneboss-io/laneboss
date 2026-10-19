// Frozen reference from 7328683, wire/screen.go. Identifier prefixes only.
// Keep its patterns and behavior independent of production. Test-only code.
package wire

import (
	"encoding/json"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"unicode"

	"laneboss.io/laneboss/internal/typesafe"
)

type fix1CredentialShape struct {
	re    *regexp.Regexp
	digit bool
}

func fix1Shape(pattern string, digit bool) fix1CredentialShape {
	// Credential-shaped substrings remain sensitive when arbitrary text touches
	// either end. A Unicode/ASCII word boundary would hide a credential appended
	// to a word or to the complete long CJK input used by the suffix canary.
	return fix1CredentialShape{regexp.MustCompile(pattern), digit}
}

const fix1SecretWords = `(?:ap[iİı][ _-]?key|ap[iİı]key|access[ _-]?key|secret[ _-]?key|pr[iİı]vate[ _-]?key|cl[iİı]ent[ _-]?secret|auth[ _-]?token|secret|token|passw(?:or)?d|passphrase|credent[iİı]als?)`
const fix1SecretPrefix = `(?:[A-Za-zİı0-9]+[_.-])*?`
const fix1UrlSeparator = `(?:\\?/|%2[Ff])`
const fix1SecretSpace = `[\s\v\p{Z}\x{0085}\x{001c}-\x{001f}]`

// These are the retained credential shapes, not a command allowlist or deny
// engine. A match withholds a judge request and never grants/refuses an action.
var fix1CredentialShapes = []fix1CredentialShape{
	fix1Shape(`-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----`, false),
	fix1Shape(`(?i:(?:proxy-)?author[iİı]zat[iİı]on["']?`+fix1SecretSpace+`*[:=]`+fix1SecretSpace+
		`*["']?(?:bearer|bas[iİı]c|token|d[iİı]gest)`+fix1SecretSpace+`+[A-Za-zİı0-9._~+/=-]{8,})`, false),
	fix1Shape(`(?i:bearer`+fix1SecretSpace+`+[A-Za-zİı0-9._~+/-]{16,})`, false),
	fix1Shape(`(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,}|glpat-[A-Za-z0-9_-]{20,})`, false),
	fix1Shape(`xox[abposr]-[A-Za-z0-9-]{10,}`, false),
	fix1Shape(`[MNO][A-Za-z0-9_-]{23,27}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,40}`, false),
	fix1Shape(`[0-9]{8,10}:AA[A-Za-z0-9_-]{33}`, false),
	fix1Shape(`(?:AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}`, false),
	fix1Shape(`AIza[0-9A-Za-z_-]{35}`, false),
	fix1Shape(`ya29\.[0-9A-Za-z_-]{20,}`, false),
	fix1Shape(`sk-[A-Za-z0-9_-]{20,}`, true),
	fix1Shape(`(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}`, false),
	fix1Shape(`(?:npm_[A-Za-z0-9]{36}|pypi-[A-Za-z0-9_-]{50,})`, false),
	fix1Shape(`hf_[A-Za-z0-9]{30,}`, false),
	fix1Shape(`pa-[A-Za-z0-9_-]{40,}`, true),
	fix1Shape(`eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}`, false),
	fix1Shape(`[A-Za-z][A-Za-z0-9+.-]*://[^[:space:]\p{Z}\x{0085}\x{001c}-\x{001f}/:@]+:[^[:space:]\p{Z}\x{0085}\x{001c}-\x{001f}/@]+@`, false),
	fix1Shape(`(?i:d[iİı]scord(?:app)?\.com)`+fix1UrlSeparator+`api`+fix1UrlSeparator+
		`(?:v[0-9]+`+fix1UrlSeparator+`)?webhooks`+fix1UrlSeparator+`[0-9]{5,}`+
		fix1UrlSeparator+`[A-Za-z0-9_-]{6,}`, false),
	fix1Shape(`(?i:hooks\.slack\.com)`+fix1UrlSeparator+`(?:services`+fix1UrlSeparator+
		`T[A-Z0-9]{5,}`+fix1UrlSeparator+`B[A-Z0-9]{5,}|workflows`+fix1UrlSeparator+
		`T[A-Z0-9]{5,}`+fix1UrlSeparator+`A[A-Z0-9]{5,}`+fix1UrlSeparator+
		`[0-9]{5,}|triggers`+fix1UrlSeparator+`T[A-Z0-9]{5,}`+fix1UrlSeparator+
		`[0-9]{5,})`+fix1UrlSeparator+`[A-Za-z0-9_-]{6,}`, false),
	fix1Shape(`(?i:scr[iİı]pt\.google\.com)`+fix1UrlSeparator+`(?:a`+fix1UrlSeparator+
		`(?:macros`+fix1UrlSeparator+`)?[A-Za-z0-9.-]+`+fix1UrlSeparator+
		`)?(?:macros`+fix1UrlSeparator+`)?(?:u`+fix1UrlSeparator+`[0-9]+`+fix1UrlSeparator+
		`)?s`+fix1UrlSeparator+`[A-Za-z0-9_-]{10,}`, false),
	fix1Shape(`AKfycb[A-Za-z0-9_-]{40,}`, false),
}

var fix1Assignment = regexp.MustCompile(`(?i:` + fix1SecretPrefix + fix1SecretWords + `["'*_]*[ \t]*(?::=|=>|=|:))`)
var fix1SensitiveName = regexp.MustCompile(`(?i:^` + fix1SecretPrefix + fix1SecretWords + `$)`)
var fix1Reference = regexp.MustCompile(`^(?:\$[A-Z_][A-Z0-9_]*|\$\{[A-Za-z_][A-Za-z0-9_]*\}|<[A-Za-z_][A-Za-z0-9_ .-]*>|\{\{?[ ]*[A-Za-z_][A-Za-z0-9_. -]*[ ]*\}?\})$`)
var fix1NamedReference = regexp.MustCompile(`^[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+$`)
var fix1CodeReference = regexp.MustCompile(`^(?:[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*\(.*|[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)+|[A-Za-z_][A-Za-z0-9_.]*\[.*|[a-z][a-z0-9]*(?:_[a-z0-9]+)+|[a-z]+(?:[A-Z][a-z]+)+)$`)
var fix1ProseWord = regexp.MustCompile(`^[A-Za-z][a-z]*$`)
var fix1Mask = regexp.MustCompile(`^[xX*.-]+$`)

var fix1Placeholders = func() map[string]bool {
	m := map[string]bool{}
	words := "none null nil empty required optional provided redacted omitted unset " +
		"unchanged unknown missing hidden masked rotated revoked expired n/a tbd " +
		"true false yes no str string bytes int integer bool boolean number float any object dict list"
	for _, word := range strings.Fields(words) {
		m[word] = true
	}
	return m
}()

func fix1CredentialText(text string) bool {
	for _, rule := range fix1CredentialShapes {
		for _, match := range rule.re.FindAllStringIndex(text, -1) {
			if rule.digit && !strings.ContainsAny(text[match[0]:match[1]], "0123456789") {
				continue
			}
			return true
		}
	}
	return false
}

func fix1SecretText(text string) bool {
	if fix1CredentialText(text) {
		return true
	}
	for _, match := range fix1Assignment.FindAllStringIndex(text, -1) {
		separator := text[match[1]-1]
		if match[1] < len(text) && (separator == '=' && text[match[1]] == '=' ||
			separator == ':' && (text[match[1]] == ':' || text[match[1]] == '=')) {
			continue
		}
		if fix1LiteralValue(text[match[1]:]) {
			return true
		}
	}
	return false
}

func fix1LiteralToken(value string, moreWords bool) bool {
	value = strings.TrimRight(strings.Trim(value, "*_"), ",;.")
	if value == "" || fix1Reference.MatchString(value) || fix1NamedReference.MatchString(value) ||
		fix1CodeReference.MatchString(value) || fix1Placeholders[strings.ToLower(value)] || fix1Mask.MatchString(value) {
		return false
	}
	return !(moreWords && fix1ProseWord.MatchString(value))
}

func fix1TextSpace(r rune) bool { return unicode.IsSpace(r) || r >= 0x1c && r <= 0x1f }

func fix1LiteralQuoted(value string) bool {
	value = strings.TrimFunc(value, fix1TextSpace)
	return value != "" && !fix1Reference.MatchString(value) &&
		(len(strings.FieldsFunc(value, fix1TextSpace)) > 1 || fix1LiteralToken(value, false))
}

func fix1LiteralValue(text string) bool {
	text = strings.TrimFunc(text, fix1TextSpace)
	if text == "" {
		return false
	}
	if strings.ContainsRune("\"'`", rune(text[0])) {
		end := strings.IndexByte(text[1:], text[0])
		if end >= 0 {
			return fix1LiteralQuoted(text[1 : 1+end])
		}
		return fix1LiteralQuoted(text[1:])
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
			if fix1Reference.MatchString(text[:end]) {
				return false
			}
		}
	}
	words := strings.FieldsFunc(text, fix1TextSpace)
	return fix1LiteralToken(words[0], len(words) > 1)
}

// fix1Sensitive recursively checks every decoded string key and value, including
// JSON-escaped echoes of the actual key. It returns no matched content.
func fix1Sensitive(value any, key string) bool {
	check := func(s string) bool { return key != "" && strings.Contains(s, key) || fix1SecretText(s) }
	var names, values, combined []string
	var walk func(any, int) bool
	walk = func(value any, depth int) bool {
		if depth > 128 {
			return true // Uninspectable nesting is withheld, never shortened.
		}
		switch v := value.(type) {
		case string:
			if check(v) {
				return true
			}
			values, combined = append(values, v), append(combined, v)
			// A field may itself carry JSON text. Decode a separate screening
			// view without modifying or shortening the actual outgoing string.
			text := strings.TrimSpace(v)
			if len(text) > 0 && strings.ContainsRune("{[\"", rune(text[0])) && json.Valid([]byte(text)) {
				decoded, err := typesafe.Decode([]byte(`{"value":` + text + `}`))
				if err != nil || walk(decoded["value"], depth+1) {
					return true
				}
			}
		case map[string]any:
			keys := make([]string, 0, len(v))
			for name := range v {
				keys = append(keys, name)
			}
			sort.Strings(keys)
			for _, name := range keys {
				child := v[name]
				if check(name) {
					return true
				}
				names, combined = append(names, name), append(combined, name)
				if text, ok := child.(string); ok && fix1SensitiveName.MatchString(name) && fix1LiteralQuoted(text) {
					return true
				}
				if walk(child, depth+1) {
					return true
				}
			}
		case []any:
			for _, child := range v {
				if walk(child, depth+1) {
					return true
				}
			}
		}
		return false
	}
	if walk(value, 0) {
		return true
	}
	// Adjacent fragments can span keys/values or separate fields. Stable views
	// catch both split markers and split marker/token pairs. They cover complete
	// strings; no prefix, suffix, field or byte window is discarded.
	fragments := func(text string) bool {
		return key != "" && strings.Contains(text, key) || fix1CredentialText(text)
	}
	for _, parts := range [][]string{names, values, combined} {
		// Only signatures/exact key echoes span fields. Reapplying the generic
		// fix1Assignment heuristic here could turn a complete benign fix1Reference into
		// an apparent literal by appending an unrelated next field to it.
		if fragments(strings.Join(parts, "")) || fragments(strings.Join(parts, " ")) {
			return true
		}
	}
	return false
}

// fix1Nil includes typed-nil dependency interfaces without calling their methods.
func fix1Nil(value any) bool {
	if value == nil {
		return true
	}
	v := reflect.ValueOf(value)
	switch v.Kind() {
	case reflect.Pointer, reflect.Interface, reflect.Func, reflect.Map, reflect.Slice:
		return v.IsNil()
	}
	return false
}
