package judge

import (
	"reflect"
	"regexp"
	"strings"
	"unicode"
)

// RE2 has no lookaround. Boundary and digit requirements are checked explicitly,
// without retaining or returning the matched credential.
type credentialShape struct {
	re    *regexp.Regexp
	digit bool
}

func shape(pattern, left, right string, digit bool) credentialShape {
	// Consume an allowed boundary in the expression itself. Rejecting the first
	// match afterwards can skip an overlapping, valid credential inside it.
	classes := map[string]string{"word": `\p{L}\p{N}_`, "upper": `A-Z0-9`, "alnum": `A-Za-z0-9`, "token": `A-Za-z0-9_-`}
	pattern = "(?:" + pattern + ")"
	if left != "" {
		pattern = `(?:^|[^` + classes[left] + `])` + pattern
	}
	if right != "" {
		pattern += `(?:$|[^` + classes[right] + `])`
	}
	return credentialShape{regexp.MustCompile(pattern), digit}
}

const credentialWords = `(?:ap[iİı][ _-]?key|ap[iİı]key|access[ _-]?key|secret[ _-]?key|pr[iİı]vate[ _-]?key|cl[iİı]ent[ _-]?secret|auth[ _-]?token|secret|token|passw(?:or)?d|passphrase|credent[iİı]als?)`
const credentialPrefix = `(?:[A-Za-zİı0-9]+[_.-])*?`
const urlSeparator = `(?:\\?/|%2[Ff])`
const credentialSpace = `[\s\p{Z}\x{0085}\x{001c}-\x{001f}]`

var credentialShapes = []credentialShape{
	shape(`-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----`, "", "", false),
	shape(`(?i:(?:proxy-)?author[iİı]zat[iİı]on["']?`+credentialSpace+`*[:=]`+credentialSpace+`*["']?(?:bearer|bas[iİı]c|token|d[iİı]gest)`+credentialSpace+`+[A-Za-zİı0-9._~+/=-]{8,})`, "word", "", false),
	shape(`(?i:bearer`+credentialSpace+`+[A-Za-zİı0-9._~+/-]{16,})`, "word", "", false),
	shape(`(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,}|glpat-[A-Za-z0-9_-]{20,})`, "word", "", false),
	shape(`xox[abposr]-[A-Za-z0-9-]{10,}`, "word", "", false),
	shape(`[MNO][A-Za-z0-9_-]{23,27}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,40}`, "word", "token", false),
	shape(`[0-9]{8,10}:AA[A-Za-z0-9_-]{33}`, "word", "token", false),
	shape(`(?:AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}`, "upper", "upper", false),
	shape(`AIza[0-9A-Za-z_-]{35}`, "word", "", false),
	shape(`ya29\.[0-9A-Za-z_-]{20,}`, "word", "", false),
	shape(`sk-[A-Za-z0-9_-]{20,}`, "alnum", "", true),
	shape(`(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}`, "word", "", false),
	shape(`(?:npm_[A-Za-z0-9]{36}|pypi-[A-Za-z0-9_-]{50,})`, "word", "", false),
	shape(`hf_[A-Za-z0-9]{30,}`, "word", "", false),
	shape(`pa-[A-Za-z0-9_-]{40,}`, "alnum", "", true),
	shape(`eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}`, "word", "", false),
	shape(`[A-Za-z][A-Za-z0-9+.-]*://[^[:space:]\p{Z}\x{0085}\x{001c}-\x{001f}/:@]+:[^[:space:]\p{Z}\x{0085}\x{001c}-\x{001f}/@]+@`, "word", "", false),
	shape(`(?i:d[iİı]scord(?:app)?\.com)`+urlSeparator+`api`+urlSeparator+`(?:v[0-9]+`+urlSeparator+`)?webhooks`+urlSeparator+`[0-9]{5,}`+urlSeparator+`[A-Za-z0-9_-]{6,}`, "", "", false),
	shape(`(?i:hooks\.slack\.com)`+urlSeparator+`(?:services`+urlSeparator+`T[A-Z0-9]{5,}`+urlSeparator+`B[A-Z0-9]{5,}|workflows`+urlSeparator+`T[A-Z0-9]{5,}`+urlSeparator+`A[A-Z0-9]{5,}`+urlSeparator+`[0-9]{5,}|triggers`+urlSeparator+`T[A-Z0-9]{5,}`+urlSeparator+`[0-9]{5,})`+urlSeparator+`[A-Za-z0-9_-]{6,}`, "", "", false),
	shape(`(?i:scr[iİı]pt\.google\.com)`+urlSeparator+`(?:a`+urlSeparator+`(?:macros`+urlSeparator+`)?[A-Za-z0-9.-]+`+urlSeparator+`)?(?:macros`+urlSeparator+`)?(?:u`+urlSeparator+`[0-9]+`+urlSeparator+`)?s`+urlSeparator+`[A-Za-z0-9_-]{10,}`, "", "", false),
	shape(`AKfycb[A-Za-z0-9_-]{40,}`, "token", "", false),
}
var (
	assignmentPattern      = regexp.MustCompile(`(?:^|[^A-Za-z0-9_])(?i:` + credentialPrefix + credentialWords + `["'*_]*[ \t]*(?::=|=>|=|:))`)
	sensitivePattern       = regexp.MustCompile(`(?i:^` + credentialPrefix + credentialWords + `$)`)
	referencePattern       = regexp.MustCompile(`^(?:\$[A-Z_][A-Z0-9_]*|\$\{[A-Za-z_][A-Za-z0-9_]*\}|<[A-Za-z_][A-Za-z0-9_ .-]*>|\{\{?[ ]*[A-Za-z_][A-Za-z0-9_. -]*[ ]*\}?\})$`)
	secretReferencePattern = regexp.MustCompile(`^[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+$`)
	codeReferencePattern   = regexp.MustCompile(`^(?:[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*\(.*|[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)+|[A-Za-z_][A-Za-z0-9_.]*\[.*|[a-z][a-z0-9]*(?:_[a-z0-9]+)+|[a-z]+(?:[A-Z][a-z]+)+)$`)
	proseWordPattern       = regexp.MustCompile(`^[A-Za-z][a-z]*$`)
	maskPattern            = regexp.MustCompile(`^[xX*.-]+$`)
)
var placeholderWords = func() map[string]bool {
	m := map[string]bool{}
	for _, s := range strings.Fields("none null nil empty required optional provided redacted omitted unset unchanged unknown missing hidden masked rotated revoked expired n/a tbd true false yes no str string bytes int integer bool boolean number float any object dict list") {
		m[s] = true
	}
	return m
}()

func hasCredential(text string) bool {
	for _, rule := range credentialShapes {
		for _, match := range rule.re.FindAllStringIndex(text, -1) {
			if rule.digit {
				found := false
				for _, c := range text[match[0]:match[1]] {
					if c >= '0' && c <= '9' {
						found = true
						break
					}
				}
				if !found {
					continue
				}
			}
			return true
		}
	}
	for _, match := range assignmentPattern.FindAllStringIndex(text, -1) {
		separator := text[match[1]-1]
		if match[1] < len(text) && (separator == '=' && text[match[1]] == '=' || separator == ':' && (text[match[1]] == ':' || text[match[1]] == '=')) {
			continue
		}
		rest := text[match[1]:]
		if end := strings.IndexByte(rest, '\n'); end >= 0 {
			rest = rest[:end]
		}
		if literalValue(rest) {
			return true
		}
	}
	return false
}
func literalToken(value string, moreWords bool) bool {
	value = strings.TrimRight(strings.Trim(value, "*_"), ",;.")
	if value == "" || referencePattern.MatchString(value) || secretReferencePattern.MatchString(value) || codeReferencePattern.MatchString(value) || placeholderWords[lowerText(value)] || maskPattern.MatchString(value) {
		return false
	}
	return !(moreWords && proseWordPattern.MatchString(value))
}

func lowerText(s string) string { return strings.ToLower(strings.ReplaceAll(s, "İ", "i\u0307")) }
func literalQuoted(value string) bool {
	value = trimWhitespace(value)
	if value == "" || referencePattern.MatchString(value) {
		return false
	}
	return len(textWords(value)) > 1 || literalToken(value, false)
}
func literalValue(text string) bool {
	text = trimWhitespace(text)
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
		if end := strings.IndexByte(text, closing); end >= 0 {
			end++
			if end < len(text) && text[end] == '}' {
				end++
			}
			if referencePattern.MatchString(text[:end]) {
				return false
			}
		}
	}
	words := textWords(text)
	return literalToken(words[0], len(words) > 1)
}

func textSpace(r rune) bool          { return unicode.IsSpace(r) || r >= 0x1c && r <= 0x1f }
func trimWhitespace(s string) string { return strings.TrimFunc(s, textSpace) }
func textWords(s string) []string    { return strings.FieldsFunc(s, textSpace) }

func safeCredentialField(top, value string) string {
	key, text := strings.ToLower(top), strings.ToLower(value)
	if key == "" || strings.Contains(key, text) || len(key) >= 3 && strings.Contains(text, key) {
		return "(top level)"
	}
	return top
}

func credentialField(value any, top string) (string, bool) {
	switch v := value.(type) {
	case string:
		if hasCredential(v) {
			return safeCredentialField(top, v), true
		}
	case map[string]any:
		for _, key := range sortedKeys(v) {
			here := top
			if here == "" {
				here = key
			}
			if hasCredential(key) {
				if top == "" {
					here = "(top level)"
				}
				return safeCredentialField(here, key), true
			}
			if item, ok := v[key].(string); ok && sensitivePattern.MatchString(key) && literalQuoted(item) {
				return safeCredentialField(here, item), true
			}
			if field, ok := credentialField(v[key], here); ok {
				return field, true
			}
		}
	default:
		rv := reflect.ValueOf(value)
		if rv.IsValid() && (rv.Kind() == reflect.Slice || rv.Kind() == reflect.Array) {
			for i := 0; i < rv.Len(); i++ {
				if field, ok := credentialField(rv.Index(i).Interface(), top); ok {
					return field, true
				}
			}
		}
	}
	return "", false
}
