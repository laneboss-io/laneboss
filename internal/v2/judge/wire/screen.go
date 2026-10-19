package wire

import (
	"reflect"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

type credentialShape struct {
	re       *regexp.Regexp
	digit    bool
	required []string
	folded   bool
}

func shape(pattern string, digit bool, required ...string) credentialShape {
	// Credential-shaped substrings remain sensitive when arbitrary text touches
	// either end. A Unicode/ASCII word boundary would hide a credential appended
	// to a word or to the complete long CJK input used by the suffix canary.
	return credentialShape{re: regexp.MustCompile(pattern), digit: digit,
		required: required, folded: strings.HasPrefix(pattern, "(?i:")}
}

func urlShape(pattern string) credentialShape {
	return shape(pattern, false, "://")
}

const secretWords = `(?:ap[iİı][ _-]?key|ap[iİı]key|access[ _-]?key|secret[ _-]?key|pr[iİı]vate[ _-]?key|cl[iİı]ent[ _-]?secret|auth[ _-]?token|secret|token|passw(?:or)?d|passphrase|credent[iİı]als?)`
const secretPrefix = `(?:[A-Za-zİı0-9]+[_.-])*?`
const urlSeparator = `(?:\\?/|%2[Ff])`
const secretSpace = `[\s\v\p{Z}\x{0085}\x{001c}-\x{001f}]`

// These are the retained credential shapes, not a command allowlist or deny
// engine. A match withholds a judge request and never grants/refuses an action.
var credentialShapes = []credentialShape{
	shape(`-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----`, false, "PRIVATE KEY"),
	shape(`(?i:(?:proxy-)?author[iİı]zat[iİı]on["']?`+secretSpace+`*[:=]`+secretSpace+
		`*["']?(?:bearer|bas[iİı]c|token|d[iİı]gest)`+secretSpace+`+[A-Za-zİı0-9._~+/=-]{8,})`, false, "auth"),
	shape(`(?i:bearer`+secretSpace+`+[A-Za-zİı0-9._~+/-]{16,})`, false, "bearer"),
	shape(`(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,}|glpat-[A-Za-z0-9_-]{20,})`, false, "gh", "github_pat_", "glpat-"),
	shape(`xox[abposr]-[A-Za-z0-9-]{10,}`, false, "xox"),
	shape(`[MNO][A-Za-z0-9_-]{23,27}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,40}`, false, "."),
	shape(`[0-9]{8,10}:AA[A-Za-z0-9_-]{33}`, false, ":AA"),
	shape(`(?:AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}`, false, "AKIA", "ASIA", "ABIA", "ACCA"),
	shape(`AIza[0-9A-Za-z_-]{35}`, false, "AIza"),
	shape(`ya29\.[0-9A-Za-z_-]{20,}`, false, "ya29."),
	shape(`sk-[A-Za-z0-9_-]{20,}`, true, "sk-"),
	shape(`(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}`, false, "sk_", "rk_"),
	shape(`(?:npm_[A-Za-z0-9]{36}|pypi-[A-Za-z0-9_-]{50,})`, false, "npm_", "pypi-"),
	shape(`hf_[A-Za-z0-9]{30,}`, false, "hf_"),
	shape(`pa-[A-Za-z0-9_-]{40,}`, true, "pa-"),
	shape(`eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}`, false, "eyJ"),
	urlShape(`[A-Za-z][A-Za-z0-9+.-]*://[^[:space:]\p{Z}\x{0085}\x{001c}-\x{001f}/:@]+:[^[:space:]\p{Z}\x{0085}\x{001c}-\x{001f}/@]+@`),
	shape(`(?i:d[iİı]scord(?:app)?\.com)`+urlSeparator+`api`+urlSeparator+
		`(?:v[0-9]+`+urlSeparator+`)?webhooks`+urlSeparator+`[0-9]{5,}`+
		urlSeparator+`[A-Za-z0-9_-]{6,}`, false, "cord"),
	shape(`(?i:hooks\.slack\.com)`+urlSeparator+`(?:services`+urlSeparator+
		`T[A-Z0-9]{5,}`+urlSeparator+`B[A-Z0-9]{5,}|workflows`+urlSeparator+
		`T[A-Z0-9]{5,}`+urlSeparator+`A[A-Z0-9]{5,}`+urlSeparator+
		`[0-9]{5,}|triggers`+urlSeparator+`T[A-Z0-9]{5,}`+urlSeparator+
		`[0-9]{5,})`+urlSeparator+`[A-Za-z0-9_-]{6,}`, false, ".com"),
	shape(`(?i:scr[iİı]pt\.google\.com)`+urlSeparator+`(?:a`+urlSeparator+
		`(?:macros`+urlSeparator+`)?[A-Za-z0-9.-]+`+urlSeparator+
		`)?(?:macros`+urlSeparator+`)?(?:u`+urlSeparator+`[0-9]+`+urlSeparator+
		`)?s`+urlSeparator+`[A-Za-z0-9_-]{10,}`, false, ".google.com"),
	shape(`AKfycb[A-Za-z0-9_-]{40,}`, false, "AKfycb"),
}

// An unanchored search needs only the secret word. The optional name prefix
// contains no separator and cannot change any match's end/value; searching
// for it makes RE2 track arbitrary ordinary identifiers on the hot path.
// sensitiveName retains the full anchored grammar for structured field names.
var assignment = regexp.MustCompile(`(?i:` + secretWords + `["'*_]*[ \t]*(?::=|=>|=|:))`)
var sensitiveName = regexp.MustCompile(`(?i:^` + secretPrefix + secretWords + `$)`)
var reference = regexp.MustCompile(`^(?:\$[A-Z_][A-Z0-9_]*|\$\{[A-Za-z_][A-Za-z0-9_]*\}|<[A-Za-z_][A-Za-z0-9_ .-]*>|\{\{?[ ]*[A-Za-z_][A-Za-z0-9_. -]*[ ]*\}?\})$`)
var namedReference = regexp.MustCompile(`^[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+$`)
var codeReference = regexp.MustCompile(`^(?:[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*\(.*|[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)+|[A-Za-z_][A-Za-z0-9_.]*\[.*|[a-z][a-z0-9]*(?:_[a-z0-9]+)+|[a-z]+(?:[A-Z][a-z]+)+)$`)
var proseWord = regexp.MustCompile(`^[A-Za-z][a-z]*$`)
var mask = regexp.MustCompile(`^[xX*.-]+$`)

var placeholders = func() map[string]bool {
	m := map[string]bool{}
	words := "none null nil empty required optional provided redacted omitted unset " +
		"unchanged unknown missing hidden masked rotated revoked expired n/a tbd " +
		"true false yes no str string bytes int integer bool boolean number float any object dict list"
	for _, word := range strings.Fields(words) {
		m[word] = true
	}
	return m
}()

func credentialText(text string) bool {
	// Required literals are necessary conditions, never sufficient matches.
	// Fold once, using fragments without s/k/i so RE2's extra Unicode folds
	// (long s, Kelvin sign and the explicit dotted/dotless i) cannot be lost.
	var folded string
	foldedReady := false
	for _, rule := range credentialShapes {
		if len(rule.required) != 0 {
			view := text
			if rule.folded {
				if !foldedReady {
					folded, foldedReady = strings.ToLower(text), true
				}
				view = folded
			}
			present := false
			for _, required := range rule.required {
				if strings.Contains(view, required) {
					present = true
					break
				}
			}
			if !present {
				continue
			}
		}
		if !rule.digit {
			if rule.re.MatchString(text) {
				return true
			}
			continue
		}
		for _, match := range rule.re.FindAllStringIndex(text, -1) {
			if !strings.ContainsAny(text[match[0]:match[1]], "0123456789") {
				continue
			}
			return true
		}
	}
	return false
}

// Assignment inspection is bounded independently for each complete string.
// This permits original whole-value semantics even for overlapping matches:
// exhaustion withholds, while ordinary adjacent assignments remain linear.
const maxAssignmentWorkFactor = 8

type assignmentWork struct {
	left   int
	capped bool
	shared func(int) bool
}

func (w *assignmentWork) take(n int) bool {
	if w.capped || n < 0 || n > w.left || w.shared != nil && !w.shared(n) {
		w.capped = true
		return false
	}
	w.left -= n
	return true
}

func secretText(text string) bool {
	hit, _ := screenText(text, nil)
	return hit
}

func screenText(text string, shared func(int) bool) (bool, bool) {
	if len(text) > MaxScreenInputBytes {
		return true, true
	}
	if credentialText(text) {
		return true, false
	}
	w := &assignmentWork{left: maxAssignmentWorkFactor*len(text) + 32, shared: shared}
	hit := visitAssignments(text, literalValue, w)
	return hit, w.capped
}

func visitAssignmentValues(text string, visit func(string) bool) bool {
	w := &assignmentWork{left: maxAssignmentWorkFactor*len(text) + 32}
	return visitAssignments(text, visit, w)
}

func visitAssignments(text string, visit func(string) bool, w *assignmentWork) bool {
	if !strings.ContainsAny(text, "=:") {
		return false
	}
	for _, match := range assignment.FindAllStringIndex(text, -1) {
		separator := text[match[1]-1]
		if match[1] < len(text) && (separator == '=' && text[match[1]] == '=' ||
			separator == ':' && (text[match[1]] == ':' || text[match[1]] == '=')) {
			continue
		}
		// Each match retains the original tail's first complete value and its
		// more-words context. Another assignment never cuts the value. Nested
		// matches are checked independently, subject to the same linear budget.
		region := assignmentRegion(text[match[1]:], w)
		if w.capped || !w.take(2*len(region)) || visit(region) {
			return true
		}
	}
	return false
}

func assignmentRegion(text string, w *assignmentWork) string {
	value := strings.TrimLeftFunc(text, textSpace)
	if !w.take(len(text)-len(value)) || value == "" {
		return ""
	}
	if strings.ContainsRune("\x22\x27\x60", rune(value[0])) {
		end := strings.IndexByte(value[1:], value[0])
		if end < 0 {
			w.take(len(value))
			return value
		}
		end += 2
		w.take(end)
		if assignmentTail(value[end:]) {
			// Named extra: quote-tail (including spaced-tail). The reference
			// stops at the first closing quote; a glued suffix is still part
			// of the assigned shell/config value and must not pass as empty.
			return value[:end+1]
		}
		return value[:end]
	}
	if value[0] == '<' || value[0] == '{' {
		closing := byte('}')
		if value[0] == '<' {
			closing = '>'
		}
		end := strings.IndexByte(value, closing)
		searched := len(value)
		if end >= 0 {
			end++
			if end < len(value) && value[end] == '}' {
				end++
			}
			searched = end
		}
		if !w.take(searched) {
			return ""
		}
		if end > 0 && reference.MatchString(value[:end]) {
			if assignmentTail(value[end:]) {
				return value[:end+1]
			}
			return value[:end]
		}
	}
	end := strings.IndexFunc(value, textSpace)
	if end < 0 {
		w.take(len(value))
		return value
	}
	if !w.take(end + 1) {
		return ""
	}
	rest := strings.TrimLeftFunc(value[end:], textSpace)
	if !w.take(len(value) - end - len(rest)) {
		return ""
	}
	if rest == "" {
		return value[:end]
	}
	_, n := utf8.DecodeRuneInString(rest)
	w.take(n)
	return value[:len(value)-len(rest)+n]
}

func literalToken(value string, moreWords bool) bool {
	value = strings.TrimRight(strings.Trim(value, "*_"), ",;.")
	if value == "" || placeholders[strings.ToLower(value)] || reference.MatchString(value) ||
		namedReference.MatchString(value) || codeReference.MatchString(value) || mask.MatchString(value) {
		return false
	}
	return !(moreWords && proseWord.MatchString(value))
}

func textSpace(r rune) bool { return unicode.IsSpace(r) || r >= 0x1c && r <= 0x1f }

func literalQuoted(value string) bool {
	value = strings.TrimFunc(value, textSpace)
	return value != "" && !reference.MatchString(value) &&
		(len(strings.FieldsFunc(value, textSpace)) > 1 || literalToken(value, false))
}

func literalValue(text string) bool {
	text = strings.TrimFunc(text, textSpace)
	if text == "" {
		return false
	}
	if strings.ContainsRune("\"'`", rune(text[0])) {
		end := strings.IndexByte(text[1:], text[0])
		if end >= 0 {
			return literalQuoted(text[1:1+end]) || assignmentTail(text[2+end:])
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
			if reference.MatchString(text[:end]) {
				return assignmentTail(text[end:])
			}
		}
	}
	end := strings.IndexFunc(text, textSpace)
	if end < 0 {
		return literalToken(text, false)
	}
	return literalToken(text[:end], true)
}

// The only non-cap extensions beyond the frozen reference are a bare suffix
// immediately after a quoted value or a complete <...> / {...} reference.
// Whitespace and JSON/shell list punctuation terminate the value normally.
func assignmentTail(tail string) bool {
	if tail == "" || strings.ContainsRune(",;)}]", rune(tail[0])) {
		return false
	}
	r, _ := utf8.DecodeRuneInString(tail)
	return !textSpace(r)
}

// Nil includes typed-nil dependency interfaces without calling their methods.
func Nil(value any) bool {
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
