package orgtree

import (
	"errors"
	"regexp"
	"strings"
	"time"
)

// Findings deliberately contain no matched bytes. Callers can name only the
// rule and line, even when the credential occurs in a field or file name.
type finding struct {
	rule string
	line int
}

type credentialShape struct {
	rule    string
	pattern *regexp.Regexp
	left    string
	right   string
	digit   bool
}

func shape(rule, pattern, left, right string, digit bool) credentialShape {
	return credentialShape{rule, regexp.MustCompile(pattern), left, right, digit}
}

const asciiUpper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
const asciiLower = "abcdefghijklmnopqrstuvwxyz"
const asciiDigits = "0123456789"
const asciiWord = asciiUpper + asciiLower + asciiDigits + "_"
const asciiAlphaNum = asciiUpper + asciiLower + asciiDigits
const tokenChars = asciiWord + "-"
const upperDigits = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
const addressSep = `(\\?/|%2[Ff])`

// Python's Unicode \s includes separators, vertical tab and U+001C..U+001F;
// RE2's bare \s covers only its ASCII subset.
const credentialSpace = `[\s\x{b}\x{85}\x{1c}-\x{1f}\p{Z}]`

var credentialShapes = []credentialShape{
	shape("private-key", `-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----`, "", "", false),
	shape("authorization-header", `(?i)(?:proxy-)?authorization["']?`+credentialSpace+`*[:=]`+credentialSpace+`*["']?(?:bearer|basic|token|digest)`+credentialSpace+`+[A-Za-z0-9._~+/=-]{8,}`, asciiWord, "", false),
	shape("bearer-token", `(?i)bearer`+credentialSpace+`+[A-Za-z0-9._~+/-]{16,}`, asciiWord, "", false),
	shape("code-host-token", `(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,}|glpat-[A-Za-z0-9_-]{20,})`, asciiWord, "", false),
	shape("chat-token", `xox[abposr]-[A-Za-z0-9-]{10,}`, asciiWord, "", false),
	shape("chat-bot-token", `[MNO][A-Za-z0-9_-]{23,27}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,40}`, asciiWord, tokenChars, false),
	shape("messenger-bot-token", `[0-9]{8,10}:AA[A-Za-z0-9_-]{33}`, asciiWord, tokenChars, false),
	shape("cloud-access-key-id", `(?:AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}`, upperDigits, upperDigits, false),
	shape("cloud-api-key", `AIza[0-9A-Za-z_-]{35}`, asciiWord, "", false),
	shape("oauth-access-token", `ya29\.[0-9A-Za-z_-]{20,}`, asciiWord, "", false),
	shape("prefixed-secret-key", `sk-[A-Za-z0-9_-]{20,}`, asciiAlphaNum, "", true),
	shape("payment-secret-key", `(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}`, asciiWord, "", false),
	shape("package-registry-token", `(?:npm_[A-Za-z0-9]{36}|pypi-[A-Za-z0-9_-]{50,})`, asciiWord, "", false),
	shape("model-hub-token", `hf_[A-Za-z0-9]{30,}`, asciiWord, "", false),
	shape("embedding-api-key", `pa-[A-Za-z0-9_-]{40,}`, asciiAlphaNum, "", true),
	shape("json-web-token", `eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}`, asciiWord, "", false),
	shape("url-credentials", `[A-Za-z][A-Za-z0-9+.-]*://[^\s/:@]+:[^\s/@]+@`, asciiWord, "", false),
	shape("chat-webhook-url", `(?i:discord(?:app)?\.com)`+addressSep+`api`+addressSep+`(?:v[0-9]+`+addressSep+`)?webhooks`+addressSep+`[0-9]{5,}`+addressSep+`[A-Za-z0-9_-]{6,}`, "", "", false),
	shape("chat-webhook-url", `(?i:hooks\.slack\.com)`+addressSep+`(?:services`+addressSep+`T[A-Z0-9]{5,}`+addressSep+`B[A-Z0-9]{5,}|workflows`+addressSep+`T[A-Z0-9]{5,}`+addressSep+`A[A-Z0-9]{5,}`+addressSep+`[0-9]{5,}|triggers`+addressSep+`T[A-Z0-9]{5,}`+addressSep+`[0-9]{5,})`+addressSep+`[A-Za-z0-9_-]{6,}`, "", "", false),
	shape("script-web-app-url", `(?i:script\.google\.com)`+addressSep+`(?:a`+addressSep+`(?:macros`+addressSep+`)?[A-Za-z0-9.-]+`+addressSep+`)?(?:macros`+addressSep+`)?(?:u`+addressSep+`[0-9]+`+addressSep+`)?s`+addressSep+`[A-Za-z0-9_-]{10,}`, "", "", false),
	shape("script-web-app-url", `AKfycb[A-Za-z0-9_-]{40,}`, tokenChars, "", false),
}

const sensitiveWords = `(?:api[ _-]?key|apikey|access[ _-]?key|secret[ _-]?key|private[ _-]?key|client[ _-]?secret|auth[ _-]?token|secret|token|passw(?:or)?d|passphrase|credentials?)`
const sensitivePrefix = `(?:[A-Za-z0-9]+[_.-])*?`

var (
	sensitiveName  = regexp.MustCompile(`(?i)^` + sensitivePrefix + sensitiveWords + `$`)
	assignment     = regexp.MustCompile(`(?i)` + sensitivePrefix + sensitiveWords + `["'*_]*[ \t]*(?::=|=>|=|:)`)
	reference      = regexp.MustCompile(`^(?:\$[A-Z_][A-Z0-9_]*|\$\{[A-Za-z_][A-Za-z0-9_]*\}|<[A-Za-z_][A-Za-z0-9_ .-]*>|\{\{?[ ]*[A-Za-z_][A-Za-z0-9_. -]*[ ]*\}?\})$`)
	credentialName = regexp.MustCompile(`^[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+$`)
	codeValue      = regexp.MustCompile(`^(?:[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*\(.*|[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)+|[A-Za-z_][A-Za-z0-9_.]*\[.*|[a-z][a-z0-9]*(?:_[a-z0-9]+)+|[a-z]+(?:[A-Z][a-z]+)+)$`)
	proseWord      = regexp.MustCompile(`^[A-Za-z][a-z]*$`)
	mask           = regexp.MustCompile(`^[xX*.-]+$`)
)

var placeholders = func() map[string]bool {
	result := make(map[string]bool)
	for _, word := range strings.Fields("none null nil empty required optional provided redacted omitted unset unchanged unknown missing hidden masked rotated revoked expired n/a tbd true false yes no str string bytes int integer bool boolean number float any object dict list") {
		result[word] = true
	}
	return result
}()

func literalToken(value string, moreWords bool) bool {
	value = strings.TrimRight(strings.Trim(value, "*_"), ",;.")
	if value == "" || reference.MatchString(value) || credentialName.MatchString(value) || codeValue.MatchString(value) {
		return false
	}
	if placeholders[strings.ToLower(value)] || mask.MatchString(value) {
		return false
	}
	return !(moreWords && proseWord.MatchString(value))
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
		close := byte('}')
		if text[0] == '<' {
			close = '>'
		}
		if end := strings.IndexByte(text, close); end >= 0 {
			if end+1 < len(text) && text[end+1] == '}' {
				end++
			}
			if reference.MatchString(text[:end+1]) {
				return false
			}
		}
	}
	words := strings.Fields(text)
	return literalToken(words[0], len(words) > 1)
}

func findCredential(text string) *finding {
	found, err := findCredentialUntil(text, time.Time{})
	if err != nil {
		panic(err)
	}
	return found
}

func scanTime(deadline time.Time) error {
	if !deadline.IsZero() && !time.Now().Before(deadline) {
		return errors.New("org credential inspection exceeded its time limit")
	}
	return nil
}

func findCredentialUntil(text string, deadline time.Time) (*finding, error) {
	for _, shape := range credentialShapes {
		if err := scanTime(deadline); err != nil {
			return nil, err
		}
		for _, span := range shape.pattern.FindAllStringIndex(text, -1) {
			if err := scanTime(deadline); err != nil {
				return nil, err
			}
			if span[0] > 0 && strings.ContainsRune(shape.left, rune(text[span[0]-1])) {
				continue
			}
			if span[1] < len(text) && strings.ContainsRune(shape.right, rune(text[span[1]])) {
				continue
			}
			if shape.digit && !strings.ContainsAny(text[span[0]:span[1]], "0123456789") {
				continue
			}
			return &finding{shape.rule, strings.Count(text[:span[0]], "\n") + 1}, nil
		}
	}
	for _, span := range assignment.FindAllStringIndex(text, -1) {
		if err := scanTime(deadline); err != nil {
			return nil, err
		}
		if span[0] > 0 && strings.ContainsRune(asciiWord, rune(text[span[0]-1])) {
			continue
		}
		separator := text[span[1]-1]
		if span[1] < len(text) && (separator == '=' && text[span[1]] == '=' || separator == ':' && strings.ContainsRune(":=", rune(text[span[1]]))) {
			continue
		}
		end := strings.IndexByte(text[span[1]:], '\n')
		if end < 0 {
			end = len(text) - span[1]
		}
		if literalValue(text[span[1] : span[1]+end]) {
			return &finding{"secret-assignment", strings.Count(text[:span[0]], "\n") + 1}, nil
		}
	}
	return nil, scanTime(deadline)
}

func credentialInValue(value any) bool {
	found, err := credentialValueUntil(value, time.Time{})
	if err != nil {
		panic(err)
	}
	return found
}

func credentialValueUntil(value any, deadline time.Time) (bool, error) {
	if err := scanTime(deadline); err != nil {
		return false, err
	}
	switch value := value.(type) {
	case string:
		found, err := findCredentialUntil(value, deadline)
		return found != nil, err
	case map[string]any:
		for key, item := range value {
			if found, err := findCredentialUntil(key, deadline); err != nil || found != nil {
				return found != nil, err
			}
			if text, ok := item.(string); ok && sensitiveName.MatchString(key) && literalQuoted(text) {
				return true, nil
			}
			if found, err := credentialValueUntil(item, deadline); err != nil || found {
				return found, err
			}
		}
	default:
		if items, ok := array(value); ok {
			for _, item := range items {
				if found, err := credentialValueUntil(item, deadline); err != nil || found {
					return found, err
				}
			}
		}
	}
	return false, scanTime(deadline)
}
