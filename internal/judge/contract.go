package judge

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"math"
	"math/big"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

var errJSON = errors.New("not one valid JSON object")

// Read tokens rather than unmarshalling into a map: Unmarshal silently accepts
// duplicate keys, and floats would lose the exact bounds of a probability.
func parseJSON(data []byte) (any, error) {
	if !utf8.Valid(data) || !json.Valid(data) || !validJSONUnicode(data) {
		return nil, errJSON
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	v, err := readJSONValue(d, 0)
	if err != nil {
		return nil, err
	}
	if _, err = d.Token(); err != io.EOF {
		return nil, errJSON
	}
	return v, nil
}
func readJSONValue(d *json.Decoder, depth int) (any, error) {
	if depth > 128 {
		return nil, errJSON
	}
	t, err := d.Token()
	if err != nil {
		return nil, errJSON
	}
	if delim, ok := t.(json.Delim); ok {
		switch delim {
		case '{':
			m := map[string]any{}
			for d.More() {
				key, err := d.Token()
				if err != nil {
					return nil, errJSON
				}
				s, ok := key.(string)
				if !ok {
					return nil, errJSON
				}
				if _, exists := m[s]; exists {
					return nil, errJSON
				}
				value, err := readJSONValue(d, depth+1)
				if err != nil {
					return nil, err
				}
				m[s] = value
			}
			if end, err := d.Token(); err != nil || end != json.Delim('}') {
				return nil, errJSON
			}
			return m, nil
		case '[':
			a := []any{}
			for d.More() {
				v, err := readJSONValue(d, depth+1)
				if err != nil {
					return nil, err
				}
				a = append(a, v)
			}
			if end, err := d.Token(); err != nil || end != json.Delim(']') {
				return nil, errJSON
			}
			return a, nil
		default:
			return nil, errJSON
		}
	}
	return t, nil
}
func validJSONUnicode(data []byte) bool {
	inside := false
	for i := 0; i < len(data); i++ {
		if data[i] == '"' {
			inside = !inside
			continue
		}
		if !inside || data[i] != '\\' {
			continue
		}
		i++
		if i >= len(data) {
			return false
		}
		if data[i] != 'u' {
			continue
		}
		if i+4 >= len(data) {
			return false
		}
		n, err := strconv.ParseUint(string(data[i+1:i+5]), 16, 16)
		if err != nil {
			return false
		}
		i += 4
		if n >= 0xdc00 && n <= 0xdfff {
			return false
		}
		if n >= 0xd800 && n <= 0xdbff {
			if i+6 >= len(data) || data[i+1] != '\\' || data[i+2] != 'u' {
				return false
			}
			low, err := strconv.ParseUint(string(data[i+3:i+7]), 16, 16)
			if err != nil || low < 0xdc00 || low > 0xdfff {
				return false
			}
			i += 6
		}
	}
	return true
}

// Compare the decimal as written with [0,1] before converting to binary64. The
// exponent is bounded in memory; a tiny valid decimal may round down to zero.
func probability(value any) (float64, bool) {
	n, ok := value.(json.Number)
	if !ok {
		return 0, false
	}
	raw := n.String()
	negative := strings.HasPrefix(raw, "-")
	mantissa := strings.TrimPrefix(raw, "-")
	exponent := new(big.Int)
	if at := strings.IndexAny(mantissa, "eE"); at >= 0 {
		if _, ok := exponent.SetString(mantissa[at+1:], 10); !ok {
			return 0, false
		}
		mantissa = mantissa[:at]
	}
	// Match the decimal parser's representable exponent range without allocating
	// a power of ten, even if an adversarial answer has thousands of exponent digits.
	bound := big.NewInt(999999999999999999)
	if new(big.Int).Abs(new(big.Int).Set(exponent)).Cmp(bound) > 0 {
		return 0, false
	}
	fraction := 0
	if at := strings.IndexByte(mantissa, '.'); at >= 0 {
		fraction = len(mantissa) - at - 1
		mantissa = mantissa[:at] + mantissa[at+1:]
	}
	digits := strings.TrimLeft(mantissa, "0")
	if digits == "" {
		return 0, true
	}
	if negative {
		return 0, false
	}
	order := new(big.Int).Add(exponent, big.NewInt(int64(len(digits)-fraction-1)))
	if order.Sign() > 0 {
		return 0, false
	}
	if order.Sign() == 0 && (digits[0] != '1' || strings.Trim(digits[1:], "0") != "") {
		return 0, false
	}
	p, err := strconv.ParseFloat(raw, 64)
	if err != nil || math.IsNaN(p) || math.IsInf(p, 0) {
		return 0, false
	}
	return p + 0.0, true
}
func optionalIdentifier(value any) (*string, bool) {
	if value == nil {
		return nil, true
	}
	s, ok := value.(string)
	if !ok || !identifierPattern.MatchString(s) || hasCredential(s) {
		return nil, false
	}
	return &s, true
}

type answer struct {
	p              *float64
	model, request *string
}

func readAnswer(raw []byte) (answer, bool) {
	var a answer
	v, err := parseJSON(raw)
	if err != nil {
		return a, false
	}
	m, ok := v.(map[string]any)
	if !ok {
		return a, false
	}
	for key := range m {
		if key != "probability" && key != "model" && key != "request" {
			return a, false
		}
	}
	p, ok := probability(m["probability"])
	if !ok {
		return a, false
	}
	model, ok := optionalIdentifier(m["model"])
	if !ok {
		return a, false
	}
	request, ok := optionalIdentifier(m["request"])
	if !ok {
		return a, false
	}
	a.p, a.model, a.request = &p, model, request
	return a, true
}
func explanation(raw []byte) string {
	text := strings.ToValidUTF8(string(raw), "�")
	lines := strings.FieldsFunc(text, func(r rune) bool {
		return r == '\n' || r == '\r' || r == '\v' || r == '\f' || r == 0x1c || r == 0x1d || r == 0x1e || r == 0x85 || r == 0x2028 || r == 0x2029
	})
	line := ""
	for _, s := range lines {
		if s = trimWhitespace(s); s != "" {
			line = s
			break
		}
	}
	if hasCredential(line) {
		return withheldText
	}
	line = strings.Map(func(r rune) rune {
		if !unicode.IsPrint(r) {
			return '?'
		}
		return r
	}, line)
	line = firstCharacters(line, 300)
	if hasCredential(line) {
		return withheldText
	}
	return line
}
func parseMoment(s string, recorded bool) (time.Time, error) {
	pattern := timestampPattern
	if recorded {
		pattern = recordedPattern
	}
	if !pattern.MatchString(s) || strings.HasPrefix(s, "0000-") {
		return time.Time{}, errJSON
	}
	if s[len(s)-1] != 'Z' {
		offset := s[len(s)-5:]
		hour, _ := strconv.Atoi(offset[:2])
		minute, _ := strconv.Atoi(offset[3:])
		if hour > 23 || minute > 59 {
			return time.Time{}, errJSON
		}
	}
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return time.Time{}, errJSON
	}
	return t, nil
}
func nonnegativeInteger(v any) bool {
	n, ok := v.(json.Number)
	if !ok || strings.ContainsAny(n.String(), ".eE") {
		return false
	}
	i, ok := new(big.Int).SetString(n.String(), 10)
	return ok && i.Sign() >= 0
}
func matchesString(v any, pattern interface{ MatchString(string) bool }) bool {
	s, ok := v.(string)
	return ok && pattern.MatchString(s)
}
func logNames(v any) bool {
	a, ok := v.([]any)
	if !ok {
		return false
	}
	for _, item := range a {
		s, ok := item.(string)
		if !ok || !subjectPattern.MatchString(s) || hasCredential(s) {
			return false
		}
	}
	return true
}
func exactKeys(m map[string]any, fields string) bool {
	keys := strings.Fields(fields)
	if len(m) != len(keys) {
		return false
	}
	for _, key := range keys {
		if _, ok := m[key]; !ok {
			return false
		}
	}
	return true
}
func parseLogLine(raw []byte) (map[string]any, error) {
	v, err := parseJSON(raw)
	if err != nil {
		return nil, err
	}
	m, ok := v.(map[string]any)
	if !ok {
		return nil, errJSON
	}
	event, ok := m["event"].(string)
	if !ok {
		return nil, errJSON
	}
	if event == "sent" {
		if !exactKeys(m, "at ask event judge question lane request_sha256 request_bytes withheld cut") {
			return nil, errJSON
		}
	} else if event == "outcome" {
		if !exactKeys(m, "at ask event outcome probability model request duration_ms") {
			return nil, errJSON
		}
	} else {
		return nil, errJSON
	}
	at, ok := m["at"].(string)
	if !ok {
		return nil, errJSON
	}
	if _, err := parseMoment(at, true); err != nil {
		return nil, err
	}
	if !matchesString(m["ask"], askPattern) {
		return nil, errJSON
	}
	if event == "sent" {
		q, ok := m["question"].(string)
		if !ok || len(q) > 64 || !questionPattern.MatchString(q) || !matchesString(m["judge"], namePattern) || (m["lane"] != nil && !matchesString(m["lane"], lanePattern)) || !matchesString(m["request_sha256"], digestPattern) || !nonnegativeInteger(m["request_bytes"]) || !logNames(m["withheld"]) || !logNames(m["cut"]) {
			return nil, errJSON
		}
		for _, key := range []string{"judge", "question", "lane"} {
			if s, ok := m[key].(string); ok && hasCredential(s) {
				return nil, errJSON
			}
		}
	} else {
		if !nonnegativeInteger(m["duration_ms"]) {
			return nil, errJSON
		}
		if _, ok := optionalIdentifier(m["model"]); !ok {
			return nil, errJSON
		}
		if _, ok := optionalIdentifier(m["request"]); !ok {
			return nil, errJSON
		}
		outcome, ok := m["outcome"].(string)
		if !ok {
			return nil, errJSON
		}
		if outcome == "answered" {
			if _, ok := probability(m["probability"]); !ok {
				return nil, errJSON
			}
		} else if outcome == "timeout" || outcome == "exit" || outcome == "output" || outcome == "not-found" {
			if m["probability"] != nil || m["model"] != nil || m["request"] != nil {
				return nil, errJSON
			}
		} else {
			return nil, errJSON
		}
	}
	return m, nil
}

// Python counts unfinished sends using its spaced JSON markers. Keep those
// separators so a Python writer reserves room for Go asks still in flight.
func logBytes(record map[string]any) []byte {
	raw := encodeJSON(record)
	var b bytes.Buffer
	inside, escape := false, false
	for _, c := range raw {
		b.WriteByte(c)
		if inside {
			if escape {
				escape = false
			} else if c == '\\' {
				escape = true
			} else if c == '"' {
				inside = false
			}
			continue
		}
		if c == '"' {
			inside = true
		} else if c == ':' || c == ',' {
			b.WriteByte(' ')
		}
	}
	b.WriteByte('\n')
	return b.Bytes()
}
