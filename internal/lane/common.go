package lane

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"laneboss.io/laneboss/internal/jsontext"
	"math"
	"math/big"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"laneboss.io/laneboss/internal/cliargs"
)

type object = map[string]any
type problem struct {
	code            int
	prefix, message string
}

func (e *problem) Error() string           { return e.message }
func refuse(format string, a ...any) error { return &problem{2, "refused", fmt.Sprintf(format, a...)} }
func integrity(format string, a ...any) error {
	return &problem{3, "integrity problem", fmt.Sprintf(format, a...)}
}
func invalid(file, field, message string) error {
	return &problem{2, "invalid configuration", file + ": " + field + ": " + message}
}
func obj(v any) object { m, _ := v.(map[string]any); return m }
func str(v any) string { s, _ := v.(string); return s }
func flag(v any) bool  { b, _ := v.(bool); return b }
func list(v any) []any {
	switch x := v.(type) {
	case []any:
		return x
	case []map[string]any:
		r := make([]any, len(x))
		for i, m := range x {
			r[i] = m
		}
		return r
	case []string:
		r := make([]any, len(x))
		for i, s := range x {
			r[i] = s
		}
		return r
	}
	return nil
}
func stringsOf(v any) []string {
	r := []string{}
	for _, x := range list(v) {
		r = append(r, str(x))
	}
	return r
}
func number(v any) float64 {
	switch n := v.(type) {
	case int:
		return float64(n)
	case int64:
		return float64(n)
	case uint64:
		return float64(n)
	case float64:
		return n
	case json.Number:
		f, _ := n.Float64()
		return f
	}
	return 0
}
func integer(v any) int {
	switch value := v.(type) {
	case int:
		return value
	case int64:
		return int(value)
	case json.Number:
		if n, err := value.Int64(); err == nil {
			return int(n)
		}
	case float64:
		return int(value)
	case uint64:
		return int(value)
	}
	return 0
}
func valueOr(m object, k string, d any) any {
	if v, ok := m[k]; ok {
		return v
	}
	return d
}
func nullable(s string) any {
	if s == "" {
		return nil
	}
	return s
}
func contains(a []string, s string) bool {
	for _, x := range a {
		if x == s {
			return true
		}
	}
	return false
}
func unique(a []string) []string {
	sort.Strings(a)
	r := []string{}
	for _, s := range a {
		if len(r) == 0 || s != r[len(r)-1] {
			r = append(r, s)
		}
	}
	return r
}
func match(p, s string) bool { return regexp.MustCompile("^(?:" + p + ")$").MatchString(s) }
func digest(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func newID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	b[6] = (b[6] & 15) | 64
	b[8] = (b[8] & 63) | 128
	return hex.EncodeToString(b)
}
func uuid() string {
	s := newID()
	return s[:8] + "-" + s[8:12] + "-" + s[12:16] + "-" + s[16:20] + "-" + s[20:]
}
func utcNow() string            { return time.Now().UTC().Format("2006-01-02T15:04:05.000000Z") }
func rounded(n float64) float64 { return math.Round(n*1000) / 1000 }
func clone(m object) object {
	r := object{}
	for k, v := range m {
		r[k] = v
	}
	return r
}

func nativeJSON(v any) any {
	switch x := v.(type) {
	case map[string]any:
		if x == nil {
			return nil
		}
		m := object{}
		for k, v := range x {
			m[k] = nativeJSON(v)
		}
		return m
	case []map[string]any:
		return nativeJSON(list(x))
	case []any:
		a := make([]any, len(x))
		for i, v := range x {
			a[i] = nativeJSON(v)
		}
		return a
	default:
		return v
	}
}

// canonical preserves Python's number types and UTF-8 spelling; hashes cover these exact bytes.
func canonical(v any) []byte { var b bytes.Buffer; writeJSON(&b, v); return b.Bytes() }
func writeJSON(b *bytes.Buffer, v any) {
	switch x := v.(type) {
	case nil:
		b.WriteString("null")
	case string:
		b.WriteByte('"')
		for _, r := range x {
			switch r {
			case '"', '\\':
				b.WriteByte('\\')
				b.WriteRune(r)
			case '\b':
				b.WriteString("\\b")
			case '\f':
				b.WriteString("\\f")
			case '\n':
				b.WriteString("\\n")
			case '\r':
				b.WriteString("\\r")
			case '\t':
				b.WriteString("\\t")
			default:
				if r < 32 {
					fmt.Fprintf(b, "\\u%04x", r)
				} else {
					b.WriteRune(r)
				}
			}
		}
		b.WriteByte('"')
	case bool:
		if x {
			b.WriteString("true")
		} else {
			b.WriteString("false")
		}
	case json.Number:
		b.WriteString(string(x))
	case int:
		fmt.Fprint(b, x)
	case int64:
		fmt.Fprint(b, x)
	case uint64:
		fmt.Fprint(b, x)
	case float64:
		b.WriteString(pythonFloat(x))
	case map[string]any:
		if x == nil {
			b.WriteString("null")
			return
		}
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		b.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				b.WriteByte(',')
			}
			writeJSON(b, k)
			b.WriteByte(':')
			writeJSON(b, x[k])
		}
		b.WriteByte('}')
	case []any:
		b.WriteByte('[')
		for i, e := range x {
			if i > 0 {
				b.WriteByte(',')
			}
			writeJSON(b, e)
		}
		b.WriteByte(']')
	case []map[string]any:
		writeJSON(b, list(x))
	case []string:
		b.WriteByte('[')
		for i, e := range x {
			if i > 0 {
				b.WriteByte(',')
			}
			writeJSON(b, e)
		}
		b.WriteByte(']')
	default:
		panic(fmt.Sprintf("unsupported JSON type %T", v))
	}
}

func pythonFloat(x float64) string {
	format := byte('f')
	absolute := math.Abs(x)
	if absolute != 0 && (absolute < 1e-4 || absolute >= 1e16) {
		format = 'e'
	}
	s := strconv.FormatFloat(x, format, -1, 64)
	if !strings.ContainsAny(s, ".eE") {
		s += ".0"
	}
	if pos := strings.IndexByte(s, 'e'); pos >= 0 {
		exp := s[pos+1:]
		sign := "+"
		if strings.HasPrefix(exp, "-") {
			sign = "-"
			exp = exp[1:]
		} else {
			exp = strings.TrimPrefix(exp, "+")
		}
		if len(exp) == 1 {
			exp = "0" + exp
		}
		s = s[:pos] + "e" + sign + exp
	}
	return s
}
func parseJSON(b []byte) (any, error) {
	if !utf8.Valid(b) || !validJSONUnicode(b) {
		return nil, refuse("JSON text must be valid Unicode without unpaired surrogates")
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	v, err := readJSON(d)
	if err != nil {
		return nil, refuse("JSON is not valid or contains a duplicate field")
	}
	if _, err = d.Token(); err != io.EOF {
		return nil, refuse("JSON must contain exactly one value")
	}
	return v, nil
}
func readJSON(d *json.Decoder) (any, error) {
	t, err := d.Token()
	if err != nil {
		return nil, err
	}
	switch x := t.(type) {
	case json.Delim:
		if x == '{' {
			m := object{}
			for d.More() {
				k, e := d.Token()
				if e != nil {
					return nil, e
				}
				s, ok := k.(string)
				if !ok {
					return nil, fmt.Errorf("field")
				}
				if _, ok = m[s]; ok {
					return nil, fmt.Errorf("duplicate")
				}
				v, e := readJSON(d)
				if e != nil {
					return nil, e
				}
				m[s] = v
			}
			_, e := d.Token()
			return m, e
		}
		if x == '[' {
			a := []any{}
			for d.More() {
				v, e := readJSON(d)
				if e != nil {
					return nil, e
				}
				a = append(a, v)
			}
			_, e := d.Token()
			return a, e
		}
		return nil, fmt.Errorf("delimiter")
	case json.Number:
		if len(strings.TrimPrefix(string(x), "-")) > 4300 {
			return nil, fmt.Errorf("integer too long")
		}
		if strings.ContainsAny(string(x), ".eE") {
			f, e := x.Float64()
			if e != nil || math.IsInf(f, 0) || math.IsNaN(f) {
				return nil, fmt.Errorf("number")
			}
			original, ok1 := new(big.Rat).SetString(string(x))
			kept, ok2 := new(big.Rat).SetString(pythonFloat(f))
			if !ok1 || !ok2 || original.Cmp(kept) != 0 {
				return nil, fmt.Errorf("inexact number")
			}
			return f, nil
		}
		value, ok := new(big.Int).SetString(string(x), 10)
		if !ok {
			return nil, fmt.Errorf("integer")
		}
		return json.Number(value.String()), nil
	default:
		return t, nil
	}
}

func validJSONUnicode(b []byte) bool { return jsontext.ValidUnicode(b) }

type arguments struct {
	action   string
	values   map[string]string
	booleans map[string]bool
	touches  []string
}

func (a arguments) get(k string) string { return a.values[k] }
func (a arguments) has(k string) bool   { return a.booleans[k] }
func parseArgs(args []string) (arguments, error) {
	a := arguments{values: map[string]string{}, booleans: map[string]bool{}, touches: []string{}}
	if len(args) == 0 {
		return a, refuse("%s", cliargs.Required("ACTION"))
	}
	a.action = args[0]
	options := map[string]string{
		"start":  "config lane brief project difficulty runner model effort account budget touches worktree base reuse turns idle",
		"resume": "config lane message account budget", "stop": "config lane run", "status": "config lane", "check": "config lane", "mark": "config lane state landing gone accept-uncovered", "clean": "config lane", "scan": "config lane", "refusals": "config lane", "review": "config lane refusal path verdict note"}
	allowed, ok := options[a.action]
	if !ok {
		return a, refuse("%s", cliargs.Reject("ACTION"))
	}
	for i := 1; i < len(args); i++ {
		key := strings.TrimPrefix(args[i], "--")
		v := ""
		inline := false
		if p := strings.IndexByte(key, '='); p >= 0 {
			v = key[p+1:]
			key = key[:p]
			inline = true
		}
		if !strings.HasPrefix(args[i], "--") || !contains(strings.Fields(allowed), key) {
			return a, refuse("%s", cliargs.Reject(""))
		}
		if contains([]string{"reuse", "turns", "gone", "accept-uncovered"}, key) {
			if inline {
				return a, refuse("%s", cliargs.Reject("--"+key))
			}
			a.booleans[key] = true
			continue
		}
		if !inline {
			i++
			if i == len(args) || strings.HasPrefix(args[i], "--") {
				return a, refuse("%s", cliargs.Expected("--"+key))
			}
			v = args[i]
		}
		if rule, _ := credential(v); rule != "" && key != "account" {
			return a, refuse("--%s: looks like a credential (%s)", key, rule)
		}
		if key == "touches" {
			a.touches = append(a.touches, v)
		} else {
			a.values[key] = v
		}
	}
	if !contains([]string{"status", "check", "refusals"}, a.action) && a.get("lane") == "" {
		return a, refuse("%s", cliargs.Required("--lane"))
	}
	if a.get("lane") != "" && !match(`[a-z0-9][a-z0-9._-]{0,63}`, a.get("lane")) {
		return a, refuse("--lane must match [a-z0-9][a-z0-9._-]{0,63}")
	}
	if a.action == "start" && a.get("brief") == "" {
		return a, refuse("%s", cliargs.Required("--brief"))
	}
	for _, k := range []string{"refusal", "path", "verdict"} {
		if a.action == "review" && a.get(k) == "" {
			return a, refuse("%s", cliargs.Required("--"+k))
		}
	}
	return a, nil
}
func parseBudget(s string) (any, error) {
	if s == "" {
		return nil, nil
	}
	if !match(`[0-9]{1,5}(?:\.[0-9]{1,3})?`, s) {
		return nil, refuse("--budget: must be a number of minutes, for example 30 or 0.5")
	}
	n, _ := strconv.ParseFloat(s, 64)
	if n <= 0 || n > 10080 {
		return nil, refuse("--budget: must be above 0 and at most 10080 minutes")
	}
	if strings.Contains(s, ".") {
		return n, nil
	}
	return int(n), nil
}
