// Package doctorbase holds the private configuration and filesystem helpers used
// by the doctor and disk command groups.
package doctorbase

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"math/big"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"

	"laneboss.io/laneboss/internal/cliargs"
)

const MarkerName = ".laneboss-state"
const StoreName = "events.sqlite"
const ProtocolVersion = "1.2.0"

var Name = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)
var Digest = regexp.MustCompile(`^[0-9a-f]{64}$`)
var StoreID = regexp.MustCompile(`^[0-9a-f]{32}$`)
var RecordedAt = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{6}Z$`)

type Error struct {
	Code           int
	Prefix, Detail string
}

func (e *Error) Error() string { return e.Detail }
func Refuse(format string, args ...any) error {
	return &Error{2, "refused", fmt.Sprintf(format, args...)}
}
func Integrity(format string, args ...any) error {
	return &Error{3, "integrity problem", fmt.Sprintf(format, args...)}
}
func Invalid(label, field, detail string) error {
	if field == "" {
		field = "(top level)"
	}
	return &Error{2, "invalid configuration", label + ": " + field + ": " + detail}
}
func ExitError(w io.Writer, err error) int {
	var e *Error
	if errors.As(err, &e) {
		fmt.Fprintf(w, "%s: %s\n", e.Prefix, e.Detail)
		return e.Code
	}
	fmt.Fprintf(w, "refused: a file-system operation failed (%s)\n", OSReason(err))
	return 2
}
func OSReason(err error) string {
	var errno syscall.Errno
	if errors.As(err, &errno) {
		return errno.Error()
	}
	return "operating system error"
}
func RandomID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
func UTCNow() string       { return time.Now().UTC().Format("2006-01-02T15:04:05.000000Z") }
func Hash(b []byte) string { sum := sha256.Sum256(b); return hex.EncodeToString(sum[:]) }
func Object(v any) map[string]any {
	m, _ := v.(map[string]any)
	if m == nil {
		return map[string]any{}
	}
	return m
}
func Array(v any) []any   { a, _ := v.([]any); return a }
func String(v any) string { s, _ := v.(string); return s }
func Number(v any) float64 {
	switch n := v.(type) {
	case int:
		return float64(n)
	case int64:
		return float64(n)
	case float64:
		return n
	case json.Number:
		f, _ := n.Float64()
		return f
	}
	return math.NaN()
}
func Keys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
func ExactKeys(m map[string]any, names ...string) bool {
	if len(m) != len(names) {
		return false
	}
	for _, k := range names {
		if _, ok := m[k]; !ok {
			return false
		}
	}
	return true
}

// Canonical matches the Python store's sorted UTF-8 JSON, including the distinction
// between a JSON integer and a floating point number.
func Canonical(value any) ([]byte, error) {
	var out bytes.Buffer
	var write func(any) error
	quoted := func(s string) error {
		if !utf8.ValidString(s) {
			return fmt.Errorf("text must be valid Unicode")
		}
		out.WriteByte('"')
		for _, r := range s {
			switch r {
			case '"', '\\':
				out.WriteByte('\\')
				out.WriteRune(r)
			case '\b':
				out.WriteString(`\b`)
			case '\f':
				out.WriteString(`\f`)
			case '\n':
				out.WriteString(`\n`)
			case '\r':
				out.WriteString(`\r`)
			case '\t':
				out.WriteString(`\t`)
			default:
				if r < 32 {
					fmt.Fprintf(&out, `\u%04x`, r)
				} else {
					out.WriteRune(r)
				}
			}
		}
		out.WriteByte('"')
		return nil
	}
	writeFloat := func(f float64) error {
		if math.IsNaN(f) || math.IsInf(f, 0) {
			return fmt.Errorf("numbers must be finite")
		}
		s := strconv.FormatFloat(f, 'e', -1, 64)
		parts := strings.Split(s, "e")
		exponent, _ := strconv.Atoi(parts[1])
		if exponent >= -4 && exponent < 16 {
			s = strconv.FormatFloat(f, 'f', -1, 64)
			if !strings.Contains(s, ".") {
				s += ".0"
			}
		}
		out.WriteString(s)
		return nil
	}
	write = func(v any) error {
		switch x := v.(type) {
		case nil:
			out.WriteString("null")
		case string:
			return quoted(x)
		case bool:
			out.WriteString(strconv.FormatBool(x))
		case int:
			out.WriteString(strconv.Itoa(x))
		case int64:
			out.WriteString(strconv.FormatInt(x, 10))
		case uint64:
			out.WriteString(strconv.FormatUint(x, 10))
		case float64:
			return writeFloat(x)
		case json.Number:
			if strings.ContainsAny(x.String(), ".eE") {
				f, err := x.Float64()
				if err != nil {
					return err
				}
				return writeFloat(f)
			}
			if len(strings.TrimPrefix(x.String(), "-")) > 4300 {
				return fmt.Errorf("a JSON integer has more than 4300 digits")
			}
			n, ok := new(big.Int).SetString(x.String(), 10)
			if !ok {
				return fmt.Errorf("invalid JSON integer")
			}
			out.WriteString(n.String())
		case map[string]any:
			out.WriteByte('{')
			for i, k := range Keys(x) {
				if i > 0 {
					out.WriteByte(',')
				}
				if err := quoted(k); err != nil {
					return err
				}
				out.WriteByte(':')
				if err := write(x[k]); err != nil {
					return err
				}
			}
			out.WriteByte('}')
		case []any:
			out.WriteByte('[')
			for i, item := range x {
				if i > 0 {
					out.WriteByte(',')
				}
				if err := write(item); err != nil {
					return err
				}
			}
			out.WriteByte(']')
		default:
			return fmt.Errorf("unsupported JSON value")
		}
		return nil
	}
	if err := write(value); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

func ParseJSON(data []byte) (any, error) {
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	var read func() (any, error)
	read = func() (any, error) {
		token, err := d.Token()
		if err != nil {
			return nil, err
		}
		if delim, ok := token.(json.Delim); ok {
			if delim == '{' {
				m := map[string]any{}
				for d.More() {
					key, err := d.Token()
					if err != nil {
						return nil, err
					}
					k, ok := key.(string)
					if !ok {
						return nil, fmt.Errorf("invalid JSON field")
					}
					if _, ok := m[k]; ok {
						return nil, fmt.Errorf("JSON contains a duplicate field")
					}
					v, err := read()
					if err != nil {
						return nil, err
					}
					m[k] = v
				}
				_, err = d.Token()
				return m, err
			}
			if delim == '[' {
				a := []any{}
				for d.More() {
					v, err := read()
					if err != nil {
						return nil, err
					}
					a = append(a, v)
				}
				_, err = d.Token()
				return a, err
			}
			return nil, fmt.Errorf("invalid JSON")
		}
		return token, nil
	}
	v, err := read()
	if err != nil {
		return nil, err
	}
	if _, err := d.Token(); err != io.EOF {
		return nil, fmt.Errorf("invalid JSON trailing data")
	}
	return v, nil
}

func Bind(args []string) (string, error) {
	var selected *string
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--config" {
			if i+1 == len(args) || strings.HasPrefix(args[i+1], "--") {
				return "", Refuse("%s", cliargs.Expected("--config"))
			}
			i++
			value := args[i]
			selected = &value
		} else if strings.HasPrefix(arg, "--config=") {
			value := strings.TrimPrefix(arg, "--config=")
			selected = &value
		} else {
			return "", Refuse("%s", cliargs.Reject(""))
		}
	}
	bound := os.Getenv("LANEBOSS_CONFIG")
	if selected != nil && !Name.MatchString(*selected) {
		return "", Refuse("the configuration name given by --config must match [a-z0-9][a-z0-9-]{0,31}")
	}
	if bound != "" && !Name.MatchString(bound) {
		return "", Refuse("the configuration name in LANEBOSS_CONFIG must match [a-z0-9][a-z0-9-]{0,31}")
	}
	if selected != nil && bound != "" && *selected != bound {
		return "", Refuse("--config %s conflicts with LANEBOSS_CONFIG=%s; a session is bound to exactly one configuration", ShownName(*selected), ShownName(bound))
	}
	if selected != nil {
		return *selected, nil
	}
	if bound == "" {
		return "", Refuse("no configuration is bound: pass --config NAME or set LANEBOSS_CONFIG; %s", describeNames())
	}
	return bound, nil
}
