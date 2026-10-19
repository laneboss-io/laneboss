package boxcfg

import (
	"fmt"
	"math"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	"laneboss.io/laneboss/internal/doctorbase"
)

type validation struct {
	file string
	env  Env
	err  error
}

type section struct {
	v      *validation
	prefix string
	data   map[string]any
}

func invalid(file, key, rule string) error {
	return fmt.Errorf("%s: %s: %s", file, key, rule)
}

func (v *validation) fail(key, rule string) {
	if v.err == nil {
		v.err = invalid(v.file, key, rule)
	}
}

func joinKey(prefix, key string) string {
	if prefix == "" {
		return key
	}
	return prefix + "." + key
}

func keys(data map[string]any) []string {
	result := make([]string, 0, len(data))
	for key := range data {
		result = append(result, key)
	}
	sort.Strings(result)
	return result
}

func array(value any) ([]any, bool) {
	switch a := value.(type) {
	case []any:
		return a, true
	case []map[string]any:
		result := make([]any, len(a))
		for i, row := range a {
			result[i] = row
		}
		return result, true
	default:
		return nil, false
	}
}

func credentialPath(value any, path string) (string, bool) {
	switch x := value.(type) {
	case string:
		return path, doctorbase.CredentialText(x)
	case map[string]any:
		for _, key := range keys(x) {
			// A credential used as a key must not become part of an error.
			if doctorbase.CredentialText(key) {
				return joinKey(path, "<key>"), true
			}
			if found, ok := credentialPath(x[key], joinKey(path, key)); ok {
				return found, true
			}
		}
	default:
		if a, ok := array(value); ok {
			for i, item := range a {
				if found, hit := credentialPath(item, fmt.Sprintf("%s[%d]", path, i)); hit {
					return found, true
				}
			}
		}
	}
	return "", false
}

func (s section) key(key string) string { return joinKey(s.prefix, key) }

func (s section) allowed(names string) {
	allowed := strings.Fields(names)
	for _, key := range keys(s.data) {
		if !slices.Contains(allowed, key) {
			s.v.fail(s.key(key), "unknown key")
		}
	}
}

func (s section) child(key string) section {
	child := section{v: s.v, prefix: s.key(key)}
	if value, ok := s.data[key]; ok {
		var table bool
		child.data, table = value.(map[string]any)
		if !table {
			s.v.fail(child.prefix, "must be a table")
		}
	}
	return child
}

func (s section) text(key, fallback string, required bool, check func(string) bool) string {
	value, present := s.data[key]
	if !present {
		if required {
			s.v.fail(s.key(key), "is required")
		}
		return fallback
	}
	text, ok := value.(string)
	if !ok {
		s.v.fail(s.key(key), "must be a string")
		return ""
	}
	if check != nil && !check(text) {
		s.v.fail(s.key(key), "does not satisfy the required string rule")
	}
	return text
}

func (s section) integer(key string, fallback int, required bool, low, high int64) int {
	value, present := s.data[key]
	if !present {
		if required {
			s.v.fail(s.key(key), "is required")
		}
		return fallback
	}
	n, ok := value.(int64)
	if !ok {
		s.v.fail(s.key(key), "must be an integer")
		return 0
	}
	if n < low || n > high {
		s.v.fail(s.key(key), "integer is outside the allowed bounds")
		return 0
	}
	return int(n)
}

func (s section) number(key string, fallback float64, required bool, low, high float64, strict bool) float64 {
	value, present := s.data[key]
	if !present {
		if required {
			s.v.fail(s.key(key), "is required")
		}
		return fallback
	}
	var n float64
	switch x := value.(type) {
	case int64:
		n = float64(x)
	case float64:
		n = x
	default:
		s.v.fail(s.key(key), "must be a number")
		return 0
	}
	if math.IsNaN(n) || math.IsInf(n, 0) || n < low || n > high || strict && n == low {
		s.v.fail(s.key(key), "number must be finite and within the allowed bounds")
	}
	return n
}

func (s section) boolean(key string, fallback bool) bool {
	value, present := s.data[key]
	if !present {
		return fallback
	}
	b, ok := value.(bool)
	if !ok {
		s.v.fail(s.key(key), "must be a boolean")
	}
	return b
}

func (s section) texts(key string, fallback []string, required bool, low, high int, check func(string) bool) []string {
	value, present := s.data[key]
	if !present {
		if required {
			s.v.fail(s.key(key), "is required")
		}
		return slices.Clone(fallback)
	}
	a, ok := array(value)
	if !ok {
		s.v.fail(s.key(key), "must be an array")
		return nil
	}
	if len(a) < low || high >= 0 && len(a) > high {
		s.v.fail(s.key(key), "array length is outside the allowed bounds")
	}
	result := make([]string, len(a))
	for i, item := range a {
		path := fmt.Sprintf("%s[%d]", s.key(key), i)
		text, ok := item.(string)
		if !ok {
			s.v.fail(path, "must be a string")
		} else if check != nil && !check(text) {
			s.v.fail(path, "does not satisfy the required string rule")
		}
		result[i] = text
	}
	return result
}

func (s section) expand(key, value string, empty bool) string {
	if value == "" && empty {
		return value
	}
	if value == "~" {
		value = s.v.env.UserHome
	} else if strings.HasPrefix(value, "~/") {
		value = filepath.Join(s.v.env.UserHome, value[2:])
	}
	if !filepath.IsAbs(value) {
		s.v.fail(s.key(key), "must be absolute after tilde expansion")
	}
	return value
}

func (s section) path(key, fallback string, required, empty bool) string {
	return s.expand(key, s.text(key, fallback, required, nil), empty)
}

func grammar(pattern string) func(string) bool {
	return regexp.MustCompile("^(?:" + pattern + ")$").MatchString
}

func choice(options ...string) func(string) bool {
	return func(s string) bool { return slices.Contains(options, s) }
}

func optional(check func(string) bool) func(string) bool {
	return func(s string) bool { return s == "" || check(s) }
}

func boundedText(s string, low, high int) bool {
	n := utf8.RuneCountInString(s)
	if n < low || n > high {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}
