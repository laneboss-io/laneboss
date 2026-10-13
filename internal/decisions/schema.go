package decisions

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"os"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"laneboss.io/laneboss/internal/decisions/jsonout"
)

type object = map[string]any
type problem struct {
	code    int
	message string
}

func (p *problem) Error() string   { return p.message }
func invalid(s string) error       { return &problem{2, s} }
func integrity(s string) error     { return &problem{3, s} }
func providerError(s string) error { return &problem{4, s} }
func access(s string) error        { return &problem{6, s} }
func str(v any) string             { s, _ := v.(string); return s }
func obj(v any) object             { m, _ := v.(map[string]any); return m }
func list(v any) []any             { a, _ := v.([]any); return a }
func keys(m object) []string {
	a := make([]string, 0, len(m))
	for k := range m {
		a = append(a, k)
	}
	sort.Strings(a)
	return a
}
func integer(v any) (int64, bool) {
	switch n := v.(type) {
	case int:
		return int64(n), true
	case int64:
		return n, true
	case json.Number:
		x, e := n.Int64()
		return x, e == nil
	}
	return 0, false
}
func number(v any) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, !math.IsNaN(n) && !math.IsInf(n, 0)
	case int:
		return float64(n), true
	case int64:
		return float64(n), true
	case json.Number:
		x, e := n.Float64()
		return x, e == nil && !math.IsNaN(x) && !math.IsInf(x, 0)
	}
	return 0, false
}
func digest(v any) string {
	var b []byte
	if x, ok := v.([]byte); ok {
		b = x
	} else {
		b = []byte(str(v))
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}
func canonicalJSON(v any) (string, error) {
	s, err := jsonout.Canonical(v)
	if err != nil {
		return "", invalid(err.Error())
	}
	return s, nil
}
func canonical(v any) string {
	s, err := canonicalJSON(v)
	if err != nil {
		// Callers construct or validate these values first. Never hash empty bytes
		// when that invariant fails; Run reports this as a command failure.
		panic(err)
	}
	return s
}
func clone(m object) object {
	v, e := parseJSON([]byte(canonical(m)))
	if e != nil {
		return nil
	}
	return obj(v)
}
func equal(a, b any) bool {
	left, err := canonicalJSON(a)
	if err != nil {
		return false
	}
	right, err := canonicalJSON(b)
	return err == nil && left == right
}
func parseJSON(raw []byte) (any, error) {
	if !utf8.Valid(raw) {
		return nil, invalid("invalid JSON")
	}
	// encoding/json replaces unpaired UTF-16 escapes. Refuse them instead of changing answer bytes.
	for i := 0; i < len(raw); i++ {
		if raw[i] != '\\' {
			continue
		}
		i++
		if i >= len(raw) {
			break
		}
		if raw[i] != 'u' {
			continue
		}
		if i+4 >= len(raw) {
			return nil, invalid("invalid JSON")
		}
		n, e := strconv.ParseUint(string(raw[i+1:i+5]), 16, 16)
		if e != nil {
			return nil, invalid("invalid JSON")
		}
		i += 4
		if n >= 0xd800 && n <= 0xdbff {
			if i+6 >= len(raw) || string(raw[i+1:i+3]) != `\u` {
				return nil, invalid("invalid JSON text")
			}
			lo, e := strconv.ParseUint(string(raw[i+3:i+7]), 16, 16)
			if e != nil || lo < 0xdc00 || lo > 0xdfff {
				return nil, invalid("invalid JSON text")
			}
			i += 6
		} else if n >= 0xdc00 && n <= 0xdfff {
			return nil, invalid("invalid JSON text")
		}
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	v, e := decodeValue(d, 0)
	if e != nil {
		return nil, e
	}
	if _, e = d.Token(); e != io.EOF {
		return nil, invalid("invalid JSON")
	}
	return v, nil
}
func decodeValue(d *json.Decoder, depth int) (any, error) {
	if depth > 512 {
		return nil, invalid("invalid JSON")
	}
	t, e := d.Token()
	if e != nil {
		return nil, invalid("invalid JSON")
	}
	switch x := t.(type) {
	case json.Delim:
		if x == '{' {
			m := object{}
			for d.More() {
				k, e := d.Token()
				if e != nil {
					return nil, invalid("invalid JSON")
				}
				s, ok := k.(string)
				if !ok {
					return nil, invalid("invalid JSON")
				}
				if _, ok = m[s]; ok {
					return nil, invalid("JSON contains a duplicate field")
				}
				v, e := decodeValue(d, depth+1)
				if e != nil {
					return nil, e
				}
				m[s] = v
			}
			t, e = d.Token()
			if e != nil || t != json.Delim('}') {
				return nil, invalid("invalid JSON")
			}
			return m, nil
		}
		if x == '[' {
			a := []any{}
			for d.More() {
				v, e := decodeValue(d, depth+1)
				if e != nil {
					return nil, e
				}
				a = append(a, v)
			}
			t, e = d.Token()
			if e != nil || t != json.Delim(']') {
				return nil, invalid("invalid JSON")
			}
			return a, nil
		}
		return nil, invalid("invalid JSON")
	case json.Number:
		if strings.ContainsAny(string(x), ".eE") {
			if _, ok := number(x); !ok {
				return nil, invalid("JSON must contain finite numbers")
			}
		}
	}
	return t, nil
}
func readJSON(path string) (any, error) {
	b, e := os.ReadFile(path)
	if e != nil {
		return nil, invalid("cannot read JSON file")
	}
	return parseJSON(b)
}
func allowed(v any, names, field string) error {
	m, ok := v.(map[string]any)
	if !ok {
		return invalid(field + " must be an object")
	}
	set := map[string]bool{}
	for _, k := range strings.Fields(names) {
		set[k] = true
	}
	for _, k := range keys(m) {
		if !set[k] {
			return invalid("unknown field: " + field + "." + k)
		}
	}
	return nil
}
func required(m object, path string) (any, error) {
	var v any = m
	for _, k := range strings.Split(path, ".") {
		o := obj(v)
		if o == nil || o[k] == nil {
			return nil, invalid("missing required field: " + path)
		}
		v = o[k]
	}
	return v, nil
}
func whitespace(r rune) bool  { return unicode.IsSpace(r) || (r >= 0x1c && r <= 0x1f) }
func trimmed(s string) string { return strings.TrimFunc(s, whitespace) }
func textValue(v any, field string, empty, nul bool) error {
	s, ok := v.(string)
	if !ok || (!empty && trimmed(s) == "") {
		return invalid(field + " must be a nonempty string")
	}
	if !utf8.ValidString(s) {
		return invalid(field + " must be valid UTF-8 text")
	}
	if !nul && strings.ContainsRune(s, 0) {
		return invalid(field + " cannot contain NUL")
	}
	return nil
}
func stringList(v any, field string, nonempty bool) error {
	a, ok := v.([]any)
	if !ok || (nonempty && len(a) == 0) {
		return invalid(field + " must be a list")
	}
	for _, x := range a {
		if e := textValue(x, field, false, false); e != nil {
			return e
		}
	}
	return nil
}

func positiveInteger(v any) bool {
	if n, ok := integer(v); ok {
		return n > 0
	}
	n, ok := v.(json.Number)
	if !ok || len(n) == 0 {
		return false
	}
	nonzero := false
	for _, r := range string(n) {
		if r < '0' || r > '9' {
			return false
		}
		nonzero = nonzero || r != '0'
	}
	return nonzero
}

var timePattern = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{3}([0-9]{3})?)?(Z|[+-][0-9]{2}:[0-9]{2})$`)
var idPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
var instancePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
var hashPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

func timestamp(v any, field string) (time.Time, error) {
	s, ok := v.(string)
	if !ok || !timePattern.MatchString(s) {
		return time.Time{}, invalid(field + " must be an ISO 8601 timestamp with offset")
	}
	t, e := time.Parse(time.RFC3339Nano, s)
	if e != nil || t.Year() < 1 || t.Year() > 9999 {
		return time.Time{}, invalid(field + " must be an ISO 8601 timestamp with offset")
	}
	_, offset := t.Zone()
	if offset <= -24*60*60 || offset >= 24*60*60 || t.UTC().Year() < 1 || t.UTC().Year() > 9999 {
		return time.Time{}, invalid(field + " must be an ISO 8601 timestamp with offset")
	}
	return t.UTC(), nil
}
func iso(t time.Time, full bool) string {
	layout := "2006-01-02T15:04:05"
	if full || t.Nanosecond() != 0 {
		layout += ".000000"
	}
	return t.UTC().Format(layout) + "+00:00"
}
func now() string { return iso(time.Now(), true) }
func scope(v object) error {
	if v["level"] == nil && v["instance"] == nil {
		return nil
	}
	n, ok := integer(v["level"])
	if !ok || n < 3 || n > 6 {
		return invalid("level must be an integer from 3 to 6")
	}
	if !instancePattern.MatchString(str(v["instance"])) {
		return invalid("instance must match [A-Za-z0-9][A-Za-z0-9._-]{0,63}")
	}
	return nil
}

const kinds = "decision answer instruction preference correction question_from_owner owner-decision ledger report board bulletin"
const statuses = "in_force superseded withdrawn fulfilled"

func member(s, set string) bool {
	for _, v := range strings.Fields(set) {
		if s == v {
			return true
		}
	}
	return false
}
func validateOutcome(v any) error {
	if e := allowed(v, "actions evidence followups", "outcome"); e != nil {
		return e
	}
	m := obj(v)
	for _, f := range []string{"evidence", "followups"} {
		if x, ok := m[f]; ok {
			if e := stringList(x, "outcome."+f, false); e != nil {
				return e
			}
		}
	}
	if v, ok := m["actions"]; ok {
		a, ok := v.([]any)
		if !ok {
			return invalid("outcome.actions must be a list")
		}
		for _, x := range a {
			if e := allowed(x, "at text", "outcome.actions"); e != nil {
				return e
			}
			m := obj(x)
			v, e := required(m, "at")
			if e != nil {
				return e
			}
			if _, e = timestamp(v, "outcome.actions.at"); e != nil {
				return e
			}
			v, e = required(m, "text")
			if e != nil {
				return e
			}
			if e = textValue(v, "outcome.actions.text", false, false); e != nil {
				return e
			}
		}
	}
	return nil
}
func validateRecord(original any) (object, error) {
	if obj(original) == nil {
		return nil, invalid("record must be an object")
	}
	v := clone(obj(original))
	if v == nil {
		return nil, invalid("record contains invalid JSON text")
	}
	if e := allowed(v, "id kind schema_version asked_at answered_at project area topics question answer scope status supersedes superseded_by status_before_superseded outcome provenance level instance", "record"); e != nil {
		return nil, e
	}
	if e := scope(v); e != nil {
		return nil, e
	}
	for _, f := range strings.Fields("id kind asked_at answered_at project area topics question.text question.background answer.verbatim answer.channel scope.applies_to status provenance provenance.recorded_by provenance.recorded_at provenance.sources") {
		if _, e := required(v, f); e != nil {
			return nil, e
		}
	}
	if _, ok := v["schema_version"]; !ok {
		v["schema_version"] = 1
	}
	if n, ok := integer(v["schema_version"]); !ok || n != 1 {
		return nil, invalid("schema_version must be 1")
	}
	for _, f := range strings.Fields("id kind project area status question.text question.background answer.verbatim answer.channel provenance.recorded_by") {
		x, _ := required(v, f)
		if e := textValue(x, f, false, f == "answer.verbatim"); e != nil {
			return nil, e
		}
	}
	if !idPattern.MatchString(str(v["id"])) {
		return nil, invalid("id must match [A-Za-z0-9][A-Za-z0-9._:-]{0,127}")
	}
	for _, c := range []struct{ field, names string }{{"question", "text background asked_by options recommendation default_if_unanswered"}, {"answer", "verbatim language channel message_id selected_option interpreted_as ambiguity sha256 interpretation_label"}, {"scope", "applies_to does_not_authorize reversible valid_until"}, {"provenance", "recorded_by recorded_at sources"}} {
		if e := allowed(v[c.field], c.names, c.field); e != nil {
			return nil, e
		}
	}
	if !member(str(v["kind"]), kinds) {
		return nil, invalid("kind is not a supported record kind")
	}
	if !member(str(v["status"]), statuses) {
		return nil, invalid("status is not a supported record status")
	}
	for _, f := range []string{"asked_at", "answered_at", "provenance.recorded_at"} {
		x, _ := required(v, f)
		if _, e := timestamp(x, f); e != nil {
			return nil, e
		}
	}
	if e := stringList(v["topics"], "topics", true); e != nil {
		return nil, e
	}
	sc := obj(v["scope"])
	if _, ok := sc["applies_to"].([]any); ok {
		if e := stringList(sc["applies_to"], "scope.applies_to", true); e != nil {
			return nil, e
		}
	} else if e := textValue(sc["applies_to"], "scope.applies_to", false, false); e != nil {
		return nil, e
	}
	q, a := obj(v["question"]), obj(v["answer"])
	for _, c := range []struct {
		m              object
		prefix, fields string
	}{{q, "question", "asked_by recommendation default_if_unanswered"}, {a, "answer", "language message_id selected_option interpreted_as ambiguity"}} {
		for _, f := range strings.Fields(c.fields) {
			if c.m[f] != nil {
				if e := textValue(c.m[f], c.prefix+"."+f, true, false); e != nil {
					return nil, e
				}
			}
		}
	}
	if x, ok := q["options"]; ok {
		options, ok := x.([]any)
		if !ok {
			return nil, invalid("question.options must be a list")
		}
		for _, o := range options {
			if e := allowed(o, "label text", "question.options"); e != nil {
				return nil, e
			}
			for _, f := range []string{"label", "text"} {
				x, e := required(obj(o), f)
				if e != nil {
					return nil, e
				}
				if e = textValue(x, "question.options."+f, false, false); e != nil {
					return nil, e
				}
			}
		}
	}
	if x, ok := sc["reversible"]; ok {
		if _, ok := x.(bool); !ok {
			return nil, invalid("scope.reversible must be a boolean")
		}
	}
	if sc["valid_until"] != nil {
		if _, e := timestamp(sc["valid_until"], "scope.valid_until"); e != nil {
			return nil, e
		}
	}
	if x := sc["does_not_authorize"]; x != nil {
		if _, ok := x.([]any); ok {
			if e := stringList(x, "scope.does_not_authorize", false); e != nil {
				return nil, e
			}
		} else if e := textValue(x, "scope.does_not_authorize", true, false); e != nil {
			return nil, e
		}
	}
	for _, f := range []string{"supersedes", "superseded_by"} {
		if v[f] != nil {
			if e := textValue(v[f], f, false, false); e != nil {
				return nil, e
			}
			if v[f] == v["id"] {
				return nil, invalid(f + " cannot refer to the record itself")
			}
		}
	}
	if x := v["status_before_superseded"]; x != nil {
		if v["status"] != "superseded" || !member(str(x), "in_force withdrawn fulfilled") {
			return nil, invalid("status_before_superseded is only valid for a superseded record")
		}
	}
	if v["status"] == "superseded" && str(v["superseded_by"]) == "" {
		return nil, invalid("superseded_by is required for status superseded")
	}
	if str(v["superseded_by"]) != "" && v["status"] != "superseded" {
		return nil, invalid("superseded_by requires status superseded")
	}
	if _, ok := v["outcome"]; !ok {
		v["outcome"] = object{}
	}
	if e := validateOutcome(v["outcome"]); e != nil {
		return nil, e
	}
	sources, ok := obj(v["provenance"])["sources"].([]any)
	if !ok {
		return nil, invalid("provenance.sources must be a list")
	}
	for _, x := range sources {
		if e := allowed(x, "path line sha256_of_line line_text", "provenance.sources"); e != nil {
			return nil, e
		}
		s := obj(x)
		for _, f := range []string{"path", "line", "sha256_of_line"} {
			if _, e := required(s, f); e != nil {
				return nil, e
			}
		}
		if e := textValue(s["path"], "provenance.sources.path", false, false); e != nil {
			return nil, e
		}
		if !positiveInteger(s["line"]) {
			return nil, invalid("provenance.sources.line must be a positive integer")
		}
		if !hashPattern.MatchString(str(s["sha256_of_line"])) {
			return nil, invalid("provenance.sources.sha256_of_line must be a SHA-256 hex digest")
		}
		if x, ok := s["line_text"]; ok {
			if e := textValue(x, "provenance.sources.line_text", true, true); e != nil {
				return nil, e
			}
			if digest(x) != s["sha256_of_line"] {
				return nil, invalid("provenance.sources.sha256_of_line does not match line_text")
			}
		}
	}
	if _, ok := a["message_id"]; !ok {
		a["message_id"] = nil
	}
	h := digest(a["verbatim"])
	if x, ok := a["sha256"]; ok && x != h {
		return nil, invalid("answer.sha256 does not match answer.verbatim")
	}
	a["sha256"] = h
	if a["interpreted_as"] != nil {
		a["interpretation_label"] = "supervisor interpretation"
	} else if a["interpretation_label"] != nil {
		return nil, invalid("answer.interpretation_label requires interpreted_as")
	}
	return v, nil
}
func markSuperseding(v object, id string) error {
	if v["supersedes"] != nil && v["supersedes"] != id {
		return invalid("supersedes conflicts with OLD_ID")
	}
	if !member(str(v["status"]), "in_force fulfilled") || str(v["superseded_by"]) != "" {
		return invalid("new record status must be in_force or fulfilled")
	}
	v["supersedes"] = id
	if v["id"] == id {
		return invalid("supersede requires a new id; answer.verbatim is immutable")
	}
	return nil
}
func markSuperseded(v object, id string) error {
	if v["status"] == "superseded" {
		return invalid("old record is already superseded")
	}
	v["status_before_superseded"] = v["status"]
	v["status"] = "superseded"
	v["superseded_by"] = id
	return nil
}
func flatten(v any) string {
	switch x := v.(type) {
	case nil:
		return ""
	case string:
		return x
	case []any:
		a := []string{}
		for _, v := range x {
			a = append(a, flatten(v))
		}
		return strings.Join(a, "\n")
	case map[string]any:
		a := []string{}
		for _, k := range keys(x) {
			a = append(a, flatten(x[k]))
		}
		return strings.Join(a, "\n")
	case bool:
		if x {
			return "True"
		}
		return "False"
	default:
		return fmt.Sprint(v)
	}
}
func projections(v object) (string, string) {
	q, a := obj(v["question"]), obj(v["answer"])
	return strings.Join([]string{flatten(q["text"]), flatten(q["background"]), flatten(q["options"]), flatten(q["recommendation"]), flatten(v["topics"])}, "\n"), strings.Join([]string{flatten(a["verbatim"]), flatten(a["interpreted_as"]), flatten(v["scope"]), flatten(v["outcome"])}, "\n")
}
func entryHash(v object) string {
	m := object{}
	for k, x := range v {
		if k != "entry_sha256" && k != "vector" {
			m[k] = x
		}
	}
	return digest(canonical(m))
}
func checkEntry(v object, label string) error {
	for _, value := range v {
		if s, ok := value.(string); ok && !utf8.ValidString(s) {
			return integrity(label + ": invalid metadata")
		}
	}
	metadata := object{}
	for key, value := range v {
		if key != "vector" {
			metadata[key] = value
		}
	}
	if _, err := canonicalJSON(metadata); err != nil {
		return integrity(label + ": invalid metadata")
	}
	if v["entry_sha256"] != entryHash(v) {
		return integrity(label + ": metadata hash mismatch")
	}
	return nil
}
func storedEqual(a, b any) bool {
	if y, ok := b.([]byte); ok {
		x, ok := a.([]byte)
		return ok && bytes.Equal(x, y)
	}
	if x, ok := a.([]byte); ok {
		y, ok := b.([]byte)
		return ok && bytes.Equal(x, y)
	}
	return reflect.DeepEqual(a, b) || equal(a, b)
}
