package decisionsrv

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"laneboss.io/laneboss/internal/decisions/jsonout"
)

type object = map[string]any

var idPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
var instancePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
var configPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)
var lanePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
var hashPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
var stampPattern = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{3}(?:[0-9]{3})?)?(?:Z|[+-][0-9]{2}:[0-9]{2})$`)
var stampInText = regexp.MustCompile(`[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{3}(?:[0-9]{3})?)?(?:Z|[+-][0-9]{2}:[0-9]{2})`)
var kinds = wordsSet("decision answer instruction preference correction question_from_owner owner-decision ledger report board bulletin")
var statuses = wordsSet("in_force superseded withdrawn fulfilled")
var feedbackEvents = map[string]int{"merged": 1, "accepted": 1, "abandoned": -1, "refusal": -1, "cited": 1}

func wordsSet(s string) map[string]bool {
	m := map[string]bool{}
	for _, w := range strings.Fields(s) {
		m[w] = true
	}
	return m
}
func str(v any) string { s, _ := v.(string); return s }
func obj(v any) object { m, _ := v.(map[string]any); return m }
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
	if i, ok := integer(v); ok {
		return float64(i), true
	}
	n, ok := v.(float64)
	if !ok {
		if j, yes := v.(json.Number); yes {
			n, e := j.Float64()
			return n, e == nil && finite(n)
		}
	}
	return n, ok && finite(n)
}
func finite(v float64) bool { return !math.IsNaN(v) && !math.IsInf(v, 0) }
func digest(v any) string {
	var b []byte
	switch x := v.(type) {
	case string:
		b = []byte(x)
	case []byte:
		b = x
	default:
		panic("digest requires text or bytes")
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}
func utcNow() string { return time.Now().UTC().Format("2006-01-02T15:04:05.000000+00:00") }
func timestamp(v any, field string) (time.Time, error) {
	s, ok := v.(string)
	if !ok || !stampPattern.MatchString(s) {
		return time.Time{}, invalid(field + " must be an ISO 8601 timestamp with offset")
	}
	t, e := time.Parse(time.RFC3339Nano, s)
	if e != nil {
		return time.Time{}, invalid(field + " must be an ISO 8601 timestamp with offset")
	}
	_, offset := t.Zone()
	utc := t.UTC()
	if t.Year() < 1 || t.Year() > 9999 || utc.Year() < 1 || utc.Year() > 9999 || offset <= -24*3600 || offset >= 24*3600 {
		return time.Time{}, invalid(field + " must be an ISO 8601 timestamp with offset")
	}
	return utc, nil
}
func pythonTime(t time.Time) string {
	if t.Nanosecond() == 0 {
		return t.UTC().Format("2006-01-02T15:04:05+00:00")
	}
	return t.UTC().Format("2006-01-02T15:04:05.000000+00:00")
}

// Token decoding rejects duplicate fields, including those in nested objects.
func parseJSON(data []byte) (any, error) {
	if !utf8.Valid(data) || !validSurrogates(data) {
		return nil, invalid("invalid JSON")
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	v, e := jsonValue(d, 0)
	if e != nil {
		return nil, e
	}
	if _, e = d.Token(); e != io.EOF {
		return nil, invalid("invalid JSON")
	}
	return v, nil
}
func validSurrogates(data []byte) bool {
	quoted := false
	for i := 0; i < len(data); i++ {
		if data[i] == '"' {
			quoted = !quoted
			continue
		}
		if !quoted || data[i] != '\\' {
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
		n, e := strconv.ParseUint(string(data[i+1:i+5]), 16, 16)
		if e != nil {
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
			low, e := strconv.ParseUint(string(data[i+3:i+7]), 16, 16)
			if e != nil || low < 0xdc00 || low > 0xdfff {
				return false
			}
			i += 6
		}
	}
	return true
}
func jsonValue(d *json.Decoder, depth int) (any, error) {
	if depth > 256 {
		return nil, invalid("invalid JSON")
	}
	t, e := d.Token()
	if e != nil {
		return nil, invalid("invalid JSON")
	}
	if delim, ok := t.(json.Delim); ok {
		switch delim {
		case '{':
			m := object{}
			for d.More() {
				k, e := d.Token()
				if e != nil {
					return nil, invalid("invalid JSON")
				}
				key, ok := k.(string)
				if !ok {
					return nil, invalid("invalid JSON")
				}
				if _, ok = m[key]; ok {
					return nil, invalid("JSON contains a duplicate field")
				}
				v, e := jsonValue(d, depth+1)
				if e != nil {
					return nil, e
				}
				m[key] = v
			}
			end, e := d.Token()
			if e != nil || end != json.Delim('}') {
				return nil, invalid("invalid JSON")
			}
			return m, nil
		case '[':
			a := []any{}
			for d.More() {
				v, e := jsonValue(d, depth+1)
				if e != nil {
					return nil, e
				}
				a = append(a, v)
			}
			end, e := d.Token()
			if e != nil || end != json.Delim(']') {
				return nil, invalid("invalid JSON")
			}
			return a, nil
		default:
			return nil, invalid("invalid JSON")
		}
	}
	if n, ok := t.(json.Number); ok {
		if strings.ContainsAny(string(n), ".eE") {
			f, e := n.Float64()
			if e != nil || !finite(f) {
				return nil, invalid("JSON must contain finite numbers")
			}
			return f, nil
		}
		i, e := n.Int64()
		if e != nil {
			return n, nil
		}
		return i, nil
	}
	return t, nil
}

// Stored metadata uses Python's compact UTF-8 representation for its hashes.
func canonical(v any) (string, error) {
	s, err := jsonout.Canonical(v)
	if err != nil {
		return "", invalid(err.Error())
	}
	return s, nil
}
func canonicalHash(v any) (string, error) {
	s, e := canonical(v)
	if e != nil {
		return "", e
	}
	return digest(s), nil
}
func entryHash(v object) (string, error) {
	m := object{}
	for k, x := range v {
		if k != "entry_sha256" && k != "vector" {
			m[k] = x
		}
	}
	return canonicalHash(m)
}
func checkEntry(v object, label string) error {
	h, e := entryHash(v)
	if e != nil {
		return integrity(label + ": invalid metadata")
	}
	if v["entry_sha256"] != h {
		return integrity(label + ": metadata hash mismatch")
	}
	return nil
}
func copyObject(m object) object {
	n := object{}
	for k, v := range m {
		n[k] = v
	}
	return n
}
func unknown(m object, allowed, field string) error {
	if m == nil {
		return invalid(field + " must be an object")
	}
	keys := []string{}
	set := wordsSet(allowed)
	for k := range m {
		if !set[k] {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	if len(keys) > 0 {
		return invalid("unknown field: " + field + "." + keys[0])
	}
	return nil
}
func required(m object, field string) (any, error) {
	var v any = m
	for _, p := range strings.Split(field, ".") {
		o := obj(v)
		if o == nil || o[p] == nil {
			return nil, invalid("missing required field: " + field)
		}
		v = o[p]
	}
	return v, nil
}
func textValue(v any, field string, empty, nul bool) error {
	s, ok := v.(string)
	if !ok || (!empty && strings.TrimSpace(s) == "") {
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
func validateScope(m object) error {
	if m["level"] == nil && m["instance"] == nil {
		return nil
	}
	l, ok := integer(m["level"])
	if !ok || l < 3 || l > 6 {
		return invalid("level must be an integer from 3 to 6")
	}
	if !instancePattern.MatchString(str(m["instance"])) {
		return invalid("instance must match [A-Za-z0-9][A-Za-z0-9._-]{0,63}")
	}
	return nil
}

func validateRecord(m object) (object, error) {
	if e := unknown(m, "id kind schema_version asked_at answered_at project area topics question answer scope status supersedes superseded_by status_before_superseded outcome provenance level instance", "record"); e != nil {
		return nil, e
	}
	if e := validateScope(m); e != nil {
		return nil, e
	}
	for _, f := range strings.Fields("id kind asked_at answered_at project area topics question.text question.background answer.verbatim answer.channel scope.applies_to status provenance provenance.recorded_by provenance.recorded_at provenance.sources") {
		if _, e := required(m, f); e != nil {
			return nil, e
		}
	}
	if m["schema_version"] == nil {
		m["schema_version"] = int64(1)
	}
	if n, ok := integer(m["schema_version"]); !ok || n != 1 {
		return nil, invalid("schema_version must be 1")
	}
	for _, f := range strings.Fields("id kind project area status question.text question.background answer.verbatim answer.channel provenance.recorded_by") {
		v, _ := required(m, f)
		if e := textValue(v, f, false, f == "answer.verbatim"); e != nil {
			return nil, e
		}
	}
	if !idPattern.MatchString(str(m["id"])) {
		return nil, invalid("id must match [A-Za-z0-9][A-Za-z0-9._:-]{0,127}")
	}
	q, a, s, p := obj(m["question"]), obj(m["answer"]), obj(m["scope"]), obj(m["provenance"])
	for _, c := range []struct {
		m            object
		fields, name string
	}{{q, "text background asked_by options recommendation default_if_unanswered", "question"}, {a, "verbatim language channel message_id selected_option interpreted_as ambiguity sha256 interpretation_label", "answer"}, {s, "applies_to does_not_authorize reversible valid_until", "scope"}, {p, "recorded_by recorded_at sources", "provenance"}} {
		if e := unknown(c.m, c.fields, c.name); e != nil {
			return nil, e
		}
	}
	if !kinds[str(m["kind"])] {
		return nil, invalid("kind is not a supported record kind")
	}
	if !statuses[str(m["status"])] {
		return nil, invalid("status is not a supported record status")
	}
	for _, f := range []string{"asked_at", "answered_at", "provenance.recorded_at"} {
		v, _ := required(m, f)
		if _, e := timestamp(v, f); e != nil {
			return nil, e
		}
	}
	if e := stringList(m["topics"], "topics", true); e != nil {
		return nil, e
	}
	if _, ok := s["applies_to"].([]any); ok {
		if e := stringList(s["applies_to"], "scope.applies_to", true); e != nil {
			return nil, e
		}
	} else if e := textValue(s["applies_to"], "scope.applies_to", false, false); e != nil {
		return nil, e
	}
	for _, c := range []struct {
		m            object
		fields, name string
	}{{q, "asked_by recommendation default_if_unanswered", "question"}, {a, "language message_id selected_option interpreted_as ambiguity", "answer"}} {
		for _, f := range strings.Fields(c.fields) {
			if c.m[f] != nil {
				if e := textValue(c.m[f], c.name+"."+f, true, false); e != nil {
					return nil, e
				}
			}
		}
	}
	if v, ok := q["options"]; ok {
		arr, ok := v.([]any)
		if !ok {
			return nil, invalid("question.options must be a list")
		}
		for _, v := range arr {
			o := obj(v)
			if e := unknown(o, "label text", "question.options"); e != nil {
				return nil, e
			}
			for _, f := range []string{"label", "text"} {
				if e := textValue(o[f], "question.options."+f, false, false); e != nil {
					return nil, e
				}
			}
		}
	}
	if v, ok := s["reversible"]; ok {
		if _, yes := v.(bool); !yes {
			return nil, invalid("scope.reversible must be a boolean")
		}
	}
	if s["valid_until"] != nil {
		if _, e := timestamp(s["valid_until"], "scope.valid_until"); e != nil {
			return nil, e
		}
	}
	if v := s["does_not_authorize"]; v != nil {
		if _, ok := v.([]any); ok {
			if e := stringList(v, "scope.does_not_authorize", false); e != nil {
				return nil, e
			}
		} else if e := textValue(v, "scope.does_not_authorize", true, false); e != nil {
			return nil, e
		}
	}
	for _, f := range []string{"supersedes", "superseded_by"} {
		if m[f] != nil {
			if e := textValue(m[f], f, false, false); e != nil {
				return nil, e
			}
			if m[f] == m["id"] {
				return nil, invalid(f + " cannot refer to the record itself")
			}
		}
	}
	if m["status_before_superseded"] != nil && (m["status"] != "superseded" || !statuses[str(m["status_before_superseded"])] || m["status_before_superseded"] == "superseded") {
		return nil, invalid("status_before_superseded is only valid for a superseded record")
	}
	if m["status"] == "superseded" && str(m["superseded_by"]) == "" {
		return nil, invalid("superseded_by is required for status superseded")
	}
	if str(m["superseded_by"]) != "" && m["status"] != "superseded" {
		return nil, invalid("superseded_by requires status superseded")
	}
	if m["outcome"] == nil {
		m["outcome"] = object{}
	}
	if e := validateOutcome(obj(m["outcome"])); e != nil {
		return nil, e
	}
	arr, ok := p["sources"].([]any)
	if !ok {
		return nil, invalid("provenance.sources must be a list")
	}
	for _, v := range arr {
		o := obj(v)
		if e := unknown(o, "path line sha256_of_line line_text", "provenance.sources"); e != nil {
			return nil, e
		}
		if e := textValue(o["path"], "provenance.sources.path", false, false); e != nil {
			return nil, e
		}
		n, ok := integer(o["line"])
		if !ok || n < 1 {
			return nil, invalid("provenance.sources.line must be a positive integer")
		}
		if !hashPattern.MatchString(str(o["sha256_of_line"])) {
			return nil, invalid("provenance.sources.sha256_of_line must be a SHA-256 hex digest")
		}
		if v, ok := o["line_text"]; ok {
			if e := textValue(v, "provenance.sources.line_text", true, true); e != nil {
				return nil, e
			}
			if digest(str(v)) != o["sha256_of_line"] {
				return nil, invalid("provenance.sources.sha256_of_line does not match line_text")
			}
		}
	}
	if _, ok := a["message_id"]; !ok {
		a["message_id"] = nil
	}
	h := digest(str(a["verbatim"]))
	if v, ok := a["sha256"]; ok && v != h {
		return nil, invalid("answer.sha256 does not match answer.verbatim")
	}
	a["sha256"] = h
	if a["interpreted_as"] != nil {
		a["interpretation_label"] = "supervisor interpretation"
	} else if a["interpretation_label"] != nil {
		return nil, invalid("answer.interpretation_label requires interpreted_as")
	}
	if _, e := canonical(m); e != nil {
		return nil, e
	}
	return m, nil
}
func validateOutcome(m object) error {
	if e := unknown(m, "actions evidence followups", "outcome"); e != nil {
		return e
	}
	for _, f := range []string{"evidence", "followups"} {
		if v, ok := m[f]; ok {
			if e := stringList(v, "outcome."+f, false); e != nil {
				return e
			}
		}
	}
	if v, ok := m["actions"]; ok {
		a, ok := v.([]any)
		if !ok {
			return invalid("outcome.actions must be a list")
		}
		for _, v := range a {
			o := obj(v)
			if e := unknown(o, "at text", "outcome.actions"); e != nil {
				return e
			}
			if _, e := timestamp(o["at"], "outcome.actions.at"); e != nil {
				return e
			}
			if e := textValue(o["text"], "outcome.actions.text", false, false); e != nil {
				return e
			}
		}
	}
	return nil
}
func flatten(v any) string {
	if v == nil {
		return ""
	}
	switch x := v.(type) {
	case string:
		return x
	case []any:
		s := []string{}
		for _, v := range x {
			s = append(s, flatten(v))
		}
		return strings.Join(s, "\n")
	case object:
		keys := []string{}
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		s := []string{}
		for _, k := range keys {
			s = append(s, flatten(x[k]))
		}
		return strings.Join(s, "\n")
	case bool:
		if x {
			return "True"
		}
		return "False"
	default:
		return fmt.Sprint(v)
	}
}
func projections(r object) (string, string) {
	q, a := obj(r["question"]), obj(r["answer"])
	return strings.Join([]string{flatten(q["text"]), flatten(q["background"]), flatten(q["options"]), flatten(q["recommendation"]), flatten(r["topics"])}, "\n"), strings.Join([]string{flatten(a["verbatim"]), flatten(a["interpreted_as"]), flatten(r["scope"]), flatten(r["outcome"])}, "\n")
}
func laneRecordID(config, lane, part, h string) (string, error) {
	if !configPattern.MatchString(config) {
		return "", invalid("config must match [a-z0-9][a-z0-9-]{0,31}")
	}
	if !lanePattern.MatchString(lane) {
		return "", invalid("lane must match [a-z0-9][a-z0-9._-]{0,63}")
	}
	if part != "report" && part != "events" && part != "attachment" {
		return "", invalid("part must be one of report, events, attachment")
	}
	if !hashPattern.MatchString(h) {
		return "", invalid("source sha256 must be a SHA-256 hex digest")
	}
	return config + "/" + lane + "/" + part + "/" + h[:16], nil
}
func validateLaneRecord(r object) error {
	if e := unknown(r, "id config lane part source_path source_sha256 text created_utc ingested_utc level instance", "lane record"); e != nil {
		return e
	}
	if e := validateScope(r); e != nil {
		return e
	}
	for _, f := range strings.Fields("id config lane part source_path source_sha256 text created_utc ingested_utc") {
		if e := textValue(r[f], f, false, false); e != nil {
			return e
		}
	}
	id, e := laneRecordID(str(r["config"]), str(r["lane"]), str(r["part"]), str(r["source_sha256"]))
	if e != nil {
		return e
	}
	if r["id"] != id {
		return invalid("id does not name its configuration, lane, part and source hash")
	}
	if digest(str(r["text"])) != r["source_sha256"] {
		return invalid("source_sha256 does not name the record's own text")
	}
	for _, f := range []string{"created_utc", "ingested_utc"} {
		if _, e := timestamp(r[f], f); e != nil {
			return e
		}
	}
	return nil
}
