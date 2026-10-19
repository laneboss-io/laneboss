// Package settings is the shared, typed resolver for org, role, instance and
// lane settings. It reads names and policy, never environment variable values.
package settings

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"unicode/utf8"

	"github.com/BurntSushi/toml"
	"laneboss.io/laneboss/internal/faults"
	"laneboss.io/laneboss/internal/instancename"
)

const MaxBytes = 1024 * 1024

var Keys = []string{"runner", "model", "effort", "budget_minutes", "account", "seat_class", "env_allow", "tool_allow_add", "tool_deny_add"}
var token = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)
var accountName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
var modelName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/@+\[\]-]{0,127}$`)
var envName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,127}$`)
var toolName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$`)

// Layer retains each definition's actual origin. Event is used for a lane's
// explicit overrides; File and Line refer to the bytes that were read.
type Layer struct {
	Scope  string `json:"scope"`
	Value  any    `json:"value"`
	File   string `json:"file,omitempty"`
	Line   int    `json:"line,omitempty"`
	Event  string `json:"event,omitempty"`
	Option string `json:"option,omitempty"`
	SHA256 string `json:"sha256,omitempty"`
}

type Entry struct {
	Value  any     `json:"value"`
	Layers []Layer `json:"layers"`
	Winner int     `json:"winner"`
	Merge  string  `json:"merge,omitempty"`
}

type Snapshot struct {
	Values     map[string]any    `json:"values"`
	Entries    map[string]Entry  `json:"entries"`
	Overrides  map[string]any    `json:"overrides"`
	Instance   string            `json:"instance"`
	Sources    map[string]string `json:"sources"`
	Delegation *Limits           `json:"delegation,omitempty"`
}

func Empty() *Snapshot {
	s := &Snapshot{Values: map[string]any{}, Entries: map[string]Entry{}, Overrides: map[string]any{}, Sources: map[string]string{}}
	for _, key := range []string{"env_allow", "tool_allow_add", "tool_deny_add"} {
		s.Add(key, Layer{Scope: "base", Value: []string{}, Event: "built-in deny-by-default"})
	}
	return s
}

func Known(key string) bool {
	for _, name := range Keys {
		if key == name {
			return true
		}
	}
	return false
}

func Strings(value any) []string {
	if value == nil {
		return nil
	}
	v := reflect.ValueOf(value)
	if v.Kind() != reflect.Slice {
		return nil
	}
	result := make([]string, v.Len())
	for i := range result {
		result[i], _ = v.Index(i).Interface().(string)
	}
	return result
}

func Number(value any) (float64, bool) {
	switch value := value.(type) {
	case int:
		return float64(value), true
	case int64:
		return float64(value), true
	case float64:
		return value, true
	case json.Number:
		n, err := value.Float64()
		return n, err == nil
	}
	if value != nil {
		v := reflect.ValueOf(value)
		if v.Kind() == reflect.Float64 {
			return v.Float(), true
		}
	}
	return 0, false
}

func Validate(key string, value any) error {
	return validateWithLimit(key, value, 256)
}

func validateWithLimit(key string, value any, arrayLimit int) error {
	if !Known(key) {
		return errors.New("settings contain an unknown key")
	}
	bad := func() error { return fmt.Errorf("settings.%s: invalid type or value", key) }
	if key == "budget_minutes" {
		n, ok := Number(value)
		if !ok || math.IsNaN(n) || math.IsInf(n, 0) || n <= 0 || n > 10080 {
			return bad()
		}
		return nil
	}
	if key == "env_allow" || key == "tool_allow_add" || key == "tool_deny_add" {
		if value == nil {
			return bad()
		}
		v := reflect.ValueOf(value)
		if v.Kind() != reflect.Slice || v.Len() > arrayLimit {
			return bad()
		}
		seen := map[string]bool{}
		for i := 0; i < v.Len(); i++ {
			name, ok := v.Index(i).Interface().(string)
			pattern := toolName
			if key == "env_allow" {
				pattern = envName
			}
			if !ok || !pattern.MatchString(name) || seen[name] {
				return bad()
			}
			if key == "env_allow" && ReservedEnv(name) {
				return errors.New("settings.env_allow: launcher and tmux names are reserved")
			}
			seen[name] = true
		}
		return nil
	}
	text, ok := value.(string)
	if !ok || !utf8.ValidString(text) {
		return bad()
	}
	pattern := token
	if key == "account" {
		pattern = accountName
	}
	if key == "model" {
		pattern = modelName
	}
	if !pattern.MatchString(text) || key == "model" && !strings.ContainsAny(text, "0123456789") {
		return bad()
	}
	return nil
}

func ValidateTable(value any) error {
	data, ok := value.(map[string]any)
	if !ok {
		return errors.New("settings must be a table")
	}
	keys := make([]string, 0, len(data))
	for key := range data {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		if err := Validate(key, data[key]); err != nil {
			return err
		}
	}
	return nil
}

func (s *Snapshot) Add(key string, layer Layer) {
	entry := s.Entries[key]
	entry.Layers = append(entry.Layers, layer)
	entry.Winner = len(entry.Layers) - 1
	entry.Value = layer.Value
	if key == "tool_deny_add" {
		entry.Merge = "union"
		entry.Value = denyUnion(entry.Layers)
		if faults.Get("settings-deny-replace").Point != "" {
			if err := faults.Reach("settings-deny-replace"); err != nil {
				panic(err)
			}
			entry.Merge, entry.Value = "", layer.Value
		}
	}
	s.Entries[key], s.Values[key] = entry, entry.Value
}

func denyUnion(layers []Layer) []string {
	seen := map[string]bool{}
	for _, layer := range layers {
		for _, name := range Strings(layer.Value) {
			seen[name] = true
		}
	}
	result := make([]string, 0, len(seen))
	for name := range seen {
		result = append(result, name)
	}
	sort.Strings(result)
	return result
}

func (s *Snapshot) Selected(key string) bool {
	entry, exists := s.Entries[key]
	if !exists {
		return false
	}
	scope := entry.Layers[entry.Winner].Scope
	return scope != "base" && scope != "default"
}

func (s *Snapshot) MarkChoices(chosen map[string]any) {
	for _, key := range []string{"runner", "model", "effort", "account"} {
		entry, exists := s.Entries[key]
		if !exists {
			continue
		}
		scope := entry.Layers[entry.Winner].Scope
		if scope == "org" || scope == "role" || scope == "instance" {
			chosen[key] = "settings"
		}
	}
}

// Defaults only fill absent selections. Their origin is explicitly a legacy
// routing/default decision, rather than falsely attributing it to an org file.
func (s *Snapshot) Defaults(values map[string]any, origin string) {
	for _, key := range Keys {
		if value := values[key]; value != nil && s.Values[key] == nil {
			s.Add(key, Layer{Scope: "default", Value: value, Event: origin})
		}
	}
}

// RequestAccount selects an account for this run without replacing a retained
// --set account choice. Both definitions remain in the run's provenance.
func (s *Snapshot) RequestAccount(value any) error {
	if err := Validate("account", value); err != nil {
		return err
	}
	s.Add("account", Layer{Scope: "lane", Value: value, Event: "lane.started", Option: "--account"})
	return nil
}

// matchesOverride normally checks the winning lane layer. A per-run account
// flag can mask the immediately preceding persistent choice, but cannot itself
// become that persistent choice or authorize an unrelated override.
func (s *Snapshot) matchesOverride(key string, value any) bool {
	entry, exists := s.Entries[key]
	if !exists || entry.Winner < 0 || entry.Winner >= len(entry.Layers) {
		return false
	}
	index := entry.Winner
	if key == "account" && entry.Layers[index].Scope == "lane" && entry.Layers[index].Option == "--account" {
		index--
		if index < 0 || entry.Layers[index].Option == "--account" {
			return false
		}
	}
	return entry.Layers[index].Scope == "lane" && equal(value, entry.Layers[index].Value)
}

// Parse uses TOML types for numeric and array overrides; scalar strings may be
// bare CLI tokens or TOML quoted strings. Rejected input is never repeated.
func Parse(items []string, screen func([]byte) error) (map[string]any, error) {
	result := map[string]any{}
	for _, item := range items {
		if screen != nil {
			if err := screen([]byte(item)); err != nil {
				return nil, err
			}
		}
		key, raw, ok := strings.Cut(item, "=")
		if !ok || !Known(key) || raw == "" {
			return nil, errors.New("--set requires a documented KEY=VALUE")
		}
		if _, exists := result[key]; exists {
			return nil, errors.New("--set defines a key more than once")
		}
		var value any = raw
		if key == "budget_minutes" || strings.HasSuffix(key, "_add") || key == "env_allow" || strings.HasPrefix(raw, "\"") || strings.HasPrefix(raw, "'") {
			var data map[string]any
			if _, err := toml.Decode("value = "+raw, &data); err != nil || len(data) != 1 {
				return nil, errors.New("--set value must have the documented TOML type")
			}
			value = data["value"]
		}
		if err := Validate(key, value); err != nil {
			return nil, err
		}
		if screen != nil {
			decoded, err := json.Marshal(value)
			if err != nil {
				return nil, errors.New("--set value cannot be checked")
			}
			if err := screen(decoded); err != nil {
				return nil, err
			}
		}
		result[key] = value
	}
	return result, nil
}

// Source files use flat keys. Requiring a real assignment line also prevents
// inline tables/dotted syntax from being assigned a fabricated source location.
func ParseFile(data []byte, file, scope, block string, screen func([]byte) error) (map[string]Layer, error) {
	if len(data) > MaxBytes || !utf8.Valid(data) {
		return nil, errors.New("settings file must be UTF-8 within 1 MiB")
	}
	if screen != nil {
		if err := screen(data); err != nil {
			return nil, err
		}
	}
	if _, enabled := os.LookupEnv("BURNTSUSHI_TOML_110"); enabled {
		return nil, errors.New("settings require TOML 1.0 parser mode")
	}
	var document map[string]any
	if _, err := toml.Decode(string(data), &document); err != nil {
		return nil, errors.New("settings file has invalid TOML syntax")
	}
	if screen != nil {
		decoded, err := json.Marshal(document)
		if err != nil {
			return nil, errors.New("settings decoded values cannot be checked")
		}
		if err := screen(decoded); err != nil {
			return nil, err
		}
	}
	values := document
	if block != "" {
		if document[block] == nil {
			return map[string]Layer{}, nil
		}
		var ok bool
		values, ok = document[block].(map[string]any)
		if !ok {
			return nil, errors.New("role settings must be a table")
		}
	}
	if err := ValidateTable(values); err != nil {
		return nil, err
	}
	result := map[string]Layer{}
	active := block == ""
	depth := 0
	for i, line := range strings.Split(string(data), "\n") {
		text := strings.TrimSpace(line)
		if depth == 0 && strings.HasPrefix(text, "[") {
			heading := strings.TrimSpace(strings.SplitN(text, "#", 2)[0])
			active = heading == "["+block+"]" || heading == "[\""+block+"\"]" || heading == "['"+block+"']"
			continue
		}
		if active && depth == 0 {
			key, _, found := strings.Cut(text, "=")
			key = strings.Trim(strings.TrimSpace(key), "\"'")
			if found {
				if value, exists := values[key]; exists {
					result[key] = Layer{Scope: scope, Value: value, File: file, Line: i + 1, SHA256: SourceHash(data)}
				}
			}
		}
		// All accepted strings are single-line. Count array brackets outside
		// quoted strings/comments so a multiline array cannot fake an assignment.
		quote, escaped := byte(0), false
		for j := 0; j < len(line); j++ {
			c := line[j]
			if quote != 0 {
				if escaped {
					escaped = false
				} else if c == '\\' && quote == '"' {
					escaped = true
				} else if c == quote {
					quote = 0
				}
				continue
			}
			if c == '#' {
				break
			}
			if c == '"' || c == '\'' {
				quote = c
			} else if c == '[' {
				depth++
			} else if c == ']' {
				depth--
			}
		}
	}
	if len(result) != len(values) {
		return nil, errors.New("settings need flat assignment lines (role defaults use a [settings] block)")
	}
	return result, nil
}

func Read(root, relative string) ([]byte, error) {
	r, err := os.OpenRoot(root)
	if err != nil {
		return nil, errors.New("settings org folder cannot be opened")
	}
	defer r.Close()
	for p := relative; p != "."; p = filepath.Dir(p) {
		info, err := r.Lstat(p)
		if err != nil {
			return nil, err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return nil, errors.New("settings sources must not be symbolic links")
		}
	}
	f, err := r.OpenFile(relative, os.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > MaxBytes {
		return nil, errors.New("settings source must be a regular file within 1 MiB")
	}
	data, err := io.ReadAll(io.LimitReader(f, MaxBytes+1))
	if err != nil || len(data) > MaxBytes {
		return nil, errors.New("settings source could not be read within 1 MiB")
	}
	return data, nil
}

func Instance(root, name string, screen func([]byte) error) (int, string, error) {
	if !instancename.Valid(name) {
		return 0, "", errors.New("instance name must be one safe name")
	}
	if faults.Get("settings-short-instance").Point != "" {
		if err := faults.Reach("settings-short-instance"); err != nil {
			return 0, "", err
		}
		if !accountName.MatchString(name) {
			return 0, "", errors.New("instance name must be one safe name")
		}
	}
	data, err := Read(root, filepath.Join(".laneboss", "instances", name, "instance.toml"))
	if err != nil {
		return 0, "", errors.New("settings instance identity cannot be read")
	}
	if screen != nil {
		if err := screen(data); err != nil {
			return 0, "", err
		}
	}
	var document map[string]any
	if _, err := toml.Decode(string(data), &document); err != nil {
		return 0, "", errors.New("settings instance identity must be TOML")
	}
	level, ok := Number(document["level"])
	role, roleOK := document["role"].(string)
	if !ok || level < 3 || level > 6 || level != math.Trunc(level) || !roleOK || strings.TrimSpace(role) == "" || strings.ContainsAny(role, "/\\") || role == "." || role == ".." || strings.IndexFunc(role, func(r rune) bool { return r < 32 || r == 127 }) >= 0 {
		return 0, "", errors.New("settings instance needs a level within 3-6 and a safe role")
	}
	return int(level), role, nil
}

func Resolve(root string, level int, role, instance string, overrides map[string]any, screen func([]byte) error) (*Snapshot, error) {
	s := Empty()
	s.Instance = instance
	if root != "" {
		paths := []struct{ path, scope, block string }{{".laneboss/settings.toml", "org", ""}}
		if role != "" {
			if strings.ContainsAny(role, "/\\") || role == "." || role == ".." || level < 3 || level > 6 {
				return nil, errors.New("settings role identity is invalid")
			}
			paths = append(paths, struct{ path, scope, block string }{fmt.Sprintf(".laneboss/L%d/roles/%s.toml", level, role), "role", "settings"})
		}
		if instance != "" {
			l, r, err := Instance(root, instance, screen)
			if err != nil {
				return nil, err
			}
			if l != level || r != role {
				return nil, errors.New("settings instance and lane role must agree")
			}
			paths = append(paths, struct{ path, scope, block string }{filepath.Join(".laneboss", "instances", instance, "settings.toml"), "instance", ""})
		}
		for _, source := range paths {
			data, err := Read(root, source.path)
			if os.IsNotExist(err) {
				if source.block != "" && faults.Get("settings-role-required").Point != "" {
					if err := faults.Reach("settings-role-required"); err != nil {
						return nil, err
					}
				} else {
					continue
				}
			}
			if err != nil {
				return nil, errors.New("settings source cannot be read safely: " + source.path)
			}
			layers, err := ParseFile(data, filepath.Join(root, source.path), source.scope, source.block, screen)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", source.path, err)
			}
			if len(layers) > 0 {
				s.Sources[filepath.Join(root, source.path)] = string(data)
			}
			for _, key := range Keys {
				if layer, ok := layers[key]; ok {
					s.Add(key, layer)
				}
			}
		}
	} else if instance != "" {
		return nil, errors.New("instance settings require an org folder")
	}
	if err := ValidateTable(overrides); err != nil {
		return nil, err
	}
	for _, key := range Keys {
		if value, exists := overrides[key]; exists {
			s.Add(key, Layer{Scope: "lane", Value: value, Event: "lane.started", Option: "--set/launch option"})
			s.Overrides[key] = value
		}
	}
	return s, nil
}

// Map makes snapshots usable by every legacy event writer's map-based encoder.
func (s *Snapshot) Map() map[string]any {
	data, err := json.Marshal(s)
	if err != nil {
		panic(err)
	}
	var result map[string]any
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.UseNumber()
	if err := decoder.Decode(&result); err != nil {
		panic(err)
	}
	return result
}

func Decode(value any) (*Snapshot, error) {
	data, err := json.Marshal(value)
	if err != nil {
		return nil, errors.New("recorded settings cannot be decoded")
	}
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.UseNumber()
	decoder.DisallowUnknownFields()
	var s Snapshot
	if err := decoder.Decode(&s); err != nil || s.Values == nil || s.Entries == nil || s.Overrides == nil || s.Sources == nil || len(s.Sources) > 3 {
		return nil, errors.New("recorded settings snapshot is malformed")
	}
	for key, value := range s.Values {
		limit := 256
		if key == "tool_deny_add" && s.Entries[key].Merge == "union" {
			limit = 1024
		}
		if err := validateWithLimit(key, value, limit); err != nil {
			return nil, err
		}
	}
	if err := ValidateTable(s.Overrides); err != nil {
		return nil, err
	}
	if len(s.Values) != len(s.Entries) {
		return nil, errors.New("recorded settings provenance is incomplete")
	}
	definedSources := map[string]map[string]Layer{}
	for key, entry := range s.Entries {
		if !Known(key) || len(entry.Layers) == 0 || len(entry.Layers) > 16 || entry.Winner != len(entry.Layers)-1 {
			return nil, errors.New("recorded settings winner is invalid")
		}
		for _, layer := range entry.Layers {
			if err := Validate(key, layer.Value); err != nil {
				return nil, err
			}
			if layer.Scope != "base" && layer.Scope != "default" && layer.Scope != "org" && layer.Scope != "role" && layer.Scope != "instance" && layer.Scope != "lane" {
				return nil, errors.New("recorded settings layer is invalid")
			}
			if layer.File != "" {
				if !filepath.IsAbs(layer.File) || layer.Line < 1 || layer.Event != "" || layer.Scope != "org" && layer.Scope != "role" && layer.Scope != "instance" {
					return nil, errors.New("recorded settings file source is invalid")
				}
				text, exists := s.Sources[layer.File]
				if !exists || SourceHash([]byte(text)) != layer.SHA256 {
					return nil, errors.New("recorded settings source bytes or hash are missing")
				}
				block := ""
				if layer.Scope == "role" {
					block = "settings"
				}
				cacheKey := layer.File + "\x00" + layer.Scope
				defined := definedSources[cacheKey]
				if defined == nil {
					var err error
					defined, err = ParseFile([]byte(text), layer.File, layer.Scope, block, nil)
					if err != nil {
						return nil, errors.New("recorded settings source is invalid")
					}
					definedSources[cacheKey] = defined
				}
				if defined[key].Line != layer.Line || !equal(defined[key].Value, layer.Value) {
					return nil, errors.New("recorded settings source does not define the claimed value and line")
				}
			} else if layer.Event == "" || layer.Line != 0 {
				return nil, errors.New("recorded settings event source is invalid")
			}
		}
		expected := entry.Layers[entry.Winner].Value
		if entry.Merge == "union" && key == "tool_deny_add" {
			expected = denyUnion(entry.Layers)
		} else if entry.Merge != "" {
			return nil, errors.New("recorded settings merge is invalid")
		}
		if !equal(entry.Value, s.Values[key]) || !equal(entry.Value, expected) {
			return nil, errors.New("recorded settings value and winner disagree")
		}
		if value, ok := s.Overrides[key]; ok {
			if !s.matchesOverride(key, value) {
				return nil, errors.New("recorded lane overrides and winner disagree")
			}
		}
	}
	for key, value := range s.Overrides {
		if !s.matchesOverride(key, value) {
			return nil, errors.New("recorded override has no matching lane winner")
		}
	}
	if s.Instance != "" && !instancename.Valid(s.Instance) {
		return nil, errors.New("recorded settings instance is invalid")
	}
	if err := s.CheckDelegation(); err != nil {
		return nil, err
	}
	return &s, nil
}

func equal(a, b any) bool {
	if n, ok := Number(a); ok {
		m, other := Number(b)
		return other && n == m
	}
	x, ex := json.Marshal(a)
	y, ey := json.Marshal(b)
	return ex == nil && ey == nil && string(x) == string(y)
}

func ValidateEvent(payload map[string]any) error {
	value, exists := payload["settings"]
	if !exists {
		return nil
	} // Historic events remain readable.
	s, err := Decode(value)
	if err != nil {
		return err
	}
	if s.Delegation != nil && payload["starter"] != nil && payload["starter"] != s.Delegation.Starter {
		return errors.New("recorded delegation starter disagrees with the report line")
	}
	for _, key := range []string{"runner", "model", "effort", "account", "budget_minutes"} {
		if !equal(payload[key], s.Values[key]) {
			return fmt.Errorf("recorded settings.%s disagrees with run identity", key)
		}
	}
	chosen, _ := payload["chosen_by"].(map[string]any)
	for _, key := range []string{"runner", "model", "effort", "account"} {
		entry, exists := s.Entries[key]
		if !exists {
			continue
		}
		scope := entry.Layers[entry.Winner].Scope
		if (scope == "org" || scope == "role" || scope == "instance") && chosen[key] != "settings" {
			return errors.New("recorded choice must name the settings source")
		}
	}
	return nil
}

func EventField(payload map[string]any) func(any, string) error {
	return func(value any, _ string) error {
		candidate := map[string]any{}
		for key, item := range payload {
			candidate[key] = item
		}
		candidate["settings"] = value
		return ValidateEvent(candidate)
	}
}

func EventSource(s *Snapshot, seq, run int) *Snapshot {
	for key, entry := range s.Entries {
		for i := range entry.Layers {
			prefix := "lane.started seq=" + strconv.Itoa(seq) + " run=" + strconv.Itoa(run)
			if entry.Layers[i].Scope == "lane" {
				entry.Layers[i].Event = prefix
			}
			if entry.Layers[i].Scope == "default" {
				entry.Layers[i].Event = prefix + ": " + entry.Layers[i].Event
			}
		}
		s.Entries[key] = entry
	}
	return s
}
