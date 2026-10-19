package orghook

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"syscall"
	"unicode/utf8"

	"github.com/BurntSushi/toml"
	"laneboss.io/laneboss/internal/hookblacklist"
	"laneboss.io/laneboss/internal/instancename"
)

const (
	maxBytes            = 2 * 1024 * 1024
	maxRules            = 512
	maxReadPaths        = 4096
	maxDescriptionBytes = 4096
)

var validName = instancename.Expression

func invalid(message string) error { return errors.New(message) }

type observationGap struct{ err error }

func (e *observationGap) Error() string { return e.err.Error() }
func (e *observationGap) Unwrap() error { return e.err }

func observation(err error) error {
	if err == nil {
		return nil
	}
	return &observationGap{err: err}
}

func isObservationGap(err error) bool {
	var gap *observationGap
	return errors.As(err, &gap)
}
func object(value any) (map[string]any, bool) {
	result, ok := value.(map[string]any)
	return result, ok
}
func array(value any) ([]any, bool) {
	if value == nil {
		return nil, false
	}
	v := reflect.ValueOf(value)
	if v.Kind() != reflect.Slice {
		return nil, false
	}
	result := make([]any, v.Len())
	for i := range result {
		result[i] = v.Index(i).Interface()
	}
	return result, true
}

func parseJSON(data []byte, label string) (map[string]any, error) {
	if !utf8.Valid(data) {
		return nil, invalid(label + " must be valid UTF-8 JSON")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	value, err := jsonValue(decoder, 0)
	if err != nil {
		return nil, invalid(label + " must be valid UTF-8 JSON without duplicate object fields")
	}
	if _, err = decoder.Token(); err != io.EOF {
		return nil, invalid(label + " must contain one JSON object")
	}
	result, ok := object(value)
	if !ok {
		return nil, invalid(label + " must be a JSON object")
	}
	return result, nil
}

func jsonValue(decoder *json.Decoder, depth int) (any, error) {
	if depth > 128 {
		return nil, invalid("JSON nesting exceeds the inspection limit")
	}
	token, err := decoder.Token()
	if err != nil {
		return nil, err
	}
	switch token {
	case json.Delim('{'):
		result := map[string]any{}
		for decoder.More() {
			key, err := decoder.Token()
			if err != nil {
				return nil, err
			}
			name, ok := key.(string)
			if !ok {
				return nil, invalid("JSON object field is invalid")
			}
			if _, exists := result[name]; exists {
				return nil, invalid("JSON has duplicate object fields")
			}
			value, err := jsonValue(decoder, depth+1)
			if err != nil {
				return nil, err
			}
			result[name] = value
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim('}') {
			return nil, invalid("JSON object is incomplete")
		}
		return result, nil
	case json.Delim('['):
		result := []any{}
		for decoder.More() {
			value, err := jsonValue(decoder, depth+1)
			if err != nil {
				return nil, err
			}
			result = append(result, value)
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim(']') {
			return nil, invalid("JSON array is incomplete")
		}
		return result, nil
	case json.Delim('}'), json.Delim(']'):
		return nil, invalid("JSON delimiter is unexpected")
	default:
		return token, nil
	}
}

func readBytes(path, label string) ([]byte, error) {
	// Check before opening: opening a FIFO would otherwise block the hot path indefinitely.
	info, err := os.Stat(path)
	if err != nil {
		return nil, invalid(label + " is missing or unreadable")
	}
	if !info.Mode().IsRegular() {
		return nil, invalid(label + " must be a regular file")
	}
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, invalid(label + " is missing or unreadable")
	}
	defer file.Close()
	info, err = file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return nil, invalid(label + " must be a regular file")
	}
	data, err := io.ReadAll(io.LimitReader(file, maxBytes+1))
	if err != nil {
		return nil, invalid(label + " is missing or unreadable")
	}
	if len(data) > maxBytes {
		return nil, invalid(label + " exceeds the input limit")
	}
	return data, nil
}

func readTOML(path, label string) (map[string]any, error) {
	data, err := readBytes(path, label)
	if err != nil {
		return nil, err
	}
	return parseTOML(data, label)
}

func parseTOML(data []byte, label string) (map[string]any, error) {
	if !utf8.Valid(data) {
		return nil, invalid(label + " is broken TOML")
	}
	result := map[string]any{}
	if _, err := toml.Decode(string(data), &result); err != nil {
		return nil, invalid(label + " is broken TOML")
	}
	return result, nil
}

func stringList(value any, label string, empty bool) ([]string, error) {
	values, ok := array(value)
	if !ok || len(values) > maxRules || (!empty && len(values) == 0) {
		return nil, invalid(label + " must be an array of nonempty strings")
	}
	result := make([]string, len(values))
	for i, value := range values {
		word, ok := value.(string)
		if !ok || word == "" || hasControl(word) {
			return nil, invalid(label + " must be an array of nonempty strings")
		}
		result[i] = word
	}
	return result, nil
}

func hasControl(word string) bool {
	for _, c := range word {
		if c < 32 {
			return true
		}
	}
	return false
}
func integer(value any) (int, bool) {
	switch n := value.(type) {
	case int64:
		return int(n), int64(int(n)) == n
	case int:
		return n, true
	}
	return 0, false
}
func allowedLevel(level int) bool { return level >= 3 && level <= 6 }
func onlyKeys(data map[string]any, keys ...string) bool {
	for key := range data {
		if !contains(keys, key) {
			return false
		}
	}
	return true
}
func contains(words []string, word string) bool {
	for _, candidate := range words {
		if candidate == word {
			return true
		}
	}
	return false
}

// resolvePath resolves existing symlink components while permitting not-yet-created tails.
// '..' is processed after symlinks, never cleaned away before resolving them.
func resolvePath(word, directory string) (string, error) {
	root := directory
	if filepath.IsAbs(word) {
		root = string(filepath.Separator)
	}
	parts := strings.Split(word, string(filepath.Separator))
	links := 0
	for len(parts) != 0 {
		part := parts[0]
		parts = parts[1:]
		switch part {
		case "", ".":
			continue
		case "..":
			root = filepath.Dir(root)
			continue
		}
		candidate := filepath.Join(root, part)
		info, err := os.Lstat(candidate)
		if err != nil {
			if !os.IsNotExist(err) {
				return "", invalid("a file path cannot be resolved")
			}
			root = candidate
			continue
		}
		if info.Mode()&os.ModeSymlink != 0 {
			links++
			if links > 40 {
				return "", invalid("a file path cannot be resolved")
			}
			target, err := os.Readlink(candidate)
			if err != nil {
				return "", invalid("a file path cannot be resolved")
			}
			if filepath.IsAbs(target) {
				root = string(filepath.Separator)
			}
			parts = append(strings.Split(target, string(filepath.Separator)), parts...)
		} else {
			root = candidate
		}
	}
	return root, nil
}

func pathAt(value any, directory string) (string, error) {
	word, ok := value.(string)
	if !ok || word == "" || hasControl(word) {
		return "", invalid("a file path is empty or contains control characters")
	}
	if strings.ContainsAny(word, "$`*?[]{}") || strings.HasPrefix(word, "~") || strings.Contains(word, "://") {
		return "", invalid("a file path needs expansion; use a literal path")
	}
	// Check the raw spelling before resolution can discard a trailing '/.' or '/'.
	raw := word
	if !filepath.IsAbs(raw) {
		raw = strings.TrimRight(directory, string(filepath.Separator)) + string(filepath.Separator) + raw
	}
	if _, err := os.Stat(raw); err != nil && !os.IsNotExist(err) {
		return "", invalid("a file path cannot be resolved")
	}
	return resolvePath(word, directory)
}

func orgHome(org string) (string, error) {
	cwd, err := currentDirectory()
	if err != nil {
		return "", err
	}
	root, err := pathAt(org, cwd)
	if err != nil {
		return "", invalid("the org path cannot be resolved")
	}
	home := root
	if filepath.Base(root) != ".laneboss" {
		home = filepath.Join(root, ".laneboss")
	}
	if _, err := readTOML(filepath.Join(home, "org.toml"), "org.toml"); err != nil {
		return "", err
	}
	return home, nil
}

func regular(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.Mode().IsRegular()
}
func isDirectory(path string) bool { info, err := os.Stat(path); return err == nil && info.IsDir() }
func isSymlink(path string) bool {
	info, err := os.Lstat(path)
	return err == nil && info.Mode()&os.ModeSymlink != 0
}
func homeFromDirectory(directory string) (string, error) {
	for parent := directory; ; parent = filepath.Dir(parent) {
		if filepath.Base(parent) == ".laneboss" && regular(filepath.Join(parent, "org.toml")) {
			return parent, nil
		}
		home := filepath.Join(parent, ".laneboss")
		if regular(filepath.Join(home, "org.toml")) {
			return home, nil
		}
		if filepath.Dir(parent) == parent {
			break
		}
	}
	return "", invalid("no org was found from the working directory")
}
func instanceFromDirectory(directory string) string {
	for parent := directory; ; parent = filepath.Dir(parent) {
		if filepath.Base(filepath.Dir(parent)) == "instances" && filepath.Base(filepath.Dir(filepath.Dir(parent))) == ".laneboss" {
			return parent
		}
		if filepath.Dir(parent) == parent {
			return ""
		}
	}
}

type instance struct {
	home, directory, name, role, worktree    string
	level                                    int
	hookMode                                 string
	blacklist                                []blacklistRule
	blacklistSources                         []string
	data                                     map[string]any
	writableRepos, allowedTools, secretNames []string
}

// blacklistRule is the one org-level hook entry format. A rule may have a
// deterministic matcher, a decision/job reference for the judge, or both.
// Empty scope lists mean every level or role, respectively.
type blacklistRule struct {
	id, description, band, instead string
	source                         string
	why                            string
	builtIn                        bool
	patternOnly                    bool
	argv                           [][]string
	argvWords                      []string
	pathGlob, toolGlob             string
	decision, job                  string
	levels                         []int
	roles                          []string
	identityScope                  bool
	examplesNotOK, examplesOK      []string
	pathRoots                      []string
	hookPaths                      bool
	secretNames                    []string
	legacySecret                   bool
}

type hookPolicy struct {
	mode      string
	blacklist []blacklistRule
}

func hookText(value any, label string, limit int) (string, error) {
	text, ok := value.(string)
	if !ok || strings.TrimSpace(text) == "" || len([]byte(text)) > limit || hasControl(text) {
		return "", invalid(label + " must be nonempty text within the byte limit")
	}
	return text, nil
}

func hookExamples(value any, label string) ([]string, error) {
	if value == nil {
		return nil, nil
	}
	items, ok := array(value)
	if !ok || len(items) > 8 {
		return nil, invalid(label + " must be an array of at most 8 examples")
	}
	result := make([]string, len(items))
	total := 0
	for i, item := range items {
		text, err := hookText(item, fmt.Sprintf("%s[%d]", label, i), 512)
		if err != nil {
			return nil, err
		}
		total += len([]byte(text))
		if total > 4096 {
			return nil, invalid(label + " exceeds the combined example byte limit")
		}
		result[i] = text
	}
	return result, nil
}

func hookScope(value any, label string) ([]int, []string, error) {
	if value == nil {
		return nil, nil, nil
	}
	data, ok := object(value)
	if !ok || !onlyKeys(data, "levels", "roles", "identities") {
		return nil, nil, invalid(label + " must be a table with optional levels and roles")
	}
	levels := []int(nil)
	if raw, exists := data["levels"]; exists {
		values, ok := array(raw)
		if !ok || len(values) == 0 || len(values) > maxRules {
			return nil, nil, invalid(label + ".levels must be a nonempty array of levels")
		}
		seen := map[int]bool{}
		for _, value := range values {
			level, ok := integer(value)
			if !ok || !allowedLevel(level) || seen[level] {
				return nil, nil, invalid(label + ".levels must contain distinct levels from 3 to 6")
			}
			seen[level] = true
			levels = append(levels, level)
		}
	}
	roles := []string(nil)
	key := "roles"
	if _, exists := data[key]; !exists {
		key = "identities" // Existing refusal descriptions used this name.
	}
	if raw, exists := data[key]; exists {
		values, err := stringList(raw, label+"."+key, false)
		if err != nil {
			return nil, nil, err
		}
		roles = values
	}
	return levels, roles, nil
}

func parseHookBlacklist(home string) (hookPolicy, error) {
	policy := hookPolicy{mode: "blacklist"}
	raw, err := readTOML(filepath.Join(home, "org.toml"), "org.toml")
	if err != nil {
		return policy, err
	}
	value, exists := raw["hooks"]
	if !exists {
		return policy, nil
	}
	hooks, ok := object(value)
	if !ok || !onlyKeys(hooks, "mode", "blacklist") {
		return policy, invalid("org.toml hooks must contain only mode and blacklist")
	}
	if value, exists := hooks["mode"]; exists {
		mode, ok := value.(string)
		if !ok || (mode != "blacklist" && mode != "strict") {
			return policy, invalid("org.toml hooks.mode must be blacklist or strict")
		}
		// Accept the removed spelling for source compatibility. Every org uses
		// blacklist semantics; render/validate report the deprecation.
	}
	rowsValue, exists := hooks["blacklist"]
	if !exists {
		return policy, nil
	}
	rows, err := hookblacklist.Parse(rowsValue, "org.toml hooks.blacklist")
	if err != nil {
		return policy, err
	}
	policy.blacklist = hookBlacklistRows(rows, "", filepath.Join(home, "org.toml"))
	return policy, nil
}

func loadInstance(directory string) (*instance, error) {
	if filepath.Base(directory) == "instance.toml" {
		directory = filepath.Dir(directory)
	}
	if !validName.MatchString(filepath.Base(directory)) || isSymlink(directory) || filepath.Base(filepath.Dir(directory)) != "instances" || filepath.Base(filepath.Dir(filepath.Dir(directory))) != ".laneboss" {
		return nil, invalid("unknown instance: expected .laneboss/instances/NAME/instance.toml")
	}
	home, err := orgHome(filepath.Dir(filepath.Dir(directory)))
	if err != nil {
		return nil, err
	}
	hook, err := parseHookBlacklist(home)
	if err != nil {
		return nil, err
	}
	data, err := readTOML(filepath.Join(directory, "instance.toml"), "instance.toml")
	if err != nil {
		return nil, err
	}
	name, ok := data["name"].(string)
	if !ok || name != filepath.Base(directory) || !validName.MatchString(name) {
		return nil, invalid("instance.toml name does not match its directory")
	}
	level, ok := integer(data["level"])
	if !ok || !allowedLevel(level) {
		return nil, invalid("instance.toml level must be 3, 4, 5 or 6")
	}
	role, ok := data["role"].(string)
	if !ok || strings.TrimSpace(role) == "" {
		return nil, invalid("instance.toml needs a role")
	}
	var sources []string
	hook.blacklist, sources, err = effectiveHookBlacklist(home, level, role, hook.blacklist)
	if err != nil {
		return nil, err
	}
	repos, err := stringList(data["writable_repos"], "instance writable_repos", true)
	if err != nil {
		return nil, err
	}
	tools := []string{}
	if value, exists := data["allowed_tools"]; exists {
		tools, err = stringList(value, "instance allowed_tools", true)
		if err != nil {
			return nil, err
		}
	}
	secretsValue, exists := data["secret_names"]
	if !exists {
		secretsValue = data["secrets"]
	}
	secrets, err := stringList(secretsValue, "instance secret_names", true)
	if err != nil {
		return nil, err
	}
	for i, repo := range repos {
		repos[i], err = pathAt(repo, filepath.Dir(home))
		if err != nil {
			return nil, err
		}
	}
	worktree := directory
	if len(repos) == 1 {
		worktree = repos[0]
	}
	if value, exists := data["worktree"]; exists {
		worktree, err = pathAt(value, filepath.Dir(home))
		if err != nil {
			return nil, err
		}
	}
	return &instance{home: home, directory: directory, name: name, role: role, level: level, hookMode: hook.mode,
		blacklist: hook.blacklist, blacklistSources: sources, data: data, writableRepos: repos, allowedTools: tools, secretNames: secrets, worktree: worktree}, nil
}

func findInstance(cwd, pinned string) (*instance, error) {
	inferred := instanceFromDirectory(cwd)
	explicit := os.Getenv("LANEBOSS_INSTANCE")
	chosen := pinned
	if chosen == "" {
		chosen = explicit
	}
	candidate := inferred
	if chosen != "" {
		if validName.MatchString(chosen) {
			home, err := homeFromDirectory(cwd)
			if err != nil {
				return nil, err
			}
			candidate = filepath.Join(home, "instances", chosen)
		} else {
			if !filepath.IsAbs(chosen) {
				return nil, invalid("LANEBOSS_INSTANCE must be a name or an absolute instance path")
			}
			candidate = chosen
			if filepath.Base(candidate) == "instance.toml" {
				candidate = filepath.Dir(candidate)
			}
		}
		if isSymlink(candidate) {
			return nil, invalid("an instance directory may not be a symlink")
		}
		var err error
		candidate, err = pathAt(candidate, cwd)
		if err != nil {
			return nil, err
		}
	}
	if candidate == "" {
		return nil, invalid("unknown instance: start in an instance directory or set LANEBOSS_INSTANCE")
	}
	inst, err := loadInstance(candidate)
	if err != nil {
		return nil, err
	}
	if inferred != "" && inferred != inst.directory {
		return nil, invalid("the working directory and the selected instance disagree")
	}
	if pinned != "" && explicit != "" && explicit != inst.name && explicit != inst.directory && explicit != filepath.Join(inst.directory, "instance.toml") {
		return nil, invalid("LANEBOSS_INSTANCE disagrees with the pinned instance")
	}
	return inst, nil
}

type rule struct {
	data, refusal map[string]any
	source        string
}

func validateRefusal(data map[string]any, label string) error {
	id, ok := data["id"].(string)
	if !ok || !validName.MatchString(id) {
		return invalid(label + " needs a valid refusal id")
	}
	for _, key := range []string{"refuses", "why", "instead"} {
		value, ok := data[key].(string)
		if !ok || strings.TrimSpace(value) == "" {
			return invalid(label + " needs " + key)
		}
	}
	applies, ok := object(data["applies_to"])
	if !ok {
		return invalid(label + " needs applies_to")
	}
	if _, _, err := hookScope(applies, label+" applies_to"); err != nil {
		return err
	}
	for _, key := range []string{"examples_allowed", "examples_refused"} {
		if _, err := stringList(data[key], label+" "+key, true); err != nil {
			return err
		}
	}
	return nil
}

func loadRuleRows(value any, layer, source string) ([]rule, error) {
	rows, ok := array(value)
	if !ok || len(rows) > maxRules {
		return nil, invalid(source + " rules must be an array of tables")
	}
	result := []rule{}
	seen := map[string]bool{}
	for _, value := range rows {
		row, ok := object(value)
		if !ok {
			return nil, invalid(source + " rules must be an array of tables")
		}
		id, ok := row["id"].(string)
		if !ok || !validName.MatchString(id) || seen[id] {
			return nil, invalid(source + " has an invalid or duplicate rule id")
		}
		seen[id] = true
		kind, ok := row["kind"].(string)
		fields := map[string][]string{"write-scope": {"paths", "deny_paths"}, "secret-read": {"names"}, "tool-allowlist": {"tools"}, "command-pattern": {"patterns"}}
		keys, known := fields[kind]
		if !ok || !known {
			return nil, invalid(source + " has an unknown rule kind")
		}
		if !onlyKeys(row, append([]string{"id", "kind", "applies_to"}, keys...)...) {
			return nil, invalid(source + " has an unknown rule field")
		}
		if kind == "command-pattern" {
			patterns, ok := array(row["patterns"])
			if !ok || len(patterns) == 0 || len(patterns) > maxRules {
				return nil, invalid(source + " command patterns must be arrays of argv words")
			}
			for _, pattern := range patterns {
				if _, err := stringList(pattern, source+" command pattern", false); err != nil {
					return nil, err
				}
			}
		} else {
			if _, err := stringList(row[keys[0]], source+" "+keys[0], true); err != nil {
				return nil, err
			}
			if kind == "write-scope" {
				if value, exists := row["deny_paths"]; exists {
					if _, err := stringList(value, source+" deny_paths", true); err != nil {
						return nil, err
					}
				}
			}
		}
		label := source + " refusal file " + id + ".toml"
		refusal, err := readTOML(filepath.Join(layer, "refusals", id+".toml"), label)
		if err != nil {
			return nil, err
		}
		if err := validateRefusal(refusal, label); err != nil {
			return nil, err
		}
		if refusal["id"] != id {
			return nil, invalid(source + " rule and refusal description disagree")
		}
		if applies, exists := row["applies_to"]; exists && !reflect.DeepEqual(applies, refusal["applies_to"]) {
			return nil, invalid(source + " rule and refusal description disagree")
		}
		result = append(result, rule{row, refusal, source})
	}
	return result, nil
}

func loadRules(inst *instance) ([]rule, error) {
	result := []rule{}
	for _, layer := range []string{"shared", fmt.Sprintf("L%d", inst.level)} {
		source := layer + "/hooks/rules.toml"
		path := filepath.Join(inst.home, filepath.FromSlash(source))
		// Rule sources are owner-authored and optional. A present but unreadable,
		// malformed or dangling-link source must still fail closed.
		if _, err := os.Lstat(path); os.IsNotExist(err) {
			continue
		} else if err != nil {
			return nil, invalid(source + " is unreadable")
		}
		data, err := readTOML(path, source)
		if err != nil {
			return nil, err
		}
		version, ok := integer(data["schema_version"])
		if !ok || version != 1 {
			return nil, invalid(source + " needs schema_version = 1")
		}
		if !onlyKeys(data, "schema_version", "rules") {
			return nil, invalid(source + " has an unknown policy field")
		}
		rows, err := loadRuleRows(data["rules"], filepath.Join(inst.home, layer), source)
		if err != nil {
			return nil, err
		}
		result = append(result, rows...)
	}
	hooks := map[string]any{}
	if value, exists := inst.data["hooks"]; exists {
		var ok bool
		hooks, ok = object(value)
		if !ok {
			return nil, invalid("instance hooks must be a table")
		}
	}
	if !onlyKeys(hooks, "rules") {
		return nil, invalid("instance hooks has an unknown policy field")
	}
	rowsValue, exists := hooks["rules"]
	if !exists {
		rowsValue = []any{}
	}
	rows, err := loadRuleRows(rowsValue, inst.directory, "instance.toml hooks")
	if err != nil {
		return nil, err
	}
	result = append(result, rows...)
	if len(result) > maxRules {
		return nil, invalid("the combined policy exceeds the rule limit")
	}
	return result, nil
}

func refusalText(data map[string]any, detail string, routes ...string) string {
	text := fmt.Sprintf("[%s] Refuses: %s\nWhy: %s", data["id"], data["refuses"], data["why"])
	if detail != "" {
		text += "\nInspection: " + detail
	}
	original := fmt.Sprint(data["instead"])
	route := original
	if len(routes) > 0 && routes[0] != "" {
		route = routes[0]
	}
	if route != original || strings.ContainsAny(original, "\r\n") {
		text += "\nRecorded alternative: " + original
	}
	return text + "\n" + routeScope + "\nInstead: " + strings.Join(strings.Fields(route), " ")
}

func listRefusals(org string) ([]map[string]any, error) {
	home, err := orgHome(org)
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(home)
	if err != nil {
		return nil, invalid("the org directory is unreadable")
	}
	layers := []string{filepath.Join(home, "shared")}
	for _, entry := range entries {
		if len(entry.Name()) == 2 && entry.Name()[0] == 'L' && entry.Name()[1] >= '3' && entry.Name()[1] <= '6' {
			layers = append(layers, filepath.Join(home, entry.Name()))
		}
	}
	instances := filepath.Join(home, "instances")
	if isDirectory(instances) {
		entries, err := os.ReadDir(instances)
		if err != nil {
			return nil, invalid("the instances directory is unreadable")
		}
		for _, entry := range entries {
			layer := filepath.Join(instances, entry.Name())
			if isDirectory(filepath.Join(layer, "refusals")) {
				layers = append(layers, layer)
			}
		}
	}
	result := []map[string]any{}
	for _, layer := range layers {
		files, err := os.ReadDir(filepath.Join(layer, "refusals"))
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return nil, invalid("a required refusals directory is missing or unreadable")
		}
		for _, file := range files {
			if !strings.HasSuffix(file.Name(), ".toml") {
				continue
			}
			path := filepath.Join(layer, "refusals", file.Name())
			data, err := readTOML(path, "refusal description")
			if err != nil {
				return nil, err
			}
			if err := validateRefusal(data, "refusal description"); err != nil {
				return nil, err
			}
			if strings.TrimSuffix(file.Name(), ".toml") != data["id"] {
				return nil, invalid("a refusal id does not match its filename")
			}
			relative, err := filepath.Rel(home, path)
			if err != nil {
				return nil, invalid("a refusal path cannot be resolved")
			}
			data["source"] = filepath.ToSlash(relative)
			result = append(result, data)
			if len(result) > maxRules {
				return nil, invalid("the refusal catalog exceeds the record limit")
			}
		}
	}
	return result, nil
}

func sortedKeys(data map[string]any) []string {
	keys := make([]string, 0, len(data))
	for key := range data {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
