// Package hookblacklist validates the shared org and role blacklist entry schema.
package hookblacklist

import (
	"errors"
	"fmt"
	"laneboss.io/laneboss/internal/instancename"
	"reflect"
	"strings"
)

const maxRules = 512
const maxDescriptionBytes = 4096

var validName = instancename.Expression

func invalid(message string) error { return errors.New(message) }

type Rule struct {
	ID, Description, Band, Instead string
	Argv                           [][]string
	ArgvWords                      []string
	PathGlob, ToolGlob             string
	Decision, Job                  string
	Levels                         []int
	Roles                          []string
	IdentityScope                  bool
	ExamplesNotOK, ExamplesOK      []string
	PatternOnly                    bool
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

// Parse validates entries identically for org.toml and role sources.
func Parse(value any, label string) ([]Rule, error) {
	if value == nil {
		return nil, nil
	}
	rows, err := parse(value)
	if err != nil {
		return nil, errors.New(strings.ReplaceAll(err.Error(), "org.toml hooks.blacklist", label))
	}
	return rows, nil
}

func parse(rowsValue any) ([]Rule, error) {
	result := []Rule{}
	rows, ok := array(rowsValue)
	if !ok || len(rows) > maxRules {
		return result, invalid("org.toml hooks.blacklist must be an array of tables")
	}
	seen := map[string]bool{}
	for _, rawRow := range rows {
		row, ok := object(rawRow)
		if !ok {
			return result, invalid("org.toml hooks.blacklist must contain tables")
		}
		allowed := []string{"id", "description", "band", "instead", "argv", "argv_prefix", "argv_words", "pattern", "path", "path_glob", "tool", "applies_to", "levels", "roles", "identities", "decision", "job", "examples_not_ok", "examples_ok", "pattern_only"}
		if !onlyKeys(row, allowed...) {
			return result, invalid("org.toml hooks.blacklist has an unknown field")
		}
		id, ok := row["id"].(string)
		if !ok || !validName.MatchString(id) || seen[id] {
			return result, invalid("org.toml hooks.blacklist has an invalid or duplicate id")
		}
		seen[id] = true
		description, err := hookText(row["description"], "org.toml hooks.blacklist.description", maxDescriptionBytes)
		if err != nil {
			return result, err
		}
		band, ok := row["band"].(string)
		if !ok || (band != "refuse" && band != "warn") {
			return result, invalid("org.toml hooks.blacklist.band must be refuse or warn")
		}
		instead := "leave the call undone and report the matched blacklist entry to the supervisor."
		if value, exists := row["instead"]; exists {
			instead, err = hookText(value, "org.toml hooks.blacklist.instead", maxDescriptionBytes)
			if err != nil {
				return result, err
			}
		}
		patterns := [][]string{}
		for _, key := range []string{"argv", "argv_prefix", "pattern"} {
			if value, exists := row[key]; exists {
				if len(patterns) > 0 {
					return result, invalid("org.toml hooks.blacklist may name only one argv prefix field")
				}
				if key == "argv" {
					values, ok := array(value)
					if !ok || len(values) == 0 {
						return result, invalid("org.toml hooks.blacklist.argv must be a nonempty array of argv prefixes")
					}
					if len(values) > maxRules {
						return result, invalid("org.toml hooks.blacklist.argv has too many prefixes")
					}
					for _, prefix := range values {
						words, err := stringList(prefix, "org.toml hooks.blacklist.argv prefix", false)
						if err != nil {
							return result, err
						}
						for _, word := range words {
							if contains([]string{";", "&&", "||", "|", "|&", "&", "(", ")", ";;", ";&", ";;&"}, word) {
								return result, invalid("org.toml hooks.blacklist argv prefixes cannot contain shell operators")
							}
						}
						patterns = append(patterns, words)
					}
				} else {
					words, err := stringList(value, "org.toml hooks.blacklist."+key, false)
					if err != nil {
						return result, err
					}
					for _, word := range words {
						if contains([]string{";", "&&", "||", "|", "|&", "&", "(", ")", ";;", ";&", ";;&"}, word) {
							return result, invalid("org.toml hooks.blacklist argv prefixes cannot contain shell operators")
						}
					}
					patterns = append(patterns, words)
				}
			}
		}
		var argvWords []string
		if value, exists := row["argv_words"]; exists {
			if len(patterns) > 0 {
				return result, invalid("org.toml hooks.blacklist.argv_words cannot be combined with argv, argv_prefix or pattern")
			}
			words, err := stringList(value, "org.toml hooks.blacklist.argv_words", false)
			if err != nil {
				return result, err
			}
			for _, word := range words {
				if contains([]string{";", "&&", "||", "|", "|&", "&", "(", ")", ";;", ";&", ";;&",
					">", ">>", "<", "<<", "<<-", "<<<", ">|", "<>", "&>", "&>>", ">&", "<&", "!"}, word) {
					return result, invalid("org.toml hooks.blacklist.argv_words cannot contain shell operators")
				}
			}
			argvWords = words
		}
		pathGlob := ""
		for _, key := range []string{"path", "path_glob"} {
			if value, exists := row[key]; exists {
				if pathGlob != "" {
					return result, invalid("org.toml hooks.blacklist may name only one of path or path_glob")
				}
				pathGlob, err = hookText(value, "org.toml hooks.blacklist.path", maxDescriptionBytes)
				if err != nil {
					return result, err
				}
			}
		}
		toolGlob := ""
		if value, exists := row["tool"]; exists {
			toolGlob, err = hookText(value, "org.toml hooks.blacklist.tool", maxDescriptionBytes)
			if err != nil {
				return result, err
			}
		}
		identityScope := false
		if scope, ok := object(row["applies_to"]); ok {
			_, hasRoles := scope["roles"]
			_, identityScope = scope["identities"]
			if hasRoles {
				identityScope = false
			}
		}
		levels, roles, err := hookScope(row["applies_to"], "org.toml hooks.blacklist.applies_to")
		if err != nil {
			return result, err
		}
		if row["applies_to"] == nil {
			scope := map[string]any{}
			for _, key := range []string{"levels", "roles", "identities"} {
				if value, exists := row[key]; exists {
					scope[key] = value
				}
			}
			levels, roles, err = hookScope(scope, "org.toml hooks.blacklist scope")
			_, identityScope = scope["identities"]
			if err != nil {
				return result, err
			}
		}
		examplesNotOK, err := hookExamples(row["examples_not_ok"], "org.toml hooks.blacklist.examples_not_ok")
		if err != nil {
			return result, err
		}
		examplesOK, err := hookExamples(row["examples_ok"], "org.toml hooks.blacklist.examples_ok")
		if err != nil {
			return result, err
		}
		decision, job := "", ""
		for _, key := range []string{"decision", "job"} {
			if value, exists := row[key]; exists {
				text, err := hookText(value, "org.toml hooks.blacklist."+key, 256)
				if err != nil {
					return result, err
				}
				if key == "decision" {
					decision = text
				} else {
					job = text
				}
			}
		}
		if job != "" {
			return result, invalid("org.toml hooks.blacklist.job is not supported until the job catalog is available")
		}
		patternOnly := false
		if value, exists := row["pattern_only"]; exists {
			var ok bool
			patternOnly, ok = value.(bool)
			if !ok || (patternOnly && (len(patterns) == 0 && len(argvWords) == 0 && pathGlob == "" && toolGlob == "" || decision != "" || job != "")) {
				return result, invalid("org.toml hooks.blacklist.pattern_only must be a boolean and needs a deterministic matcher and no decision or job reference when true")
			}
		}
		result = append(result, Rule{PatternOnly: patternOnly, ID: id, Description: description, Band: band, Instead: instead,
			Argv: patterns, ArgvWords: argvWords, PathGlob: pathGlob, ToolGlob: toolGlob, Decision: decision, Job: job, Levels: levels, Roles: roles, IdentityScope: identityScope,
			ExamplesNotOK: examplesNotOK, ExamplesOK: examplesOK})
	}
	return result, nil
}
