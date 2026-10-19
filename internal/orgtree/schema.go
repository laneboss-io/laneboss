package orgtree

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"laneboss.io/laneboss/internal/instancename"
	"laneboss.io/laneboss/internal/rolepolicy"
)

var (
	namePattern       = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
	secretNamePattern = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,63}$`)
	toolNamePattern   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$`)
	channelPattern    = regexp.MustCompile(`^[0-9]{1,20}$`)
)

var instanceOrder = []string{"schema_version", "name", "level", "role", "discord_channel_id", "services", "secrets", "writable_repos", "allowed_tools"}

// Defaults stay last so an appended scalar still belongs to that table.
var orgOrder = []string{"schema_version", "name", "company", "levels", "owner_channel", "secret_store", "hooks", "defaults"}

type problem struct {
	Path    string `json:"path"`
	Message string `json:"message"`
}

type checks struct {
	label    string
	problems []problem
}

func (c *checks) fail(field, message string) {
	c.problems = append(c.problems, problem{c.label, field + ": " + message})
}

func (c *checks) table(value any, field string, allowed, required []string) map[string]any {
	data, ok := value.(map[string]any)
	if !ok {
		c.fail(field, "must be a table")
		return map[string]any{}
	}
	for key := range data {
		if !contains(allowed, key) {
			c.fail(field, "contains an unknown field")
			break
		}
	}
	missing := append([]string{}, required...)
	sort.Strings(missing)
	for _, key := range missing {
		if _, exists := data[key]; !exists {
			if field == "document" {
				c.fail(key, "is required")
			} else {
				c.fail(field+"."+key, "is required")
			}
		}
	}
	return data
}

func contains(values []string, value string) bool {
	for _, item := range values {
		if item == value {
			return true
		}
	}
	return false
}

func integer(value any) (int, bool) {
	switch value := value.(type) {
	case int:
		return value, true
	case int64:
		result := int(value)
		return result, int64(result) == value
	case json.Number:
		if strings.ContainsAny(string(value), ".eE") {
			return 0, false
		}
		result, err := strconv.Atoi(string(value))
		return result, err == nil
	}
	return 0, false
}

func array(value any) ([]any, bool) {
	if value == nil {
		return nil, false
	}
	rv := reflect.ValueOf(value)
	if rv.Kind() != reflect.Slice {
		return nil, false
	}
	result := make([]any, rv.Len())
	for i := range result {
		result[i] = rv.Index(i).Interface()
	}
	return result, true
}

func (c *checks) text(value any, field string, pattern *regexp.Regexp, maximum int) bool {
	text, ok := value.(string)
	if !ok || strings.TrimSpace(text) == "" || utf8.RuneCountInString(text) > maximum {
		c.fail(field, fmt.Sprintf("must be a nonempty string of at most %d characters", maximum))
		return false
	}
	if !utf8.ValidString(text) {
		c.fail(field, "must be valid UTF-8 without invalid Unicode sequences")
		return false
	}
	for _, r := range text {
		if r < 32 || r == 127 || r >= 0xd800 && r <= 0xdfff {
			c.fail(field, "must not contain control characters or Unicode surrogates")
			return false
		}
	}
	if pattern != nil && !pattern.MatchString(text) {
		c.fail(field, "must match "+strings.TrimSuffix(strings.TrimPrefix(pattern.String(), "^"), "$"))
		return false
	}
	return true
}

func (c *checks) level(value any, field string) bool {
	level, ok := integer(value)
	if !ok || level < 3 || level > 6 {
		c.fail(field, "must be an integer from 3 to 6")
		return false
	}
	return true
}

func (c *checks) version(value any) {
	version, ok := integer(value)
	if !ok || version != 1 {
		c.fail("schema_version", "must be 1")
	}
}

func (c *checks) repos(value any, field string) {
	if c.text(value, field, nil, 1024) {
		text := value.(string)
		bad := strings.Contains(text, "\\")
		for _, part := range strings.Split(text, "/") {
			bad = bad || part == "" || part == "." || part == ".."
		}
		if bad {
			c.fail(field, "must be an org-relative path without empty, '.' or '..' parts")
		}
	}
}

func (c *checks) array(value any, field string, itemCheck func(any, string)) {
	items, ok := array(value)
	if !ok {
		c.fail(field, "must be an array")
		return
	}
	seen := make(map[any]bool)
	for i, item := range items {
		itemCheck(item, fmt.Sprintf("%s[%d]", field, i))
		var key any
		if text, ok := item.(string); ok {
			key = text
		} else if number, ok := integer(item); ok {
			key = number
		}
		if key != nil {
			if seen[key] {
				c.fail(field, "must not repeat an item")
				break
			}
			seen[key] = true
		}
	}
}

func (c *checks) instanceFields(data map[string]any, prefix string) {
	if value, exists := data["level"]; exists {
		c.level(value, prefix+"level")
	}
	if value, exists := data["role"]; exists {
		c.text(value, prefix+"role", nil, 128)
	}
	if value, exists := data["discord_channel_id"]; exists {
		c.text(value, prefix+"discord_channel_id", channelPattern, 128)
	}
	for _, field := range []string{"services", "secrets", "allowed_tools"} {
		if value, exists := data[field]; exists {
			pattern := namePattern
			if field == "secrets" {
				pattern = secretNamePattern
			} else if field == "allowed_tools" {
				pattern = toolNamePattern
			}
			c.array(value, prefix+field, func(item any, name string) { c.text(item, name, pattern, 128) })
		}
	}
	if value, exists := data["writable_repos"]; exists {
		c.array(value, prefix+"writable_repos", c.repos)
	}
}

func (c *checks) hookPolicy(value any, field string, enabled []any) {
	hooks := c.table(value, field, []string{"mode", "blacklist"}, nil)
	if mode, exists := hooks["mode"]; exists {
		if !c.text(mode, field+".mode", nil, 16) || (mode != "blacklist" && mode != "strict") {
			c.fail(field+".mode", "must be blacklist or strict")
		}
	}
	rows, exists := hooks["blacklist"]
	if !exists {
		return
	}
	items, ok := array(rows)
	if !ok || len(items) > 512 {
		c.fail(field+".blacklist", "must be an array of at most 512 tables")
		return
	}
	seen := map[string]bool{}
	for i, item := range items {
		prefix := fmt.Sprintf("%s.blacklist[%d]", field, i)
		row, ok := item.(map[string]any)
		if !ok {
			c.fail(prefix, "must be a table")
			continue
		}
		allowed := []string{"id", "description", "band", "instead", "argv", "argv_prefix", "argv_words", "pattern", "path", "path_glob", "tool", "applies_to", "levels", "roles", "identities", "decision", "job", "examples_not_ok", "examples_ok", "pattern_only"}
		for key := range row {
			if !contains(allowed, key) {
				c.fail(prefix, "contains an unknown field")
			}
		}
		id, idOK := row["id"].(string)
		if !idOK || !namePattern.MatchString(id) || seen[id] {
			c.fail(prefix+".id", "must be a unique simple name")
		} else {
			seen[id] = true
		}
		c.text(row["description"], prefix+".description", nil, 4096)
		band, bandOK := row["band"].(string)
		if !bandOK || (band != "refuse" && band != "warn") {
			c.fail(prefix+".band", "must be refuse or warn")
		}
		if value, exists := row["argv"]; exists {
			values, ok := array(value)
			if !ok || len(values) == 0 {
				c.fail(prefix+".argv", "must be a nonempty array")
			} else {
				for j, value := range values {
					c.array(value, fmt.Sprintf("%s.argv[%d]", prefix, j), func(item any, name string) {
						if c.text(item, name, nil, 1024) && contains([]string{";", "&&", "||", "|", "|&", "&", "(", ")", ";;", ";&", ";;&"}, item.(string)) {
							c.fail(name, "cannot contain shell operators")
						}
					})
				}
			}
		}
		for _, key := range []string{"argv_prefix", "pattern"} {
			if value, exists := row[key]; exists {
				c.array(value, prefix+"."+key, func(item any, name string) {
					if c.text(item, name, nil, 1024) && contains([]string{";", "&&", "||", "|", "|&", "&", "(", ")", ";;", ";&", ";;&"}, item.(string)) {
						c.fail(name, "cannot contain shell operators")
					}
				})
			}
		}
		for _, key := range []string{"path", "path_glob", "tool", "decision", "job", "instead"} {
			if value, exists := row[key]; exists {
				c.text(value, prefix+"."+key, nil, 4096)
			}
		}
		if value, exists := row["argv_words"]; exists {
			if words, ok := array(value); !ok || len(words) == 0 {
				c.fail(prefix+".argv_words", "must be a nonempty array")
			}
			c.array(value, prefix+".argv_words", func(item any, name string) {
				if c.text(item, name, nil, 1024) && contains([]string{";", "&&", "||", "|", "|&", "&", "(", ")", ";;", ";&", ";;&",
					">", ">>", "<", "<<", "<<-", "<<<", ">|", "<>", "&>", "&>>", ">&", "<&", "!"}, item.(string)) {
					c.fail(name, "cannot contain shell operators")
				}
			})
			for _, key := range []string{"argv", "argv_prefix", "pattern"} {
				if _, exists := row[key]; exists {
					c.fail(prefix+".argv_words", "cannot be combined with argv, argv_prefix or pattern")
				}
			}
		}
		if _, exists := row["job"]; exists {
			c.fail(prefix+".job", "is not supported until the job catalog is available")
		}
		if value, exists := row["pattern_only"]; exists {
			patternOnly, ok := value.(bool)
			if !ok {
				c.fail(prefix+".pattern_only", "must be a boolean")
			} else if patternOnly {
				matched := false
				for _, key := range []string{"argv", "argv_prefix", "argv_words", "pattern", "path", "path_glob", "tool"} {
					if words, ok := array(row[key]); ok {
						matched = matched || len(words) > 0
					} else if text, ok := row[key].(string); ok {
						matched = matched || strings.TrimSpace(text) != ""
					}
				}
				if !matched || row["decision"] != nil || row["job"] != nil {
					c.fail(prefix+".pattern_only", "requires a deterministic matcher and no decision or job reference")
				}
			}
		}
		for _, key := range []string{"examples_not_ok", "examples_ok"} {
			if value, exists := row[key]; exists {
				values, ok := array(value)
				if !ok || len(values) > 8 {
					c.fail(prefix+"."+key, "must be an array of at most 8 examples")
					continue
				}
				total := 0
				for j, item := range values {
					if c.text(item, fmt.Sprintf("%s.%s[%d]", prefix, key, j), nil, 512) {
						total += len([]byte(item.(string)))
					}
				}
				if total > 4096 {
					c.fail(prefix+"."+key, "exceeds the combined example byte limit")
				}
			}
		}
		if scope, exists := row["applies_to"]; exists {
			c.hookScope(scope, prefix+".applies_to", enabled)
		}
	}
}

func (c *checks) hookScope(value any, field string, enabled []any) {
	scope, ok := value.(map[string]any)
	if !ok {
		c.fail(field, "must be a table")
		return
	}
	for key := range scope {
		if key != "levels" && key != "roles" && key != "identities" {
			c.fail(field, "contains an unknown field")
		}
	}
	if raw, exists := scope["levels"]; exists {
		c.array(raw, field+".levels", func(item any, name string) { c.level(item, name) })
	}
	for _, key := range []string{"roles", "identities"} {
		if raw, exists := scope[key]; exists {
			c.array(raw, field+"."+key, func(item any, name string) { c.text(item, name, namePattern, 128) })
		}
	}
	if raw, exists := scope["levels"]; exists {
		if values, ok := array(raw); ok && len(enabled) > 0 {
			for _, value := range values {
				level, ok := integer(value)
				if ok && !hasLevel(enabled, level) {
					c.fail(field+".levels", "must use enabled levels")
				}
			}
		}
	}
}

func checkOrg(value any, label, root string) []problem {
	c := checks{label: label}
	// The Discord command consumes this optional service table. It must also be
	// accepted by render/validate; otherwise registering a channel invalidates
	// the same org that channel add has just written.
	allowed := append(append([]string{}, orgOrder...), "services", "lane_roles")
	required := []string{}
	for _, key := range orgOrder {
		if key != "hooks" { // Optional for existing orgs, regardless of table order.
			required = append(required, key)
		}
	}
	data := c.table(value, "document", allowed, required)
	if value, exists := data["schema_version"]; exists {
		c.version(value)
	}
	for _, field := range []string{"name", "company", "owner_channel"} {
		if value, exists := data[field]; exists {
			c.text(value, field, namePattern, 128)
		}
	}
	levels, levelsOK := array(data["levels"])
	if value, exists := data["levels"]; exists {
		c.array(value, "levels", func(item any, field string) { c.level(item, field) })
		if levelsOK && len(levels) == 0 {
			c.fail("levels", "must enable at least one level")
		}
	}
	if value, exists := data["secret_store"]; exists {
		store := c.table(value, "secret_store", []string{"kind", "path"}, []string{"kind", "path"})
		kind, _ := store["kind"].(string)
		if _, exists := store["kind"]; exists && kind != "keychain" && kind != "file" {
			c.fail("secret_store.kind", "must be keychain or file")
		}
		if value, exists := store["path"]; exists && c.text(value, "secret_store.path", nil, 4096) {
			path := value.(string)
			if kind == "keychain" {
				for _, part := range strings.Split(path, "/") {
					if !namePattern.MatchString(part) {
						c.fail("secret_store.path", "must be a keychain namespace of simple names separated by '/'")
						break
					}
				}
			} else if kind == "file" {
				bad := !filepath.IsAbs(path)
				for _, part := range strings.Split(path, "/")[1:] {
					bad = bad || part == "" || part == "." || part == ".."
				}
				if bad {
					c.fail("secret_store.path", "must be an absolute external file path without '.' or '..'")
				} else if resolved, err := resolvePath(path); err != nil {
					c.fail("secret_store.path", "cannot resolve the external file path")
				} else if inside(root, resolved) {
					c.fail("secret_store.path", "secret values must live outside the org folder")
				}
			}
		}
	}
	if value, exists := data["defaults"]; exists {
		defaults := c.table(value, "defaults", instanceOrder[2:], []string{"level", "role"})
		c.instanceFields(defaults, "defaults.")
		if level, ok := integer(defaults["level"]); ok && levelsOK && !hasLevel(levels, level) {
			c.fail("defaults.level", "must be an enabled level")
		}
	}
	if value, exists := data["hooks"]; exists {
		c.hookPolicy(value, "hooks", levels)
	}
	if _, exists := data["lane_roles"]; exists && levelsOK {
		enabled := []int{}
		for _, item := range levels {
			if level, ok := integer(item); ok {
				enabled = append(enabled, level)
			}
		}
		if _, err := rolepolicy.Settings(data, enabled); err != nil {
			c.fail("lane_roles", err.Error())
		}
	}
	if value, exists := data["services"]; exists {
		// Python's Discord reader consumes only its own table and leaves other
		// services and unknown service settings alone. Preserve that behavior.
		services, ok := value.(map[string]any)
		if !ok {
			c.fail("services", "must be a table")
			return c.problems
		}
		if value, exists := services["discord"]; exists {
			discord, ok := value.(map[string]any)
			if !ok {
				c.fail("services.discord", "must be a table")
				return c.problems
			}
			for _, field := range []string{"guild_id", "token_secret"} {
				if _, exists := discord[field]; !exists {
					c.fail("services.discord."+field, "is required")
				}
			}
			for _, field := range []string{"guild_id", "owner_id"} {
				if value, exists := discord[field]; exists {
					c.text(value, "services.discord."+field, regexp.MustCompile(`^[1-9][0-9]{0,19}$`), 20)
				}
			}
			if value, exists := discord["token_secret"]; exists {
				c.text(value, "services.discord.token_secret", secretNamePattern, 64)
			}
		}
	}
	return c.problems
}

func hasLevel(items []any, level int) bool {
	for _, item := range items {
		if number, ok := integer(item); ok && number == level {
			return true
		}
	}
	return false
}

func checkInstance(value any, label, directoryName string, levels []int) []problem {
	c := checks{label: label}
	required := []string{}
	for _, key := range instanceOrder {
		if key != "discord_channel_id" && key != "allowed_tools" {
			required = append(required, key)
		}
	}
	data := c.table(value, "document", instanceOrder, required)
	if value, exists := data["schema_version"]; exists {
		c.version(value)
	}
	if value, exists := data["name"]; exists {
		c.text(value, "name", instancename.Expression, instancename.MaxLength)
		if text, ok := value.(string); !ok || text != directoryName {
			c.fail("name", "must match the instance directory name")
		}
	}
	c.instanceFields(data, "")
	if level, ok := integer(data["level"]); ok {
		found := false
		for _, enabled := range levels {
			found = found || enabled == level
		}
		if !found {
			c.fail("level", "the instance level is not enabled in org.toml")
		}
	}
	return c.problems
}
