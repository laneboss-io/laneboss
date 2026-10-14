package judge

import (
	"fmt"
	"math"
	"reflect"
	"regexp"
	"regexp/syntax"
	"strings"
	"unicode/utf8"

	"laneboss.io/laneboss/internal/runnermodel"
)

// These private configuration checks preserve the launcher's schema and cross
// rules without depending on a command group that is being ported separately.
type checker struct{ label string }
type validation func(any, string) error

func (c checker) fail(path, message string) error {
	return &commandError{2, "invalid configuration", c.label + ": " + path + ": " + message}
}
func tableValue(v any) map[string]any { m, _ := v.(map[string]any); return m }
func sliceValues(v any) []any {
	r := reflect.ValueOf(v)
	if !r.IsValid() || r.Kind() != reflect.Slice {
		return nil
	}
	a := make([]any, r.Len())
	for i := range a {
		a[i] = r.Index(i).Interface()
	}
	return a
}
func stringValues(v any) []string {
	a := sliceValues(v)
	out := make([]string, 0, len(a))
	for _, item := range a {
		if s, ok := item.(string); ok {
			out = append(out, s)
		}
	}
	return out
}
func keyPath(parent, key string) string {
	if parent == "" {
		return key
	}
	return parent + "." + key
}
func (c checker) text(pattern string, limit int) validation {
	var re *regexp.Regexp
	if pattern != "" {
		re = regexp.MustCompile("^(?:" + pattern + ")$")
	}
	return func(v any, p string) error {
		s, ok := v.(string)
		if !ok {
			return c.fail(p, "must be a string")
		}
		if trimWhitespace(s) == "" {
			return c.fail(p, "must not be empty")
		}
		if !utf8.ValidString(s) || utf8.RuneCountInString(s) > limit {
			return c.fail(p, fmt.Sprintf("must be valid Unicode with at most %d characters", limit))
		}
		for _, ch := range s {
			if ch < 32 || ch == 127 {
				return c.fail(p, "must not contain control characters")
			}
		}
		if re != nil && !re.MatchString(s) {
			return c.fail(p, "does not match the required grammar")
		}
		return nil
	}
}
func (c checker) integer(min, max int64) validation {
	return func(v any, p string) error {
		n, ok := v.(int64)
		if !ok {
			return c.fail(p, "must be an integer")
		}
		if n < min || n > max {
			return c.fail(p, fmt.Sprintf("must be from %d to %d", min, max))
		}
		return nil
	}
}
func (c checker) choice(choices string) validation {
	return func(v any, p string) error {
		s, ok := v.(string)
		if ok {
			for _, choice := range strings.Fields(choices) {
				if s == choice {
					return nil
				}
			}
		}
		return c.fail(p, "must be one of "+choices)
	}
}
func (c checker) array(item validation, nonempty, unique bool) validation {
	return func(v any, p string) error {
		rv := reflect.ValueOf(v)
		if !rv.IsValid() || rv.Kind() != reflect.Slice {
			return c.fail(p, "must be an array")
		}
		values := sliceValues(v)
		if nonempty && len(values) == 0 {
			return c.fail(p, "must not be empty")
		}
		seen := map[string]bool{}
		for i, v := range values {
			if err := item(v, fmt.Sprintf("%s[%d]", p, i)); err != nil {
				return err
			}
			if unique {
				key := string(encodeJSON(v))
				if seen[key] {
					return c.fail(p, "must not repeat an item")
				}
				seen[key] = true
			}
		}
		return nil
	}
}
func (c checker) table(fields map[string]validation, required string) validation {
	return func(v any, p string) error {
		m, ok := v.(map[string]any)
		if !ok {
			return c.fail(p, "must be a table")
		}
		for _, key := range sortedKeys(m) {
			if _, ok := fields[key]; !ok {
				return c.fail(keyPath(p, key), "unknown key")
			}
		}
		for _, key := range strings.Fields(required) {
			if _, ok := m[key]; !ok {
				return c.fail(keyPath(p, key), "is required")
			}
		}
		for _, key := range sortedKeys(m) {
			if err := fields[key](m[key], keyPath(p, key)); err != nil {
				return err
			}
		}
		return nil
	}
}
func (c checker) named(item validation, minimum int) validation {
	return func(v any, p string) error {
		m, ok := v.(map[string]any)
		if !ok {
			return c.fail(p, "must be a table")
		}
		if len(m) < minimum {
			return c.fail(p, "must define at least one entry")
		}
		for _, key := range sortedKeys(m) {
			if !namePattern.MatchString(key) {
				return c.fail(p, "has a key that is not a valid name")
			}
			if err := item(m[key], keyPath(p, key)); err != nil {
				return err
			}
		}
		return nil
	}
}
func validAbsolutePath(s string) bool {
	if !strings.HasPrefix(s, "/") {
		return false
	}
	for _, part := range strings.Split(s, "/") {
		if part == "." || part == ".." {
			return false
		}
	}
	return true
}
func (c checker) absolute(v any, p string) error {
	if err := c.text("", 4096)(v, p); err != nil {
		return err
	}
	if !validAbsolutePath(v.(string)) {
		return c.fail(p, "must be an absolute path without '.' or '..' parts")
	}
	return nil
}
func (c checker) relative(v any, p string) error {
	if err := c.text("", 1024)(v, p); err != nil {
		return err
	}
	s := v.(string)
	if strings.HasPrefix(s, "/") || strings.Contains(s, "\\") {
		return c.fail(p, "must be a relative path")
	}
	for _, part := range strings.Split(s, "/") {
		if part == "" || part == "." || part == ".." {
			return c.fail(p, "must be a relative path without '.', '..' or empty parts")
		}
	}
	return nil
}
func (c checker) rules(v any, p string) error {
	if err := c.relative(v, p); err != nil {
		return err
	}
	if strings.Split(v.(string), "/")[0] == "orgs" {
		return c.fail(p, "must not start with orgs")
	}
	return nil
}
func (c checker) schemaVersion(v any, p string) error {
	if n, ok := v.(int64); !ok || n != 1 {
		return c.fail(p, "unsupported schema version; this launcher reads schema_version = 1")
	}
	return nil
}
func (c checker) number(v any, p string) error {
	var n float64
	switch value := v.(type) {
	case int64:
		n = float64(value)
	case float64:
		n = value
	default:
		return c.fail(p, "must be a number")
	}
	if math.IsInf(n, 0) || math.IsNaN(n) || n < 0 {
		return c.fail(p, "must be a finite number that is not negative")
	}
	return nil
}
func (c checker) budget(v any, p string) error {
	if err := c.number(v, p); err != nil {
		return err
	}
	var n float64
	if i, ok := v.(int64); ok {
		n = float64(i)
	} else {
		n = v.(float64)
	}
	if n <= 0 || n > 10080 {
		return c.fail(p, "must be above zero and at most 10080 minutes")
	}
	return nil
}
func (c checker) boolean(v any, p string) error {
	if _, ok := v.(bool); !ok {
		return c.fail(p, "must be true or false")
	}
	return nil
}

const plainPlaceholders = "account brief effort lane log machine model project worktree"
const runnerPlaceholders = plainPlaceholders + " session"

var commandNamePattern = regexp.MustCompile(`^[A-Za-z0-9_.+-]+$`)

func templateFields(s string) ([]string, bool) {
	fields := []string{}
	for i := 0; i < len(s); i++ {
		if s[i] != '{' && s[i] != '}' {
			continue
		}
		if i+1 < len(s) && s[i+1] == s[i] {
			i++
			continue
		}
		if s[i] == '}' {
			return nil, false
		}
		end := strings.IndexByte(s[i+1:], '}')
		if end < 0 {
			return nil, false
		}
		field := s[i+1 : i+1+end]
		if strings.ContainsAny(field, "{:!") {
			return nil, false
		}
		fields = append(fields, field)
		i += end + 1
	}
	return fields, true
}
func usesTemplate(command []string, field string) bool {
	for _, arg := range command[1:] {
		fields, ok := templateFields(arg)
		if ok {
			for _, name := range fields {
				if name == field {
					return true
				}
			}
		}
	}
	return false
}
func (c checker) placeholders(v any, p, allowed string) error {
	fields, ok := templateFields(v.(string))
	if !ok {
		return c.fail(p, "has an unbalanced brace or invalid placeholder")
	}
	permitted := map[string]bool{}
	for _, name := range strings.Fields(allowed) {
		permitted[name] = true
	}
	for _, name := range fields {
		if !permitted[name] {
			return c.fail(p, "uses an unknown placeholder")
		}
	}
	return nil
}
func (c checker) command(allowed string, plain bool) validation {
	return func(v any, p string) error {
		if err := c.array(c.text("", 4096), true, false)(v, p); err != nil {
			return err
		}
		argv := stringValues(v)
		if !commandNamePattern.MatchString(argv[0]) && !strings.HasPrefix(argv[0], "/") {
			return c.fail(p+"[0]", "must be a command name or an absolute path")
		}
		for i, arg := range argv {
			field := fmt.Sprintf("%s[%d]", p, i)
			if plain || i == 0 {
				if strings.ContainsAny(arg, "{}") {
					return c.fail(field, "must not contain braces")
				}
			} else {
				if err := c.placeholders(arg, field, allowed); err != nil {
					return err
				}
			}
		}
		return nil
	}
}

func nestedGuardRepeat(re *syntax.Regexp, inside bool) bool {
	repeat := re.Op == syntax.OpStar || re.Op == syntax.OpPlus || re.Op == syntax.OpRepeat
	if repeat && inside && (re.Op != syntax.OpRepeat || re.Max > 1 || re.Max < 0) {
		return true
	}
	endless := re.Op == syntax.OpStar || re.Op == syntax.OpPlus || re.Op == syntax.OpRepeat && re.Max < 0
	for _, sub := range re.Sub {
		if nestedGuardRepeat(sub, inside || endless) {
			return true
		}
	}
	return false
}
func (c checker) pattern(guard bool) validation {
	return func(v any, p string) error {
		if err := c.text("", 1000)(v, p); err != nil {
			return err
		}
		s := v.(string)
		re, err := regexp.Compile(s)
		if err != nil {
			return c.fail(p, "is not a supported regular expression")
		}
		if re.MatchString("") {
			return c.fail(p, "must not match an empty line")
		}
		if guard {
			tree, err := syntax.Parse(s, syntax.Perl)
			if err != nil || nestedGuardRepeat(tree, false) {
				return c.fail(p, "cannot be bounded: it repeats a part that itself repeats")
			}
		}
		return nil
	}
}
func (c checker) runner(v any, p string) error {
	account := c.text("[A-Za-z0-9][A-Za-z0-9._-]{0,63}", 1000)
	secret := c.text("[A-Z][A-Z0-9_]{0,63}", 1000)
	fields := map[string]validation{"command": c.command(runnerPlaceholders, false), "resume": c.command(runnerPlaceholders+" message", false), "prompt": c.choice("argument stdin"), "stream": c.choice("text claude-stream-json"), "room": c.command("account", false), "accounts": c.array(account, false, true), "secrets": c.array(secret, false, true), "limit_patterns": c.array(c.pattern(false), true, true), "dropped_patterns": c.array(c.pattern(false), true, true), "quiet_seconds": c.integer(1, 604800), "description": c.text("", 1000), "records": c.array(c.record, true, false)}
	fields["api_models"] = func(value any, path string) error {
		if err := runnermodel.Validate(value); err != nil {
			return c.fail(path, err.Error())
		}
		return nil
	}
	if err := c.table(fields, "command")(v, p); err != nil {
		return err
	}
	m := tableValue(v)
	command := stringValues(m["command"])
	if m["prompt"] != "stdin" && !usesTemplate(command, "brief") {
		return c.fail(p+".command", "must pass the rendered brief with {brief}, or take its prompt on standard input")
	}
	if resume, ok := m["resume"]; ok && usesTemplate(command, "session") != usesTemplate(stringValues(resume), "session") {
		return c.fail(p+".resume", "command and resume must both use {session}, or neither")
	}
	return nil
}
func (c checker) record(v any, p string) error {
	pathRule := func(v any, p string) error {
		if err := c.text("", 4096)(v, p); err != nil {
			return err
		}
		if err := c.placeholders(v, p, "account effort lane log model project session worktree"); err != nil {
			return err
		}
		s := v.(string)
		if !strings.HasPrefix(s, "/") && !strings.HasPrefix(s, "~/") && !strings.HasPrefix(s, "{worktree}") && !strings.HasPrefix(s, "{log}") {
			return c.fail(p, "must be an absolute path or glob, or start with ~/, {worktree} or {log}")
		}
		return nil
	}
	if err := c.table(map[string]validation{"format": c.choice("claude-code text"), "paths": c.array(pathRule, true, true)}, "format paths")(v, p); err != nil {
		return err
	}
	m := tableValue(v)
	paths := stringValues(m["paths"])
	if m["format"] == "text" && (len(paths) != 1 || paths[0] != "{log}") {
		return c.fail(p+".paths", "format text reads only the run's own log: paths must be [\"{log}\"]")
	}
	return nil
}
func (c checker) supervisor(v any, p string) error {
	m := tableValue(v)
	_, level := m["level"]
	_, role := m["role"]
	if level == role {
		return c.fail(p, "give exactly one of level and role")
	}
	name := c.text("[a-z0-9][a-z0-9-]{0,31}", 1000)
	return c.table(map[string]validation{"level": c.integer(4, 6), "role": c.choice("top mini"), "runner": name, "projects": c.array(name, false, true), "owner_channel": name, "description": c.text("", 1000)}, "runner")(v, p)
}
func (c checker) environment(v any, p string) error {
	m := tableValue(v)
	if err := c.choice("cloud host local")(m["kind"], p+".kind"); err != nil {
		return err
	}
	kind := m["kind"].(string)
	fields := map[string]validation{"kind": c.choice("cloud host local"), "description": c.text("", 1000), "secrets": c.array(c.text("[A-Z][A-Z0-9_]{0,63}", 1000), false, true), "attest": c.command(plainPlaceholders, false), "launch": c.command(plainPlaceholders, false), "collect": c.command(plainPlaceholders, false), "max_machines": c.integer(1, 64), "idle_minutes": c.integer(1, 1440), "hard_minutes": c.integer(1, 10080)}
	required := "kind"
	if kind == "cloud" {
		fields["identity"] = c.text("[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,127}", 1000)
		fields["region"] = c.text("[a-z0-9][a-z0-9-]{0,31}", 1000)
		required += " identity"
	}
	if kind == "host" {
		fields["host"] = c.text("[A-Za-z0-9][A-Za-z0-9._-]{0,127}", 1000)
		required += " host"
	}
	if err := c.table(fields, required)(v, p); err != nil {
		return err
	}
	if len(sliceValues(m["secrets"])) > 0 {
		if _, ok := m["attest"]; !ok {
			return c.fail(p+".attest", "is required when secrets are listed: a secret goes only to a verified machine")
		}
	}
	return nil
}
func (c checker) channel(v any, p string) error {
	m := tableValue(v)
	if err := c.choice("chat file")(m["kind"], p+".kind"); err != nil {
		return err
	}
	fields := map[string]validation{"kind": c.choice("chat file"), "description": c.text("", 1000)}
	required := "kind"
	if m["kind"] == "file" {
		fields["path"] = c.relative
		required += " path"
	} else {
		fields["service"] = c.text("[a-z0-9][a-z0-9.-]{0,63}", 1000)
		fields["target"] = c.text("", 200)
		fields["token_secret"] = c.text("[A-Z][A-Z0-9_]{0,63}", 1000)
		required += " service target"
	}
	return c.table(fields, required)(v, p)
}
func (c checker) resource(v any, p string) error {
	envRule := func(v any, p string) error {
		if err := c.text("[A-Z][A-Z0-9_]{0,63}", 1000)(v, p); err != nil {
			return err
		}
		s := v.(string)
		if s == "PATH" || strings.HasPrefix(s, "LANEBOSS_") {
			return c.fail(p, "must not name the fixed PATH or the launcher's own variables")
		}
		return nil
	}
	fields := map[string]validation{"description": c.text("", 1000), "command": c.command("", true), "kind": c.choice("machine credential"), "credential_env": envRule, "credential_profile": c.text("[A-Za-z0-9][A-Za-z0-9._-]{0,63}", 1000), "acquire_seconds": c.integer(1, 900), "describe_seconds": c.integer(1, 300), "release_seconds": c.integer(1, 600), "acquire_bound_minutes": c.integer(1, 1440), "hard_cap_minutes": c.integer(1, 10080), "release_by_itself": c.boolean, "read_back_wait_seconds": c.integer(0, 3600)}
	if err := c.table(fields, "command kind hard_cap_minutes")(v, p); err != nil {
		return err
	}
	m := tableValue(v)
	seconds, bound := int64(300), int64(15)
	if n, ok := m["acquire_seconds"].(int64); ok {
		seconds = n
	}
	if n, ok := m["acquire_bound_minutes"].(int64); ok {
		bound = n
	}
	if bound < (seconds+59)/60+1 {
		return c.fail(p+".acquire_bound_minutes", "must be at least one minute more than acquire_seconds rounded up")
	}
	return nil
}
func (c checker) disk(v any, p string) error {
	if err := c.table(map[string]validation{"path": c.absolute, "warn_percent": c.integer(1, 99), "stop_percent": c.integer(1, 99)}, "")(v, p); err != nil {
		return err
	}
	m := tableValue(v)
	warn, stop := int64(85), int64(90)
	if n, ok := m["warn_percent"].(int64); ok {
		warn = n
	}
	if n, ok := m["stop_percent"].(int64); ok {
		stop = n
	}
	if warn >= stop {
		return c.fail(p+".warn_percent", "must be below stop_percent")
	}
	return nil
}
func (c checker) guards(v any, p string) error {
	rule := c.table(map[string]validation{"name": c.text("[A-Za-z0-9][A-Za-z0-9._-]{0,63}", 1000), "kind": c.choice("hook permission harness"), "pattern": c.pattern(true), "description": c.text("", 1000)}, "name pattern")
	if err := c.array(rule, false, false)(v, p); err != nil {
		return err
	}
	seen := map[string]bool{}
	for i, item := range sliceValues(v) {
		name := tableValue(item)["name"].(string)
		if seen[name] {
			return c.fail(fmt.Sprintf("%s[%d].name", p, i), "repeats the name of an earlier guard")
		}
		seen[name] = true
	}
	return nil
}
func (c checker) validateConfiguration(v any) error {
	name := c.text("[a-z0-9][a-z0-9-]{0,31}", 1000)
	secret := c.text("[A-Z][A-Z0-9_]{0,63}", 1000)
	model := func(v any, p string) error {
		if err := c.text(`[A-Za-z0-9][A-Za-z0-9._:/@+\[\]-]{0,127}`, 128)(v, p); err != nil {
			return err
		}
		if !strings.ContainsAny(v.(string), "0123456789") {
			return c.fail(p, "must be a full model name that includes its version")
		}
		return nil
	}
	route := c.table(map[string]validation{"runner": name, "model": model, "effort": c.text("[a-z0-9][a-z0-9-]{0,31}", 1000)}, "runner model")
	routing := map[string]validation{}
	for _, difficulty := range []string{"mechanical", "standard", "hard", "review"} {
		routing[difficulty] = c.array(route, true, false)
	}
	fields := map[string]validation{
		"schema_version": c.schemaVersion, "name": name, "description": c.text("", 1000), "organisation": name, "rules": c.array(c.rules, false, true), "organisation_rules": c.array(c.relative, false, true), "secrets": c.array(secret, false, true), "owner_channel": name, "test_environment": name,
		"state": c.table(map[string]validation{"path": c.absolute}, ""),
		"lanes": c.table(map[string]validation{"budget_minutes": c.budget, "quiet_seconds": c.integer(1, 604800), "stop_grace_seconds": c.integer(1, 600), "lock_wait_seconds": c.integer(1, 3600), "room_timeout_seconds": c.integer(1, 60)}, ""),
		"turns": c.table(map[string]validation{"idle_message": c.relative, "idle_seconds": c.integer(1, 604800), "poll_seconds": c.integer(1, 3600), "backoff_seconds": c.integer(1, 604800), "limit_backoff_seconds": c.integer(1, 604800)}, ""),
		"disk":  c.disk, "runners": c.named(c.runner, 1), "supervisors": c.named(c.supervisor, 0), "judges": c.named(c.table(map[string]validation{"description": c.text("", 1000), "command": c.command("", true), "timeout_seconds": c.integer(1, 60)}, "command"), 0), "resources": c.named(c.resource, 0), "routing": c.table(routing, ""), "test_environments": c.named(c.environment, 0), "owner_channels": c.named(c.channel, 0),
		"cost": c.table(map[string]validation{"currency": c.text("[A-Z]{3}", 1000), "daily_cap": c.number, "per_run_cap": c.number, "report_threshold": c.number}, "currency"), "guards": c.guards,
	}
	return c.table(fields, "schema_version name runners")(v, "")
}
func (c checker) validateProject(v any) error {
	name := c.text("[a-z0-9][a-z0-9-]{0,31}", 1000)
	return c.table(map[string]validation{"schema_version": c.schemaVersion, "name": name, "description": c.text("", 1000), "repository": c.text("", 1024), "lane_prefix": c.text("[a-z0-9][a-z0-9-]{0,15}", 1000), "workers": c.array(name, false, true), "gates": c.array(name, true, true), "excluded_accounts": c.array(c.text("[A-Za-z0-9][A-Za-z0-9._-]{0,63}", 1000), false, true), "test_environment": name, "reserved_paths": c.array(c.relative, false, true), "owner_channel": name, "landing_authority": name, "rules": c.array(c.rules, false, true)}, "schema_version name")(v, "")
}
