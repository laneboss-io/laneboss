package start

import (
	"encoding/json"
	"fmt"
	"math"
	"regexp"
	"regexp/syntax"
	"strconv"
	"strings"
	"unicode/utf8"

	"laneboss.io/laneboss/internal/runnermodel"
)

const nameRule = `[a-z0-9][a-z0-9-]{0,31}`

var nameRE = rx(`^` + nameRule + `$`)

const accountRule = `[A-Za-z0-9][A-Za-z0-9._-]{0,63}`
const modelRule = `[A-Za-z0-9][A-Za-z0-9._:/@+\[\]-]{0,127}`

type validator func(string, any, string) error

func fieldPath(base, key string) string {
	if base == "" {
		return key
	}
	return base + "." + key
}
func textCheck(pattern string, limit int) validator {
	var re *regexp.Regexp
	if pattern != "" {
		re = rx(`^(?:` + pattern + `)$`)
	}
	return func(label string, v any, path string) error {
		s, ok := v.(string)
		if !ok {
			return invalid(label, path, "must be a string")
		}
		if strings.TrimSpace(s) == "" {
			return invalid(label, path, "must not be empty")
		}
		if utf8.RuneCountInString(s) > limit {
			return invalid(label, path, fmt.Sprintf("must be at most %d characters", limit))
		}
		for _, r := range s {
			if r < 32 || r == 127 {
				return invalid(label, path, "must not contain control characters")
			}
		}
		if re != nil && !re.MatchString(s) {
			return invalid(label, path, "must match "+pattern)
		}
		return nil
	}
}
func intValue(v any) (int64, bool) {
	switch n := v.(type) {
	case int:
		return int64(n), true
	case int64:
		return n, true
	case json.Number:
		if strings.ContainsAny(string(n), ".eE") {
			return 0, false
		}
		val, err := strconv.ParseInt(string(n), 10, 64)
		return val, err == nil
	}
	return 0, false
}
func numberValue(v any) (float64, bool) {
	if n, ok := intValue(v); ok {
		return float64(n), true
	}
	switch n := v.(type) {
	case float64:
		return n, !math.IsNaN(n) && !math.IsInf(n, 0)
	case json.Number:
		value, err := n.Float64()
		return value, err == nil && !math.IsNaN(value) && !math.IsInf(value, 0)
	}
	return 0, false
}
func integerCheck(min, max int64) validator {
	return func(l string, v any, p string) error {
		n, ok := intValue(v)
		if !ok {
			return invalid(l, p, "must be an integer")
		}
		if n < min || n > max {
			return invalid(l, p, fmt.Sprintf("must be from %d to %d", min, max))
		}
		return nil
	}
}
func numberCheck(min, max float64, above bool) validator {
	return func(l string, v any, p string) error {
		n, ok := numberValue(v)
		if !ok || n < min || n > max || above && n == min {
			return invalid(l, p, "must be a finite number in the permitted range")
		}
		return nil
	}
}
func choices(values ...string) validator {
	return func(l string, v any, p string) error {
		s, ok := v.(string)
		if !ok || !contains(values, s) {
			return invalid(l, p, "must be one of: "+strings.Join(values, ", "))
		}
		return nil
	}
}
func boolCheck(l string, v any, p string) error {
	if _, ok := v.(bool); !ok {
		return invalid(l, p, "must be true or false")
	}
	return nil
}
func nullable(check validator) validator {
	return func(l string, v any, p string) error {
		if v == nil {
			return nil
		}
		return check(l, v, p)
	}
}
func listCheck(check validator, nonempty, unique bool, maximum int) validator {
	return func(l string, v any, p string) error {
		a, ok := v.([]any)
		if !ok {
			return invalid(l, p, "must be an array")
		}
		if nonempty && len(a) == 0 {
			return invalid(l, p, "must not be empty")
		}
		if maximum > 0 && len(a) > maximum {
			return invalid(l, p, "has too many items")
		}
		seen := map[string]bool{}
		for i, item := range a {
			if err := check(l, item, fmt.Sprintf("%s[%d]", p, i)); err != nil {
				return err
			}
			data, err := json.Marshal(item)
			if err != nil {
				return invalid(l, p, "has an invalid item")
			}
			key := string(data)
			if unique && seen[key] {
				return invalid(l, p, "must not repeat an item")
			}
			seen[key] = true
		}
		return nil
	}
}
func tableCheck(fields map[string]validator, required ...string) validator {
	return func(l string, v any, p string) error {
		m, ok := v.(map[string]any)
		if !ok {
			return invalid(l, p, "must be a table")
		}
		for _, key := range sortedKeys(m) {
			if _, ok := fields[key]; !ok {
				return invalid(l, fieldPath(p, key), "unknown key")
			}
		}
		for _, key := range required {
			if _, ok := m[key]; !ok {
				return invalid(l, fieldPath(p, key), "is required")
			}
		}
		for _, key := range sortedKeys(m) {
			if err := fields[key](l, m[key], fieldPath(p, key)); err != nil {
				return err
			}
		}
		return nil
	}
}
func namedCheck(check validator, min int) validator {
	return func(l string, v any, p string) error {
		m, ok := v.(map[string]any)
		if !ok {
			return invalid(l, p, "must be a table")
		}
		if len(m) < min {
			return invalid(l, p, fmt.Sprintf("must define at least %d entry", min))
		}
		for _, key := range sortedKeys(m) {
			if !nameRE.MatchString(key) {
				return invalid(l, p, "has a key that is not a valid name ("+nameRule+")")
			}
			if err := check(l, m[key], fieldPath(p, key)); err != nil {
				return err
			}
		}
		return nil
	}
}
func relativeCheck(l string, v any, p string) error {
	if err := textCheck("", 1024)(l, v, p); err != nil {
		return err
	}
	s := str(v)
	if strings.HasPrefix(s, "/") || strings.Contains(s, "\\") {
		return invalid(l, p, "must be a relative path without '..', '.' or empty parts")
	}
	for _, part := range strings.Split(s, "/") {
		if part == "" || part == "." || part == ".." {
			return invalid(l, p, "must be a relative path without '..', '.' or empty parts")
		}
	}
	return nil
}
func rulesCheck(l string, v any, p string) error {
	if err := relativeCheck(l, v, p); err != nil {
		return err
	}
	if strings.Split(str(v), "/")[0] == "orgs" {
		return invalid(l, p, "must not start with orgs: orgs/NAME/<path> is the label of an organisation's rules file")
	}
	return nil
}
func absoluteCheck(l string, v any, p string) error {
	if err := textCheck("", 4096)(l, v, p); err != nil {
		return err
	}
	s := str(v)
	if !strings.HasPrefix(s, "/") {
		return invalid(l, p, "must be an absolute path without '.' or '..' parts")
	}
	for _, part := range strings.Split(s, "/") {
		if part == "." || part == ".." {
			return invalid(l, p, "must be an absolute path without '.' or '..' parts")
		}
	}
	return nil
}
func modelCheck(l string, v any, p string) error {
	if err := textCheck(modelRule, 128)(l, v, p); err != nil {
		return err
	}
	if !digit.MatchString(str(v)) {
		return invalid(l, p, "must be a full model name that includes its version, not a family alias")
	}
	return nil
}

func apiModelsCheck(l string, v any, p string) error {
	if err := runnermodel.Validate(v); err != nil {
		return invalid(l, p, err.Error())
	}
	return nil
}

var basePlaceholders = strings.Fields("account brief effort lane log machine model project worktree")

func templateFields(s string) ([]string, error) {
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
			return nil, fmt.Errorf("brace")
		}
		end := strings.IndexByte(s[i+1:], '}')
		if end < 0 {
			return nil, fmt.Errorf("brace")
		}
		end += i + 1
		fields = append(fields, s[i+1:end])
		i = end
	}
	return fields, nil
}
func uses(v any, field string) bool {
	for i, s := range stringsOf(v) {
		if i == 0 {
			continue
		}
		fields, err := templateFields(s)
		if err != nil {
			return false
		}
		if contains(fields, field) {
			return true
		}
	}
	return false
}
func templateCheck(allowed []string, plain bool) validator {
	return func(l string, v any, p string) error {
		if err := listCheck(textCheck("", 4096), true, false, 0)(l, v, p); err != nil {
			return err
		}
		items := stringsOf(v)
		first := items[0]
		if !(rx(`^[A-Za-z0-9_.+-]+$`).MatchString(first) || strings.HasPrefix(first, "/") && !strings.ContainsAny(first, "{}")) {
			return invalid(l, p+"[0]", "must be a command name or an absolute path, without placeholders")
		}
		for i, s := range items {
			if plain {
				if strings.ContainsAny(s, "{}") {
					return invalid(l, fmt.Sprintf("%s[%d]", p, i), "must not contain braces: this command has no placeholders in version 1")
				}
				continue
			}
			if i == 0 {
				continue
			}
			fields, err := templateFields(s)
			if err != nil {
				return invalid(l, fmt.Sprintf("%s[%d]", p, i), "has an unbalanced brace; write {{ or }} for a literal brace")
			}
			for _, field := range fields {
				if !contains(allowed, field) {
					return invalid(l, fmt.Sprintf("%s[%d]", p, i), "uses an unknown placeholder")
				}
			}
		}
		return nil
	}
}
func regexCheck(l string, v any, p string) error {
	if err := textCheck("", 1000)(l, v, p); err != nil {
		return err
	}
	pattern, err := regexp.Compile(str(v))
	if err != nil {
		return invalid(l, p, "is not a regular expression supported by Go")
	}
	if pattern.MatchString("") {
		return invalid(l, p, "must not match an empty line")
	}
	return nil
}
func guardCheck(l string, v any, p string) error {
	if err := regexCheck(l, v, p); err != nil {
		return err
	}
	parsed, err := syntax.Parse(str(v), syntax.Perl)
	if err != nil {
		return invalid(l, p, "is not a regular expression supported by Go")
	}
	var nested func(*syntax.Regexp, bool) bool
	nested = func(node *syntax.Regexp, inside bool) bool {
		repeats, endless := false, false
		switch node.Op {
		case syntax.OpStar, syntax.OpPlus:
			repeats, endless = true, true
		case syntax.OpRepeat:
			repeats, endless = node.Max > 1 || node.Max == -1, node.Max == -1
		}
		if inside && repeats {
			return true
		}
		for _, child := range node.Sub {
			if nested(child, inside || endless) {
				return true
			}
		}
		return false
	}
	if nested(parsed, false) {
		return invalid(l, p, "cannot be bounded: it repeats without bound a part that itself repeats")
	}
	return nil
}
func versionCheck(l string, v any, p string) error {
	n, ok := intValue(v)
	if !ok || n != 1 {
		return invalid(l, p, "unsupported schema version; this launcher reads schema_version = 1")
	}
	return nil
}
func supervisorCheck(l string, v any, p string) error {
	m := object(v)
	_, level := m["level"]
	_, role := m["role"]
	if level && role {
		return invalid(l, p, "has both level and role: role is the old spelling of level, so give level only")
	}
	if !level && !role {
		return invalid(l, fieldPath(p, "level"), "is required: 4 (mini-supervisor), 5 (top supervisor) or 6 (super top)")
	}
	return tableCheck(map[string]validator{"level": integerCheck(4, 6), "role": choices("top", "mini"), "runner": textCheck(nameRule, 1000), "projects": listCheck(textCheck(nameRule, 1000), false, true, 0), "owner_channel": textCheck(nameRule, 1000), "description": textCheck("", 1000)}, "runner")(l, v, p)
}
func runnerCheck(l string, v any, p string) error {
	allowed := append(append([]string{}, basePlaceholders...), "session")
	resume := append(append([]string{}, allowed...), "message")
	fields := map[string]validator{"command": templateCheck(allowed, false), "resume": templateCheck(resume, false), "prompt": choices("argument", "stdin"), "stream": choices("text", "claude-stream-json"), "room": templateCheck([]string{"account"}, false), "accounts": listCheck(textCheck(accountRule, 1000), false, true, 0), "secrets": secretList, "limit_patterns": listCheck(regexCheck, true, true, 0), "dropped_patterns": listCheck(regexCheck, true, true, 0), "quiet_seconds": integerCheck(1, 604800), "description": textCheck("", 1000), "records": listCheck(recordCheck, true, false, 0)}
	fields["api_models"] = apiModelsCheck
	if err := tableCheck(fields, "command")(l, v, p); err != nil {
		return err
	}
	m := object(v)
	if m["prompt"] != "stdin" && !uses(m["command"], "brief") {
		return invalid(l, p+".command", "must pass the rendered brief with {brief}, or take its prompt on standard input (prompt = \"stdin\")")
	}
	if r, ok := m["resume"]; ok && uses(m["command"], "session") != uses(r, "session") {
		return invalid(l, p+".resume", "command and resume must both use {session} or neither may use it")
	}
	return nil
}
func recordCheck(l string, v any, p string) error {
	pathCheck := func(l string, v any, p string) error {
		if err := textCheck("", 4096)(l, v, p); err != nil {
			return err
		}
		s := str(v)
		if !strings.HasPrefix(s, "/") && !strings.HasPrefix(s, "~/") && !strings.HasPrefix(s, "{worktree}") && !strings.HasPrefix(s, "{log}") {
			return invalid(l, p, "must be an absolute path or glob, or start with ~/, {worktree} or {log}")
		}
		fields, err := templateFields(s)
		if err != nil {
			return invalid(l, p, "has an unbalanced brace")
		}
		for _, field := range fields {
			if !contains(strings.Fields("account effort lane log model project session worktree"), field) {
				return invalid(l, p, "uses an unknown placeholder")
			}
		}
		return nil
	}
	if err := tableCheck(map[string]validator{"format": choices("claude-code", "text"), "paths": listCheck(pathCheck, true, true, 0)}, "format", "paths")(l, v, p); err != nil {
		return err
	}
	m := object(v)
	if m["format"] == "text" && (len(array(m["paths"])) != 1 || array(m["paths"])[0] != "{log}") {
		return invalid(l, p+".paths", "format text reads only the run's own log: its paths must be exactly [\"{log}\"]")
	}
	return nil
}

var secretList = listCheck(textCheck(`[A-Z][A-Z0-9_]{0,63}`, 1000), false, true, 0)

func environmentCheck(l string, v any, p string) error {
	m := object(v)
	kind := str(m["kind"])
	fields := map[string]validator{"kind": choices("cloud", "host", "local"), "description": textCheck("", 1000), "secrets": secretList, "attest": templateCheck(basePlaceholders, false), "launch": templateCheck(basePlaceholders, false), "collect": templateCheck(basePlaceholders, false), "max_machines": integerCheck(1, 64), "idle_minutes": integerCheck(1, 1440), "hard_minutes": integerCheck(1, 10080)}
	required := []string{"kind"}
	if kind == "cloud" {
		fields["identity"] = textCheck(`[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,127}`, 1000)
		fields["region"] = textCheck(nameRule, 1000)
		required = append(required, "identity")
	}
	if kind == "host" {
		fields["host"] = textCheck(`[A-Za-z0-9][A-Za-z0-9._-]{0,127}`, 1000)
		required = append(required, "host")
	}
	if err := tableCheck(fields, required...)(l, v, p); err != nil {
		return err
	}
	if len(array(m["secrets"])) > 0 && m["attest"] == nil {
		return invalid(l, p+".attest", "is required when secrets are listed: a secret goes only to a verified machine")
	}
	return nil
}
func channelCheck(l string, v any, p string) error {
	m := object(v)
	fields := map[string]validator{"kind": choices("chat", "file"), "description": textCheck("", 1000)}
	required := []string{"kind"}
	if m["kind"] == "chat" {
		fields["service"] = textCheck(`[a-z0-9][a-z0-9.-]{0,63}`, 1000)
		fields["target"] = textCheck("", 200)
		fields["token_secret"] = textCheck(`[A-Z][A-Z0-9_]{0,63}`, 1000)
		required = append(required, "service", "target")
	} else if m["kind"] == "file" {
		fields["path"] = relativeCheck
		required = append(required, "path")
	}
	return tableCheck(fields, required...)(l, v, p)
}
func resourceCheck(l string, v any, p string) error {
	credentialEnv := func(l string, v any, p string) error {
		if err := textCheck(`[A-Z][A-Z0-9_]{0,63}`, 1000)(l, v, p); err != nil {
			return err
		}
		if v == "PATH" || strings.HasPrefix(str(v), "LANEBOSS_") {
			return invalid(l, p, "must not name PATH or a LANEBOSS_ variable")
		}
		return nil
	}
	fields := map[string]validator{"description": textCheck("", 1000), "command": templateCheck(nil, true), "kind": choices("machine", "credential"), "credential_env": credentialEnv, "credential_profile": textCheck(accountRule, 1000), "acquire_seconds": integerCheck(1, 900), "describe_seconds": integerCheck(1, 300), "release_seconds": integerCheck(1, 600), "acquire_bound_minutes": integerCheck(1, 1440), "hard_cap_minutes": integerCheck(1, 10080), "release_by_itself": boolCheck, "read_back_wait_seconds": integerCheck(0, 3600)}
	if err := tableCheck(fields, "command", "kind", "hard_cap_minutes")(l, v, p); err != nil {
		return err
	}
	m := object(v)
	seconds, bound := int64(300), int64(15)
	if n, ok := intValue(m["acquire_seconds"]); ok {
		seconds = n
	}
	if n, ok := intValue(m["acquire_bound_minutes"]); ok {
		bound = n
	}
	if bound < (seconds+59)/60+1 {
		return invalid(l, p+".acquire_bound_minutes", "must be at least one minute more than acquire_seconds rounded up to whole minutes")
	}
	return nil
}
func configCheck(l string, v any, p string) error {
	name := textCheck(nameRule, 1000)
	disk := func(l string, v any, p string) error {
		if err := tableCheck(map[string]validator{"path": absoluteCheck, "warn_percent": integerCheck(1, 99), "stop_percent": integerCheck(1, 99)})(l, v, p); err != nil {
			return err
		}
		m := object(v)
		warn, stop := int64(85), int64(90)
		if n, ok := intValue(m["warn_percent"]); ok {
			warn = n
		}
		if n, ok := intValue(m["stop_percent"]); ok {
			stop = n
		}
		if warn >= stop {
			return invalid(l, p+".warn_percent", "must be below stop_percent")
		}
		return nil
	}
	guards := listCheck(tableCheck(map[string]validator{"name": textCheck(accountRule, 1000), "kind": choices("hook", "permission", "harness"), "pattern": guardCheck, "description": textCheck("", 1000)}, "name", "pattern"), false, false, 0)
	fields := map[string]validator{"schema_version": versionCheck, "name": name, "description": textCheck("", 1000), "organisation": name, "rules": listCheck(rulesCheck, false, true, 0), "organisation_rules": listCheck(relativeCheck, false, true, 0), "secrets": secretList, "owner_channel": name, "test_environment": name, "state": tableCheck(map[string]validator{"path": absoluteCheck}), "disk": disk, "runners": namedCheck(runnerCheck, 1), "supervisors": namedCheck(supervisorCheck, 0), "judges": namedCheck(tableCheck(map[string]validator{"description": textCheck("", 1000), "command": templateCheck(nil, true), "timeout_seconds": integerCheck(1, 60)}, "command"), 0), "resources": namedCheck(resourceCheck, 0), "test_environments": namedCheck(environmentCheck, 0), "owner_channels": namedCheck(channelCheck, 0), "guards": guards,
		"lanes": tableCheck(map[string]validator{"budget_minutes": numberCheck(0, 10080, true), "quiet_seconds": integerCheck(1, 604800), "stop_grace_seconds": integerCheck(1, 600), "lock_wait_seconds": integerCheck(1, 3600), "room_timeout_seconds": integerCheck(1, 60)}),
		"turns": tableCheck(map[string]validator{"idle_message": relativeCheck, "idle_seconds": integerCheck(1, 604800), "poll_seconds": integerCheck(1, 3600), "backoff_seconds": integerCheck(1, 604800), "limit_backoff_seconds": integerCheck(1, 604800)}),
		"cost":  tableCheck(map[string]validator{"currency": textCheck(`[A-Z]{3}`, 1000), "daily_cap": numberCheck(0, math.MaxFloat64, false), "per_run_cap": numberCheck(0, math.MaxFloat64, false), "report_threshold": numberCheck(0, math.MaxFloat64, false)}, "currency")}
	route := listCheck(tableCheck(map[string]validator{"runner": name, "model": modelCheck, "effort": name}, "runner", "model"), true, false, 0)
	fields["routing"] = tableCheck(map[string]validator{"mechanical": route, "standard": route, "hard": route, "review": route})
	if err := tableCheck(fields, "schema_version", "name", "runners")(l, v, p); err != nil {
		return err
	}
	seen := map[string]bool{}
	for i, item := range array(object(v)["guards"]) {
		name := str(object(item)["name"])
		if seen[name] {
			return invalid(l, fmt.Sprintf("guards[%d].name", i), "repeats the name of an earlier guard")
		}
		seen[name] = true
	}
	return nil
}
func projectCheck(l string, v any, p string) error {
	name := textCheck(nameRule, 1000)
	return tableCheck(map[string]validator{"schema_version": versionCheck, "name": name, "description": textCheck("", 1000), "repository": textCheck("", 1024), "lane_prefix": textCheck(`[a-z0-9][a-z0-9-]{0,15}`, 1000), "workers": listCheck(name, false, true, 0), "gates": listCheck(name, true, true, 0), "excluded_accounts": listCheck(textCheck(accountRule, 1000), false, true, 0), "test_environment": name, "reserved_paths": listCheck(relativeCheck, false, true, 0), "owner_channel": name, "landing_authority": name, "rules": listCheck(rulesCheck, false, true, 0)}, "schema_version", "name")(l, v, p)
}
