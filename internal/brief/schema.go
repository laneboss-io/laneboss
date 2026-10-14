package brief

import (
	"fmt"
	"math"
	"regexp"
	"regexp/syntax"
	"strings"
	"unicode/utf8"

	"laneboss.io/laneboss/internal/runnermodel"
)

const nameRule = `[a-z0-9][a-z0-9-]{0,31}`

var (
	namePattern  = regexp.MustCompile(`^` + nameRule + `$`)
	lanePattern  = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
	modelPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/@+\[\]-]{0,127}$`)
)

type validator func(any, string) string

func fieldPath(parent, child string) string {
	if parent == "" {
		return child
	}
	return parent + "." + child
}

func checkText(pattern string, maximum int) validator {
	var re *regexp.Regexp
	if pattern != "" {
		re = regexp.MustCompile(`^(?:` + pattern + `)$`)
	}
	return func(value any, path string) string {
		s, ok := value.(string)
		if !ok {
			return path + ": must be a string"
		}
		if strings.TrimSpace(s) == "" {
			return path + ": must not be empty"
		}
		if utf8.RuneCountInString(s) > maximum {
			return fmt.Sprintf("%s: must be at most %d characters", path, maximum)
		}
		for _, r := range s {
			if r < 32 || r == 127 {
				return path + ": must not contain control characters"
			}
		}
		if re != nil && !re.MatchString(s) {
			return path + ": must match " + pattern
		}
		return ""
	}
}

func checkInteger(minimum, maximum int64) validator {
	return func(value any, path string) string {
		n, ok := value.(int64)
		if !ok {
			return path + ": must be an integer"
		}
		if n < minimum || n > maximum {
			return fmt.Sprintf("%s: must be from %d to %d", path, minimum, maximum)
		}
		return ""
	}
}

func checkChoice(choices ...string) validator {
	return func(value any, path string) string {
		for _, choice := range choices {
			if value == choice {
				return ""
			}
		}
		return path + ": must be one of: " + strings.Join(choices, ", ")
	}
}

func checkArray(item validator, nonempty, unique bool) validator {
	return func(value any, path string) string {
		items, ok := value.([]any)
		if !ok {
			return path + ": must be an array"
		}
		if nonempty && len(items) == 0 {
			return path + ": must not be empty"
		}
		seen := map[string]bool{}
		for i, value := range items {
			if message := item(value, fmt.Sprintf("%s[%d]", path, i)); message != "" {
				return message
			}
			if unique {
				data, err := canonical(value)
				if err != nil {
					return path + ": has an invalid item"
				}
				if seen[string(data)] {
					return path + ": must not repeat an item"
				}
				seen[string(data)] = true
			}
		}
		return ""
	}
}

func checkTable(fields map[string]validator, required ...string) validator {
	return func(value any, path string) string {
		m, ok := value.(map[string]any)
		if !ok {
			return path + ": must be a table"
		}
		for _, key := range sortedKeys(m) {
			if _, ok := fields[key]; !ok {
				return fieldPath(path, safeField(key)) + ": unknown key"
			}
		}
		for _, key := range required {
			if _, ok := m[key]; !ok {
				return fieldPath(path, key) + ": is required"
			}
		}
		for _, key := range sortedKeys(m) {
			if message := fields[key](m[key], fieldPath(path, key)); message != "" {
				return message
			}
		}
		return ""
	}
}

func checkNamed(item validator, minimum int) validator {
	return func(value any, path string) string {
		m, ok := value.(map[string]any)
		if !ok {
			return path + ": must be a table"
		}
		if len(m) < minimum {
			return path + ": must define at least one entry"
		}
		for _, key := range sortedKeys(m) {
			if !namePattern.MatchString(key) {
				return path + ": has a key that is not a valid name (" + nameRule + ")"
			}
			if message := item(m[key], fieldPath(path, shownName(key))); message != "" {
				return message
			}
		}
		return ""
	}
}

func checkRelative(value any, path string) string {
	if message := checkText("", 1024)(value, path); message != "" {
		return message
	}
	s := value.(string)
	if strings.HasPrefix(s, "/") || strings.Contains(s, `\`) {
		return path + ": must be a relative path without '..', '.' or empty parts"
	}
	for _, part := range strings.Split(s, "/") {
		if part == "" || part == "." || part == ".." {
			return path + ": must be a relative path without '..', '.' or empty parts"
		}
	}
	return ""
}
func checkRulesPath(value any, path string) string {
	if message := checkRelative(value, path); message != "" {
		return message
	}
	if strings.Split(value.(string), "/")[0] == "orgs" {
		return path + ": must not start with orgs: orgs/NAME/<path> labels an organisation's rules file"
	}
	return ""
}
func checkAbsolute(value any, path string) string {
	if message := checkText("", 4096)(value, path); message != "" {
		return message
	}
	s := value.(string)
	if !strings.HasPrefix(s, "/") {
		return path + ": must be an absolute path without '.' or '..' parts"
	}
	for _, part := range strings.Split(s, "/") {
		if part == "." || part == ".." {
			return path + ": must be an absolute path without '.' or '..' parts"
		}
	}
	return ""
}

func checkAmount(value any, path string) string {
	var number float64
	switch v := value.(type) {
	case int64:
		number = float64(v)
	case float64:
		number = v
	default:
		return path + ": must be a finite number that is not negative"
	}
	if math.IsInf(number, 0) || math.IsNaN(number) || number < 0 {
		return path + ": must be a finite number that is not negative"
	}
	return ""
}
func checkBudget(value any, path string) string {
	if message := checkAmount(value, path); message != "" {
		return message
	}
	n := float64(0)
	switch v := value.(type) {
	case int64:
		n = float64(v)
	case float64:
		n = v
	}
	if n <= 0 || n > 10080 {
		return path + ": must be a number of minutes above 0 and at most 10080"
	}
	return ""
}
func checkBoolean(value any, path string) string {
	if _, ok := value.(bool); !ok {
		return path + ": must be true or false"
	}
	return ""
}
func checkVersion(value any, path string) string {
	if n, ok := value.(int64); !ok || n != 1 {
		return path + ": unsupported schema version; this launcher reads schema_version = 1"
	}
	return ""
}
func checkModel(value any, path string) string {
	if message := checkText(modelPattern.String()[1:len(modelPattern.String())-1], 128)(value, path); message != "" {
		return message
	}
	if !strings.ContainsAny(value.(string), "0123456789") {
		return path + ": must be a full model name that includes its version, not a family alias"
	}
	return ""
}

func checkAPIModels(value any, path string) string {
	if err := runnermodel.Validate(value); err != nil {
		return path + ": " + err.Error()
	}
	return ""
}

var commonPlaceholders = strings.Fields("account brief effort lane log machine model project worktree")
var runnerPlaceholders = append(append([]string{}, commonPlaceholders...), "session")

func templateFields(text string) ([]string, bool) {
	var fields []string
	for i := 0; i < len(text); i++ {
		if text[i] != '{' && text[i] != '}' {
			continue
		}
		if i+1 < len(text) && text[i+1] == text[i] {
			i++
			continue
		}
		if text[i] == '}' {
			return nil, false
		}
		end := strings.IndexByte(text[i+1:], '}')
		if end < 0 {
			return nil, false
		}
		field := text[i+1 : i+1+end]
		if strings.ContainsRune(field, '{') {
			return nil, false
		}
		fields = append(fields, field)
		i += end + 1
	}
	return fields, true
}
func checkPlaceholders(text, path string, allowed []string) string {
	fields, ok := templateFields(text)
	if !ok {
		return path + ": has an unbalanced brace; write {{ or }} for a literal brace"
	}
	for _, field := range fields {
		if !hasString(allowed, field) {
			return path + ": uses an unknown placeholder"
		}
	}
	return ""
}
func checkTemplate(allowed []string, plain bool) validator {
	return func(value any, path string) string {
		if message := checkArray(checkText("", 4096), true, false)(value, path); message != "" {
			return message
		}
		items := value.([]any)
		first := items[0].(string)
		if !regexp.MustCompile(`^[A-Za-z0-9_.+-]+$`).MatchString(first) && !(strings.HasPrefix(first, "/") && (plain || !strings.ContainsAny(first, "{}"))) {
			return path + "[0]: must be a command name or an absolute path, without placeholders"
		}
		for i, item := range items {
			if plain {
				if strings.ContainsAny(item.(string), "{}") {
					return fmt.Sprintf("%s[%d]: must not contain braces: this command has no placeholders in version 1", path, i)
				}
			} else if i > 0 {
				if message := checkPlaceholders(item.(string), fmt.Sprintf("%s[%d]", path, i), allowed); message != "" {
					return message
				}
			}
		}
		return ""
	}
}
func usesTemplate(value any, field string) bool {
	for _, item := range value.([]any)[1:] {
		fields, _ := templateFields(item.(string))
		if hasString(fields, field) {
			return true
		}
	}
	return false
}

func checkPattern(guard bool) validator {
	return func(value any, path string) string {
		if message := checkText("", 1000)(value, path); message != "" {
			return message
		}
		pattern := value.(string)
		re, err := regexp.Compile(pattern)
		if err != nil {
			return path + ": is not a valid supported regular expression"
		}
		if re.MatchString("") {
			return path + ": must not match an empty line"
		}
		if guard {
			parsed, err := syntax.Parse(pattern, syntax.Perl)
			if err != nil {
				return path + ": is not a valid regular expression"
			}
			var walk func(*syntax.Regexp, bool) bool
			walk = func(re *syntax.Regexp, inside bool) bool {
				repeat := re.Op == syntax.OpStar || re.Op == syntax.OpPlus || re.Op == syntax.OpQuest || re.Op == syntax.OpRepeat
				multiple := re.Op == syntax.OpStar || re.Op == syntax.OpPlus || re.Op == syntax.OpRepeat && (re.Max < 0 || re.Max > 1)
				if repeat && multiple && inside {
					return true
				}
				endless := re.Op == syntax.OpStar || re.Op == syntax.OpPlus || re.Op == syntax.OpRepeat && re.Max < 0
				for _, sub := range re.Sub {
					if walk(sub, inside || endless) {
						return true
					}
				}
				return false
			}
			if walk(parsed, false) {
				return path + ": cannot be bounded: it repeats without bound a part that itself repeats"
			}
		}
		return ""
	}
}

func checkRecord(value any, path string) string {
	format := func(value any, path string) string {
		if value == "codex" {
			return path + ": the codex format is not supported yet; use format text on the run's own log"
		}
		return checkChoice("claude-code", "text")(value, path)
	}
	paths := func(value any, path string) string {
		if message := checkText("", 4096)(value, path); message != "" {
			return message
		}
		s := value.(string)
		if message := checkPlaceholders(s, path, strings.Fields("account effort lane log model project session worktree")); message != "" {
			return message
		}
		if !(strings.HasPrefix(s, "/") || strings.HasPrefix(s, "~/") || strings.HasPrefix(s, "{worktree}") || strings.HasPrefix(s, "{log}")) {
			return path + ": must be an absolute path or glob, or start with ~/, {worktree} or {log}"
		}
		return ""
	}
	if message := checkTable(map[string]validator{"format": format, "paths": checkArray(paths, true, true)}, "format", "paths")(value, path); message != "" {
		return message
	}
	m := value.(map[string]any)
	if m["format"] == "text" {
		a := m["paths"].([]any)
		if len(a) != 1 || a[0] != "{log}" {
			return path + ".paths: format text reads only the run's own log: paths must be exactly [\"{log}\"]"
		}
	}
	return ""
}

func checkRunner(value any, path string) string {
	fields := map[string]validator{
		"command": checkTemplate(runnerPlaceholders, false), "resume": checkTemplate(append(append([]string{}, runnerPlaceholders...), "message"), false),
		"prompt": checkChoice("argument", "stdin"), "stream": checkChoice("text", "claude-stream-json"), "room": checkTemplate([]string{"account"}, false),
		"accounts": checkArray(checkText(`[A-Za-z0-9][A-Za-z0-9._-]{0,63}`, 1000), false, true), "secrets": secretNames(), "api_models": checkAPIModels,
		"limit_patterns": checkArray(checkPattern(false), true, true), "dropped_patterns": checkArray(checkPattern(false), true, true),
		"quiet_seconds": checkInteger(1, 604800), "records": checkArray(checkRecord, true, false), "description": checkText("", 1000),
	}
	if message := checkTable(fields, "command")(value, path); message != "" {
		return message
	}
	m := value.(map[string]any)
	if m["prompt"] != "stdin" && !usesTemplate(m["command"], "brief") {
		return path + ".command: must pass the rendered brief with {brief}, or set prompt = \"stdin\""
	}
	if resume, ok := m["resume"]; ok && usesTemplate(m["command"], "session") != usesTemplate(resume, "session") {
		key := "command"
		if usesTemplate(m["command"], "session") {
			key = "resume"
		}
		return path + "." + key + ": must use {session} in both command and resume"
	}
	return ""
}

func secretNames() validator { return checkArray(checkText(`[A-Z][A-Z0-9_]{0,63}`, 1000), false, true) }
func names() validator       { return checkArray(checkText(nameRule, 1000), false, true) }

func checkSupervisor(value any, path string) string {
	level := func(value any, path string) string {
		if n, ok := value.(int64); ok && (n == 4 || n == 5 || n == 6) {
			return ""
		}
		return path + ": must be 4 (mini-supervisor), 5 (top supervisor) or 6 (super top)"
	}
	if m, ok := value.(map[string]any); ok {
		_, hasLevel := m["level"]
		_, hasRole := m["role"]
		if hasLevel && hasRole {
			return path + ": has both level and role: give level only"
		}
		if !hasLevel && !hasRole {
			return path + ".level: is required"
		}
	}
	return checkTable(map[string]validator{"level": level, "role": checkChoice("top", "mini"), "runner": checkText(nameRule, 1000), "projects": names(), "owner_channel": checkText(nameRule, 1000), "description": checkText("", 1000)}, "runner")(value, path)
}

func checkEnvironment(value any, path string) string {
	m, ok := value.(map[string]any)
	if !ok {
		return path + ": must be a table"
	}
	if _, ok := m["kind"]; !ok {
		return path + ".kind: is required"
	}
	if message := checkChoice("cloud", "host", "local")(m["kind"], path+".kind"); message != "" {
		return message
	}
	fields := map[string]validator{"kind": checkChoice("cloud", "host", "local"), "description": checkText("", 1000), "secrets": secretNames(),
		"attest": checkTemplate(commonPlaceholders, false), "launch": checkTemplate(commonPlaceholders, false), "collect": checkTemplate(commonPlaceholders, false),
		"max_machines": checkInteger(1, 64), "idle_minutes": checkInteger(1, 1440), "hard_minutes": checkInteger(1, 10080)}
	required := []string{"kind"}
	switch m["kind"] {
	case "cloud":
		fields["identity"] = checkText(`[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,127}`, 1000)
		fields["region"] = checkText(nameRule, 1000)
		required = append(required, "identity")
	case "host":
		fields["host"] = checkText(`[A-Za-z0-9][A-Za-z0-9._-]{0,127}`, 1000)
		required = append(required, "host")
	}
	if message := checkTable(fields, required...)(value, path); message != "" {
		return message
	}
	if secrets, ok := m["secrets"].([]any); ok && len(secrets) > 0 {
		if _, ok := m["attest"]; !ok {
			return path + ".attest: is required when secrets are listed: a secret goes only to a verified machine"
		}
	}
	return ""
}

func checkChannel(value any, path string) string {
	m, ok := value.(map[string]any)
	if !ok {
		return path + ": must be a table"
	}
	if _, ok := m["kind"]; !ok {
		return path + ".kind: is required"
	}
	if message := checkChoice("chat", "file")(m["kind"], path+".kind"); message != "" {
		return message
	}
	fields := map[string]validator{"kind": checkChoice("chat", "file"), "description": checkText("", 1000)}
	required := []string{"kind"}
	if m["kind"] == "chat" {
		fields["service"] = checkText(`[a-z0-9][a-z0-9.-]{0,63}`, 1000)
		fields["target"] = checkText("", 200)
		fields["token_secret"] = checkText(`[A-Z][A-Z0-9_]{0,63}`, 1000)
		required = append(required, "service", "target")
	} else {
		fields["path"] = checkRelative
		required = append(required, "path")
	}
	return checkTable(fields, required...)(value, path)
}

func checkResource(value any, path string) string {
	credentialEnv := func(value any, path string) string {
		if message := checkText(`[A-Z][A-Z0-9_]{0,63}`, 1000)(value, path); message != "" {
			return message
		}
		if value == "PATH" || strings.HasPrefix(value.(string), "LANEBOSS_") {
			return path + ": must not name the adapter's fixed PATH or the launcher's LANEBOSS_ settings"
		}
		return ""
	}
	fields := map[string]validator{"description": checkText("", 1000), "command": checkTemplate(nil, true), "kind": checkChoice("machine", "credential"),
		"credential_env": credentialEnv, "credential_profile": checkText(`[A-Za-z0-9][A-Za-z0-9._-]{0,63}`, 1000),
		"acquire_seconds": checkInteger(1, 900), "describe_seconds": checkInteger(1, 300), "release_seconds": checkInteger(1, 600),
		"acquire_bound_minutes": checkInteger(1, 1440), "hard_cap_minutes": checkInteger(1, 10080), "release_by_itself": checkBoolean, "read_back_wait_seconds": checkInteger(0, 3600)}
	if message := checkTable(fields, "command", "kind", "hard_cap_minutes")(value, path); message != "" {
		return message
	}
	m := value.(map[string]any)
	bound, seconds := int64(15), int64(300)
	if n, ok := m["acquire_bound_minutes"].(int64); ok {
		bound = n
	}
	if n, ok := m["acquire_seconds"].(int64); ok {
		seconds = n
	}
	if bound < (seconds+59)/60+1 {
		return path + ".acquire_bound_minutes: must be at least one minute more than acquire_seconds rounded up to whole minutes"
	}
	return ""
}

func checkGuards(value any, path string) string {
	item := checkTable(map[string]validator{"name": checkText(`[A-Za-z0-9][A-Za-z0-9._-]{0,63}`, 1000), "kind": checkChoice("hook", "permission", "harness"), "pattern": checkPattern(true), "description": checkText("", 1000)}, "name", "pattern")
	if message := checkArray(item, false, false)(value, path); message != "" {
		return message
	}
	seen := map[string]bool{}
	for i, item := range value.([]any) {
		name := item.(map[string]any)["name"].(string)
		if seen[name] {
			return fmt.Sprintf("%s[%d].name: repeats the name of an earlier guard", path, i)
		}
		seen[name] = true
	}
	return ""
}

func configurationSchema() validator {
	name := checkText(nameRule, 1000)
	text := checkText("", 1000)
	disk := func(value any, path string) string {
		if message := checkTable(map[string]validator{"path": checkAbsolute, "warn_percent": checkInteger(1, 99), "stop_percent": checkInteger(1, 99)})(value, path); message != "" {
			return message
		}
		m := value.(map[string]any)
		warn, stop := int64(85), int64(90)
		if n, ok := m["warn_percent"].(int64); ok {
			warn = n
		}
		if n, ok := m["stop_percent"].(int64); ok {
			stop = n
		}
		if warn >= stop {
			return path + ".warn_percent: must be below stop_percent"
		}
		return ""
	}
	route := checkTable(map[string]validator{"runner": name, "model": checkModel, "effort": name}, "runner", "model")
	return checkTable(map[string]validator{
		"schema_version": checkVersion, "name": name, "description": text, "organisation": name,
		"rules": checkArray(checkRulesPath, false, true), "organisation_rules": checkArray(checkRelative, false, true), "secrets": secretNames(),
		"owner_channel": name, "test_environment": name, "state": checkTable(map[string]validator{"path": checkAbsolute}),
		"lanes": checkTable(map[string]validator{"budget_minutes": checkBudget, "quiet_seconds": checkInteger(1, 604800), "stop_grace_seconds": checkInteger(1, 600), "lock_wait_seconds": checkInteger(1, 3600), "room_timeout_seconds": checkInteger(1, 60)}),
		"turns": checkTable(map[string]validator{"idle_message": checkRelative, "idle_seconds": checkInteger(1, 604800), "poll_seconds": checkInteger(1, 3600), "backoff_seconds": checkInteger(1, 604800), "limit_backoff_seconds": checkInteger(1, 604800)}),
		"disk":  disk, "runners": checkNamed(checkRunner, 1), "supervisors": checkNamed(checkSupervisor, 0),
		"judges":    checkNamed(checkTable(map[string]validator{"description": text, "command": checkTemplate(nil, true), "timeout_seconds": checkInteger(1, 60)}, "command"), 0),
		"resources": checkNamed(checkResource, 0), "routing": checkTable(map[string]validator{"mechanical": checkArray(route, true, false), "standard": checkArray(route, true, false), "hard": checkArray(route, true, false), "review": checkArray(route, true, false)}),
		"test_environments": checkNamed(checkEnvironment, 0), "owner_channels": checkNamed(checkChannel, 0),
		"cost":   checkTable(map[string]validator{"currency": checkText(`[A-Z]{3}`, 1000), "daily_cap": checkAmount, "per_run_cap": checkAmount, "report_threshold": checkAmount}, "currency"),
		"guards": checkGuards,
	}, "schema_version", "name", "runners")
}

func projectSchema() validator {
	name := checkText(nameRule, 1000)
	return checkTable(map[string]validator{
		"schema_version": checkVersion, "name": name, "description": checkText("", 1000), "repository": checkText("", 1024),
		"lane_prefix": checkText(`[a-z0-9][a-z0-9-]{0,15}`, 1000), "workers": names(), "gates": checkArray(name, true, true),
		"excluded_accounts": checkArray(checkText(`[A-Za-z0-9][A-Za-z0-9._-]{0,63}`, 1000), false, true),
		"test_environment":  name, "reserved_paths": checkArray(checkRelative, false, true), "owner_channel": name, "landing_authority": name,
		"rules": checkArray(checkRulesPath, false, true),
	}, "schema_version", "name")
}

func schemaError(label, message string) error {
	if message == "" {
		return nil
	}
	field, note, ok := strings.Cut(message, ": ")
	if !ok {
		return invalid(label, "", "invalid structure")
	}
	return invalid(label, field, note)
}
