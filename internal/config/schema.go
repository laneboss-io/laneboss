package config

import (
	"encoding/json"
	"fmt"
	"math"
	"regexp"
	"regexp/syntax"
	"sort"
	"strings"
	"unicode/utf8"
)

var namePattern = regexp.MustCompile("^" + NameRule + "$")

const (
	secretNameRule = "[A-Z][A-Z0-9_]{0,63}"
	accountRule    = "[A-Za-z0-9][A-Za-z0-9._-]{0,63}"
	modelRule      = `[A-Za-z0-9][A-Za-z0-9._:/@+\[\]-]{0,127}`
	identityRule   = "[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,127}"
	hostRule       = "[A-Za-z0-9][A-Za-z0-9._-]{0,127}"
	serviceRule    = "[a-z0-9][a-z0-9.-]{0,63}"
	levelNote      = "4 (mini-supervisor), 5 (top supervisor) or 6 (super top)"
)

var commandName = regexp.MustCompile(`^[A-Za-z0-9_.+-]+$`)
var versionDigit = regexp.MustCompile(`[0-9]`)
var placeholders = []string{"account", "brief", "effort", "lane", "log", "machine", "model", "project", "worktree"}
var runnerPlaceholders = []string{"account", "brief", "effort", "lane", "log", "machine", "model", "project", "session", "worktree"}
var resumePlaceholders = []string{"account", "brief", "effort", "lane", "log", "machine", "model", "project", "session", "worktree", "message"}
var recordPlaceholders = []string{"account", "effort", "lane", "log", "model", "project", "session", "worktree"}

type checker struct{ label string }
type check func(checker, any, string) error

func (c checker) fail(path, message string) error {
	if path == "" {
		path = "(top level)"
	}
	return invalid(c.label + ": " + path + ": " + message)
}

func join(path, key string) string {
	if path == "" {
		return key
	}
	return path + "." + key
}

func keys[V any](value map[string]V) []string {
	result := make([]string, 0, len(value))
	for key := range value {
		result = append(result, key)
	}
	sort.Strings(result)
	return result
}

func tableOf(value any) map[string]any { table, _ := value.(map[string]any); return table }
func arrayOf(value any) []any          { array, _ := value.([]any); return array }
func stringOf(value any) string        { text, _ := value.(string); return text }
func stringsOf(value any) []string {
	result := []string{}
	for _, item := range arrayOf(value) {
		result = append(result, stringOf(item))
	}
	return result
}
func contains(items []string, item string) bool {
	for _, found := range items {
		if found == item {
			return true
		}
	}
	return false
}
func intDefault(table map[string]any, key string, fallback int64) int64 {
	if number, ok := table[key].(int64); ok {
		return number
	}
	return fallback
}

func text(rule string, limit int) check {
	var pattern *regexp.Regexp
	if rule != "" {
		pattern = regexp.MustCompile("^(?:" + rule + ")$")
	}
	return func(c checker, value any, path string) error {
		word, ok := value.(string)
		if !ok {
			return c.fail(path, "must be a string")
		}
		if strings.TrimSpace(word) == "" {
			return c.fail(path, "must not be empty")
		}
		if utf8.RuneCountInString(word) > limit {
			return c.fail(path, fmt.Sprintf("must be at most %d characters", limit))
		}
		for _, char := range word {
			if char < 32 || char == 127 {
				return c.fail(path, "must not contain control characters")
			}
		}
		if pattern != nil && !pattern.MatchString(word) {
			return c.fail(path, "must match "+rule)
		}
		return nil
	}
}

func integer(minimum, maximum int64) check {
	return func(c checker, value any, path string) error {
		number, ok := value.(int64)
		if !ok {
			return c.fail(path, "must be an integer")
		}
		if number < minimum || number > maximum {
			return c.fail(path, fmt.Sprintf("must be from %d to %d", minimum, maximum))
		}
		return nil
	}
}

func number(value any) (float64, bool) {
	switch value := value.(type) {
	case int64:
		return float64(value), true
	case float64:
		return value, !math.IsInf(value, 0) && !math.IsNaN(value)
	default:
		return 0, false
	}
}

func amount(c checker, value any, path string) error {
	valueNumber, ok := number(value)
	if !ok || valueNumber < 0 {
		return c.fail(path, "must be a finite number that is not negative")
	}
	return nil
}

func budget(c checker, value any, path string) error {
	valueNumber, ok := number(value)
	if !ok || valueNumber <= 0 || valueNumber > 10080 {
		return c.fail(path, "must be a number of minutes above 0 and at most 10080")
	}
	return nil
}

func boolean(c checker, value any, path string) error {
	if _, ok := value.(bool); !ok {
		return c.fail(path, "must be true or false")
	}
	return nil
}

func choice(options ...string) check {
	return func(c checker, value any, path string) error {
		word, ok := value.(string)
		if !ok || !contains(options, word) {
			return c.fail(path, "must be one of: "+strings.Join(options, ", "))
		}
		return nil
	}
}

func array(item check, nonempty, unique bool) check {
	return func(c checker, value any, path string) error {
		values, ok := value.([]any)
		if !ok {
			return c.fail(path, "must be an array")
		}
		if nonempty && len(values) == 0 {
			return c.fail(path, "must not be empty")
		}
		seen := map[string]bool{}
		duplicate := false
		for index, element := range values {
			if err := item(c, element, fmt.Sprintf("%s[%d]", path, index)); err != nil {
				return err
			}
			if unique {
				encoded, err := json.Marshal(element)
				if err != nil {
					return c.fail(path, "cannot compare array items")
				}
				if seen[string(encoded)] {
					duplicate = true
				}
				seen[string(encoded)] = true
			}
		}
		if duplicate {
			return c.fail(path, "must not repeat an item")
		}
		return nil
	}
}

func table(fields map[string]check, required ...string) check {
	return func(c checker, value any, path string) error {
		values, ok := value.(map[string]any)
		if !ok {
			return c.fail(path, "must be a table")
		}
		for _, key := range keys(values) {
			if _, exists := fields[key]; !exists {
				return c.fail(join(path, key), "unknown key")
			}
		}
		for _, key := range required {
			if _, exists := values[key]; !exists {
				return c.fail(join(path, key), "is required")
			}
		}
		for _, key := range keys(values) {
			if err := fields[key](c, values[key], join(path, key)); err != nil {
				return err
			}
		}
		return nil
	}
}

func namedTables(item check, minimum int) check {
	return func(c checker, value any, path string) error {
		values, ok := value.(map[string]any)
		if !ok {
			return c.fail(path, "must be a table")
		}
		if len(values) < minimum {
			return c.fail(path, fmt.Sprintf("must define at least %d entry", minimum))
		}
		for _, key := range keys(values) {
			if !namePattern.MatchString(key) {
				return c.fail(path, "has a key that is not a valid name ("+NameRule+")")
			}
			if err := item(c, values[key], join(path, key)); err != nil {
				return err
			}
		}
		return nil
	}
}

func relativePath(c checker, value any, path string) error {
	if err := text("", 1024)(c, value, path); err != nil {
		return err
	}
	word := value.(string)
	if strings.HasPrefix(word, "/") || strings.Contains(word, `\`) {
		return c.fail(path, "must be a relative path without '..', '.' or empty parts")
	}
	for _, part := range strings.Split(word, "/") {
		if part == "" || part == "." || part == ".." {
			return c.fail(path, "must be a relative path without '..', '.' or empty parts")
		}
	}
	return nil
}

func rulesPath(c checker, value any, path string) error {
	if err := relativePath(c, value, path); err != nil {
		return err
	}
	if strings.Split(value.(string), "/")[0] == "orgs" {
		return c.fail(path, "must not start with orgs: orgs/NAME/<path> is the label of an organisation's rules file")
	}
	return nil
}

func absolutePath(c checker, value any, path string) error {
	if err := text("", 4096)(c, value, path); err != nil {
		return err
	}
	word := value.(string)
	if !strings.HasPrefix(word, "/") {
		return c.fail(path, "must be an absolute path without '.' or '..' parts")
	}
	for _, part := range strings.Split(word, "/") {
		if part == "." || part == ".." {
			return c.fail(path, "must be an absolute path without '.' or '..' parts")
		}
	}
	return nil
}

func modelName(c checker, value any, path string) error {
	if err := text(modelRule, 128)(c, value, path); err != nil {
		return err
	}
	if !versionDigit.MatchString(value.(string)) {
		return c.fail(path, "must be a full model name that includes its version, not a family alias")
	}
	return nil
}

func templateFields(word string) ([]string, bool) {
	fields := []string{}
	for index := 0; index < len(word); {
		switch word[index] {
		case '{':
			if index+1 < len(word) && word[index+1] == '{' {
				index += 2
				continue
			}
			end := strings.IndexByte(word[index+1:], '}')
			if end < 0 {
				return nil, false
			}
			end += index + 1
			field := word[index+1 : end]
			if strings.Contains(field, "{") {
				return nil, false
			}
			fields = append(fields, field)
			index = end + 1
		case '}':
			if index+1 >= len(word) || word[index+1] != '}' {
				return nil, false
			}
			index += 2
		default:
			index++
		}
	}
	return fields, true
}

func checkPlaceholders(c checker, word, path string, allowed []string) error {
	fields, balanced := templateFields(word)
	if !balanced {
		return c.fail(path, "has an unbalanced brace; write {{ or }} for a literal brace")
	}
	for _, field := range fields {
		if !contains(allowed, field) {
			shown := make([]string, len(allowed))
			for index, name := range allowed {
				shown[index] = "{" + name + "}"
			}
			return c.fail(path, "uses an unknown placeholder; allowed: "+strings.Join(shown, ", "))
		}
	}
	return nil
}

func template(allowed []string) check {
	return func(c checker, value any, path string) error {
		if err := array(text("", 4096), true, false)(c, value, path); err != nil {
			return err
		}
		values := value.([]any)
		first := values[0].(string)
		if !commandName.MatchString(first) && !(strings.HasPrefix(first, "/") && !strings.ContainsAny(first, "{}")) {
			return c.fail(path+"[0]", "must be a command name or an absolute path, without placeholders")
		}
		for index, element := range values[1:] {
			if err := checkPlaceholders(c, element.(string), fmt.Sprintf("%s[%d]", path, index+1), allowed); err != nil {
				return err
			}
		}
		return nil
	}
}

func uses(value any, field string) bool {
	values := arrayOf(value)
	for _, element := range values[1:] {
		fields, _ := templateFields(element.(string))
		if contains(fields, field) {
			return true
		}
	}
	return false
}

func plainCommand(kind string) check {
	article := "a"
	if kind == "adapter" {
		article = "an"
	}
	return func(c checker, value any, path string) error {
		if err := array(text("", 4096), true, false)(c, value, path); err != nil {
			return err
		}
		values := value.([]any)
		if first := values[0].(string); !commandName.MatchString(first) && !strings.HasPrefix(first, "/") {
			return c.fail(path+"[0]", "must be a command name or an absolute path")
		}
		for index, element := range values {
			if strings.ContainsAny(element.(string), "{}") {
				return c.fail(fmt.Sprintf("%s[%d]", path, index), "must not contain braces: "+article+" "+kind+" command has no placeholders in version 1")
			}
		}
		return nil
	}
}

func schemaVersion(c checker, value any, path string) error {
	if version, ok := value.(int64); !ok || version != SchemaVersion {
		return c.fail(path, "unsupported schema version; this launcher reads schema_version = 1")
	}
	return nil
}

func regexCheck(guard bool) check {
	return func(c checker, value any, path string) error {
		if err := text("", 1000)(c, value, path); err != nil {
			return err
		}
		word := value.(string)
		compiled, err := regexp.Compile(word)
		if err != nil {
			return c.fail(path, "is not a valid regular expression in the bounded Go syntax")
		}
		if compiled.MatchString("") {
			if guard {
				return c.fail(path, "must not match the empty string")
			}
			return c.fail(path, "must not match an empty line")
		}
		if guard {
			parsed, err := syntax.Parse(word, syntax.Perl)
			if err != nil {
				return c.fail(path, "is not a valid regular expression")
			}
			if nestedRepeat(parsed, false) {
				return c.fail(path, "cannot be bounded: it repeats without bound a part that itself repeats")
			}
		}
		return nil
	}
}

func nestedRepeat(expression *syntax.Regexp, inside bool) bool {
	repeating := expression.Op == syntax.OpStar || expression.Op == syntax.OpPlus || (expression.Op == syntax.OpRepeat && (expression.Max < 0 || expression.Max > 1))
	if inside && repeating {
		return true
	}
	endless := expression.Op == syntax.OpStar || expression.Op == syntax.OpPlus || (expression.Op == syntax.OpRepeat && expression.Max < 0)
	for _, sub := range expression.Sub {
		if nestedRepeat(sub, inside || endless) {
			return true
		}
	}
	return false
}

var secretNames = array(text(secretNameRule, 1000), false, true)

func supervisorLevel(c checker, value any, path string) error {
	level, ok := value.(int64)
	if ok && (level == 4 || level == 5 || level == 6) {
		return nil
	}
	note := ""
	if ok && level == 3 {
		note = "; level 3 is a lane, and a lane is not a [supervisors] entry"
	}
	return c.fail(path, "must be "+levelNote+note)
}

func supervisor(c checker, value any, path string) error {
	if values, ok := value.(map[string]any); ok {
		_, hasLevel := values["level"]
		_, hasRole := values["role"]
		if hasLevel && hasRole {
			return c.fail(path, "has both level and role: role is the old spelling of level, so give level only")
		}
		if !hasLevel && !hasRole {
			return c.fail(join(path, "level"), "is required: "+levelNote+" (the old spelling role = \"mini\" or \"top\" is still read)")
		}
	}
	return table(map[string]check{
		"level": supervisorLevel, "role": choice("top", "mini"), "runner": text(NameRule, 1000),
		"projects": array(text(NameRule, 1000), false, true), "owner_channel": text(NameRule, 1000), "description": text("", 1000),
	}, "runner")(c, value, path)
}

func recordEntry(c checker, value any, path string) error {
	format := func(c checker, value any, path string) error {
		if word, ok := value.(string); ok && word == "codex" {
			return c.fail(path, "the codex format is not supported yet; watch such a runner with format text on the run's own log ({log})")
		}
		return choice("claude-code", "text")(c, value, path)
	}
	recordPath := func(c checker, value any, path string) error {
		if err := text("", 4096)(c, value, path); err != nil {
			return err
		}
		word := value.(string)
		if err := checkPlaceholders(c, word, path, recordPlaceholders); err != nil {
			return err
		}
		if !strings.HasPrefix(word, "/") && !strings.HasPrefix(word, "~/") && !strings.HasPrefix(word, "{worktree}") && !strings.HasPrefix(word, "{log}") {
			return c.fail(path, "must be an absolute path or glob, or start with ~/, {worktree} or {log}")
		}
		return nil
	}
	if err := table(map[string]check{"format": format, "paths": array(recordPath, true, true)}, "format", "paths")(c, value, path); err != nil {
		return err
	}
	values := value.(map[string]any)
	if values["format"] == "text" {
		paths := stringsOf(values["paths"])
		if len(paths) != 1 || paths[0] != "{log}" {
			return c.fail(join(path, "paths"), "format text reads only the run's own log: its paths must be exactly [\"{log}\"] (a later version may read other text files)")
		}
	}
	return nil
}

func runnerEntry(c checker, value any, path string) error {
	if err := table(map[string]check{
		"command": template(runnerPlaceholders), "resume": template(resumePlaceholders), "prompt": choice("argument", "stdin"),
		"stream": choice("text", "claude-stream-json"), "room": template([]string{"account"}),
		"accounts": array(text(accountRule, 1000), false, true), "secrets": secretNames,
		"limit_patterns": array(regexCheck(false), true, true), "dropped_patterns": array(regexCheck(false), true, true),
		"quiet_seconds": integer(1, 604800), "records": array(recordEntry, true, false), "description": text("", 1000),
	}, "command")(c, value, path); err != nil {
		return err
	}
	values := value.(map[string]any)
	if values["prompt"] != "stdin" && !uses(values["command"], "brief") {
		return c.fail(join(path, "command"), "must pass the rendered brief with {brief}, or the runner must take its prompt on standard input (prompt = \"stdin\"): a lane's brief always reaches its runner as a file or on standard input")
	}
	if resume, exists := values["resume"]; exists && uses(values["command"], "session") != uses(resume, "session") {
		if uses(values["command"], "session") {
			return c.fail(join(path, "resume"), "must use {session} as command does: a resume that does not name the lane's session identifier could continue another session")
		}
		return c.fail(join(path, "command"), "must use {session} as resume does: a lane started without an identifier cannot be resumed by one")
	}
	return nil
}

func guardList(c checker, value any, path string) error {
	guard := table(map[string]check{"name": text(accountRule, 1000), "kind": choice("hook", "permission", "harness"), "pattern": regexCheck(true), "description": text("", 1000)}, "name", "pattern")
	if err := array(guard, false, false)(c, value, path); err != nil {
		return err
	}
	seen := map[string]bool{}
	for index, item := range value.([]any) {
		name := item.(map[string]any)["name"].(string)
		if seen[name] {
			return c.fail(fmt.Sprintf("%s[%d].name", path, index), "repeats the name of an earlier guard")
		}
		seen[name] = true
	}
	return nil
}

func resourceEntry(c checker, value any, path string) error {
	credentialEnv := func(c checker, value any, path string) error {
		if err := text(secretNameRule, 1000)(c, value, path); err != nil {
			return err
		}
		word := value.(string)
		if word == "PATH" {
			return c.fail(path, "must not name the fixed PATH the adapter runs with")
		}
		if strings.HasPrefix(word, "LANEBOSS_") {
			return c.fail(path, "must not start with LANEBOSS_: those names are the launcher's own")
		}
		return nil
	}
	if err := table(map[string]check{
		"description": text("", 1000), "command": plainCommand("adapter"), "kind": choice("machine", "credential"),
		"credential_env": credentialEnv, "credential_profile": text(accountRule, 1000),
		"acquire_seconds": integer(1, 900), "describe_seconds": integer(1, 300), "release_seconds": integer(1, 600),
		"acquire_bound_minutes": integer(1, 1440), "hard_cap_minutes": integer(1, 10080), "release_by_itself": boolean, "read_back_wait_seconds": integer(0, 3600),
	}, "command", "kind", "hard_cap_minutes")(c, value, path); err != nil {
		return err
	}
	values := value.(map[string]any)
	if intDefault(values, "acquire_bound_minutes", 15) < (intDefault(values, "acquire_seconds", 300)+59)/60+1 {
		return c.fail(join(path, "acquire_bound_minutes"), "must be at least one minute more than acquire_seconds rounded up to whole minutes")
	}
	return nil
}

func kindTable(c checker, value any, path string, all map[string]check, permitted map[string][]string, required map[string][]string) error {
	values, ok := value.(map[string]any)
	if !ok {
		return c.fail(path, "must be a table")
	}
	if _, exists := values["kind"]; !exists {
		return c.fail(join(path, "kind"), "is required")
	}
	if err := all["kind"](c, values["kind"], join(path, "kind")); err != nil {
		return err
	}
	kind := values["kind"].(string)
	specific := map[string]bool{}
	for _, fields := range permitted {
		for _, field := range fields {
			specific[field] = true
		}
	}
	allowed := map[string]check{}
	for key, item := range all {
		if !specific[key] || contains(permitted[kind], key) {
			allowed[key] = item
		}
	}
	for _, key := range keys(values) {
		if _, ok := allowed[key]; !ok {
			if _, known := all[key]; known {
				return c.fail(join(path, key), "is not valid for kind "+kind)
			}
			return c.fail(join(path, key), "unknown key")
		}
	}
	return table(allowed, required[kind]...)(c, value, path)
}

func testEnvironment(c checker, value any, path string) error {
	err := kindTable(c, value, path, map[string]check{
		"kind": choice("cloud", "host", "local"), "description": text("", 1000), "identity": text(identityRule, 1000),
		"region": text(NameRule, 1000), "host": text(hostRule, 1000), "secrets": secretNames,
		"attest": template(placeholders), "launch": template(placeholders), "collect": template(placeholders),
		"max_machines": integer(1, 64), "idle_minutes": integer(1, 1440), "hard_minutes": integer(1, 10080),
	}, map[string][]string{"cloud": {"identity", "region"}, "host": {"host"}, "local": {}},
		map[string][]string{"cloud": {"kind", "identity"}, "host": {"kind", "host"}, "local": {"kind"}})
	if err != nil {
		return err
	}
	values := value.(map[string]any)
	if len(arrayOf(values["secrets"])) > 0 {
		if _, exists := values["attest"]; !exists {
			return c.fail(join(path, "attest"), "is required when secrets are listed: a secret goes only to a verified machine")
		}
	}
	return nil
}

func ownerChannel(c checker, value any, path string) error {
	return kindTable(c, value, path, map[string]check{
		"kind": choice("chat", "file"), "description": text("", 1000), "service": text(serviceRule, 1000),
		"target": text("", 200), "token_secret": text(secretNameRule, 1000), "path": relativePath,
	}, map[string][]string{"chat": {"service", "target", "token_secret"}, "file": {"path"}},
		map[string][]string{"chat": {"kind", "service", "target"}, "file": {"kind", "path"}})
}

func diskSection(c checker, value any, path string) error {
	if err := table(map[string]check{"path": absolutePath, "warn_percent": integer(1, 99), "stop_percent": integer(1, 99)})(c, value, path); err != nil {
		return err
	}
	values := value.(map[string]any)
	if intDefault(values, "warn_percent", DefaultWarnPercent) >= intDefault(values, "stop_percent", DefaultStopPercent) {
		return c.fail(join(path, "warn_percent"), "must be below stop_percent")
	}
	return nil
}

var configSchema = table(map[string]check{
	"schema_version": schemaVersion, "name": text(NameRule, 1000), "description": text("", 1000), "organisation": text(NameRule, 1000),
	"rules": array(rulesPath, false, true), "organisation_rules": array(relativePath, false, true), "secrets": secretNames,
	"owner_channel": text(NameRule, 1000), "test_environment": text(NameRule, 1000), "state": table(map[string]check{"path": absolutePath}),
	"lanes": table(map[string]check{"budget_minutes": budget, "quiet_seconds": integer(1, 604800), "stop_grace_seconds": integer(1, 600), "lock_wait_seconds": integer(1, 3600), "room_timeout_seconds": integer(1, 60)}),
	"turns": table(map[string]check{"idle_message": relativePath, "idle_seconds": integer(1, 604800), "poll_seconds": integer(1, 3600), "backoff_seconds": integer(1, 604800), "limit_backoff_seconds": integer(1, 604800)}),
	"disk":  diskSection, "runners": namedTables(runnerEntry, 1), "supervisors": namedTables(supervisor, 0),
	"judges":    namedTables(table(map[string]check{"description": text("", 1000), "command": plainCommand("judge"), "timeout_seconds": integer(1, 60)}, "command"), 0),
	"resources": namedTables(resourceEntry, 0),
	"routing":   routingSchema(), "test_environments": namedTables(testEnvironment, 0), "owner_channels": namedTables(ownerChannel, 0),
	"cost": table(map[string]check{"currency": text("[A-Z]{3}", 1000), "daily_cap": amount, "per_run_cap": amount, "report_threshold": amount}, "currency"), "guards": guardList,
}, "schema_version", "name", "runners")

func routingSchema() check {
	fields := map[string]check{}
	route := table(map[string]check{"runner": text(NameRule, 1000), "model": modelName, "effort": text(NameRule, 1000)}, "runner", "model")
	for _, difficulty := range []string{"mechanical", "standard", "hard", "review"} {
		fields[difficulty] = array(route, true, false)
	}
	return table(fields)
}

var projectSchema = table(map[string]check{
	"schema_version": schemaVersion, "name": text(NameRule, 1000), "description": text("", 1000), "repository": text("", 1024),
	"lane_prefix": text("[a-z0-9][a-z0-9-]{0,15}", 1000), "workers": array(text(NameRule, 1000), false, true), "gates": array(text(NameRule, 1000), true, true),
	"excluded_accounts": array(text(accountRule, 1000), false, true), "test_environment": text(NameRule, 1000), "reserved_paths": array(relativePath, false, true),
	"owner_channel": text(NameRule, 1000), "landing_authority": text(NameRule, 1000), "rules": array(rulesPath, false, true),
}, "schema_version", "name")
