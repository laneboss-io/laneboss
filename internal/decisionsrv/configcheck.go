package decisionsrv

import (
	"fmt"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"regexp/syntax"
	"strings"
	"unicode/utf8"

	"github.com/BurntSushi/toml"

	"laneboss.io/laneboss/internal/runnermodel"
)

// Ingestion and capture need the launcher's configuration refusals even before
// the shared configuration port lands. These validators remain private here.
type configRule func(any, string) error

func configProblem(path, reason string) error {
	return invalid("configuration field " + path + ": " + reason)
}
func configText(pattern string, limit int) configRule {
	return func(value any, path string) error {
		text, ok := value.(string)
		if !ok || strings.TrimSpace(text) == "" || utf8.RuneCountInString(text) > limit {
			return configProblem(path, "must be nonempty text within its character limit")
		}
		for _, r := range text {
			if r < 32 || r == 127 {
				return configProblem(path, "cannot contain control characters")
			}
		}
		if pattern != "" && !regexp.MustCompile("^(?:"+pattern+")$").MatchString(text) {
			return configProblem(path, "does not match its documented grammar")
		}
		return nil
	}
}
func configInteger(low, high int64) configRule {
	return func(value any, path string) error {
		n, ok := integer(value)
		if !ok || n < low || n > high {
			return configProblem(path, "must be an integer within its documented bounds")
		}
		return nil
	}
}
func configChoice(choices string) configRule {
	return func(value any, path string) error {
		if !wordsSet(choices)[str(value)] {
			return configProblem(path, "is not a supported choice")
		}
		return nil
	}
}
func configBoolean(value any, path string) error {
	if _, ok := value.(bool); !ok {
		return configProblem(path, "must be a boolean")
	}
	return nil
}
func configArray(value any) ([]any, bool) {
	if value == nil {
		return nil, false
	}
	v := reflect.ValueOf(value)
	if v.Kind() != reflect.Slice {
		return nil, false
	}
	out := make([]any, v.Len())
	for i := range out {
		out[i] = v.Index(i).Interface()
	}
	return out, true
}
func configItems(rule configRule, nonempty, unique bool) configRule {
	return func(value any, path string) error {
		items, ok := configArray(value)
		if !ok || (nonempty && len(items) == 0) {
			return configProblem(path, "must be an array with the required number of items")
		}
		seen := map[string]bool{}
		for i, item := range items {
			if err := rule(item, fmt.Sprintf("%s[%d]", path, i)); err != nil {
				return err
			}
			if unique {
				key, err := canonical(item)
				if err != nil {
					return err
				}
				if seen[key] {
					return configProblem(path, "must not repeat an item")
				}
				seen[key] = true
			}
		}
		return nil
	}
}
func configTable(fields map[string]configRule, required ...string) configRule {
	return func(value any, path string) error {
		table := obj(value)
		if table == nil {
			return configProblem(path, "must be a table")
		}
		for key := range table {
			if fields[key] == nil {
				return configProblem(path, "has an unknown field")
			}
		}
		for _, key := range required {
			if _, ok := table[key]; !ok {
				return configProblem(path+"."+key, "is required")
			}
		}
		for key, value := range table {
			if err := fields[key](value, path+"."+key); err != nil {
				return err
			}
		}
		return nil
	}
}
func configNamed(rule configRule, minimum int) configRule {
	return func(value any, path string) error {
		table := obj(value)
		if table == nil || len(table) < minimum {
			return configProblem(path, "must define its required named tables")
		}
		for name, value := range table {
			if !configPattern.MatchString(name) {
				return configProblem(path, "contains an invalid table name")
			}
			if err := rule(value, path+"."+name); err != nil {
				return err
			}
		}
		return nil
	}
}
func configRelative(value any, path string) error {
	if err := configText("", 1024)(value, path); err != nil {
		return err
	}
	text := str(value)
	if strings.HasPrefix(text, "/") || strings.Contains(text, "\\") {
		return configProblem(path, "must be a relative path")
	}
	for _, part := range strings.Split(text, "/") {
		if part == "" || part == "." || part == ".." {
			return configProblem(path, "must have no empty or dot segments")
		}
	}
	return nil
}
func configRulesPath(value any, path string) error {
	if err := configRelative(value, path); err != nil {
		return err
	}
	if strings.Split(str(value), "/")[0] == "orgs" {
		return configProblem(path, "must not start with orgs")
	}
	return nil
}
func configAbsolute(value any, path string) error {
	if err := configText("", 4096)(value, path); err != nil {
		return err
	}
	if !filepath.IsAbs(str(value)) {
		return configProblem(path, "must be an absolute path")
	}
	for _, part := range strings.Split(str(value), "/") {
		if part == "." || part == ".." {
			return configProblem(path, "must have no dot segments")
		}
	}
	return nil
}
func configModel(value any, path string) error {
	if err := configText(`[A-Za-z0-9][A-Za-z0-9._:/@+\[\]-]{0,127}`, 128)(value, path); err != nil {
		return err
	}
	if !strings.ContainsAny(str(value), "0123456789") {
		return configProblem(path, "must name a full model version")
	}
	return nil
}
func templateFields(text string) ([]string, error) {
	fields := []string{}
	for i := 0; i < len(text); i++ {
		switch text[i] {
		case '{':
			if i+1 < len(text) && text[i+1] == '{' {
				i++
				continue
			}
			end := strings.IndexByte(text[i+1:], '}')
			if end < 0 {
				return nil, invalid("configuration template has an unbalanced brace")
			}
			field := text[i+1 : i+1+end]
			if strings.ContainsAny(field, "{!:.") {
				return nil, invalid("configuration template has an unsupported placeholder")
			}
			fields = append(fields, field)
			i += end + 1
		case '}':
			if i+1 >= len(text) || text[i+1] != '}' {
				return nil, invalid("configuration template has an unbalanced brace")
			}
			i++
		}
	}
	return fields, nil
}
func configTemplate(allowed string, plain bool) configRule {
	return func(value any, path string) error {
		if err := configItems(configText("", 4096), true, false)(value, path); err != nil {
			return err
		}
		items, _ := configArray(value)
		first := str(items[0])
		if !regexp.MustCompile(`^[A-Za-z0-9_.+-]+$`).MatchString(first) && (!filepath.IsAbs(first) || strings.ContainsAny(first, "{}")) {
			return configProblem(path, "must start with a command name or absolute path")
		}
		for _, item := range items {
			if plain && strings.ContainsAny(str(item), "{}") {
				return configProblem(path, "must not contain placeholders")
			}
		}
		for _, item := range items[1:] {
			fields, err := templateFields(str(item))
			if err != nil {
				return err
			}
			for _, field := range fields {
				if !wordsSet(allowed)[field] {
					return configProblem(path, "uses an unknown placeholder")
				}
			}
		}
		return nil
	}
}
func configUses(value any, field string) bool {
	items, _ := configArray(value)
	for _, item := range items[1:] {
		fields, err := templateFields(str(item))
		if err != nil {
			return false
		}
		if hasString(fields, field) {
			return true
		}
	}
	return false
}
func configRegex(guard bool) configRule {
	return func(value any, path string) error {
		if err := configText("", 1000)(value, path); err != nil {
			return err
		}
		expression, err := regexp.Compile(str(value))
		if err != nil {
			return configProblem(path, "is not a supported regular expression")
		}
		if expression.MatchString("") {
			return configProblem(path, "must not match an empty line")
		}
		if guard {
			tree, err := syntax.Parse(str(value), syntax.Perl)
			if err != nil {
				return configProblem(path, "is not a supported regular expression")
			}
			var walk func(*syntax.Regexp, bool) bool
			walk = func(node *syntax.Regexp, inside bool) bool {
				repeat, endless, many := false, false, false
				switch node.Op {
				case syntax.OpStar, syntax.OpPlus:
					repeat, endless, many = true, true, true
				case syntax.OpQuest:
					repeat = true
				case syntax.OpRepeat:
					repeat = true
					endless = node.Max < 0
					many = endless || node.Max > 1
				}
				if repeat && many && inside {
					return false
				}
				for _, child := range node.Sub {
					if !walk(child, inside || endless) {
						return false
					}
				}
				return true
			}
			if !walk(tree, false) {
				return configProblem(path, "repeats without bound a part that itself repeats")
			}
		}
		return nil
	}
}

func configAPIModels(value any, path string) error {
	if err := runnermodel.Validate(value); err != nil {
		return configProblem(path, err.Error())
	}
	return nil
}

func configurationSchemas() (configRule, configRule) {
	text := configText("", 1000)
	name := configText(`[a-z0-9][a-z0-9-]{0,31}`, 1000)
	account := configText(`[A-Za-z0-9][A-Za-z0-9._-]{0,63}`, 1000)
	secret := configText(`[A-Z][A-Z0-9_]{0,63}`, 1000)
	names := configItems(name, false, true)
	secrets := configItems(secret, false, true)
	relative := configItems(configRelative, false, true)
	rules := configItems(configRulesPath, false, true)
	placeholders := "account brief effort lane log machine model project worktree"
	runnerFields := placeholders + " session"
	command := configTemplate(placeholders, false)
	judgeCommand := configTemplate("", true)
	amount := func(v any, p string) error {
		n, ok := number(v)
		if !ok || n < 0 {
			return configProblem(p, "must be a finite nonnegative number")
		}
		return nil
	}
	budget := func(v any, p string) error {
		n, ok := number(v)
		if !ok || n <= 0 || n > 10080 {
			return configProblem(p, "must be positive minutes within a week")
		}
		return nil
	}
	recordPath := func(v any, p string) error {
		if err := configText("", 4096)(v, p); err != nil {
			return err
		}
		fields, err := templateFields(str(v))
		if err != nil {
			return err
		}
		for _, field := range fields {
			if !wordsSet("account effort lane log model project session worktree")[field] {
				return configProblem(p, "uses an unknown record placeholder")
			}
		}
		if !strings.HasPrefix(str(v), "/") && !strings.HasPrefix(str(v), "~/") && !strings.HasPrefix(str(v), "{worktree}") && !strings.HasPrefix(str(v), "{log}") {
			return configProblem(p, "must be an absolute record path or glob")
		}
		return nil
	}
	recordTable := configTable(map[string]configRule{"format": configChoice("claude-code text"), "paths": configItems(recordPath, true, true)}, "format", "paths")
	record := func(v any, p string) error {
		if err := recordTable(v, p); err != nil {
			return err
		}
		m := obj(v)
		if m["format"] == "text" {
			items, _ := configArray(m["paths"])
			if len(items) != 1 || items[0] != "{log}" {
				return configProblem(p+".paths", "text records read only the run's own log")
			}
		}
		return nil
	}
	runnerTable := configTable(map[string]configRule{"command": configTemplate(runnerFields, false), "resume": configTemplate(runnerFields+" message", false), "room": configTemplate("account", false), "prompt": configChoice("argument stdin"), "stream": configChoice("text claude-stream-json"), "accounts": configItems(account, false, true), "secrets": secrets, "api_models": configAPIModels, "limit_patterns": configItems(configRegex(false), true, true), "dropped_patterns": configItems(configRegex(false), true, true), "quiet_seconds": configInteger(1, 604800), "records": configItems(record, true, false), "description": text}, "command")
	runner := func(v any, p string) error {
		if err := runnerTable(v, p); err != nil {
			return err
		}
		m := obj(v)
		if m["prompt"] != "stdin" && !configUses(m["command"], "brief") {
			return configProblem(p+".command", "must pass the brief or take it on standard input")
		}
		if m["resume"] != nil && configUses(m["command"], "session") != configUses(m["resume"], "session") {
			return configProblem(p, "command and resume must agree on the session placeholder")
		}
		return nil
	}
	supervisorTable := configTable(map[string]configRule{"level": configInteger(4, 6), "role": configChoice("mini top"), "runner": name, "projects": names, "owner_channel": name, "description": text}, "runner")
	supervisor := func(v any, p string) error {
		if err := supervisorTable(v, p); err != nil {
			return err
		}
		m := obj(v)
		_, level := m["level"]
		_, role := m["role"]
		if level == role {
			return configProblem(p, "must give exactly one of level and role")
		}
		if role {
			if m["role"] == "mini" {
				m["level"] = int64(4)
			} else {
				m["level"] = int64(5)
			}
			delete(m, "role")
		}
		return nil
	}
	environment := func(v any, p string) error {
		m := obj(v)
		if m == nil {
			return configProblem(p, "must be a table")
		}
		fields := map[string]configRule{"kind": configChoice("cloud host local"), "description": text, "secrets": secrets, "attest": command, "launch": command, "collect": command, "max_machines": configInteger(1, 64), "idle_minutes": configInteger(1, 1440), "hard_minutes": configInteger(1, 10080)}
		required := []string{"kind"}
		switch m["kind"] {
		case "cloud":
			fields["identity"] = configText(`[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,127}`, 1000)
			fields["region"] = name
			required = append(required, "identity")
		case "host":
			fields["host"] = configText(`[A-Za-z0-9][A-Za-z0-9._-]{0,127}`, 1000)
			required = append(required, "host")
		}
		if err := configTable(fields, required...)(v, p); err != nil {
			return err
		}
		items, _ := configArray(m["secrets"])
		if len(items) > 0 && m["attest"] == nil {
			return configProblem(p+".attest", "is required when secrets are listed")
		}
		return nil
	}
	channel := func(v any, p string) error {
		m := obj(v)
		if m == nil {
			return configProblem(p, "must be a table")
		}
		fields := map[string]configRule{"kind": configChoice("chat file"), "description": text}
		required := []string{"kind"}
		switch m["kind"] {
		case "chat":
			fields["service"] = configText(`[a-z0-9][a-z0-9.-]{0,63}`, 1000)
			fields["target"] = configText("", 200)
			fields["token_secret"] = secret
			required = append(required, "service", "target")
		case "file":
			fields["path"] = configRelative
			required = append(required, "path")
		}
		return configTable(fields, required...)(v, p)
	}
	diskTable := configTable(map[string]configRule{"path": configAbsolute, "warn_percent": configInteger(1, 99), "stop_percent": configInteger(1, 99)})
	disk := func(v any, p string) error {
		if err := diskTable(v, p); err != nil {
			return err
		}
		m := obj(v)
		warn, stop := int64(85), int64(90)
		if v := m["warn_percent"]; v != nil {
			warn, _ = integer(v)
		}
		if v := m["stop_percent"]; v != nil {
			stop, _ = integer(v)
		}
		if warn >= stop {
			return configProblem(p, "warn_percent must be below stop_percent")
		}
		return nil
	}
	credentialEnv := func(v any, p string) error {
		if err := secret(v, p); err != nil {
			return err
		}
		if v == "PATH" || strings.HasPrefix(str(v), "LANEBOSS_") {
			return configProblem(p, "cannot name the fixed PATH or launcher variables")
		}
		return nil
	}
	resourceTable := configTable(map[string]configRule{"description": text, "command": judgeCommand, "kind": configChoice("machine credential"), "credential_env": credentialEnv, "credential_profile": account, "acquire_seconds": configInteger(1, 900), "describe_seconds": configInteger(1, 300), "release_seconds": configInteger(1, 600), "acquire_bound_minutes": configInteger(1, 1440), "hard_cap_minutes": configInteger(1, 10080), "release_by_itself": configBoolean, "read_back_wait_seconds": configInteger(0, 3600)}, "command", "kind", "hard_cap_minutes")
	resource := func(v any, p string) error {
		if err := resourceTable(v, p); err != nil {
			return err
		}
		m := obj(v)
		bound, seconds := int64(15), int64(300)
		if m["acquire_bound_minutes"] != nil {
			bound, _ = integer(m["acquire_bound_minutes"])
		}
		if m["acquire_seconds"] != nil {
			seconds, _ = integer(m["acquire_seconds"])
		}
		if bound < int64(math.Ceil(float64(seconds)/60))+1 {
			return configProblem(p, "acquisition bound does not outlive the command timeout")
		}
		return nil
	}
	guardTable := configTable(map[string]configRule{"name": account, "kind": configChoice("hook permission harness"), "pattern": configRegex(true), "description": text}, "name", "pattern")
	guards := func(v any, p string) error {
		if err := configItems(guardTable, false, false)(v, p); err != nil {
			return err
		}
		items, _ := configArray(v)
		seen := map[string]bool{}
		for _, item := range items {
			n := str(obj(item)["name"])
			if seen[n] {
				return configProblem(p, "must not repeat a guard name")
			}
			seen[n] = true
		}
		return nil
	}
	version := configInteger(1, 1)
	route := configItems(configTable(map[string]configRule{"runner": name, "model": configModel, "effort": name}, "runner", "model"), true, false)
	configuration := configTable(map[string]configRule{"schema_version": version, "name": name, "description": text, "organisation": name, "archive_command": configTemplate("", true), "identity_service": configTable(map[string]configRule{"runtime_root": configAbsolute}), "org_dir": configAbsolute, "rules": rules, "organisation_rules": relative, "secrets": secrets, "owner_channel": name, "test_environment": name, "state": configTable(map[string]configRule{"path": configAbsolute}), "dashboard": configTable(map[string]configRule{"org": configAbsolute, "board": configRelative}), "lanes": configTable(map[string]configRule{"budget_minutes": budget, "quiet_seconds": configInteger(1, 604800), "stop_grace_seconds": configInteger(1, 600), "lock_wait_seconds": configInteger(1, 3600), "room_timeout_seconds": configInteger(1, 60), "sandbox": configChoice("off laneboss-files"), "sandbox_deny_extra": configItems(configAbsolute, false, true)}), "turns": configTable(map[string]configRule{"idle_message": configRelative, "idle_seconds": configInteger(1, 604800), "poll_seconds": configInteger(1, 3600), "backoff_seconds": configInteger(1, 604800), "limit_backoff_seconds": configInteger(1, 604800)}), "disk": disk, "runners": configNamed(runner, 1), "supervisors": configNamed(supervisor, 0), "judges": configNamed(configTable(map[string]configRule{"description": text, "command": judgeCommand, "timeout_seconds": configInteger(1, 60)}, "command"), 0), "resources": configNamed(resource, 0), "routing": configTable(map[string]configRule{"mechanical": route, "standard": route, "hard": route, "review": route}), "test_environments": configNamed(environment, 0), "owner_channels": configNamed(channel, 0), "cost": configTable(map[string]configRule{"currency": configText(`[A-Z]{3}`, 1000), "daily_cap": amount, "per_run_cap": amount, "report_threshold": amount}, "currency"), "guards": guards}, "schema_version", "name", "runners")
	project := configTable(map[string]configRule{"schema_version": version, "name": name, "description": text, "repository": configText("", 1024), "lane_prefix": configText(`[a-z0-9][a-z0-9-]{0,15}`, 1000), "workers": names, "gates": configItems(name, true, true), "excluded_accounts": configItems(account, false, true), "test_environment": name, "reserved_paths": relative, "owner_channel": name, "landing_authority": name, "rules": rules}, "schema_version", "name")
	return configuration, project
}

func readConfigurationTOML(path string) (object, error) {
	text, err := readRegular(path, 1<<20)
	if err != nil {
		return nil, err
	}
	data := object{}
	if _, err = toml.Decode(text, &data); err != nil {
		return nil, invalid("invalid configuration TOML file")
	}
	if credentialsInValue(data) {
		return nil, invalid("configuration contains a credential; no value is repeated")
	}
	return data, nil
}
func readConfigurationFile(root, relative string, limit int) (string, error) {
	path, err := within(filepath.Join(root, relative), root)
	if err != nil {
		return "", err
	}
	text, err := readRegular(path, limit)
	if err != nil {
		return "", err
	}
	if credentialsInText(text) {
		return "", invalid("configuration rules or idle message contain a credential")
	}
	return text, nil
}
func validateConfiguration(c *privateConfiguration) error {
	schema, projectSchema := configurationSchemas()
	if err := schema(c.data, "config.toml"); err != nil {
		return err
	}
	projects := object{}
	directory, err := within(filepath.Join(c.directory, "projects"), c.directory)
	if err != nil {
		return err
	}
	entries, err := os.ReadDir(directory)
	if err != nil && !os.IsNotExist(err) {
		return invalid("cannot read configuration projects")
	}
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".toml") {
			continue
		}
		name := strings.TrimSuffix(entry.Name(), ".toml")
		if !configPattern.MatchString(name) {
			return invalid("invalid project file name")
		}
		path, err := within(filepath.Join(directory, entry.Name()), c.directory)
		if err != nil {
			return err
		}
		data, err := readConfigurationTOML(path)
		if err != nil {
			return err
		}
		if err = projectSchema(data, "project"); err != nil {
			return err
		}
		if data["name"] != name {
			return invalid("project name does not match its file")
		}
		projects[name] = data
	}
	runners, supervisors, channels, environments := obj(c.data["runners"]), obj(c.data["supervisors"]), obj(c.data["owner_channels"]), obj(c.data["test_environments"])
	secretNames, accounts := map[string]bool{}, map[string]bool{}
	values, _ := configArray(c.data["secrets"])
	for _, v := range values {
		secretNames[str(v)] = true
	}
	known := func(value any, choices object, field string) error {
		if choices[str(value)] == nil {
			return configProblem(field, "names an undefined entry")
		}
		return nil
	}
	for _, v := range runners {
		runner := obj(v)
		values, _ := configArray(runner["accounts"])
		for _, v := range values {
			accounts[str(v)] = true
		}
	}
	for _, table := range []object{runners, environments} {
		for _, v := range table {
			values, _ := configArray(obj(v)["secrets"])
			for _, v := range values {
				if !secretNames[str(v)] {
					return configProblem("secrets", "names a secret not listed at the top level")
				}
			}
		}
	}
	for _, v := range channels {
		if secret := obj(v)["token_secret"]; secret != nil && !secretNames[str(secret)] {
			return configProblem("owner_channels.token_secret", "names a secret not listed at the top level")
		}
	}
	for _, v := range supervisors {
		supervisor := obj(v)
		if err = known(supervisor["runner"], runners, "supervisors.runner"); err != nil {
			return err
		}
		values, _ := configArray(supervisor["projects"])
		for _, v := range values {
			if err = known(v, projects, "supervisors.projects"); err != nil {
				return err
			}
		}
		if channel := supervisor["owner_channel"]; channel != nil {
			if err = known(channel, channels, "supervisors.owner_channel"); err != nil {
				return err
			}
		}
	}
	for _, routes := range obj(c.data["routing"]) {
		values, _ := configArray(routes)
		for _, route := range values {
			if err = known(obj(route)["runner"], runners, "routing.runner"); err != nil {
				return err
			}
		}
	}
	if c.data["owner_channel"] != nil {
		if err = known(c.data["owner_channel"], channels, "owner_channel"); err != nil {
			return err
		}
	}
	if c.data["test_environment"] != nil {
		if err = known(c.data["test_environment"], environments, "test_environment"); err != nil {
			return err
		}
	}
	readRules := func(raw any, root string, limit int) error {
		values, _ := configArray(raw)
		for _, v := range values {
			if _, err := readConfigurationFile(root, str(v), limit); err != nil {
				return err
			}
		}
		return nil
	}
	if err = readRules(c.data["rules"], c.directory, 1<<20); err != nil {
		return err
	}
	for _, v := range projects {
		project := obj(v)
		values, _ := configArray(project["workers"])
		for _, v := range values {
			if err = known(v, runners, "project.workers"); err != nil {
				return err
			}
		}
		values, _ = configArray(project["excluded_accounts"])
		for _, v := range values {
			if !accounts[str(v)] {
				return configProblem("project.excluded_accounts", "names an account no runner lists")
			}
		}
		for _, field := range []string{"test_environment", "owner_channel"} {
			if value := project[field]; value != nil {
				choices := environments
				if field == "owner_channel" {
					choices = channels
				}
				if err = known(value, choices, "project."+field); err != nil {
					return err
				}
			}
		}
		if authority := project["landing_authority"]; authority != nil {
			supervisor := obj(supervisors[str(authority)])
			level, ok := integer(supervisor["level"])
			if !ok || (level != 5 && level != 6) {
				return configProblem("project.landing_authority", "must name a supervisor of level 5 or 6")
			}
		}
		if err = readRules(project["rules"], c.directory, 1<<20); err != nil {
			return err
		}
	}
	if raw, exists := c.data["organisation_rules"]; exists {
		organisation := str(c.data["organisation"])
		if organisation == "" {
			return configProblem("organisation_rules", "requires organisation")
		}
		root, err := realPath(filepath.Join(c.home, "orgs", organisation))
		if err != nil {
			return err
		}
		if err = readRules(raw, root, 1<<20); err != nil {
			return err
		}
	}
	if relative := str(obj(c.data["turns"])["idle_message"]); relative != "" {
		if _, err = readConfigurationFile(c.directory, relative, 64<<10); err != nil {
			return err
		}
	}
	if organisation := str(c.data["organisation"]); organisation != "" {
		root := filepath.Clean(filepath.Join(c.home, "orgs"))
		for _, table := range []object{runners, obj(c.data["judges"]), obj(c.data["resources"])} {
			for _, v := range table {
				for _, field := range []string{"command", "resume", "room"} {
					values, _ := configArray(obj(v)[field])
					for _, v := range values {
						path := str(v)
						if !filepath.IsAbs(path) {
							continue
						}
						path = filepath.Clean(path)
						if strings.HasPrefix(path, root+string(filepath.Separator)) {
							relative := strings.TrimPrefix(path, root+string(filepath.Separator))
							if strings.Split(relative, string(filepath.Separator))[0] != organisation {
								return configProblem(field, "points into another organisation's tools")
							}
						}
					}
				}
			}
		}
	}
	return nil
}
