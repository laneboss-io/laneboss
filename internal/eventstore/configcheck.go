package eventstore

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

// These private readers intentionally do not depend on another command group's port.
func normalizeTOML(v any) any {
	r := reflect.ValueOf(v)
	if !r.IsValid() {
		return nil
	}
	switch r.Kind() {
	case reflect.Map:
		m := Object{}
		for _, k := range r.MapKeys() {
			m[k.String()] = normalizeTOML(r.MapIndex(k).Interface())
		}
		return m
	case reflect.Slice:
		a := []any{}
		for i := 0; i < r.Len(); i++ {
			a = append(a, normalizeTOML(r.Index(i).Interface()))
		}
		return a
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return r.Int()
	case reflect.Float32, reflect.Float64:
		return r.Float()
	}
	return v
}
func configText(pattern string, max int) validator {
	return func(v any, w string) error {
		s, ok := v.(string)
		if !ok || strings.TrimSpace(s) == "" || utf8.RuneCountInString(s) > max || control(s) {
			return Refuse("%s: must be nonempty text of at most %d characters without controls", w, max)
		}
		if pattern != "" {
			return grammar(pattern)(v, w)
		}
		return nil
	}
}
func configTable(checks map[string]validator, required ...string) validator {
	return func(v any, w string) error {
		m := object(v)
		if m == nil {
			return Refuse("%s: must be a table", w)
		}
		for k := range m {
			if _, ok := checks[k]; !ok {
				return Refuse("%s: has an unknown key", w)
			}
		}
		for _, k := range required {
			if _, ok := m[k]; !ok {
				return Refuse("%s.%s: is required", w, k)
			}
		}
		for k, c := range checks {
			if item, ok := m[k]; ok {
				path := k
				if w != "" {
					path = w + "." + k
				}
				if err := c(item, path); err != nil {
					return err
				}
			}
		}
		return nil
	}
}
func configArray(item validator, nonempty, unique bool) validator {
	return func(v any, w string) error {
		a, ok := v.([]any)
		if !ok || nonempty && len(a) == 0 {
			return Refuse("%s: must be an array%s", w, map[bool]string{true: " that is not empty", false: ""}[nonempty])
		}
		seen := map[string]bool{}
		for i, v := range a {
			if err := item(v, fmt.Sprintf("%s[%d]", w, i)); err != nil {
				return err
			}
			if unique {
				key := Canonical(v)
				if seen[key] {
					return Refuse("%s: must not repeat an item", w)
				}
				seen[key] = true
			}
		}
		return nil
	}
}
func namedTables(item validator, minimum int) validator {
	return func(v any, w string) error {
		m := object(v)
		if m == nil || len(m) < minimum {
			return Refuse("%s: must define at least %d entries", w, minimum)
		}
		for name, value := range m {
			if !nameGrammar.MatchString(name) {
				return Refuse("%s: has a key that is not a valid name", w)
			}
			if err := item(value, w+"."+name); err != nil {
				return err
			}
		}
		return nil
	}
}
func configRelative(v any, w string) error {
	if err := configText("", 1024)(v, w); err != nil {
		return err
	}
	s := text(v)
	if strings.HasPrefix(s, "/") || strings.Contains(s, "\\") {
		return Refuse("%s: must be a relative path", w)
	}
	for _, part := range strings.Split(s, "/") {
		if part == "" || part == "." || part == ".." {
			return Refuse("%s: must be a relative path without '.', '..' or empty parts", w)
		}
	}
	return nil
}
func configRulesPath(v any, w string) error {
	if err := configRelative(v, w); err != nil {
		return err
	}
	if strings.Split(text(v), "/")[0] == "orgs" {
		return Refuse("%s: must not start with orgs", w)
	}
	return nil
}
func configAbsolute(v any, w string) error {
	if err := configText("", 4096)(v, w); err != nil {
		return err
	}
	if !strings.HasPrefix(text(v), "/") {
		return Refuse("%s: must be an absolute path", w)
	}
	for _, p := range strings.Split(text(v), "/") {
		if p == "." || p == ".." {
			return Refuse("%s: must be an absolute path without '.' or '..' parts", w)
		}
	}
	return nil
}

var templateParts = []string{"account", "brief", "effort", "lane", "log", "machine", "model", "project", "worktree"}

func placeholdersIn(s string, allowed []string) ([]string, error) {
	found := []string{}
	for i := 0; i < len(s); i++ {
		if s[i] != '{' && s[i] != '}' {
			continue
		}
		if i+1 < len(s) && s[i+1] == s[i] {
			i++
			continue
		}
		if s[i] == '}' {
			return nil, Refuse("a command template has an unbalanced brace")
		}
		end := strings.IndexByte(s[i+1:], '}')
		if end < 0 {
			return nil, Refuse("a command template has an unbalanced brace")
		}
		key := s[i+1 : i+1+end]
		if !contains(allowed, key) {
			return nil, Refuse("a command template uses an unknown placeholder")
		}
		found = append(found, key)
		i += end + 1
	}
	return found, nil
}
func commandCheck(allowed []string, plain bool) validator {
	return func(v any, w string) error {
		if err := configArray(configText("", 4096), true, false)(v, w); err != nil {
			return err
		}
		a := list(v)
		first := text(a[0])
		if !regexp.MustCompile(`^[A-Za-z0-9_.+-]+$`).MatchString(first) && !(strings.HasPrefix(first, "/") && !strings.ContainsAny(first, "{}")) {
			return Refuse("%s[0]: must be a command name or an absolute path without placeholders", w)
		}
		for i, v := range a {
			s := text(v)
			if plain && strings.ContainsAny(s, "{}") {
				return Refuse("%s[%d]: must not contain braces", w, i)
			}
			if i > 0 && !plain {
				if _, err := placeholdersIn(s, allowed); err != nil {
					return Refuse("%s[%d]: %s", w, i, err.Error())
				}
			}
		}
		return nil
	}
}
func commandUses(v any, key string, allowed []string) bool {
	for _, part := range list(v)[1:] {
		fields, _ := placeholdersIn(text(part), allowed)
		if contains(fields, key) {
			return true
		}
	}
	return false
}
func outputPattern(v any, w string) error {
	if err := configText("", 1000)(v, w); err != nil {
		return err
	}
	r, err := regexp.Compile(text(v))
	if err != nil {
		return Refuse("%s: is not a supported regular expression", w)
	}
	if r.MatchString("") {
		return Refuse("%s: must not match an empty line", w)
	}
	return nil
}
func guardPattern(v any, w string) error {
	if err := outputPattern(v, w); err != nil {
		return err
	}
	parsed, err := syntax.Parse(text(v), syntax.Perl)
	if err != nil {
		return Refuse("%s: is not a supported regular expression", w)
	}
	var walk func(*syntax.Regexp, bool) bool
	walk = func(r *syntax.Regexp, inside bool) bool {
		repeated := r.Op == syntax.OpStar || r.Op == syntax.OpPlus || r.Op == syntax.OpRepeat && (r.Max < 0 || r.Max > 1)
		endless := r.Op == syntax.OpStar || r.Op == syntax.OpPlus || r.Op == syntax.OpRepeat && r.Max < 0
		if inside && repeated {
			return true
		}
		for _, child := range r.Sub {
			if walk(child, inside || endless) {
				return true
			}
		}
		return false
	}
	if walk(parsed, false) {
		return Refuse("%s: cannot be bounded: it repeats a part that itself repeats", w)
	}
	return nil
}

var configName = configText(`[a-z0-9][a-z0-9-]{0,31}`, 1000)
var configSecrets = configArray(configText(`[A-Z][A-Z0-9_]{0,63}`, 1000), false, true)

func runnerCheck(v any, w string) error {
	allowed := append(append([]string{}, templateParts...), "session")
	recordCheck := func(v any, w string) error {
		pathCheck := func(v any, w string) error {
			if err := configText("", 4096)(v, w); err != nil {
				return err
			}
			s := text(v)
			if _, err := placeholdersIn(s, []string{"account", "effort", "lane", "log", "model", "project", "session", "worktree"}); err != nil {
				return Refuse("%s: invalid record template", w)
			}
			if !strings.HasPrefix(s, "/") && !strings.HasPrefix(s, "~/") && !strings.HasPrefix(s, "{worktree}") && !strings.HasPrefix(s, "{log}") {
				return Refuse("%s: must be an absolute path or glob, or start with ~/, {worktree} or {log}", w)
			}
			return nil
		}
		if err := configTable(map[string]validator{"format": oneOf("claude-code", "text"), "paths": configArray(pathCheck, true, true)}, "format", "paths")(v, w); err != nil {
			return err
		}
		m := object(v)
		if m["format"] == "text" && !equal(m["paths"], []any{"{log}"}) {
			return Refuse("%s.paths: format text reads only the run's own log", w)
		}
		return nil
	}
	checks := map[string]validator{"command": commandCheck(allowed, false), "resume": commandCheck(append(append([]string{}, allowed...), "message"), false), "prompt": oneOf("argument", "stdin"), "stream": oneOf("text", "claude-stream-json"), "room": commandCheck([]string{"account"}, false), "accounts": configArray(configText(`[A-Za-z0-9][A-Za-z0-9._-]{0,63}`, 1000), false, true), "secrets": configSecrets, "limit_patterns": configArray(outputPattern, true, true), "dropped_patterns": configArray(outputPattern, true, true), "quiet_seconds": whole(1, 604800), "records": configArray(recordCheck, true, false), "description": configText("", 1000)}
	checks["api_models"] = func(value any, path string) error {
		if err := runnermodel.Validate(value); err != nil {
			return Refuse("%s: %s", path, err.Error())
		}
		return nil
	}
	if err := configTable(checks, "command")(v, w); err != nil {
		return err
	}
	m := object(v)
	if m["prompt"] != "stdin" && !commandUses(m["command"], "brief", allowed) {
		return Refuse("%s.command: must pass the rendered brief with {brief}, or prompt must be stdin", w)
	}
	if resume, ok := m["resume"]; ok && commandUses(m["command"], "session", allowed) != commandUses(resume, "session", append(append([]string{}, allowed...), "message")) {
		return Refuse("%s: command and resume must both use {session} or neither", w)
	}
	return nil
}
func supervisorCheck(v any, w string) error {
	m := object(v)
	if (m["level"] != nil) == (m["role"] != nil) {
		return Refuse("%s: must give exactly one of level and role", w)
	}
	level := func(v any, w string) error {
		n, ok := integerValue(v)
		if !ok || n < 4 || n > 6 {
			return Refuse("%s: must be level 4, 5 or 6", w)
		}
		return nil
	}
	return configTable(map[string]validator{"level": level, "role": oneOf("top", "mini"), "runner": configName, "projects": configArray(configName, false, true), "owner_channel": configName, "description": configText("", 1000)}, "runner")(v, w)
}
func environmentCheck(v any, w string) error {
	m := object(v)
	kind := text(m["kind"])
	if !contains([]string{"cloud", "host", "local"}, kind) {
		return Refuse("%s.kind: must be cloud, host or local", w)
	}
	c := map[string]validator{"kind": oneOf(kind), "description": configText("", 1000), "secrets": configSecrets, "attest": commandCheck(templateParts, false), "launch": commandCheck(templateParts, false), "collect": commandCheck(templateParts, false), "max_machines": whole(1, 64), "idle_minutes": whole(1, 1440), "hard_minutes": whole(1, 10080)}
	required := []string{"kind"}
	if kind == "cloud" {
		c["identity"] = configText(`[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,127}`, 1000)
		c["region"] = configName
		required = append(required, "identity")
	}
	if kind == "host" {
		c["host"] = configText(`[A-Za-z0-9][A-Za-z0-9._-]{0,127}`, 1000)
		required = append(required, "host")
	}
	if err := configTable(c, required...)(v, w); err != nil {
		return err
	}
	if len(list(m["secrets"])) > 0 && m["attest"] == nil {
		return Refuse("%s.attest: is required when secrets are listed", w)
	}
	return nil
}
func channelCheck(v any, w string) error {
	m := object(v)
	c := map[string]validator{"kind": oneOf("chat", "file"), "description": configText("", 1000)}
	required := []string{"kind"}
	if m["kind"] == "chat" {
		c["service"] = configText(`[a-z0-9][a-z0-9.-]{0,63}`, 1000)
		c["target"] = configText("", 200)
		c["token_secret"] = configText(`[A-Z][A-Z0-9_]{0,63}`, 1000)
		required = append(required, "service", "target")
	} else if m["kind"] == "file" {
		c["path"] = configRelative
		required = append(required, "path")
	}
	return configTable(c, required...)(v, w)
}
func adapterCheck(v any, w string) error {
	envCheck := func(v any, w string) error {
		if err := configText(`[A-Z][A-Z0-9_]{0,63}`, 1000)(v, w); err != nil {
			return err
		}
		if v == "PATH" || strings.HasPrefix(text(v), "LANEBOSS_") {
			return Refuse("%s: must not name PATH or a LANEBOSS_ variable", w)
		}
		return nil
	}
	checks := map[string]validator{"description": configText("", 1000), "command": commandCheck(nil, true), "kind": oneOf("machine", "credential"), "credential_env": envCheck, "credential_profile": configText(`[A-Za-z0-9][A-Za-z0-9._-]{0,63}`, 1000), "acquire_seconds": whole(1, 900), "describe_seconds": whole(1, 300), "release_seconds": whole(1, 600), "acquire_bound_minutes": whole(1, 1440), "hard_cap_minutes": whole(1, 10080), "release_by_itself": boolean, "read_back_wait_seconds": whole(0, 3600)}
	if err := configTable(checks, "command", "kind", "hard_cap_minutes")(v, w); err != nil {
		return err
	}
	m := object(v)
	seconds, bound := int64(300), int64(15)
	if s, ok := m["acquire_seconds"]; ok {
		seconds = num(s)
	}
	if b, ok := m["acquire_bound_minutes"]; ok {
		bound = num(b)
	}
	if bound < (seconds+59)/60+1 {
		return Refuse("%s.acquire_bound_minutes: must be at least one minute more than acquire_seconds rounded up", w)
	}
	return nil
}
func configSchema(v Object) error {
	disk := func(v any, w string) error {
		if err := configTable(map[string]validator{"path": configAbsolute, "warn_percent": whole(1, 99), "stop_percent": whole(1, 99)})(v, w); err != nil {
			return err
		}
		m := object(v)
		warn, stop := int64(85), int64(90)
		if x, ok := m["warn_percent"]; ok {
			warn = num(x)
		}
		if x, ok := m["stop_percent"]; ok {
			stop = num(x)
		}
		if warn >= stop {
			return Refuse("%s.warn_percent: must be below stop_percent", w)
		}
		return nil
	}
	guards := func(v any, w string) error {
		c := configTable(map[string]validator{"name": configText(`[A-Za-z0-9][A-Za-z0-9._-]{0,63}`, 1000), "kind": oneOf("hook", "permission", "harness"), "pattern": guardPattern, "description": configText("", 1000)}, "name", "pattern")
		if err := configArray(c, false, false)(v, w); err != nil {
			return err
		}
		seen := map[string]bool{}
		for _, g := range list(v) {
			n := text(object(g)["name"])
			if seen[n] {
				return Refuse("%s: repeats a guard name", w)
			}
			seen[n] = true
		}
		return nil
	}
	route := configTable(map[string]validator{"runner": configName, "model": modelName, "effort": configText(`[a-z0-9][a-z0-9-]{0,31}`, 1000)}, "runner", "model")
	return configTable(map[string]validator{
		"schema_version": whole(1, 1), "name": configName, "description": configText("", 1000), "organisation": configName, "rules": configArray(configRulesPath, false, true), "organisation_rules": configArray(configRelative, false, true), "secrets": configSecrets, "owner_channel": configName, "test_environment": configName, "state": configTable(map[string]validator{"path": configAbsolute}),
		"lanes": configTable(map[string]validator{"budget_minutes": numeric(0, 10080, true), "quiet_seconds": whole(1, 604800), "stop_grace_seconds": whole(1, 600), "lock_wait_seconds": whole(1, 3600), "room_timeout_seconds": whole(1, 60)}),
		"turns": configTable(map[string]validator{"idle_message": configRelative, "idle_seconds": whole(1, 604800), "poll_seconds": whole(1, 3600), "backoff_seconds": whole(1, 604800), "limit_backoff_seconds": whole(1, 604800)}), "disk": disk,
		"runners": namedTables(runnerCheck, 1), "supervisors": namedTables(supervisorCheck, 0), "judges": namedTables(configTable(map[string]validator{"description": configText("", 1000), "command": commandCheck(nil, true), "timeout_seconds": whole(1, 60)}, "command"), 0), "resources": namedTables(adapterCheck, 0),
		"routing": configTable(map[string]validator{"mechanical": configArray(route, true, false), "standard": configArray(route, true, false), "hard": configArray(route, true, false), "review": configArray(route, true, false)}), "test_environments": namedTables(environmentCheck, 0), "owner_channels": namedTables(channelCheck, 0),
		"cost": configTable(map[string]validator{"currency": configText(`[A-Z]{3}`, 1000), "daily_cap": numeric(0, math.MaxFloat64, false), "per_run_cap": numeric(0, math.MaxFloat64, false), "report_threshold": numeric(0, math.MaxFloat64, false)}, "currency"), "guards": guards,
	}, "schema_version", "name", "runners")(v, "")
}
func projectSchema(v Object) error {
	return configTable(map[string]validator{
		"schema_version": whole(1, 1), "name": configName, "description": configText("", 1000), "repository": configText("", 1024), "lane_prefix": configText(`[a-z0-9][a-z0-9-]{0,15}`, 1000), "workers": configArray(configName, false, true), "gates": configArray(configText(`[a-z0-9][a-z0-9-]{0,31}`, 1000), true, true), "excluded_accounts": configArray(configText(`[A-Za-z0-9][A-Za-z0-9._-]{0,63}`, 1000), false, true), "test_environment": configName, "reserved_paths": configArray(configRelative, false, true), "owner_channel": configName, "landing_authority": configName, "rules": configArray(configRulesPath, false, true),
	}, "schema_version", "name")(v, "")
}
func readRules(base, relative, label string, limit int64) error {
	b, err := readConfigFile(base, relative, limit)
	if err != nil {
		return Refuse("%s: cannot read the rules file as a regular file", label)
	}
	if !utf8.Valid(b) {
		return Refuse("%s: rules must be UTF-8 text", label)
	}
	if rule := credentialText(string(b)); rule != "" {
		return Refuse("%s: rules look like a credential (%s)", label, rule)
	}
	return nil
}
func validateConfigFiles(base, home, name string, data Object) error {
	if err := configSchema(data); err != nil {
		return Refuse("configuration %s: config.toml: %s", shown(name), err.Error())
	}
	projects := map[string]Object{}
	projectDirectory, err := configLocation(base, "projects")
	var entries []os.DirEntry
	if err == nil {
		entries, err = os.ReadDir(projectDirectory)
	}
	if err != nil && !os.IsNotExist(err) {
		return Refuse("configuration %s: projects cannot be read", shown(name))
	}
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".toml") {
			continue
		}
		stem := strings.TrimSuffix(entry.Name(), ".toml")
		if !nameGrammar.MatchString(stem) {
			return Refuse("configuration %s: projects: a file name is not valid", shown(name))
		}
		b, err := readConfigFile(base, filepath.Join("projects", entry.Name()), 1024*1024)
		if err != nil {
			return Refuse("configuration %s: projects: a project cannot be read", shown(name))
		}
		raw := map[string]any{}
		if !utf8.Valid(b) {
			return Refuse("configuration %s: projects: a project must be UTF-8 text", shown(name))
		}
		if _, err = toml.Decode(string(b), &raw); err != nil {
			return Refuse("configuration %s: projects: a project is not valid TOML", shown(name))
		}
		p := object(normalizeTOML(raw))
		if where, rule := credentialValue(p); rule != "" {
			return Refuse("configuration %s: projects: %s looks like a credential (%s)", shown(name), where, rule)
		}
		if err = projectSchema(p); err != nil {
			return Refuse("configuration %s: projects/%s.toml: %s", shown(name), stem, err.Error())
		}
		if p["name"] != stem {
			return Refuse("configuration %s: projects/%s.toml: name must equal its file name", shown(name), stem)
		}
		projects[stem] = p
	}
	runners, channels, environments, supervisors := object(data["runners"]), object(data["owner_channels"]), object(data["test_environments"]), object(data["supervisors"])
	secrets, accounts := map[string]bool{}, map[string]bool{}
	for _, s := range list(data["secrets"]) {
		secrets[text(s)] = true
	}
	for _, r := range runners {
		for _, a := range list(object(r)["accounts"]) {
			accounts[text(a)] = true
		}
	}
	known := func(v any, m Object, field string) error {
		if m[text(v)] == nil {
			return Refuse("configuration %s: %s: names an entry that is not defined", shown(name), field)
		}
		return nil
	}
	for section, values := range map[string]Object{"runners": runners, "test_environments": environments, "owner_channels": channels} {
		for key, value := range values {
			m := object(value)
			for _, s := range list(m["secrets"]) {
				if !secrets[text(s)] {
					return Refuse("configuration %s: %s.%s.secrets: names a secret not listed at top level", shown(name), section, key)
				}
			}
			if s, ok := m["token_secret"]; ok && !secrets[text(s)] {
				return Refuse("configuration %s: owner_channels.%s.token_secret: is not listed at top level", shown(name), key)
			}
		}
	}
	for key, s := range supervisors {
		m := object(s)
		if err = known(m["runner"], runners, "supervisors."+key+".runner"); err != nil {
			return err
		}
		for _, p := range list(m["projects"]) {
			if projects[text(p)] == nil {
				return Refuse("configuration %s: supervisors.%s.projects: a project is not defined", shown(name), key)
			}
		}
		if c, ok := m["owner_channel"]; ok {
			if err = known(c, channels, "supervisors."+key+".owner_channel"); err != nil {
				return err
			}
		}
		if m["role"] != nil {
			if m["role"] == "top" {
				m["level"] = int64(5)
			} else {
				m["level"] = int64(4)
			}
		}
	}
	for difficulty, routes := range object(data["routing"]) {
		for _, r := range list(routes) {
			if err = known(object(r)["runner"], runners, "routing."+difficulty+".runner"); err != nil {
				return err
			}
		}
	}
	for field, entries := range map[string]Object{"owner_channel": channels, "test_environment": environments} {
		if value, ok := data[field]; ok {
			if err = known(value, entries, field); err != nil {
				return err
			}
		}
	}
	for _, r := range list(data["rules"]) {
		if err = readRules(base, text(r), "configuration "+shown(name)+": rules", 1024*1024); err != nil {
			return err
		}
	}
	for stem, p := range projects {
		for _, worker := range list(p["workers"]) {
			if err = known(worker, runners, "projects."+stem+".workers"); err != nil {
				return err
			}
		}
		for _, a := range list(p["excluded_accounts"]) {
			if !accounts[text(a)] {
				return Refuse("configuration %s: projects.%s.excluded_accounts: an account is not defined", shown(name), stem)
			}
		}
		for field, entries := range map[string]Object{"owner_channel": channels, "test_environment": environments} {
			if value, ok := p[field]; ok {
				if err = known(value, entries, "projects."+stem+"."+field); err != nil {
					return err
				}
			}
		}
		if a, ok := p["landing_authority"]; ok {
			level := num(object(supervisors[text(a)])["level"])
			if level != 5 && level != 6 {
				return Refuse("configuration %s: projects.%s.landing_authority: must name a supervisor of level 5 or 6", shown(name), stem)
			}
		}
		for _, r := range list(p["rules"]) {
			if err = readRules(base, text(r), "configuration "+shown(name)+": project rules", 1024*1024); err != nil {
				return err
			}
		}
	}
	if rules, ok := data["organisation_rules"]; ok {
		org := text(data["organisation"])
		if org == "" {
			return Refuse("configuration %s: organisation_rules needs organisation", shown(name))
		}
		for _, r := range list(rules) {
			if err = readRules(realPath(filepath.Join(home, "orgs", org)), text(r), "configuration "+shown(name)+": organisation_rules", 1024*1024); err != nil {
				return err
			}
		}
	}
	if idle, ok := object(data["turns"])["idle_message"]; ok {
		if err = readRules(base, text(idle), "configuration "+shown(name)+": turns.idle_message", 64*1024); err != nil {
			return err
		}
	}
	if org := text(data["organisation"]); org != "" {
		root := filepath.Join(home, "orgs") + string(filepath.Separator)
		for _, section := range []string{"runners", "judges", "resources"} {
			for _, v := range object(data[section]) {
				for _, key := range []string{"command", "resume", "room"} {
					for _, arg := range list(object(v)[key]) {
						s := text(arg)
						if !filepath.IsAbs(s) {
							continue
						}
						s = filepath.Clean(s)
						if strings.HasPrefix(s, root) {
							other := strings.Split(strings.TrimPrefix(s, root), string(filepath.Separator))[0]
							if other != org {
								return Refuse("configuration %s: %s: a command points into another organisation's directory", shown(name), section)
							}
						}
					}
				}
			}
		}
	}
	return nil
}
