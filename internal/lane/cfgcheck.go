package lane

import (
	"fmt"
	"math"
	"path/filepath"
	"regexp"
	"regexp/syntax"
	"strings"
)

type configCheck func(any) bool

func textCheck(pattern string, max int) configCheck {
	return func(v any) bool {
		s, ok := v.(string)
		return ok && strings.TrimSpace(s) != "" && len([]rune(s)) <= max && strings.IndexFunc(s, func(r rune) bool { return r < 32 || r == 127 }) < 0 && (pattern == "" || match(pattern, s))
	}
}
func wholeCheck(min, max float64) configCheck { return func(v any) bool { return whole(v, min, max) } }
func chooseCheck(choices string) configCheck {
	return func(v any) bool { _, ok := v.(string); return ok && contains(strings.Fields(choices), str(v)) }
}
func arrayCheck(item configCheck, min int, unique bool) configCheck {
	return func(v any) bool {
		a := list(v)
		if a == nil || len(a) < min {
			return false
		}
		seen := map[string]bool{}
		for _, v := range a {
			if !item(v) {
				return false
			}
			key := string(canonical(v))
			if unique && seen[key] {
				return false
			}
			seen[key] = true
		}
		return true
	}
}
func validateConfigTable(label, path string, v any, fields map[string]configCheck, required string) error {
	m := obj(v)
	if m == nil {
		return invalid(label, path, "must be a table")
	}
	for _, key := range strings.Fields(required) {
		if _, ok := m[key]; !ok {
			return invalid(label, path+"."+key, "is required")
		}
	}
	for key, value := range m {
		check, ok := fields[key]
		if !ok {
			return invalid(label, path, "unknown key")
		}
		if !check(value) {
			return invalid(label, path+"."+key, "is not in the documented form or bound")
		}
	}
	return nil
}
func relativeCheck(v any) bool {
	s, ok := v.(string)
	return ok && textCheck("", 1024)(v) && validRelative(s) && !strings.Contains(s, "\\") && !contains(strings.Split(filepath.ToSlash(s), "/"), "") && !contains(strings.Split(filepath.ToSlash(s), "/"), ".")
}
func absoluteCheck(v any) bool {
	s, ok := v.(string)
	return ok && textCheck("", 4096)(v) && filepath.IsAbs(s) && !contains(strings.Split(filepath.ToSlash(s), "/"), ".") && !contains(strings.Split(filepath.ToSlash(s), "/"), "..")
}
func nestedGuardRepeat(re *syntax.Regexp, inside bool) bool {
	repeat := re.Op == syntax.OpStar || re.Op == syntax.OpPlus || re.Op == syntax.OpQuest || re.Op == syntax.OpRepeat
	many := re.Op == syntax.OpStar || re.Op == syntax.OpPlus || (re.Op == syntax.OpRepeat && (re.Max == -1 || re.Max > 1))
	if inside && many {
		return true
	}
	unbounded := re.Op == syntax.OpStar || re.Op == syntax.OpPlus || (re.Op == syntax.OpRepeat && re.Max == -1)
	for _, child := range re.Sub {
		if nestedGuardRepeat(child, inside || (repeat && unbounded)) {
			return true
		}
	}
	return false
}
func (c *configuration) validateDetails() error {
	label := "configuration " + c.name + ": config.toml"
	text := textCheck("", 1000)
	name := textCheck(`[a-z0-9][a-z0-9-]{0,31}`, 32)
	account := textCheck(`[A-Za-z0-9][A-Za-z0-9._-]{0,63}`, 64)
	secret := textCheck(`[A-Z][A-Z0-9_]{0,63}`, 64)
	budget := func(v any) bool {
		return numeric(v) && !math.IsInf(number(v), 0) && !math.IsNaN(number(v)) && number(v) > 0 && number(v) <= 10080
	}
	amount := func(v any) bool {
		return numeric(v) && !math.IsInf(number(v), 0) && !math.IsNaN(number(v)) && number(v) >= 0
	}
	boolean := func(v any) bool { _, ok := v.(bool); return ok }
	plainCommand := func(v any) bool {
		if validateTemplate(v, "") != nil {
			return false
		}
		for _, s := range stringsOf(v) {
			if strings.ContainsAny(s, "{}") {
				return false
			}
		}
		return true
	}
	command := func(v any) bool {
		return validateTemplate(v, "account brief effort lane log machine model project worktree") == nil
	}
	if !whole(c.data["schema_version"], 1, 1) {
		return invalid(label, "schema_version", "must be the integer 1")
	}
	if len(list(c.data["organisation_rules"])) > 0 && c.data["organisation"] == nil {
		return invalid(label, "organisation_rules", "requires an organisation")
	}
	for _, key := range []string{"description"} {
		if v, ok := c.data[key]; ok && !text(v) {
			return invalid(label, key, "must be nonempty text without controls")
		}
	}
	for _, key := range []string{"organisation", "owner_channel", "test_environment"} {
		if v, ok := c.data[key]; ok && !name(v) {
			return invalid(label, key, "must be a name")
		}
	}
	for _, key := range []string{"rules", "organisation_rules"} {
		if v, ok := c.data[key]; ok && !arrayCheck(relativeCheck, 0, true)(v) {
			return invalid(label, key, "must be an array of unique relative paths")
		}
	}
	if v, ok := c.data["secrets"]; ok && !arrayCheck(secret, 0, true)(v) {
		return invalid(label, "secrets", "must be an array of secret names")
	}
	if v, ok := c.data["state"]; ok {
		if err := validateConfigTable(label, "state", v, map[string]configCheck{"path": absoluteCheck}, ""); err != nil {
			return err
		}
	}
	for section, fields := range map[string]map[string]configCheck{
		"lanes": {"budget_minutes": budget, "quiet_seconds": wholeCheck(1, 604800), "stop_grace_seconds": wholeCheck(1, 600), "lock_wait_seconds": wholeCheck(1, 3600), "room_timeout_seconds": wholeCheck(1, 60)},
		"turns": {"idle_message": relativeCheck, "idle_seconds": wholeCheck(1, 604800), "poll_seconds": wholeCheck(1, 3600), "backoff_seconds": wholeCheck(1, 604800), "limit_backoff_seconds": wholeCheck(1, 604800)},
		"disk":  {"path": absoluteCheck, "warn_percent": wholeCheck(1, 99), "stop_percent": wholeCheck(1, 99)},
		"cost":  {"currency": textCheck(`[A-Z]{3}`, 3), "daily_cap": amount, "per_run_cap": amount, "report_threshold": amount},
	} {
		if v, ok := c.data[section]; ok {
			required := ""
			if section == "cost" {
				required = "currency"
			}
			if err := validateConfigTable(label, section, v, fields, required); err != nil {
				return err
			}
		}
	}
	disk := obj(c.data["disk"])
	if number(valueOr(disk, "warn_percent", 85)) >= number(valueOr(disk, "stop_percent", 90)) {
		return invalid(label, "disk.warn_percent", "must be below stop_percent")
	}
	if inside(c.state, c.home) || inside(c.home, c.state) {
		return invalid(label, "state.path", "must not overlap the configuration home")
	}
	if _, custom := obj(c.data["state"])["path"]; custom {
		if inside(c.states, c.state) {
			return invalid(label, "state.path", "must not contain the state home")
		}
		if inside(c.state, c.states) && !inside(c.state, filepath.Join(c.states, c.name)) {
			return invalid(label, "state.path", "must not lie inside another configuration's default state directory")
		}
	}
	for runner, v := range obj(c.data["runners"]) {
		r := obj(v)
		prefix := "runners." + runner
		for _, k := range []string{"description"} {
			if v, ok := r[k]; ok && !text(v) {
				return invalid(label, prefix+"."+k, "must be text")
			}
		}
		for k, check := range map[string]configCheck{"accounts": arrayCheck(account, 0, true), "secrets": arrayCheck(secret, 0, true), "quiet_seconds": wholeCheck(1, 604800), "stream": chooseCheck("text claude-stream-json")} {
			if v, ok := r[k]; ok && !check(v) {
				return invalid(label, prefix+"."+k, "is not in the documented form")
			}
		}
		for _, sec := range stringsOf(r["secrets"]) {
			if !contains(stringsOf(c.data["secrets"]), sec) {
				return invalid(label, prefix+".secrets", "names a secret not listed at the top level")
			}
		}
		for _, k := range []string{"limit_patterns", "dropped_patterns"} {
			if v, ok := r[k]; ok {
				check := func(v any) bool {
					if !text(v) {
						return false
					}
					_, err := regexp.Compile(str(v))
					return err == nil
				}
				if !arrayCheck(check, 1, true)(v) {
					return invalid(label, prefix+"."+k, "must be unique valid regular expressions")
				}
			}
		}
		if v, ok := r["records"]; ok {
			entries := list(v)
			if entries == nil || len(entries) == 0 {
				return invalid(label, prefix+".records", "must be a nonempty array")
			}
			for index, value := range entries {
				entry := obj(value)
				path := fmt.Sprintf("%s.records[%d]", prefix, index)
				recordPathCheck := func(v any) bool {
					s, ok := v.(string)
					if !ok || !textCheck("", 4096)(v) {
						return false
					}
					if !(strings.HasPrefix(s, "/") || strings.HasPrefix(s, "~/") || strings.HasPrefix(s, "{worktree}") || strings.HasPrefix(s, "{log}")) {
						return false
					}
					for _, p := range placeholders.FindAllStringSubmatch(s, -1) {
						if !contains(strings.Fields("account effort lane log model project session worktree"), p[1]) {
							return false
						}
					}
					return !strings.ContainsAny(placeholders.ReplaceAllString(s, ""), "{}")
				}
				if err := validateConfigTable(label, path, value, map[string]configCheck{"format": chooseCheck("claude-code text"), "paths": arrayCheck(recordPathCheck, 1, true)}, "format paths"); err != nil {
					return err
				}
				if str(entry["format"]) == "text" && (len(stringsOf(entry["paths"])) != 1 || stringsOf(entry["paths"])[0] != "{log}") {
					return invalid(label, path+".paths", "format text reads only the run's own log: paths must be exactly {log}")
				}
			}
		}
	}
	if v, ok := c.data["guards"]; ok {
		a := list(v)
		if a == nil {
			return invalid(label, "guards", "must be an array")
		}
		seen := map[string]bool{}
		for i, v := range a {
			path := fmt.Sprintf("guards[%d]", i)
			pattern := func(v any) bool {
				if !text(v) {
					return false
				}
				p, err := regexp.Compile(str(v))
				if err != nil || p.MatchString("") {
					return false
				}
				tree, err := syntax.Parse(str(v), syntax.Perl)
				return err == nil && !nestedGuardRepeat(tree, false)
			}
			if err := validateConfigTable(label, path, v, map[string]configCheck{"name": account, "kind": chooseCheck("hook permission harness"), "pattern": pattern, "description": text}, "name pattern"); err != nil {
				return err
			}
			guardName := str(obj(v)["name"])
			if seen[guardName] {
				return invalid(label, path+".name", "repeats an earlier guard name")
			}
			seen[guardName] = true
		}
	}
	if routing, ok := c.data["routing"]; ok {
		routes := obj(routing)
		if routes == nil {
			return invalid(label, "routing", "must be a table")
		}
		for difficulty, v := range routes {
			if !contains(strings.Fields("mechanical standard hard review"), difficulty) || list(v) == nil || len(list(v)) == 0 {
				return invalid(label, "routing", "must contain documented difficulties with nonempty arrays")
			}
			for _, route := range list(v) {
				model := func(v any) bool {
					return textCheck(`[A-Za-z0-9][A-Za-z0-9._:/@+\[\]-]{0,127}`, 128)(v) && strings.ContainsAny(str(v), "0123456789")
				}
				if err := validateConfigTable(label, "routing."+difficulty, route, map[string]configCheck{"runner": name, "model": model, "effort": name}, "runner model"); err != nil {
					return err
				}
				if obj(c.data["runners"])[str(obj(route)["runner"])] == nil {
					return invalid(label, "routing."+difficulty+".runner", "names a runner that is not defined")
				}
			}
		}
	}
	for project, v := range c.projects {
		p := obj(v)
		prefix := "projects/" + project + ".toml"
		if err := validateConfigTable(label, prefix, p, map[string]configCheck{"schema_version": wholeCheck(1, 1), "name": name, "description": text, "repository": textCheck("", 1024), "lane_prefix": textCheck(`[a-z0-9][a-z0-9-]{0,15}`, 16), "workers": arrayCheck(name, 0, true), "gates": arrayCheck(name, 1, true), "excluded_accounts": arrayCheck(account, 0, true), "test_environment": name, "reserved_paths": arrayCheck(relativeCheck, 0, true), "owner_channel": name, "landing_authority": name, "rules": arrayCheck(relativeCheck, 0, true)}, "schema_version name"); err != nil {
			return err
		}
		for _, worker := range stringsOf(p["workers"]) {
			if obj(c.data["runners"])[worker] == nil {
				return invalid(label, prefix+".workers", "names an undefined runner")
			}
		}
		for _, acc := range stringsOf(p["excluded_accounts"]) {
			listed := false
			for _, r := range obj(c.data["runners"]) {
				listed = listed || contains(stringsOf(obj(r)["accounts"]), acc)
			}
			if !listed {
				return invalid(label, prefix+".excluded_accounts", "names an account no runner lists")
			}
		}
	}
	for section := range map[string]bool{"judges": true, "resources": true, "supervisors": true, "test_environments": true, "owner_channels": true} {
		v, ok := c.data[section]
		if !ok {
			continue
		}
		entries := obj(v)
		if entries == nil {
			return invalid(label, section, "must be a table")
		}
		for entry, value := range entries {
			if !name(entry) {
				return invalid(label, section, "entry name is invalid")
			}
			path := section + "." + entry
			m := obj(value)
			fields := map[string]configCheck{}
			required := ""
			switch section {
			case "judges":
				fields = map[string]configCheck{"description": text, "command": plainCommand, "timeout_seconds": wholeCheck(1, 60)}
				required = "command"
			case "resources":
				credentialEnv := func(v any) bool { return secret(v) && str(v) != "PATH" && !strings.HasPrefix(str(v), "LANEBOSS_") }
				fields = map[string]configCheck{"description": text, "command": plainCommand, "kind": chooseCheck("machine credential"), "credential_env": credentialEnv, "credential_profile": account, "acquire_seconds": wholeCheck(1, 900), "describe_seconds": wholeCheck(1, 300), "release_seconds": wholeCheck(1, 600), "acquire_bound_minutes": wholeCheck(1, 1440), "hard_cap_minutes": wholeCheck(1, 10080), "release_by_itself": boolean, "read_back_wait_seconds": wholeCheck(0, 3600)}
				required = "command kind hard_cap_minutes"
				if number(valueOr(m, "acquire_bound_minutes", 15)) < math.Ceil(number(valueOr(m, "acquire_seconds", 300))/60)+1 {
					return invalid(label, path+".acquire_bound_minutes", "must be at least one minute more than acquire_seconds rounded up")
				}
			case "supervisors":
				fields = map[string]configCheck{"level": wholeCheck(4, 6), "role": chooseCheck("mini top"), "runner": name, "projects": arrayCheck(name, 0, true), "owner_channel": name, "description": text}
				required = "runner"
				_, level := m["level"]
				_, role := m["role"]
				if level == role {
					return invalid(label, path+".level", "give exactly one of level and role")
				}
			case "test_environments":
				kind := str(m["kind"])
				if !contains(strings.Fields("cloud host local"), kind) {
					return invalid(label, path+".kind", "must be cloud, host or local")
				}
				fields = map[string]configCheck{"kind": chooseCheck("cloud host local"), "description": text, "secrets": arrayCheck(secret, 0, true), "attest": command, "launch": command, "collect": command, "max_machines": wholeCheck(1, 64), "idle_minutes": wholeCheck(1, 1440), "hard_minutes": wholeCheck(1, 10080)}
				required = "kind"
				if kind == "cloud" {
					fields["identity"] = textCheck(`[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,127}`, 128)
					fields["region"] = name
					required += " identity"
				}
				if kind == "host" {
					fields["host"] = textCheck(`[A-Za-z0-9][A-Za-z0-9._-]{0,127}`, 128)
					required += " host"
				}
				if len(list(m["secrets"])) > 0 && m["attest"] == nil {
					return invalid(label, path+".attest", "is required when secrets are listed")
				}
			case "owner_channels":
				kind := str(m["kind"])
				fields = map[string]configCheck{"kind": chooseCheck("chat file"), "description": text}
				required = "kind"
				if kind == "chat" {
					fields["service"] = textCheck(`[a-z0-9][a-z0-9.-]{0,63}`, 64)
					fields["target"] = textCheck("", 200)
					fields["token_secret"] = secret
					required += " service target"
				} else if kind == "file" {
					fields["path"] = relativeCheck
					required += " path"
				}
			}
			if err := validateConfigTable(label, path, value, fields, required); err != nil {
				return err
			}
		}
	}
	if org := str(c.data["organisation"]); org != "" {
		orgRoot := filepath.Join(c.home, "orgs")
		for _, section := range []string{"runners", "judges", "resources"} {
			for _, v := range obj(c.data[section]) {
				for _, key := range []string{"command", "resume", "room"} {
					for _, element := range stringsOf(obj(v)[key]) {
						if filepath.IsAbs(element) {
							p := filepath.Clean(element)
							if strings.HasPrefix(p, orgRoot+"/") {
								other := strings.Split(strings.TrimPrefix(p, orgRoot+"/"), "/")[0]
								if other != org {
									return invalid(label, section+".command", "points into another organisation's directory; tools are not shared")
								}
							}
						}
					}
				}
			}
		}
	}
	known := func(section string, value any) bool { return obj(c.data[section])[str(value)] != nil }
	for _, key := range []string{"owner_channel", "test_environment"} {
		if value, ok := c.data[key]; ok {
			section := "owner_channels"
			if key == "test_environment" {
				section = "test_environments"
			}
			if !known(section, value) {
				return invalid(label, key, "names an entry that is not defined")
			}
		}
	}
	for _, v := range obj(c.data["supervisors"]) {
		m := obj(v)
		if !known("runners", m["runner"]) {
			return invalid(label, "supervisors.runner", "names an undefined runner")
		}
		for _, project := range stringsOf(m["projects"]) {
			if c.projects[project] == nil {
				return invalid(label, "supervisors.projects", "names an undefined project")
			}
		}
		if m["owner_channel"] != nil && !known("owner_channels", m["owner_channel"]) {
			return invalid(label, "supervisors.owner_channel", "names an undefined channel")
		}
		if m["role"] != nil {
			level := 4
			if str(m["role"]) == "top" {
				level = 5
			}
			m["level"] = level
			delete(m, "role")
		}
	}
	for _, v := range c.projects {
		m := obj(v)
		if m["test_environment"] != nil && !known("test_environments", m["test_environment"]) {
			return invalid(label, "projects.test_environment", "names an undefined test environment")
		}
		if m["owner_channel"] != nil && !known("owner_channels", m["owner_channel"]) {
			return invalid(label, "projects.owner_channel", "names an undefined channel")
		}
		if m["landing_authority"] != nil {
			supervisor := obj(obj(c.data["supervisors"])[str(m["landing_authority"])])
			if supervisor == nil || integer(supervisor["level"]) < 5 {
				return invalid(label, "projects.landing_authority", "must name a supervisor of level 5 or 6")
			}
		}
	}
	for _, v := range obj(c.data["test_environments"]) {
		for _, s := range stringsOf(obj(v)["secrets"]) {
			if !contains(stringsOf(c.data["secrets"]), s) {
				return invalid(label, "test_environments.secrets", "names an unlisted secret")
			}
		}
	}
	for _, v := range obj(c.data["owner_channels"]) {
		if sec := obj(v)["token_secret"]; sec != nil && !contains(stringsOf(c.data["secrets"]), str(sec)) {
			return invalid(label, "owner_channels.token_secret", "names an unlisted secret")
		}
	}
	if relative := str(obj(c.data["turns"])["idle_message"]); relative != "" {
		root, err := rootDirectory(c.directory)
		if err != nil {
			return err
		}
		data, err := rootRead(root, relative, 65536)
		root.Close()
		if err != nil {
			return invalid(label, "turns.idle_message", "cannot read as a rules file within 64 KiB")
		}
		if rule, _ := credential(string(data)); rule != "" {
			return invalid(label, "turns.idle_message", "looks like a credential")
		}
	}
	return nil
}
