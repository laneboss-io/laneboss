package doctorbase

import (
	"fmt"
	"math"
	"regexp"
	"regexp/syntax"
	"strings"
	"unicode/utf8"

	"laneboss.io/laneboss/internal/runnermodel"
)

type validator func(any, string) error

func failure(path, message string) error { return fmt.Errorf("%s: %s", path, message) }
func text(pattern string, max int) validator {
	var r *regexp.Regexp
	if pattern != "" {
		r = regexp.MustCompile("^(?:" + pattern + ")$")
	}
	return func(v any, p string) error {
		s, ok := v.(string)
		if !ok {
			return failure(p, "must be a string")
		}
		if strings.TrimSpace(s) == "" {
			return failure(p, "must not be empty")
		}
		if utf8.RuneCountInString(s) > max {
			return failure(p, fmt.Sprintf("must be at most %d characters", max))
		}
		for _, c := range s {
			if c < 32 || c == 127 {
				return failure(p, "must not contain control characters")
			}
		}
		if r != nil && !r.MatchString(s) {
			return failure(p, "does not match the required grammar")
		}
		return nil
	}
}
func integer(low, high int64) validator {
	return func(v any, p string) error {
		n, ok := v.(int64)
		if !ok {
			return failure(p, "must be an integer")
		}
		if n < low || n > high {
			return failure(p, fmt.Sprintf("must be from %d to %d", low, high))
		}
		return nil
	}
}
func amount(low, high float64, strict bool) validator {
	return func(v any, p string) error {
		n := Number(v)
		if math.IsNaN(n) || math.IsInf(n, 0) || n < low || n > high || (strict && n == low) {
			return failure(p, "must be a finite number within the allowed bounds")
		}
		return nil
	}
}
func choice(options ...string) validator {
	return func(v any, p string) error {
		s, ok := v.(string)
		if ok {
			for _, o := range options {
				if s == o {
					return nil
				}
			}
		}
		return failure(p, "must be one of: "+strings.Join(options, ", "))
	}
}
func boolean(v any, p string) error {
	if _, ok := v.(bool); !ok {
		return failure(p, "must be true or false")
	}
	return nil
}
func array(check validator, nonempty, unique bool) validator {
	return func(v any, p string) error {
		a, ok := v.([]any)
		if !ok {
			return failure(p, "must be an array")
		}
		if nonempty && len(a) == 0 {
			return failure(p, "must not be empty")
		}
		seen := map[string]bool{}
		for i, x := range a {
			if err := check(x, fmt.Sprintf("%s[%d]", p, i)); err != nil {
				return err
			}
			b, err := Canonical(x)
			if err != nil {
				return failure(p, "invalid array item")
			}
			key := string(b)
			if unique && seen[key] {
				return failure(p, "must not repeat an item")
			}
			seen[key] = true
		}
		return nil
	}
}
func table(fields map[string]validator, required ...string) validator {
	return func(v any, p string) error {
		m, ok := v.(map[string]any)
		if !ok {
			return failure(p, "must be a table")
		}
		join := func(k string) string {
			if p == "" {
				return k
			}
			return p + "." + k
		}
		for _, k := range Keys(m) {
			if _, ok := fields[k]; !ok {
				return failure(join(k), "unknown key")
			}
		}
		for _, k := range required {
			if _, ok := m[k]; !ok {
				return failure(join(k), "is required")
			}
		}
		for _, k := range Keys(m) {
			if err := fields[k](m[k], join(k)); err != nil {
				return err
			}
		}
		return nil
	}
}
func named(check validator, min int) validator {
	return func(v any, p string) error {
		m, ok := v.(map[string]any)
		if !ok {
			return failure(p, "must be a table")
		}
		if len(m) < min {
			return failure(p, "must define at least one entry")
		}
		for _, k := range Keys(m) {
			if !Name.MatchString(k) {
				return failure(p, "has a key that is not a valid name")
			}
			if err := check(m[k], p+"."+k); err != nil {
				return err
			}
		}
		return nil
	}
}
func relative(v any, p string) error {
	if err := text("", 1024)(v, p); err != nil {
		return err
	}
	s := String(v)
	if strings.HasPrefix(s, "/") || strings.Contains(s, `\`) {
		return failure(p, "must be a relative path without '..', '.' or empty parts")
	}
	for _, part := range strings.Split(s, "/") {
		if part == "" || part == "." || part == ".." {
			return failure(p, "must be a relative path without '..', '.' or empty parts")
		}
	}
	return nil
}
func rulesPath(v any, p string) error {
	if err := relative(v, p); err != nil {
		return err
	}
	if strings.Split(String(v), "/")[0] == "orgs" {
		return failure(p, "must not start with orgs")
	}
	return nil
}
func absolute(v any, p string) error {
	if err := text("", 4096)(v, p); err != nil {
		return err
	}
	s := String(v)
	if !strings.HasPrefix(s, "/") {
		return failure(p, "must be an absolute path without '.' or '..' parts")
	}
	for _, part := range strings.Split(s, "/") {
		if part == "." || part == ".." {
			return failure(p, "must be an absolute path without '.' or '..' parts")
		}
	}
	return nil
}
func schema(v any, p string) error {
	if n, ok := v.(int64); !ok || n != 1 {
		return failure(p, "unsupported schema version; this launcher reads schema_version = 1")
	}
	return nil
}

const nameRule = "[a-z0-9][a-z0-9-]{0,31}"
const accountRule = "[A-Za-z0-9][A-Za-z0-9._-]{0,63}"
const modelRule = `[A-Za-z0-9][A-Za-z0-9._:/@+\[\]-]{0,127}`

var standardFields = strings.Fields("account brief effort lane log machine model project worktree")
var runnerFields = append(append([]string{}, standardFields...), "session")

func formatFields(s string, allowed []string) ([]string, error) {
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
			return nil, fmt.Errorf("unbalanced brace")
		}
		end := strings.IndexByte(s[i+1:], '}')
		if end < 0 {
			return nil, fmt.Errorf("unbalanced brace")
		}
		f := s[i+1 : i+1+end]
		ok := false
		for _, a := range allowed {
			if f == a {
				ok = true
			}
		}
		if !ok {
			return nil, fmt.Errorf("uses an unknown placeholder")
		}
		found = append(found, f)
		i += end + 1
	}
	return found, nil
}
func Uses(v any, field string) bool {
	a := Array(v)
	if len(a) < 2 {
		return false
	}
	for _, s := range a[1:] {
		fs, err := formatFields(String(s), append(append([]string{}, runnerFields...), "message"))
		if err != nil {
			continue
		}
		for _, f := range fs {
			if f == field {
				return true
			}
		}
	}
	return false
}
func command(allowed []string, plain bool) validator {
	return func(v any, p string) error {
		if err := array(text("", 4096), true, false)(v, p); err != nil {
			return err
		}
		a := Array(v)
		first := String(a[0])
		if !(regexp.MustCompile(`^[A-Za-z0-9_.+-]+$`).MatchString(first) || strings.HasPrefix(first, "/")) || strings.ContainsAny(first, "{}") {
			return failure(p+"[0]", "must be a command name or an absolute path, without placeholders")
		}
		for i, x := range a {
			if plain {
				if strings.ContainsAny(String(x), "{}") {
					return failure(fmt.Sprintf("%s[%d]", p, i), "must not contain braces: this command has no placeholders in version 1")
				}
			} else if i > 0 {
				if _, err := formatFields(String(x), allowed); err != nil {
					return failure(fmt.Sprintf("%s[%d]", p, i), err.Error())
				}
			}
		}
		return nil
	}
}
func pattern(v any, p string) error {
	if err := text("", 1000)(v, p); err != nil {
		return err
	}
	s := String(v)
	prefixEnd := 0
	// Accept the common syntax of the two readers. Go-only syntax must not
	// turn a configuration that Python rejects into an accepted one.
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+1 < len(s) {
			i++
			if strings.ContainsRune("pPQEz", rune(s[i])) || (s[i] == 'x' && i+1 < len(s) && s[i+1] == '{') {
				return failure(p, "is not a valid supported regular expression")
			}
			if s[i] >= '4' && s[i] <= '7' && i+2 < len(s) && s[i+1] >= '0' && s[i+1] <= '7' && s[i+2] >= '0' && s[i+2] <= '7' {
				return failure(p, "is not a valid supported regular expression")
			}
		} else if s[i] == '(' && i+2 < len(s) && s[i+1] == '?' {
			if s[i+2] == '<' {
				return failure(p, "is not a valid supported regular expression")
			}
			j := i + 2
			negative := false
			for ; j < len(s) && strings.ContainsRune("imsU-", rune(s[j])); j++ {
				if s[j] == 'U' {
					return failure(p, "is not a valid supported regular expression")
				}
				negative = negative || s[j] == '-'
			}
			if j > i+2 && j < len(s) && s[j] == ')' {
				if negative || i != prefixEnd {
					return failure(p, "is not a valid supported regular expression")
				}
				prefixEnd = j + 1
			}
		}
	}
	r, err := regexp.Compile(s)
	if err != nil {
		return failure(p, "is not a valid supported regular expression")
	}
	seen := map[string]bool{}
	for _, name := range r.SubexpNames() {
		if name == "" {
			continue
		}
		if !regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`).MatchString(name) || seen[name] {
			return failure(p, "is not a valid supported regular expression")
		}
		seen[name] = true
	}
	if r.MatchString("") {
		return failure(p, "must not match an empty line")
	}
	return nil
}
func guardPattern(v any, p string) error {
	if err := pattern(v, p); err != nil {
		return err
	}
	parsed, err := syntax.Parse(String(v), syntax.Perl)
	if err != nil {
		return failure(p, "is not a valid supported regular expression")
	}
	var unbounded func(*syntax.Regexp, bool) bool
	unbounded = func(r *syntax.Regexp, inside bool) bool {
		repeats := r.Op == syntax.OpStar || r.Op == syntax.OpPlus || r.Op == syntax.OpRepeat
		max := r.Max
		if r.Op == syntax.OpStar || r.Op == syntax.OpPlus {
			max = -1
		}
		if repeats && inside && (max < 0 || max > 1) {
			return true
		}
		endless := repeats && max < 0
		for _, child := range r.Sub {
			if unbounded(child, inside || endless) {
				return true
			}
		}
		return false
	}
	if unbounded(parsed, false) {
		return failure(p, "cannot be bounded: it repeats without bound a part that itself repeats")
	}
	return nil
}
func model(v any, p string) error {
	if err := text(modelRule, 128)(v, p); err != nil {
		return err
	}
	if !regexp.MustCompile(`[0-9]`).MatchString(String(v)) {
		return failure(p, "must be a full model name that includes its version, not a family alias")
	}
	return nil
}
func apiModels(v any, p string) error {
	if err := runnermodel.Validate(v); err != nil {
		return failure(p, err.Error())
	}
	return nil
}

func secrets(v any, p string) error {
	return array(text("[A-Z][A-Z0-9_]{0,63}", 64), false, true)(v, p)
}

func configSchema() validator {
	t := text("", 1000)
	name := text(nameRule, 32)
	names := array(name, false, true)
	record := table(map[string]validator{"format": choice("claude-code", "text"), "paths": array(func(v any, p string) error {
		if err := text("", 4096)(v, p); err != nil {
			return err
		}
		s := String(v)
		if !(strings.HasPrefix(s, "/") || strings.HasPrefix(s, "~/") || strings.HasPrefix(s, "{worktree}") || strings.HasPrefix(s, "{log}")) {
			return failure(p, "must be an absolute path or glob, or start with ~/, {worktree} or {log}")
		}
		_, err := formatFields(s, strings.Fields("account effort lane log model project session worktree"))
		if err != nil {
			return failure(p, err.Error())
		}
		return nil
	}, true, true)}, "format", "paths")
	runnerKeys := table(map[string]validator{"command": command(runnerFields, false), "resume": command(append(append([]string{}, runnerFields...), "message"), false), "prompt": choice("argument", "stdin"), "stream": choice("text", "claude-stream-json"), "room": command([]string{"account"}, false), "accounts": array(text(accountRule, 64), false, true), "secrets": secrets, "api_models": apiModels, "limit_patterns": array(pattern, true, true), "dropped_patterns": array(pattern, true, true), "quiet_seconds": integer(1, 604800), "records": array(func(v any, p string) error {
		if err := record(v, p); err != nil {
			return err
		}
		m := Object(v)
		if m["format"] == "text" && (len(Array(m["paths"])) != 1 || Array(m["paths"])[0] != "{log}") {
			return failure(p+".paths", "format text reads only the run's own log: its paths must be exactly [\"{log}\"]")
		}
		return nil
	}, true, false), "description": t}, "command")
	runner := func(v any, p string) error {
		if err := runnerKeys(v, p); err != nil {
			return err
		}
		m := Object(v)
		if m["prompt"] != "stdin" && !Uses(m["command"], "brief") {
			return failure(p+".command", "must pass the rendered brief with {brief}, or take prompt on standard input (prompt = \"stdin\")")
		}
		if resume, ok := m["resume"]; ok && Uses(m["command"], "session") != Uses(resume, "session") {
			return failure(p+".resume", "must use {session} exactly when command does")
		}
		return nil
	}
	supervisorKeys := table(map[string]validator{"level": func(v any, p string) error { return integer(4, 6)(v, p) }, "role": choice("top", "mini"), "runner": name, "projects": names, "owner_channel": name, "description": t}, "runner")
	supervisor := func(v any, p string) error {
		m := Object(v)
		_, level := m["level"]
		_, role := m["role"]
		if level == role {
			return failure(p, "give exactly one of level and role")
		}
		return supervisorKeys(v, p)
	}
	envKeys := map[string]validator{"kind": choice("cloud", "host", "local"), "description": t, "identity": text("[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,127}", 128), "region": name, "host": text("[A-Za-z0-9][A-Za-z0-9._-]{0,127}", 128), "secrets": secrets, "attest": command(standardFields, false), "launch": command(standardFields, false), "collect": command(standardFields, false), "max_machines": integer(1, 64), "idle_minutes": integer(1, 1440), "hard_minutes": integer(1, 10080)}
	environment := func(v any, p string) error {
		m := Object(v)
		kind := String(m["kind"])
		fields := map[string]validator{}
		for k, f := range envKeys {
			if k != "identity" && k != "region" && k != "host" || (kind == "cloud" && (k == "identity" || k == "region")) || (kind == "host" && k == "host") {
				fields[k] = f
			}
		}
		req := []string{"kind"}
		if kind == "cloud" {
			req = append(req, "identity")
		}
		if kind == "host" {
			req = append(req, "host")
		}
		if err := table(fields, req...)(v, p); err != nil {
			return err
		}
		if len(Array(m["secrets"])) > 0 && m["attest"] == nil {
			return failure(p+".attest", "is required when secrets are listed: a secret goes only to a verified machine")
		}
		return nil
	}
	channel := func(v any, p string) error {
		kind := String(Object(v)["kind"])
		fields := map[string]validator{"kind": choice("file", "chat"), "description": t, "token_secret": text("[A-Z][A-Z0-9_]{0,63}", 64)}
		req := []string{"kind"}
		if kind == "file" {
			fields["path"] = relative
			req = append(req, "path")
		} else if kind == "chat" {
			fields["service"] = text("[a-z0-9][a-z0-9.-]{0,63}", 64)
			fields["target"] = text("", 200)
			req = append(req, "service", "target")
		}
		return table(fields, req...)(v, p)
	}
	resourceKeys := table(map[string]validator{"description": t, "command": command(nil, true), "kind": choice("machine", "credential"), "credential_env": func(v any, p string) error {
		if err := text("[A-Z][A-Z0-9_]{0,63}", 64)(v, p); err != nil {
			return err
		}
		if v == "PATH" || strings.HasPrefix(String(v), "LANEBOSS_") {
			return failure(p, "must not name PATH or a LANEBOSS_ variable")
		}
		return nil
	}, "credential_profile": text(accountRule, 64), "acquire_seconds": integer(1, 900), "describe_seconds": integer(1, 300), "release_seconds": integer(1, 600), "acquire_bound_minutes": integer(1, 1440), "hard_cap_minutes": integer(1, 10080), "release_by_itself": boolean, "read_back_wait_seconds": integer(0, 3600)}, "command", "kind", "hard_cap_minutes")
	resource := func(v any, p string) error {
		if err := resourceKeys(v, p); err != nil {
			return err
		}
		m := Object(v)
		seconds, bound := int64(300), int64(15)
		if x, ok := m["acquire_seconds"].(int64); ok {
			seconds = x
		}
		if x, ok := m["acquire_bound_minutes"].(int64); ok {
			bound = x
		}
		if bound < (seconds+59)/60+1 {
			return failure(p+".acquire_bound_minutes", "must be at least one minute more than acquire_seconds rounded up to whole minutes")
		}
		return nil
	}
	disk := func(v any, p string) error {
		if err := table(map[string]validator{"path": absolute, "warn_percent": integer(1, 99), "stop_percent": integer(1, 99)})(v, p); err != nil {
			return err
		}
		m := Object(v)
		warn, stop := int64(85), int64(90)
		if x, ok := m["warn_percent"].(int64); ok {
			warn = x
		}
		if x, ok := m["stop_percent"].(int64); ok {
			stop = x
		}
		if warn >= stop {
			return failure(p+".warn_percent", "must be below stop_percent")
		}
		return nil
	}
	route := table(map[string]validator{"runner": name, "model": model, "effort": name}, "runner", "model")
	guardItems := array(table(map[string]validator{"name": text(accountRule, 64), "kind": choice("hook", "permission", "harness"), "pattern": guardPattern, "description": t}, "name", "pattern"), false, false)
	guards := func(v any, p string) error {
		if err := guardItems(v, p); err != nil {
			return err
		}
		seen := map[string]bool{}
		for i, item := range Array(v) {
			name := String(Object(item)["name"])
			if seen[name] {
				return failure(fmt.Sprintf("%s[%d].name", p, i), "repeats the name of an earlier guard")
			}
			seen[name] = true
		}
		return nil
	}
	return table(map[string]validator{"schema_version": schema, "name": name, "description": t, "organisation": name, "rules": array(rulesPath, false, true), "organisation_rules": array(relative, false, true), "secrets": secrets, "owner_channel": name, "test_environment": name, "state": table(map[string]validator{"path": absolute}), "lanes": table(map[string]validator{"budget_minutes": amount(0, 10080, true), "quiet_seconds": integer(1, 604800), "stop_grace_seconds": integer(1, 600), "lock_wait_seconds": integer(1, 3600), "room_timeout_seconds": integer(1, 60)}), "turns": table(map[string]validator{"idle_message": relative, "idle_seconds": integer(1, 604800), "poll_seconds": integer(1, 3600), "backoff_seconds": integer(1, 604800), "limit_backoff_seconds": integer(1, 604800)}), "disk": disk, "runners": named(runner, 1), "supervisors": named(supervisor, 0), "judges": named(table(map[string]validator{"description": t, "command": command(nil, true), "timeout_seconds": integer(1, 60)}, "command"), 0), "resources": named(resource, 0), "routing": table(map[string]validator{"mechanical": array(route, true, false), "standard": array(route, true, false), "hard": array(route, true, false), "review": array(route, true, false)}), "test_environments": named(environment, 0), "owner_channels": named(channel, 0), "cost": table(map[string]validator{"currency": text("[A-Z]{3}", 3), "daily_cap": amount(0, math.MaxFloat64, false), "per_run_cap": amount(0, math.MaxFloat64, false), "report_threshold": amount(0, math.MaxFloat64, false)}, "currency"), "guards": guards}, "schema_version", "name", "runners")
}
func projectSchema() validator {
	name := text(nameRule, 32)
	return table(map[string]validator{"schema_version": schema, "name": name, "description": text("", 1000), "repository": text("", 1024), "lane_prefix": text("[a-z0-9][a-z0-9-]{0,15}", 16), "workers": array(name, false, true), "gates": array(name, true, true), "excluded_accounts": array(text(accountRule, 64), false, true), "test_environment": name, "reserved_paths": array(relative, false, true), "owner_channel": name, "landing_authority": name, "rules": array(rulesPath, false, true)}, "schema_version", "name")
}
