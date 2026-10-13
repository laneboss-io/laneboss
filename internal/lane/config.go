package lane

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/BurntSushi/toml"
)

type zone struct{ name, path string }
type ruleInput struct {
	name string
	data []byte
}
type configuration struct {
	name, home, states, directory, state string
	data, projects                       object
	rules                                map[string][]byte
	zones                                []zone
}

func homeSetting(key, defaultPath string) (string, error) {
	p := os.Getenv(key)
	if p == "" {
		p = defaultPath
	}
	if !filepath.IsAbs(p) {
		return "", refuse("%s must be an absolute path", key)
	}
	return filepath.Clean(p), nil
}
func loadTOML(r *os.Root, path, label string) (object, error) {
	b, err := rootRead(r, path, 1024*1024)
	if err != nil {
		return nil, refuse("cannot read %s", label)
	}
	if !utf8.Valid(b) {
		return nil, invalid(label, "(top level)", "must be UTF-8 text")
	}
	var m object
	if _, err = toml.Decode(string(b), &m); err != nil {
		return nil, invalid(label, "(top level)", "TOML syntax error")
	}
	if err = checkSecrets(m); err != nil {
		return nil, invalid(label, "a field", "looks like a credential; configuration files hold secret names, never values")
	}
	if integer(m["schema_version"]) != 1 {
		return nil, invalid(label, "schema_version", "must be 1")
	}
	return m, nil
}
func knownKeys(m object, allowed, label string) error {
	if m == nil {
		return invalid(label, "(top level)", "must be a table")
	}
	for k := range m {
		if !contains(strings.Fields(allowed), k) {
			return invalid(label, "a field", "unknown key")
		}
	}
	return nil
}
func loadConfiguration(cli string) (*configuration, error) {
	env := os.Getenv("LANEBOSS_CONFIG")
	for _, n := range []string{cli, env} {
		if n != "" && !match(`[a-z0-9][a-z0-9-]{0,31}`, n) {
			return nil, refuse("the configuration name must match [a-z0-9][a-z0-9-]{0,31}")
		}
		if r, _ := credential(n); r != "" {
			return nil, refuse("the configuration name looks like a credential")
		}
	}
	if cli != "" && env != "" && cli != env {
		return nil, refuse("--config conflicts with LANEBOSS_CONFIG; a session is bound to exactly one configuration")
	}
	name := cli
	if name == "" {
		name = env
	}
	if name == "" {
		return nil, refuse("no configuration is bound: pass --config NAME or set LANEBOSS_CONFIG")
	}
	accountHome, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	home, err := homeSetting("LANEBOSS_HOME", filepath.Join(accountHome, ".config", "laneboss"))
	if err != nil {
		return nil, err
	}
	states, err := homeSetting("LANEBOSS_STATE_HOME", filepath.Join(accountHome, ".local", "state", "laneboss"))
	if err != nil {
		return nil, err
	}
	directory := realPath(filepath.Join(home, "configs", name))
	root, err := rootDirectory(directory)
	if err != nil {
		return nil, refuse("no configuration named %s", name)
	}
	defer root.Close()
	label := "configuration " + name + ": config.toml"
	data, err := loadTOML(root, "config.toml", label)
	if err != nil {
		return nil, err
	}
	if err = knownKeys(data, "schema_version name description organisation rules organisation_rules secrets owner_channel test_environment state lanes turns disk runners supervisors judges resources routing test_environments owner_channels cost guards", label); err != nil {
		return nil, err
	}
	if str(data["name"]) != name {
		return nil, invalid(label, "name", "must equal the directory name")
	}
	if len(obj(data["runners"])) == 0 {
		return nil, invalid(label, "runners", "must define at least one entry")
	}
	c := &configuration{name: name, home: realPath(home), states: realPath(states), directory: directory, data: data, projects: object{}, rules: map[string][]byte{}}
	state := str(obj(data["state"])["path"])
	if state == "" {
		state = filepath.Join(states, name)
	}
	if !filepath.IsAbs(state) {
		return nil, invalid(label, "state.path", "must be an absolute path")
	}
	c.state = realPath(state)
	for runner, v := range obj(data["runners"]) {
		if !match(`[a-z0-9][a-z0-9-]{0,31}`, runner) {
			return nil, invalid(label, "runners", "an entry name is invalid")
		}
		r := obj(v)
		if err = knownKeys(r, "description command resume accounts secrets quiet_seconds limit_patterns dropped_patterns prompt stream records room", label); err != nil {
			return nil, err
		}
		for _, kind := range []string{"command", "resume", "room"} {
			if kind != "command" && r[kind] == nil {
				continue
			}
			allowed := "account brief effort lane log machine model project worktree session"
			if kind == "resume" {
				allowed += " message"
			}
			if kind == "room" {
				allowed = "account"
			}
			if err = validateTemplate(r[kind], allowed); err != nil {
				return nil, invalid(label, "runners."+runner+"."+kind, err.Error())
			}
		}
		prompt := str(valueOr(r, "prompt", "argument"))
		if !contains([]string{"argument", "stdin"}, prompt) {
			return nil, invalid(label, "runners."+runner+".prompt", "must be argument or stdin")
		}
		if prompt == "argument" && !uses(r["command"], "brief") {
			return nil, invalid(label, "runners."+runner+".command", "must pass the rendered brief with {brief}")
		}
		if r["resume"] != nil && uses(r["command"], "session") != uses(r["resume"], "session") {
			return nil, invalid(label, "runners."+runner+".resume", "must use {session} exactly when command does")
		}
		for _, a := range stringsOf(r["accounts"]) {
			if !match(`[A-Za-z0-9][A-Za-z0-9._-]{0,63}`, a) {
				return nil, invalid(label, "runners."+runner+".accounts", "invalid account name")
			}
		}
		for _, kind := range []string{"limit_patterns", "dropped_patterns"} {
			for _, pattern := range stringsOf(r[kind]) {
				if _, e := regexp.Compile(pattern); e != nil {
					return nil, invalid(label, "runners."+runner+"."+kind, "unsupported regular expression")
				}
			}
		}
	}
	for k, v := range obj(data["lanes"]) {
		bounds := map[string][2]float64{"budget_minutes": {0.000001, 10080}, "quiet_seconds": {1, 604800}, "stop_grace_seconds": {1, 600}, "lock_wait_seconds": {1, 3600}, "room_timeout_seconds": {1, 60}}
		b, ok := bounds[k]
		if !ok || number(v) < b[0] || number(v) > b[1] {
			return nil, invalid(label, "lanes."+k, "must be within the documented bounds")
		}
	}
	if projects, e := rootChild(root, "projects", false); e == nil {
		entries, e := projects.Open(".")
		if e != nil {
			projects.Close()
			return nil, e
		}
		names, e := entries.Readdirnames(-1)
		entries.Close()
		if e != nil {
			projects.Close()
			return nil, e
		}
		for _, n := range names {
			if !strings.HasSuffix(n, ".toml") {
				continue
			}
			stem := strings.TrimSuffix(n, ".toml")
			if !match(`[a-z0-9][a-z0-9-]{0,31}`, stem) {
				projects.Close()
				return nil, invalid(label, "projects", "invalid project name")
			}
			p, e := loadTOML(projects, n, "configuration "+name+": projects/"+n)
			if e != nil {
				projects.Close()
				return nil, e
			}
			if e = knownKeys(p, "schema_version name description repository lane_prefix workers gates excluded_accounts test_environment reserved_paths owner_channel landing_authority rules", label); e != nil {
				projects.Close()
				return nil, e
			}
			if str(p["name"]) != stem {
				projects.Close()
				return nil, invalid(label, "projects.name", "must equal the file name")
			}
			c.projects[stem] = p
		}
		projects.Close()
	} else if !os.IsNotExist(e) {
		return nil, e
	}
	for _, name := range stringsOf(data["rules"]) {
		b, e := readRules(root, name, label)
		if e != nil {
			return nil, e
		}
		c.rules[name] = b
	}
	for _, v := range c.projects {
		for _, n := range stringsOf(obj(v)["rules"]) {
			if _, ok := c.rules[n]; !ok {
				b, e := readRules(root, n, label)
				if e != nil {
					return nil, e
				}
				c.rules[n] = b
			}
		}
	}
	if org := str(data["organisation"]); org != "" {
		if !match(`[a-z0-9][a-z0-9-]{0,31}`, org) {
			return nil, invalid(label, "organisation", "invalid organisation name")
		}
		orgRoot, e := rootDirectory(realPath(filepath.Join(home, "orgs", org)))
		if e != nil {
			return nil, e
		}
		for _, n := range stringsOf(data["organisation_rules"]) {
			b, e := readRules(orgRoot, n, label)
			if e != nil {
				orgRoot.Close()
				return nil, e
			}
			c.rules["orgs/"+org+"/"+n] = b
		}
		orgRoot.Close()
	}
	if err = c.validateDetails(); err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(filepath.Join(home, "configs"))
	if err != nil {
		return nil, err
	}
	for _, entry := range entries {
		other := entry.Name()
		if other == name || !match(`[a-z0-9][a-z0-9-]{0,31}`, other) {
			continue
		}
		p := realPath(filepath.Join(home, "configs", other))
		c.zones = append(c.zones, zone{other, p})
		r, e := rootDirectory(p)
		if e != nil {
			continue
		}
		d, e := loadTOML(r, "config.toml", "another configuration")
		r.Close()
		if e != nil {
			continue
		}
		s := str(obj(d["state"])["path"])
		if s == "" {
			s = filepath.Join(states, other)
		}
		c.zones = append(c.zones, zone{other, realPath(s)})
	}
	if inside(c.state, filepath.Join(home, "configs")) || inside(filepath.Join(home, "configs"), c.state) {
		return nil, invalid(label, "state.path", "overlaps the configuration home")
	}
	for _, z := range c.zones {
		if inside(c.state, z.path) || inside(z.path, c.state) {
			return nil, refuse("the state directory overlaps configuration %s's directory", z.name)
		}
	}
	return c, nil
}
func readRules(r *os.Root, path, label string) ([]byte, error) {
	if !validRelative(path) {
		return nil, invalid(label, "rules", "must be a relative path without ..")
	}
	b, e := rootRead(r, path, 1024*1024)
	if e != nil {
		return nil, e
	}
	if !utf8.Valid(b) {
		return nil, invalid(label, "rules", "must be UTF-8 text")
	}
	if rule, line := credential(string(b)); rule != "" {
		return nil, invalid(label, "rules", fmt.Sprintf("line %d looks like a credential (%s)", line, rule))
	}
	if strings.Contains(string(b), "<!-- laneboss launcher block: begin") {
		return nil, invalid(label, "rules", "must not contain a launcher block")
	}
	return b, nil
}
func validRelative(s string) bool {
	return s != "" && !filepath.IsAbs(s) && !contains(strings.Split(filepath.ToSlash(s), "/"), "..")
}
func (c *configuration) ruleInputs(project string) []ruleInput {
	r := []ruleInput{}
	org := str(c.data["organisation"])
	for _, n := range stringsOf(c.data["organisation_rules"]) {
		k := "orgs/" + org + "/" + n
		r = append(r, ruleInput{k, c.rules[k]})
	}
	names := stringsOf(c.data["rules"])
	for _, n := range stringsOf(obj(c.projects[project])["rules"]) {
		if !contains(names, n) {
			names = append(names, n)
		}
	}
	for _, n := range names {
		r = append(r, ruleInput{n, c.rules[n]})
	}
	return r
}

var placeholders = regexp.MustCompile(`\{([^{}]*)\}`)

func validateTemplate(v any, allowed string) error {
	a := stringsOf(v)
	if len(a) == 0 {
		return refuse("must be a nonempty argument vector")
	}
	if !textCheck("", 4096)(a[0]) || !(filepath.IsAbs(a[0]) || match(`[A-Za-z0-9_.+-]+`, a[0])) || strings.ContainsAny(a[0], "{}") {
		return refuse("program must be a command name or an absolute path")
	}
	for _, s := range a[1:] {
		if s == "" || len(s) > 4096 || strings.IndexFunc(s, func(r rune) bool { return r < 32 || r == 127 }) >= 0 {
			return refuse("arguments must be nonempty text without control characters")
		}
		if _, err := templateText(s, func(field string) (string, error) {
			if !contains(strings.Fields(allowed), field) {
				return "", refuse("unknown placeholder")
			}
			return "", nil
		}); err != nil {
			return err
		}
	}
	return nil
}
func uses(v any, key string) bool {
	for _, s := range stringsOf(v) {
		found := false
		templateText(s, func(field string) (string, error) {
			if field == key {
				found = true
			}
			return "", nil
		})
		if found {
			return true
		}
	}
	return false
}
func fill(v any, values object) ([]string, error) {
	a := stringsOf(v)
	for i, s := range a {
		if i == 0 {
			continue
		}
		filled, err := templateText(s, func(field string) (string, error) {
			if field == "machine" {
				return "", refuse("runner template uses {machine}; test machines are not built yet")
			}
			if values[field] == nil {
				return "", refuse("runner template uses {%s}, which this lane does not have", field)
			}
			return str(values[field]), nil
		})
		if err != nil {
			return nil, err
		}
		a[i] = filled
	}
	return a, nil
}

func templateText(text string, value func(string) (string, error)) (string, error) {
	var b strings.Builder
	for i := 0; i < len(text); {
		c := text[i]
		if c != '{' && c != '}' {
			b.WriteByte(c)
			i++
			continue
		}
		if i+1 < len(text) && text[i+1] == c {
			b.WriteByte(c)
			i += 2
			continue
		}
		if c == '}' {
			return "", refuse("unbalanced brace in template")
		}
		end := strings.IndexByte(text[i+1:], '}')
		if end < 0 {
			return "", refuse("unbalanced brace in template")
		}
		end += i + 1
		field := text[i+1 : end]
		if field == "" || strings.ContainsAny(field, "{:!") {
			return "", refuse("unknown placeholder or format specification")
		}
		filled, err := value(field)
		if err != nil {
			return "", err
		}
		b.WriteString(filled)
		i = end + 1
	}
	return b.String(), nil
}
func (c *configuration) checkPath(path, what string, write bool) error {
	abs, _ := filepath.Abs(path)
	real := realPath(path)
	for _, candidate := range append([]string{path, abs, real}, strings.Split(real, "/")...) {
		if rule, _ := credential(candidate); rule != "" {
			return refuse("%s: the path looks like a credential (%s)", what, rule)
		}
	}
	for _, z := range c.zones {
		if inside(real, z.path) {
			return refuse("%s lies inside configuration %s's directory; a command bound to %s uses only its own", what, z.name, c.name)
		}
	}
	for p := abs; ; p = filepath.Dir(p) {
		if (inside(p, c.directory) && !inside(real, c.directory)) || (inside(p, c.state) && !inside(real, c.state)) {
			return refuse("%s passes through a directory of configuration %s and leaves it through a link", what, c.name)
		}
		if p == filepath.Dir(p) {
			break
		}
	}
	for p := real; ; p = filepath.Dir(p) {
		info, err := os.Stat(p)
		if err == nil && info.IsDir() {
			r, e := rootDirectory(p)
			if e != nil {
				return e
			}
			b, e := rootRead(r, ".laneboss-state", 64*1024)
			r.Close()
			if e == nil {
				m, e := parseJSON(b)
				if e != nil || obj(m) == nil {
					return refuse("%s lies below an unreadable ownership marker", what)
				}
				if str(obj(m)["config"]) != c.name {
					return refuse("%s lies inside the state directory of another or an unknown configuration", what)
				}
			} else if !os.IsNotExist(e) {
				return refuse("%s lies below an unreadable ownership marker", what)
			}
		}
		if p == filepath.Dir(p) {
			break
		}
	}
	if inside(real, filepath.Join(c.home, "configs")) && !inside(real, c.directory) {
		return refuse("%s lies inside the configuration home but outside this configuration", what)
	}
	if inside(real, c.states) && !inside(real, c.state) && !inside(real, filepath.Join(c.states, c.name)) {
		return refuse("%s lies inside the state home but outside this configuration", what)
	}
	if write && (inside(real, c.state) || inside(real, c.directory)) {
		return refuse("%s lies inside the configuration's state or configuration directory", what)
	}
	return nil
}
func (c *configuration) external(path, what string, limit int64) ([]byte, error) {
	if err := c.checkPath(path, what, false); err != nil {
		return nil, err
	}
	p := realPath(path)
	r, err := rootDirectory(filepath.Dir(p))
	if err != nil {
		return nil, err
	}
	defer r.Close()
	b, err := rootRead(r, filepath.Base(p), limit)
	if err != nil {
		return nil, refuse("%s: cannot read the file as a regular file within its byte limit", what)
	}
	return b, nil
}
