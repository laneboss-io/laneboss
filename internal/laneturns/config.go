package laneturns

import (
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"unicode/utf8"

	"github.com/BurntSushi/toml"
)

var namePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)
var lanePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
var senderPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
var modelPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/@+\[\]-]{0,127}$`)
var uuidPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
var hashPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
var launchPattern = regexp.MustCompile(`^[0-9a-f]{32}$`)

const launcherVersion = "0.6.0-dev4"
const protocolVersion = "1.2.0"
const maxMessage = 262144
const maxBrief = 4 * 1024 * 1024

type ruleFile struct {
	path string
	data []byte
}
type configuration struct {
	name, home, states, dir, state string
	data                           object
	projects                       map[string]object
	rules                          map[string][]byte
	orgRules                       []ruleFile
	idle                           []byte
	idlePath                       string
	otherPaths                     []string
}

func absolute(path string) string {
	p, err := filepath.Abs(path)
	if err != nil {
		return filepath.Clean(path)
	}
	return p
}
func realPath(path string) string {
	p := absolute(path)
	r, err := filepath.EvalSymlinks(p)
	if err == nil {
		return r
	}
	parent := filepath.Dir(p)
	if parent == p {
		return p
	}
	return filepath.Join(realPath(parent), filepath.Base(p))
}
func within(path, root string) bool {
	rel, err := filepath.Rel(realPath(root), realPath(path))
	return err == nil && (rel == "." || rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)))
}
func sameDir(a, b string) bool {
	if realPath(a) == realPath(b) {
		return true
	}
	x, e := os.Stat(a)
	y, f := os.Stat(b)
	return e == nil && f == nil && os.SameFile(x, y)
}
func envHome(key, fallback string) (string, error) {
	v := os.Getenv(key)
	if v == "" {
		v = fallback
	}
	if !filepath.IsAbs(v) {
		return "", refused("%s must be an absolute path", key)
	}
	return filepath.Clean(v), nil
}
func readRegular(path, label string, limit int) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, refused("%s: the file does not exist", label)
		}
		return nil, refused("%s: cannot open a regular file without following a link", label)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, refused("%s: is not a regular file", label)
	}
	data, err := io.ReadAll(io.LimitReader(f, int64(limit)+1))
	if err != nil {
		return nil, refused("%s: cannot read the file", label)
	}
	if len(data) > limit {
		return nil, refused("%s: larger than %d bytes", label, limit)
	}
	return data, nil
}
func readInside(base, rel, label string, limit int) ([]byte, error) {
	if rel == "" || filepath.IsAbs(rel) || strings.Contains(rel, "\\") || filepath.Clean(rel) != rel || rel == ".." || strings.HasPrefix(rel, "../") {
		return nil, invalid("%s: must be a relative path without '..', '.' or empty parts", label)
	}
	path := realPath(filepath.Join(base, rel))
	if !within(path, base) {
		return nil, refused("%s leaves its configuration directory through a link", label)
	}
	return readRegular(path, label, limit)
}
func readTOML(base, rel, label string) (object, error) {
	data, err := readInside(base, rel, label, 1024*1024)
	if err != nil {
		return nil, err
	}
	if !utf8.Valid(data) {
		return nil, invalid("%s: must be UTF-8 text", label)
	}
	var value object
	if _, err = toml.Decode(string(data), &value); err != nil {
		return nil, invalid("%s: is not valid TOML", label)
	}
	if err = checkValueCredentials(value, "configuration", 0); err != nil {
		return nil, invalid("%s: %s", label, err.Error())
	}
	return value, nil
}
func loadConfig(name string) (*configuration, error) {
	bound := os.Getenv("LANEBOSS_CONFIG")
	if bound != "" && name != "" && bound != name {
		return nil, refused("--config differs from the configuration bound by LANEBOSS_CONFIG")
	}
	if name == "" {
		name = bound
	}
	if !namePattern.MatchString(name) {
		return nil, refused("--config: must name a configuration ([a-z0-9][a-z0-9-]{0,31})")
	}
	userHome, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	home, err := envHome("LANEBOSS_HOME", filepath.Join(userHome, ".config", "laneboss"))
	if err != nil {
		return nil, err
	}
	states, err := envHome("LANEBOSS_STATE_HOME", filepath.Join(userHome, ".local", "state", "laneboss"))
	if err != nil {
		return nil, err
	}
	c := &configuration{name: name, home: home, states: states, dir: filepath.Join(home, "configs", name), projects: map[string]object{}, rules: map[string][]byte{}}
	c.data, err = readTOML(c.dir, "config.toml", "configuration "+name+": config.toml")
	if err != nil {
		return nil, err
	}
	if err = validateConfig(c); err != nil {
		return nil, err
	}
	c.state = filepath.Join(states, name)
	if v := str(obj(c.data["state"])["path"]); v != "" {
		c.state = v
	}
	entries, err := os.ReadDir(filepath.Join(c.dir, "projects"))
	if err != nil && !os.IsNotExist(err) {
		return nil, refused("cannot list the configuration's projects")
	}
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".toml") {
			continue
		}
		key := strings.TrimSuffix(entry.Name(), ".toml")
		if !namePattern.MatchString(key) {
			return nil, invalid("projects: a name is invalid")
		}
		p, err := readTOML(c.dir, "projects/"+entry.Name(), "projects/"+entry.Name())
		if err != nil {
			return nil, err
		}
		if integer(p["schema_version"]) != 1 || str(p["name"]) != key {
			return nil, invalid("projects/%s.toml: schema_version or name is invalid", key)
		}
		if err = unknownKeys(p, "schema_version name description repository lane_prefix workers gates excluded_accounts test_environment reserved_paths owner_channel landing_authority rules", "projects/"+entry.Name()); err != nil {
			return nil, err
		}
		c.projects[key] = p
	}
	listed := texts(c.data["rules"])
	for _, p := range c.projects {
		for _, rel := range texts(p["rules"]) {
			if !contains(listed, rel) {
				listed = append(listed, rel)
			}
		}
	}
	for _, rel := range listed {
		if strings.HasPrefix(rel, "orgs/") {
			return nil, invalid("rules: must not start with orgs")
		}
		data, err := readInside(c.dir, rel, "rules", 1024*1024)
		if err != nil {
			return nil, err
		}
		if !utf8.Valid(data) {
			return nil, invalid("rules: must be UTF-8 text")
		}
		if err = credentialError("rules", data); err != nil {
			return nil, err
		}
		c.rules[rel] = data
	}
	org := str(c.data["organisation"])
	for _, rel := range texts(c.data["organisation_rules"]) {
		if !namePattern.MatchString(org) {
			return nil, invalid("organisation_rules: needs the key organisation")
		}
		data, err := readInside(filepath.Join(home, "orgs", org), rel, "organisation_rules", 1024*1024)
		if err != nil {
			return nil, err
		}
		if !utf8.Valid(data) {
			return nil, invalid("organisation_rules: must be UTF-8 text")
		}
		if err = credentialError("organisation_rules", data); err != nil {
			return nil, err
		}
		c.orgRules = append(c.orgRules, ruleFile{"orgs/" + org + "/" + rel, data})
	}
	if rel := str(obj(c.data["turns"])["idle_message"]); rel != "" {
		c.idle, err = readInside(c.dir, rel, "turns.idle_message", 65536)
		if err != nil {
			return nil, invalid("turns.idle_message: %s", err.Error())
		}
		if !utf8.Valid(c.idle) {
			return nil, invalid("turns.idle_message: must be UTF-8 text")
		}
		if err = credentialError("turns.idle_message", c.idle); err != nil {
			return nil, err
		}
		c.idlePath = realPath(filepath.Join(c.dir, rel))
	}
	other, err := os.ReadDir(filepath.Join(home, "configs"))
	if err != nil {
		return nil, refused("cannot list configuration directories")
	}
	for _, entry := range other {
		if entry.Name() == name || !namePattern.MatchString(entry.Name()) {
			continue
		}
		dir := filepath.Join(home, "configs", entry.Name())
		c.otherPaths = append(c.otherPaths, dir, filepath.Join(states, entry.Name()))
		data, err := readTOML(dir, "config.toml", "another configuration's state location")
		if err == nil {
			if path := str(obj(data["state"])["path"]); path != "" {
				c.otherPaths = append(c.otherPaths, path)
			}
		}
	}
	if within(c.state, filepath.Join(home, "configs")) || within(filepath.Join(home, "configs"), c.state) {
		return nil, refused("the state directory overlaps the configuration home")
	}
	for _, path := range c.otherPaths {
		if within(c.state, path) || within(path, c.state) {
			return nil, refused("the state directory overlaps another configuration's directory")
		}
	}
	if err = validateConfigSafety(c); err != nil {
		return nil, err
	}
	return c, nil
}
func unknownKeys(m object, allowed, label string) error {
	for key := range m {
		if !strings.Contains(" "+allowed+" ", " "+key+" ") {
			if rule, _ := findCredential(key); rule == "" && regexp.MustCompile(`^[A-Za-z0-9_.-]{1,64}$`).MatchString(key) {
				return invalid("%s.%s: unknown key", label, key)
			}
			return invalid("%s: an unknown key is present", label)
		}
	}
	return nil
}
func validateConfig(c *configuration) error {
	m := c.data
	label := "configuration " + c.name + ": config.toml"
	if err := unknownKeys(m, "schema_version name description organisation rules organisation_rules secrets owner_channel test_environment state lanes turns disk runners supervisors judges resources routing test_environments owner_channels cost guards", label); err != nil {
		return err
	}
	if integer(m["schema_version"]) != 1 {
		return invalid("%s: schema_version: must equal 1", label)
	}
	if str(m["name"]) != c.name {
		return invalid("%s: name: must equal its directory name", label)
	}
	if len(obj(m["runners"])) == 0 {
		return invalid("%s: runners: must define at least one entry", label)
	}
	for section, allowed := range map[string]string{"state": "path", "lanes": "budget_minutes quiet_seconds stop_grace_seconds lock_wait_seconds room_timeout_seconds", "turns": "idle_seconds idle_message poll_seconds backoff_seconds limit_backoff_seconds", "disk": "path warn_percent stop_percent"} {
		if v, ok := m[section]; ok {
			table := obj(v)
			if table == nil {
				return invalid("%s: %s: must be a table", label, section)
			}
			if err := unknownKeys(table, allowed, label+": "+section); err != nil {
				return err
			}
		}
	}
	for _, section := range []string{"state", "disk"} {
		if v, ok := obj(m[section])["path"]; ok {
			p, ok := v.(string)
			if !ok || !filepath.IsAbs(p) || filepath.Clean(p) != p {
				return invalid("%s: %s.path: must be an absolute path without '.' or '..' parts", label, section)
			}
		}
	}
	for _, section := range []string{"lanes", "turns"} {
		for key, v := range obj(m[section]) {
			if key == "idle_message" {
				if _, ok := v.(string); !ok {
					return invalid("%s: turns.idle_message: must be a string", label)
				}
				continue
			}
			n := number(v)
			lo, hi := 1.0, 604800.0
			if key == "budget_minutes" {
				hi = 10080
			}
			if key == "stop_grace_seconds" {
				hi = 600
			}
			if key == "lock_wait_seconds" {
				hi = 3600
			}
			if key == "poll_seconds" {
				hi = 3600
			}
			if key == "room_timeout_seconds" {
				hi = 60
			}
			_, intOK := v.(int64)
			if n < lo || n > hi || math.IsNaN(n) || math.IsInf(n, 0) || (key != "budget_minutes" && !intOK) {
				return invalid("%s: %s.%s: is outside its allowed numeric range", label, section, key)
			}
		}
	}
	for name, value := range obj(m["runners"]) {
		r := obj(value)
		if !namePattern.MatchString(name) || r == nil {
			return invalid("%s: runners: invalid named table", label)
		}
		if err := unknownKeys(r, "description command resume room accounts secrets quiet_seconds records prompt stream limit_patterns dropped_patterns", label+": runners."+name); err != nil {
			return err
		}
		for _, key := range []string{"command", "resume", "room"} {
			v, exists := r[key]
			if !exists {
				if key == "command" {
					return invalid("%s: runners.%s.command: is required", label, name)
				}
				continue
			}
			argv := texts(v)
			if len(argv) == 0 {
				return invalid("%s: runners.%s.%s: must not be empty", label, name, key)
			}
			if !(regexp.MustCompile(`^[A-Za-z0-9_.+-]+$`).MatchString(argv[0]) || filepath.IsAbs(argv[0])) || strings.ContainsAny(argv[0], "{}") {
				return invalid("%s: runners.%s.%s[0]: must be a command name or absolute path", label, name, key)
			}
			allowed := "account brief effort lane log machine model project worktree session"
			if key == "resume" {
				allowed += " message"
			}
			if key == "room" {
				allowed = "account"
			}
			for _, arg := range argv[1:] {
				if arg == "" || len(arg) > 4096 || shown(arg) != arg {
					return invalid("%s: runners.%s.%s: argument is invalid", label, name, key)
				}
				_, err := expandTemplate(arg, nil, allowed, true)
				if err != nil {
					return invalid("%s: runners.%s.%s: has an unknown placeholder or unbalanced brace", label, name, key)
				}
			}
		}
		if prompt, ok := r["prompt"]; ok && prompt != "stdin" && prompt != "argument" {
			return invalid("%s: runners.%s.prompt: must be stdin or argument", label, name)
		}
		if stream, ok := r["stream"]; ok && stream != "text" && stream != "claude-stream-json" {
			return invalid("%s: runners.%s.stream: is not a known reader", label, name)
		}
		if str(r["prompt"]) != "stdin" && !uses(r["command"], "brief") {
			return invalid("%s: runners.%s.command: must pass the rendered brief with {brief}, or take its prompt on standard input", label, name)
		}
		if r["resume"] != nil && uses(r["command"], "session") != uses(r["resume"], "session") {
			return invalid("%s: runners.%s: command and resume must both use {session}, or neither may use it", label, name)
		}
		for _, key := range []string{"limit_patterns", "dropped_patterns"} {
			for _, pattern := range texts(r[key]) {
				rx, err := regexp.Compile(pattern)
				if err != nil || rx.MatchString("") {
					return invalid("%s: runners.%s.%s: must be a valid pattern that does not match an empty line", label, name, key)
				}
			}
		}
		for _, account := range texts(r["accounts"]) {
			if !senderPattern.MatchString(account) {
				return invalid("%s: runners.%s.accounts: invalid account", label, name)
			}
		}
		if v, ok := r["quiet_seconds"]; ok {
			if n := number(v); n < 1 || n > 604800 || n != math.Trunc(n) {
				return invalid("%s: runners.%s.quiet_seconds: must be from 1 to 604800", label, name)
			}
		}
		if org := str(m["organisation"]); org != "" {
			for _, key := range []string{"command", "resume", "room"} {
				for _, arg := range texts(r[key]) {
					root := filepath.Join(c.home, "orgs")
					if filepath.IsAbs(arg) && within(arg, root) && !within(arg, filepath.Join(root, org)) {
						return invalid("%s: runners.%s.%s: points into another organisation", label, name, key)
					}
				}
			}
		}
	}
	return nil
}
func (c *configuration) setting(section, key string, fallback float64) float64 {
	if v, ok := obj(c.data[section])[key]; ok {
		return number(v)
	}
	return fallback
}
func (c *configuration) runner(name string) (object, error) {
	r := obj(obj(c.data["runners"])[name])
	if r == nil {
		return nil, refused("runner %s is not defined in configuration %s", safeName(name), c.name)
	}
	return r, nil
}
func safeName(name string) string {
	if namePattern.MatchString(name) {
		return name
	}
	return "<name>"
}
func (c *configuration) quiet(r object) int {
	if v, ok := r["quiet_seconds"]; ok {
		return integer(v)
	}
	return int(c.setting("lanes", "quiet_seconds", 900))
}
func (c *configuration) allRules(project string) []ruleFile {
	r := append([]ruleFile{}, c.orgRules...)
	listed := texts(c.data["rules"])
	for _, rel := range texts(c.projects[project]["rules"]) {
		if !contains(listed, rel) {
			listed = append(listed, rel)
		}
	}
	for _, rel := range listed {
		r = append(r, ruleFile{rel, c.rules[rel]})
	}
	return r
}
func (c *configuration) checkExternal(path, label string, write bool) error {
	if err := checkPathCredential(path, label); err != nil {
		return err
	}
	p := realPath(path)
	for _, other := range c.otherPaths {
		if within(p, other) || within(absolute(path), other) {
			return refused("%s lies inside another configuration's directory; a command bound to %s uses only its own", label, c.name)
		}
	}
	for _, own := range []string{c.dir, c.state} {
		if within(absolute(path), own) && !within(p, own) {
			return refused("%s passes through a directory of configuration %s and leaves it through a link", label, c.name)
		}
	}
	configs := filepath.Join(c.home, "configs")
	if within(p, configs) && !within(p, c.dir) {
		return refused("%s lies inside the configuration home but outside configuration %s's directory", label, c.name)
	}
	if within(p, c.states) && !within(p, c.state) && !within(p, filepath.Join(c.states, c.name)) {
		return refused("%s lies inside the state home but outside configuration %s's state directory", label, c.name)
	}
	if write && (within(p, c.state) || within(p, configs) || within(p, c.states)) {
		return refused("%s: a lane's working directory must be outside configuration and state directories", label)
	}
	current := p
	for {
		info, err := os.Stat(current)
		if err == nil && info.IsDir() {
			marker := filepath.Join(current, ".laneboss-state")
			if _, err := os.Lstat(marker); err == nil {
				data, err := readRegular(marker, "the ownership marker", 65536)
				if err != nil {
					return refused("%s lies below a directory whose ownership marker is unreadable", label)
				}
				v, err := decodeJSON(data)
				if current == realPath(c.state) && (err != nil || !validMarker(v)) {
					return integrity("the ownership marker is not a valid marker of configuration %s", c.name)
				}
				if err != nil || !validMarker(v) || str(v["config"]) != c.name {
					return refused("%s lies inside the state directory of another or an unknown configuration", label)
				}
			}
		}
		parent := filepath.Dir(current)
		if parent == current {
			break
		}
		current = parent
	}
	return nil
}
func (c *configuration) readExternal(path, label string, limit int) ([]byte, error) {
	if err := c.checkExternal(path, label, false); err != nil {
		return nil, err
	}
	return readRegular(realPath(path), label, limit)
}
func expandTemplate(template string, values object, allowed string, validate bool) (string, error) {
	var out strings.Builder
	for i := 0; i < len(template); i++ {
		ch := template[i]
		if ch == '{' || ch == '}' {
			if i+1 < len(template) && template[i+1] == ch {
				out.WriteByte(ch)
				i++
				continue
			}
			if ch == '}' {
				return "", refused("unbalanced brace")
			}
			end := strings.IndexByte(template[i+1:], '}')
			if end < 0 {
				return "", refused("unbalanced brace")
			}
			field := template[i+1 : i+1+end]
			if !strings.Contains(" "+allowed+" ", " "+field+" ") {
				return "", refused("unknown placeholder")
			}
			if !validate {
				if field == "machine" {
					return "", refused("the template uses {machine}; test machines are not built yet")
				}
				if values[field] == nil {
					return "", refused("the template uses {%s}, which this lane does not have", field)
				}
				out.WriteString(str(values[field]))
			}
			i += end + 1
		} else {
			out.WriteByte(ch)
		}
	}
	return out.String(), nil
}
func uses(template any, field string) bool {
	for _, element := range texts(template)[min(1, len(texts(template))):] {
		for i := 0; i < len(element); i++ {
			if element[i] == '{' {
				if i+1 < len(element) && element[i+1] == '{' {
					i++
					continue
				}
				if strings.HasPrefix(element[i:], "{"+field+"}") {
					return true
				}
			}
		}
	}
	return false
}
func fillTemplate(template any, values object) ([]string, error) {
	argv := texts(template)
	if len(argv) == 0 {
		return nil, refused("the runner has no template")
	}
	r := []string{argv[0]}
	for _, arg := range argv[1:] {
		s, err := expandTemplate(arg, values, "account brief effort lane log machine model project worktree session message", false)
		if err != nil {
			return nil, err
		}
		r = append(r, s)
	}
	return r, nil
}
func turnProblems(name string, r object) []string {
	p := []string{}
	if !uses(r["command"], "session") {
		p = append(p, fmt.Sprintf("its command (runners.%s.command) does not use {session}", name))
	}
	if r["resume"] == nil {
		p = append(p, fmt.Sprintf("it has no resume template (runners.%s.resume)", name))
	} else if !uses(r["resume"], "session") {
		p = append(p, fmt.Sprintf("its resume template (runners.%s.resume) does not use {session}", name))
	}
	if r["prompt"] != "stdin" {
		p = append(p, fmt.Sprintf("it does not take its prompt on standard input (runners.%s.prompt needs prompt = \"stdin\")", name))
	}
	return p
}
