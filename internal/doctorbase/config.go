package doctorbase

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"unicode/utf8"

	"github.com/BurntSushi/toml"
)

type Configuration struct {
	Order                                                    map[string][]string
	Name, Home, StateHome, ConfigDir, StateDir, Organisation string
	Data, Projects                                           map[string]any
}

func describeNames() string {
	user, err := os.UserHomeDir()
	if err != nil {
		return "no configuration can be listed"
	}
	h, err := home("LANEBOSS_HOME", filepath.Join(user, ".config", "laneboss"))
	if err != nil {
		return "the configuration home cannot be read"
	}
	entries, err := os.ReadDir(filepath.Join(h, "configs"))
	if err != nil {
		return "no configuration can be listed"
	}
	names := []string{}
	for _, entry := range entries {
		if !Name.MatchString(entry.Name()) {
			continue
		}
		info, err := os.Stat(filepath.Join(h, "configs", entry.Name(), "config.toml"))
		if err == nil && info.Mode().IsRegular() {
			names = append(names, ShownName(entry.Name()))
		}
	}
	if len(names) == 0 {
		return "no configuration exists"
	}
	return "configurations: " + strings.Join(names, ", ")
}

func home(variable, fallback string) (string, error) {
	if s := os.Getenv(variable); s != "" {
		if !filepath.IsAbs(s) {
			return "", Refuse("%s must be an absolute path", variable)
		}
		return filepath.Clean(s), nil
	}
	return fallback, nil
}
func normalize(v any) any {
	switch x := v.(type) {
	case map[string]any:
		for k, item := range x {
			x[k] = normalize(item)
		}
		return x
	case []map[string]any:
		a := make([]any, len(x))
		for i, item := range x {
			a[i] = normalize(item)
		}
		return a
	case []any:
		for i, item := range x {
			x[i] = normalize(item)
		}
		return x
	}
	return v
}
func decodeOtherTOML(data []byte) (map[string]any, error) {
	if !utf8.Valid(data) {
		return nil, fmt.Errorf("invalid text")
	}
	var m map[string]any
	if _, err := toml.Decode(string(data), &m); err != nil {
		return nil, fmt.Errorf("invalid TOML")
	}
	return Object(normalize(m)), nil
}

// insideRelative resolves a configuration's permitted internal links, then
// reconstructs a name relative to its anchored root by ancestor identity. This
// also permits absolute internal links and directory aliases on folding filesystems.
func insideRelative(root *os.Root, relative string) (string, error) {
	target, err := filepath.EvalSymlinks(filepath.Join(root.Name(), relative))
	if err != nil {
		return "", Refuse("%s cannot be read inside its own directory (%s)", relative, OSReason(err))
	}
	own, err := root.Stat(".")
	if err != nil {
		return "", err
	}
	current := target
	parts := []string{}
	for {
		info, err := os.Stat(current)
		if err != nil {
			return "", Refuse("%s cannot be read inside its own directory (%s)", relative, OSReason(err))
		}
		if info.IsDir() && os.SameFile(own, info) {
			if len(parts) == 0 {
				return ".", nil
			}
			return filepath.Join(parts...), nil
		}
		parent := filepath.Dir(current)
		if parent == current {
			return "", Refuse("%s leads outside its own directory", relative)
		}
		parts = append([]string{filepath.Base(current)}, parts...)
		current = parent
	}
}
func ReadInside(root *os.Root, relative string, limit int64) ([]byte, error) {
	inside, err := insideRelative(root, relative)
	if err != nil {
		return nil, err
	}
	f, err := root.OpenFile(inside, os.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, Refuse("%s cannot be read inside its own directory (%s)", relative, OSReason(err))
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, Refuse("%s is not a regular file", relative)
	}
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, Refuse("%s is larger than %d bytes", relative, limit)
	}
	return b, nil
}
func decodeTOML(data []byte, label string, ordering ...*map[string][]string) (map[string]any, error) {
	if len(data) > 1024*1024 {
		return nil, Invalid(label, "", "is larger than 1 MiB")
	}
	if !utf8.Valid(data) {
		return nil, Invalid(label, "", "must be UTF-8 text")
	}
	var m map[string]any
	metadata, err := toml.Decode(string(data), &m)
	if err != nil {
		var parse toml.ParseError
		if errors.As(err, &parse) {
			return nil, Invalid(label, "", fmt.Sprintf("TOML syntax error at line %d", parse.Position.Line))
		}
		return nil, Invalid(label, "", "TOML syntax error at the end of the file")
	}
	m = Object(normalize(m))
	if CredentialValue(m) {
		return nil, Invalid(label, "a top-level field", "looks like a credential; configuration files hold secret names, never values")
	}
	if len(ordering) > 0 {
		order := map[string][]string{}
		seen := map[string]bool{}
		for _, key := range metadata.Keys() {
			if len(key) < 2 || (key[0] != "runners" && key[0] != "judges" && key[0] != "resources") {
				continue
			}
			label := key[0] + "." + key[1]
			if !seen[label] {
				order[key[0]] = append(order[key[0]], key[1])
				seen[label] = true
			}
		}
		*ordering[0] = order
	}
	return m, nil
}
func schemaError(label string, err error) error {
	parts := strings.SplitN(err.Error(), ": ", 2)
	if len(parts) == 2 {
		return Invalid(label, parts[0], parts[1])
	}
	return Invalid(label, "", "does not satisfy the schema")
}
func readRules(root *os.Root, relative, label, field string, limit int64) error {
	b, err := ReadInside(root, relative, limit)
	if err != nil {
		return Invalid(label, field, err.Error())
	}
	if !utf8.Valid(b) {
		return Invalid(label, field, relative+" must be UTF-8 text")
	}
	if CredentialText(string(b)) {
		return Invalid(label, field, relative+" looks like a credential")
	}
	return nil
}
func Load(name string) (*Configuration, error) {
	if !Name.MatchString(name) {
		return nil, Refuse("the configuration name must match [a-z0-9][a-z0-9-]{0,31}")
	}
	user, err := os.UserHomeDir()
	if err != nil {
		return nil, Refuse("cannot locate the user's home directory")
	}
	h, err := home("LANEBOSS_HOME", filepath.Join(user, ".config", "laneboss"))
	if err != nil {
		return nil, err
	}
	states, err := home("LANEBOSS_STATE_HOME", filepath.Join(user, ".local", "state", "laneboss"))
	if err != nil {
		return nil, err
	}
	dir := filepath.Join(h, "configs", name)
	label := "configuration " + ShownName(name) + ": config.toml"
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, Refuse("configuration %s: cannot open its directory (%s)", ShownName(name), OSReason(err))
	}
	defer root.Close()
	b, err := ReadInside(root, "config.toml", 1024*1024)
	if err != nil {
		return nil, err
	}
	order := map[string][]string{}
	data, err := decodeTOML(b, label, &order)
	if err != nil {
		return nil, err
	}
	if err := configSchema()(data, ""); err != nil {
		return nil, schemaError(label, err)
	}
	if data["name"] != name {
		return nil, Invalid(label, "name", "must equal the configuration directory name")
	}
	for _, item := range Object(data["supervisors"]) {
		m := Object(item)
		if role, ok := m["role"]; ok {
			m["level"] = int64(4)
			if role == "top" {
				m["level"] = int64(5)
			}
			delete(m, "role")
		}
	}
	state := String(Object(data["state"])["path"])
	if state == "" {
		state = filepath.Join(states, name)
	}
	c := &Configuration{Name: name, Home: h, StateHome: states, ConfigDir: dir, StateDir: filepath.Clean(state), Organisation: String(data["organisation"]), Data: data, Projects: map[string]any{}, Order: order}
	for _, cmd := range c.Commands() {
		for i, x := range cmd.Args {
			if org := c.pathOrganisation(String(x)); org != "" && c.Organisation != "" && org != c.Organisation {
				return nil, Invalid(label, fmt.Sprintf("%s[%d]", cmd.Key, i), "points into the directory of another organisation; tools are not shared between organisations")
			}
		}
	}
	if _, err := root.Lstat("projects"); err == nil {
		inside, err := insideRelative(root, "projects")
		if err != nil {
			return nil, err
		}
		projects, err := root.OpenFile(inside, os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
		if err != nil {
			return nil, Refuse("configuration %s: projects cannot be read inside its own directory", name)
		}
		entries, readErr := projects.ReadDir(-1)
		closeErr := projects.Close()
		if readErr != nil {
			return nil, readErr
		}
		if closeErr != nil {
			return nil, closeErr
		}
		for _, entry := range entries {
			file := entry.Name()
			if !strings.HasSuffix(file, ".toml") {
				continue
			}
			stem := strings.TrimSuffix(file, ".toml")
			if !Name.MatchString(stem) {
				return nil, Invalid(label, "projects", "a project file name is not valid")
			}
			plabel := "configuration " + name + ": projects/" + file
			bytes, err := ReadInside(root, "projects/"+file, 1024*1024)
			if err != nil {
				return nil, err
			}
			p, err := decodeTOML(bytes, plabel)
			if err != nil {
				return nil, err
			}
			if err := projectSchema()(p, ""); err != nil {
				return nil, schemaError(plabel, err)
			}
			if p["name"] != stem {
				return nil, Invalid(plabel, "name", "must equal the project file name")
			}
			c.Projects[stem] = p
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	if err := c.crossCheck(root, label); err != nil {
		return nil, err
	}
	if listed, ok := data["organisation_rules"]; ok {
		if c.Organisation == "" {
			return nil, Invalid(label, "organisation_rules", "needs the key organisation")
		}
		if len(Array(listed)) > 0 {
			org, err := os.OpenRoot(filepath.Join(h, "orgs", c.Organisation))
			if err != nil {
				return nil, Invalid(label, "organisation_rules", "the organisation directory cannot be opened")
			}
			defer org.Close()
			for i, x := range Array(listed) {
				if err := readRules(org, String(x), label, fmt.Sprintf("organisation_rules[%d]", i), 1024*1024); err != nil {
					return nil, err
				}
			}
		}
	}
	if idle := String(Object(data["turns"])["idle_message"]); idle != "" {
		if err := readRules(root, idle, label, "turns.idle_message", 64*1024); err != nil {
			return nil, err
		}
	}
	if Overlap(Locate(c.StateDir), Locate(h)) {
		return nil, Invalid(label, "state.path", "the state directory must not overlap the configuration home "+h)
	}
	if Object(data["state"])["path"] != nil {
		s, sr := Locate(c.StateDir), Locate(states)
		if Inside(sr, s) {
			return nil, Invalid(label, "state.path", "must not contain the state home, which holds every default state directory")
		}
		if Inside(s, sr) && !Inside(s, Locate(filepath.Join(states, name))) {
			return nil, Invalid(label, "state.path", "must not lie inside another configuration's default state directory")
		}
	}
	for _, other := range c.OtherConfigs() {
		if Overlap(Locate(dir), Locate(filepath.Join(h, "configs", other))) {
			return nil, Invalid(label, "", "its directory overlaps configuration "+other+"'s directory")
		}
	}
	return c, nil
}

type Command struct {
	Key  string
	Args []any
}

func (c *Configuration) Commands() []Command {
	result := []Command{}
	for _, group := range []string{"runners", "judges", "resources"} {
		names := c.Order[group]
		if names == nil {
			names = Keys(Object(c.Data[group]))
		}
		for _, name := range names {
			entry := Object(Object(c.Data[group])[name])
			keys := []string{"command"}
			if group == "runners" {
				keys = append(keys, "resume", "room")
			}
			for _, key := range keys {
				if a := Array(entry[key]); len(a) > 0 {
					result = append(result, Command{group + "." + name + "." + key, a})
				}
			}
		}
	}
	return result
}
func (c *Configuration) pathOrganisation(s string) string {
	if !filepath.IsAbs(s) {
		return ""
	}
	root := filepath.Join(c.Home, "orgs") + string(filepath.Separator)
	s = filepath.Clean(s)
	if !strings.HasPrefix(s, root) {
		return ""
	}
	return strings.Split(strings.TrimPrefix(s, root), string(filepath.Separator))[0]
}
func (c *Configuration) CommandIntoOrganisation() string {
	for _, cmd := range c.Commands() {
		for i, x := range cmd.Args {
			if c.pathOrganisation(String(x)) != "" {
				return fmt.Sprintf("%s[%d]", cmd.Key, i)
			}
		}
	}
	return ""
}
func (c *Configuration) OtherConfigs() []string {
	entries, err := os.ReadDir(filepath.Join(c.Home, "configs"))
	if err != nil {
		return nil
	}
	names := []string{}
	for _, entry := range entries {
		if entry.Name() == c.Name || !Name.MatchString(entry.Name()) {
			continue
		}
		if entry.IsDir() || entry.Type()&os.ModeSymlink != 0 {
			names = append(names, entry.Name())
		}
	}
	return names
}
func (c *Configuration) crossCheck(root *os.Root, label string) error {
	d := c.Data
	runners := Object(d["runners"])
	channels := Object(d["owner_channels"])
	environments := Object(d["test_environments"])
	supervisors := Object(d["supervisors"])
	listed := map[string]bool{}
	for _, s := range Array(d["secrets"]) {
		listed[String(s)] = true
	}
	accounts := map[string]bool{}
	known := func(v any, m map[string]any, path, kind string) error {
		if _, ok := m[String(v)]; !ok {
			return Invalid(label, path, "names a "+kind+" that is not defined")
		}
		return nil
	}
	for _, group := range []string{"runners", "test_environments", "owner_channels"} {
		for _, name := range Keys(Object(d[group])) {
			entry := Object(Object(d[group])[name])
			values := Array(entry["secrets"])
			if s, ok := entry["token_secret"]; ok {
				values = append(values, s)
			}
			for _, s := range values {
				if !listed[String(s)] {
					return Invalid(label, group+"."+name+".secrets", "names a secret that is not listed in the top-level secrets")
				}
			}
			if group == "runners" {
				for _, a := range Array(entry["accounts"]) {
					accounts[String(a)] = true
				}
			}
		}
	}
	for name, x := range supervisors {
		m := Object(x)
		if err := known(m["runner"], runners, "supervisors."+name+".runner", "runner"); err != nil {
			return err
		}
		for _, p := range Array(m["projects"]) {
			if err := known(p, c.Projects, "supervisors."+name+".projects", "project file"); err != nil {
				return err
			}
		}
		if v, ok := m["owner_channel"]; ok {
			if err := known(v, channels, "supervisors."+name+".owner_channel", "owner channel"); err != nil {
				return err
			}
		}
	}
	for difficulty, rs := range Object(d["routing"]) {
		for i, x := range Array(rs) {
			if err := known(Object(x)["runner"], runners, fmt.Sprintf("routing.%s[%d].runner", difficulty, i), "runner"); err != nil {
				return err
			}
		}
	}
	for _, ref := range []struct {
		key, kind string
		items     map[string]any
	}{{"owner_channel", "owner channel", channels}, {"test_environment", "test environment", environments}} {
		if v, ok := d[ref.key]; ok {
			if err := known(v, ref.items, ref.key, ref.kind); err != nil {
				return err
			}
		}
	}
	for i, x := range Array(d["rules"]) {
		if err := readRules(root, String(x), label, fmt.Sprintf("rules[%d]", i), 1024*1024); err != nil {
			return err
		}
	}
	for name, x := range c.Projects {
		m := Object(x)
		plabel := "configuration " + c.Name + ": projects/" + name + ".toml"
		for _, worker := range Array(m["workers"]) {
			if _, ok := runners[String(worker)]; !ok {
				return Invalid(plabel, "workers", "names a runner that is not defined")
			}
		}
		for _, a := range Array(m["excluded_accounts"]) {
			if !accounts[String(a)] {
				return Invalid(plabel, "excluded_accounts", "names an account no runner lists")
			}
		}
		for _, ref := range []struct {
			key, kind string
			items     map[string]any
		}{{"owner_channel", "owner channel", channels}, {"test_environment", "test environment", environments}} {
			if v, ok := m[ref.key]; ok {
				if _, found := ref.items[String(v)]; !found {
					return Invalid(plabel, ref.key, "names a "+ref.kind+" that is not defined")
				}
			}
		}
		if v, ok := m["landing_authority"]; ok {
			authority := Object(supervisors[String(v)])
			if authority["level"] != int64(5) && authority["level"] != int64(6) {
				return Invalid(plabel, "landing_authority", "must name a supervisor of level 5 or 6")
			}
		}
		for i, r := range Array(m["rules"]) {
			if err := readRules(root, String(r), plabel, fmt.Sprintf("rules[%d]", i), 1024*1024); err != nil {
				return err
			}
		}
	}
	return nil
}
