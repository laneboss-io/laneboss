package start

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"syscall"
	"unicode/utf8"

	"github.com/BurntSushi/toml"
)

type configuration struct {
	name, home, states, directory, state string
	data                                 map[string]any
	projects                             map[string]any
	rules, organisationRules             map[string][]byte
	others                               []otherLocation
	unreadable                           []unreadableConfig
}
type otherLocation struct{ name, kind, path string }
type unreadableConfig struct{ name, why string }

func checkName(name, what string) error {
	if !nameRE.MatchString(name) {
		return refused("the " + what + " must match " + nameRule)
	}
	return nil
}
func homePath(variable, relative string) (string, error) {
	value := os.Getenv(variable)
	if value != "" {
		if !filepath.IsAbs(value) {
			return "", refused(variable + " must be an absolute path")
		}
		return filepath.Clean(value), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", refused("cannot determine the user's home directory")
	}
	return filepath.Join(home, relative), nil
}
func configDirs(home string) ([]string, error) {
	entries, err := os.ReadDir(filepath.Join(home, "configs"))
	if os.IsNotExist(err) {
		return []string{}, nil
	}
	if err != nil {
		return nil, refused("cannot list " + scrub(filepath.Join(home, "configs")))
	}
	names := []string{}
	for _, e := range entries {
		if nameRE.MatchString(e.Name()) && (e.IsDir() || e.Type()&os.ModeSymlink != 0) {
			names = append(names, e.Name())
		}
	}
	return names, nil
}
func describeNames(home string) string {
	names, err := configDirs(home)
	if err != nil {
		return "configurations cannot be listed"
	}
	listed := []string{}
	for _, name := range names {
		info, err := os.Stat(filepath.Join(home, "configs", name, "config.toml"))
		if err == nil && info.Mode().IsRegular() {
			listed = append(listed, shown(name))
		}
	}
	if len(listed) > 0 {
		return "configurations: " + strings.Join(listed, ", ")
	}
	return "no configuration exists under " + scrub(filepath.Join(home, "configs"))
}

// Resolve an existing prefix, retaining absent suffixes. Identity comparisons
// below also cover directory aliases and case-insensitive filesystems.
func resolved(path string) string {
	path = filepath.Clean(path)
	suffix := []string{}
	for {
		real, err := filepath.EvalSymlinks(path)
		if err == nil {
			for i := len(suffix) - 1; i >= 0; i-- {
				real = filepath.Join(real, suffix[i])
			}
			return real
		}
		parent := filepath.Dir(path)
		if parent == path {
			return path
		}
		suffix = append(suffix, filepath.Base(path))
		path = parent
	}
}

type location struct {
	chain     []os.FileInfo
	remainder []string
}

func locate(path string) location {
	p := resolved(path)
	out := location{}
	for {
		info, err := os.Stat(p)
		if err == nil {
			out.chain = append(out.chain, info)
			break
		}
		parent := filepath.Dir(p)
		if parent == p {
			break
		}
		out.remainder = append([]string{strings.ToLower(filepath.Base(p))}, out.remainder...)
		p = parent
	}
	for {
		parent := filepath.Dir(p)
		if parent == p {
			break
		}
		p = parent
		if info, err := os.Stat(p); err == nil {
			out.chain = append(out.chain, info)
		}
	}
	return out
}
func insideLocation(child, parent location) bool {
	if len(child.chain) == 0 || len(parent.chain) == 0 {
		return false
	}
	if len(parent.remainder) == 0 {
		for _, info := range child.chain {
			if os.SameFile(info, parent.chain[0]) {
				return true
			}
		}
		return false
	}
	if !os.SameFile(child.chain[0], parent.chain[0]) || len(child.remainder) < len(parent.remainder) {
		return false
	}
	for i, s := range parent.remainder {
		if child.remainder[i] != s {
			return false
		}
	}
	return true
}
func overlap(a, b string) bool {
	first, second := locate(a), locate(b)
	return insideLocation(first, second) || insideLocation(second, first)
}
func within(path, parent string) bool { return insideLocation(locate(path), locate(parent)) }

type configReader struct {
	root     *os.Root
	real     string
	identity os.FileInfo
}

func openConfigReader(directory, label string) (*configReader, error) {
	real, err := filepath.EvalSymlinks(directory)
	if err != nil {
		return nil, invalid(label, "", "cannot open its directory")
	}
	root, err := os.OpenRoot(real)
	if err != nil {
		return nil, invalid(label, "", "cannot open its directory")
	}
	identity, err := root.Stat(".")
	if err != nil {
		root.Close()
		return nil, invalid(label, "", "cannot inspect its directory")
	}
	return &configReader{root: root, real: real, identity: identity}, nil
}

func (r *configReader) relative(relative, label string) (string, error) {
	current, err := os.Stat(r.real)
	if err != nil || !os.SameFile(current, r.identity) {
		return "", invalid(label, relative, "its directory changed while it was being read")
	}
	target, err := filepath.EvalSymlinks(filepath.Join(r.real, relative))
	if err != nil {
		return "", invalid(label, relative, "cannot read the file inside its own directory")
	}
	rel, err := filepath.Rel(r.real, target)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return "", invalid(label, relative, "leads outside the configuration directory")
	}
	return rel, nil
}

func (r *configReader) read(relative, label string, limit int64) ([]byte, error) {
	rel, err := r.relative(relative, label)
	if err != nil {
		return nil, err
	}
	f, err := r.root.OpenFile(rel, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, invalid(label, relative, "cannot read the file inside its own directory")
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return nil, invalid(label, relative, "is not a regular file")
	}
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, invalid(label, relative, "cannot read the file")
	}
	if int64(len(data)) > limit {
		return nil, invalid(label, relative, "is larger than the permitted limit")
	}
	return data, nil
}

func (r *configReader) entries(relative, label string) ([]os.DirEntry, error) {
	rel, err := r.relative(relative, label)
	if err != nil {
		return nil, err
	}
	f, err := r.root.Open(rel)
	if err != nil {
		return nil, invalid(label, relative, "cannot list its directory")
	}
	defer f.Close()
	entries, err := f.ReadDir(-1)
	if err != nil {
		return nil, invalid(label, relative, "cannot list its directory")
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	return entries, nil
}

// The loader shares one pinned reader across the configuration, all projects and
// all its rules. Links may resolve inside that root, and may never escape it.
func readInside(directory, relative, label string, limit int64, readers ...*configReader) ([]byte, error) {
	if len(readers) > 0 {
		return readers[0].read(relative, label, limit)
	}
	reader, err := openConfigReader(directory, label)
	if err != nil {
		return nil, err
	}
	defer reader.root.Close()
	return reader.read(relative, label, limit)
}
func normalizeToml(v any) any {
	rv := reflect.ValueOf(v)
	if !rv.IsValid() {
		return nil
	}
	switch rv.Kind() {
	case reflect.Map:
		m := map[string]any{}
		iter := rv.MapRange()
		for iter.Next() {
			m[iter.Key().String()] = normalizeToml(iter.Value().Interface())
		}
		return m
	case reflect.Array, reflect.Slice:
		a := []any{}
		for i := 0; i < rv.Len(); i++ {
			a = append(a, normalizeToml(rv.Index(i).Interface()))
		}
		return a
	}
	return v
}
func parseToml(data []byte, label string, validate bool) (map[string]any, error) {
	if len(data) > 1024*1024 {
		return nil, invalid(label, "", "is larger than 1 MiB")
	}
	if !utf8.Valid(data) {
		return nil, invalid(label, "", "must be UTF-8 text")
	}
	var document map[string]any
	if _, err := toml.Decode(string(data), &document); err != nil {
		return nil, invalid(label, "", "TOML syntax error")
	}
	document = object(normalizeToml(document))
	if validate {
		if where, rule := credentialInValue(document); rule != "" {
			return nil, invalid(label, where, "looks like a credential ("+rule+"); configuration files hold secret names, never values")
		}
		if err := versionCheck(label, document["schema_version"], "schema_version"); err != nil {
			return nil, err
		}
	}
	return document, nil
}
func readRules(directory, relative, label, path string, limit int64, readers ...*configReader) ([]byte, error) {
	data, err := readInside(directory, relative, label, limit, readers...)
	if err != nil {
		return nil, invalid(label, path, err.Error())
	}
	if !utf8.Valid(data) {
		return nil, invalid(label, path, relative+" must be UTF-8 text")
	}
	if found := findCredential(string(data)); found != nil {
		return nil, invalid(label, path, fmt.Sprintf("%s line %d: looks like a credential (%s)", relative, found.line, found.rule))
	}
	return data, nil
}
func bind(selected *string) (*configuration, error) {
	env := os.Getenv("LANEBOSS_CONFIG")
	name := env
	if selected != nil {
		name = *selected
	}
	if err := checkName(name, "configuration name"); err != nil {
		return nil, err
	}
	if selected != nil && env != "" {
		if err := checkName(env, "configuration name in LANEBOSS_CONFIG"); err != nil {
			return nil, err
		}
		if *selected != env {
			return nil, refused("--config " + shown(*selected) + " conflicts with LANEBOSS_CONFIG=" + shown(env) + "; a session is bound to exactly one configuration")
		}
	}
	home, err := homePath("LANEBOSS_HOME", ".config/laneboss")
	if err != nil {
		return nil, err
	}
	states, err := homePath("LANEBOSS_STATE_HOME", ".local/state/laneboss")
	if err != nil {
		return nil, err
	}
	directory := filepath.Join(home, "configs", name)
	if _, err := os.Lstat(filepath.Join(directory, "config.toml")); os.IsNotExist(err) {
		return nil, refused("no configuration named " + shown(name) + " (" + scrub(filepath.Join(home, "configs", shown(name), "config.toml")) + " does not exist); " + describeNames(home))
	}
	label := "configuration " + shown(name) + ": config.toml"
	reader, err := openConfigReader(directory, label)
	if err != nil {
		return nil, err
	}
	defer reader.root.Close()
	data, err := readInside(directory, "config.toml", label, 1024*1024, reader)
	if err != nil {
		return nil, err
	}
	doc, err := parseToml(data, label, true)
	if err != nil {
		return nil, err
	}
	if err = configCheck(label, doc, ""); err != nil {
		return nil, err
	}
	if doc["name"] != name {
		return nil, invalid(label, "name", "must equal the directory name \""+shown(name)+"\"")
	}
	for _, v := range object(doc["supervisors"]) {
		entry := object(v)
		if role, ok := entry["role"]; ok {
			level := int64(4)
			if role == "top" {
				level = 5
			}
			entry["level"] = level
			delete(entry, "role")
		}
	}
	c := &configuration{name: name, home: home, states: states, directory: directory, state: filepath.Join(states, name), data: doc, projects: map[string]any{}, rules: map[string][]byte{}, organisationRules: map[string][]byte{}}
	if path, ok := object(doc["state"])["path"].(string); ok {
		c.state = filepath.Clean(path)
	}
	if overlap(c.state, home) {
		return nil, invalid(label, "state.path", "the state directory must not overlap the configuration home "+scrub(home))
	}
	if object(doc["state"])["path"] != nil {
		if within(states, c.state) {
			return nil, invalid(label, "state.path", "must not contain the state home, which holds every default state directory")
		}
		if within(c.state, states) && !within(c.state, filepath.Join(states, name)) {
			return nil, invalid(label, "state.path", "must not lie inside another configuration's default state directory")
		}
	}
	projectDir := filepath.Join(directory, "projects")
	if _, err := os.Lstat(projectDir); err == nil {
		entries, err := reader.entries("projects", label)
		if err != nil {
			return nil, invalid(label, "projects", "cannot list the directory")
		}
		for _, e := range entries {
			if !strings.HasSuffix(e.Name(), ".toml") {
				continue
			}
			stem := strings.TrimSuffix(e.Name(), ".toml")
			if !nameRE.MatchString(stem) {
				return nil, invalid(label, "projects", "a project file name does not match "+nameRule+".toml")
			}
			relative := "projects/" + e.Name()
			plabel := "configuration " + shown(name) + ": " + relative
			bytes, err := readInside(directory, relative, plabel, 1024*1024, reader)
			if err != nil {
				return nil, err
			}
			project, err := parseToml(bytes, plabel, true)
			if err != nil {
				return nil, err
			}
			if err = projectCheck(plabel, project, ""); err != nil {
				return nil, err
			}
			if project["name"] != stem {
				return nil, invalid(plabel, "name", "must equal the file name \""+stem+"\"")
			}
			c.projects[stem] = project
		}
	}
	if err := c.crossCheck(label); err != nil {
		return nil, err
	}
	for i, relative := range stringsOf(doc["rules"]) {
		bytes, err := readRules(directory, relative, label, fmt.Sprintf("rules[%d]", i), 1024*1024, reader)
		if err != nil {
			return nil, err
		}
		c.rules[relative] = bytes
	}
	for _, project := range sortedKeys(c.projects) {
		plabel := "configuration " + shown(name) + ": projects/" + project + ".toml"
		for i, relative := range stringsOf(object(c.projects[project])["rules"]) {
			if _, ok := c.rules[relative]; ok {
				continue
			}
			bytes, err := readRules(directory, relative, plabel, fmt.Sprintf("rules[%d]", i), 1024*1024, reader)
			if err != nil {
				return nil, err
			}
			c.rules[relative] = bytes
		}
	}
	if _, ok := doc["organisation_rules"]; ok {
		organisation := str(doc["organisation"])
		if organisation == "" {
			return nil, invalid(label, "organisation_rules", "needs the key organisation")
		}
		var orgReader *configReader
		for i, relative := range stringsOf(doc["organisation_rules"]) {
			if orgReader == nil {
				orgReader, err = openConfigReader(filepath.Join(home, "orgs", organisation), label)
				if err != nil {
					return nil, err
				}
				defer orgReader.root.Close()
			}
			bytes, err := readRules(filepath.Join(home, "orgs", organisation), relative, label, fmt.Sprintf("organisation_rules[%d]", i), 1024*1024, orgReader)
			if err != nil {
				return nil, err
			}
			c.organisationRules[relative] = bytes
		}
	}
	if relative := str(object(doc["turns"])["idle_message"]); relative != "" {
		if _, err := readRules(directory, relative, label, "turns.idle_message", 64*1024, reader); err != nil {
			return nil, err
		}
	}
	names, err := configDirs(home)
	if err != nil {
		return nil, err
	}
	for _, other := range names {
		if other == name {
			continue
		}
		otherDir := filepath.Join(home, "configs", other)
		if overlap(directory, otherDir) {
			return nil, invalid("configuration "+shown(name), "", "its directory overlaps configuration "+shown(other)+"'s directory")
		}
		c.others = append(c.others, otherLocation{other, "configuration directory", otherDir})
		path, why := declaredState(other, otherDir, states)
		if why != "" {
			c.unreadable = append(c.unreadable, unreadableConfig{other, why})
		} else {
			c.others = append(c.others, otherLocation{other, "state directory", path})
		}
	}
	if problems := c.zoneProblems(); len(problems) > 0 {
		return nil, refused(problems[0])
	}
	return c, nil
}
func declaredState(name, directory, states string) (string, string) {
	data, err := readInside(directory, "config.toml", "configuration "+shown(name), 1024*1024)
	if err != nil {
		return "", "its config.toml cannot be read inside its own directory"
	}
	doc, err := parseToml(data, "configuration "+shown(name), false)
	if err != nil {
		return "", "its config.toml cannot be read as TOML"
	}
	if doc["name"] != name {
		return "", "its name does not match its directory"
	}
	state, ok := doc["state"]
	if !ok {
		return filepath.Join(states, name), ""
	}
	m, ok := state.(map[string]any)
	if !ok {
		return "", "its state.path is not an absolute path"
	}
	path, ok := m["path"]
	if !ok {
		return filepath.Join(states, name), ""
	}
	if err := absoluteCheck("", path, ""); err != nil {
		return "", "its state.path is not an absolute path"
	}
	return filepath.Clean(str(path)), ""
}
func (c *configuration) zoneProblems() []string {
	out := []string{}
	for _, other := range c.others {
		if overlap(c.state, other.path) {
			out = append(out, "the state directory "+scrub(c.state)+" is the same as, inside or around configuration "+shown(other.name)+"'s "+other.kind)
		}
	}
	if overlap(c.state, filepath.Join(c.home, "configs")) {
		out = append(out, "the state directory "+scrub(c.state)+" overlaps the configuration home")
	}
	return out
}
func (c *configuration) crossCheck(label string) error {
	runners, supervisors, channels, environments := object(c.data["runners"]), object(c.data["supervisors"]), object(c.data["owner_channels"]), object(c.data["test_environments"])
	secrets := stringsOf(c.data["secrets"])
	accounts := []string{}
	known := func(value any, defined map[string]any, p, what string) error {
		if _, ok := defined[str(value)]; !ok {
			return invalid(label, p, "names a "+what+" that is not defined")
		}
		return nil
	}
	for _, name := range sortedKeys(runners) {
		runner := object(runners[name])
		accounts = append(accounts, stringsOf(runner["accounts"])...)
		for i, s := range stringsOf(runner["secrets"]) {
			if !contains(secrets, s) {
				return invalid(label, fmt.Sprintf("runners.%s.secrets[%d]", name, i), "names a secret that is not listed in the top-level secrets")
			}
		}
	}
	for _, name := range sortedKeys(environments) {
		for i, s := range stringsOf(object(environments[name])["secrets"]) {
			if !contains(secrets, s) {
				return invalid(label, fmt.Sprintf("test_environments.%s.secrets[%d]", name, i), "names a secret that is not listed in the top-level secrets")
			}
		}
	}
	for _, name := range sortedKeys(channels) {
		if s := str(object(channels[name])["token_secret"]); s != "" && !contains(secrets, s) {
			return invalid(label, "owner_channels."+name+".token_secret", "names a secret that is not listed in the top-level secrets")
		}
	}
	for _, name := range sortedKeys(supervisors) {
		entry := object(supervisors[name])
		base := "supervisors." + name
		if err := known(entry["runner"], runners, base+".runner", "runner"); err != nil {
			return err
		}
		for i, project := range array(entry["projects"]) {
			if err := known(project, c.projects, fmt.Sprintf("%s.projects[%d]", base, i), "project file"); err != nil {
				return err
			}
		}
		if value, ok := entry["owner_channel"]; ok {
			if err := known(value, channels, base+".owner_channel", "owner channel"); err != nil {
				return err
			}
		}
	}
	for _, difficulty := range sortedKeys(object(c.data["routing"])) {
		for i, v := range array(object(c.data["routing"])[difficulty]) {
			if err := known(object(v)["runner"], runners, fmt.Sprintf("routing.%s[%d].runner", difficulty, i), "runner"); err != nil {
				return err
			}
		}
	}
	for key, defined := range map[string]map[string]any{"owner_channel": channels, "test_environment": environments} {
		if value, ok := c.data[key]; ok {
			if err := known(value, defined, key, strings.ReplaceAll(key, "_", " ")); err != nil {
				return err
			}
		}
	}
	for _, name := range sortedKeys(c.projects) {
		project := object(c.projects[name])
		plabel := "configuration " + shown(c.name) + ": projects/" + name + ".toml"
		for i, worker := range stringsOf(project["workers"]) {
			if _, ok := runners[worker]; !ok {
				return invalid(plabel, fmt.Sprintf("workers[%d]", i), "names a runner that is not defined")
			}
		}
		for i, account := range stringsOf(project["excluded_accounts"]) {
			if !contains(accounts, account) {
				return invalid(plabel, fmt.Sprintf("excluded_accounts[%d]", i), "names an account no runner lists")
			}
		}
		for key, defined := range map[string]map[string]any{"owner_channel": channels, "test_environment": environments} {
			if value, ok := project[key]; ok {
				if _, ok := defined[str(value)]; !ok {
					return invalid(plabel, key, "names an entry that is not defined")
				}
			}
		}
		if authority, ok := project["landing_authority"]; ok {
			level, _ := intValue(object(supervisors[str(authority)])["level"])
			if level != 5 && level != 6 {
				return invalid(plabel, "landing_authority", "must name a supervisor of level 5 or 6")
			}
		}
	}
	if organisation := str(c.data["organisation"]); organisation != "" {
		root := filepath.Join(c.home, "orgs")
		for _, group := range []string{"runners", "judges", "resources"} {
			for _, name := range sortedKeys(object(c.data[group])) {
				entry := object(object(c.data[group])[name])
				for _, key := range []string{"command", "resume", "room"} {
					for i, arg := range stringsOf(entry[key]) {
						if filepath.IsAbs(arg) {
							path := filepath.Clean(arg)
							if strings.HasPrefix(path, root+"/") && strings.Split(strings.TrimPrefix(path, root+"/"), "/")[0] != organisation {
								return invalid(label, fmt.Sprintf("%s.%s.%s[%d]", group, name, key, i), "points into the directory of another organisation; tools are not shared between organisations")
							}
						}
					}
				}
			}
		}
	}
	return nil
}
func listing(role *string) (map[string]any, error) {
	home, err := homePath("LANEBOSS_HOME", ".config/laneboss")
	if err != nil {
		return nil, err
	}
	names, err := configDirs(home)
	if err != nil {
		return nil, err
	}
	found := []any{}
	for _, name := range names {
		var description, problem any
		directory := filepath.Join(home, "configs", name)
		bytes, err := readInside(directory, "config.toml", "configuration "+shown(name), 1024*1024)
		if err != nil {
			problem = "its config.toml cannot be read inside its own directory"
		} else {
			doc, err := parseToml(bytes, "configuration "+shown(name), false)
			if err != nil {
				problem = "its config.toml cannot be read as TOML"
			} else if doc["name"] != name {
				problem = "its name does not match its directory"
			} else if s, ok := doc["description"].(string); ok {
				description = shown(s)
			}
		}
		hidden := findCredential(name) != nil
		found = append(found, map[string]any{"name": shown(name), "name_withheld": hidden, "readable": problem == nil, "description": description, "problem": problem})
	}
	extra := ""
	if role != nil {
		extra = " --role " + shown(*role)
	}
	return map[string]any{"directory": scrub(filepath.Join(home, "configs")), "configurations": found, "choose": "Choose one: run laneboss start --config NAME" + extra + ", or export LANEBOSS_CONFIG=NAME and run laneboss start" + extra + " again."}, nil
}
