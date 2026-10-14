package brief

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/BurntSushi/toml"
)

type configuration struct {
	name, home, stateHome, configDir, stateDir string
	data                                       map[string]any
	projects                                   map[string]map[string]any
	ruleBytes, organisationBytes               map[string][]byte
}

func sortedKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
func safeField(key string) string {
	if !regexp.MustCompile(`^[A-Za-z0-9_.-]{1,64}$`).MatchString(key) || findCredential(key) != nil {
		return "a field"
	}
	return key
}
func hasString(items []string, needle string) bool {
	for _, item := range items {
		if item == needle {
			return true
		}
	}
	return false
}
func stringList(value any) []string {
	items, _ := value.([]any)
	result := make([]string, 0, len(items))
	for _, item := range items {
		if s, ok := item.(string); ok {
			result = append(result, s)
		}
	}
	return result
}
func tableValue(value any) map[string]any {
	m, _ := value.(map[string]any)
	if m == nil {
		return map[string]any{}
	}
	return m
}

// TOML arrays of tables and ordinary arrays decode to different Go slice types.
// Normalize both, so every validator and credential walk sees every input.
func normalize(value any) any {
	switch v := value.(type) {
	case map[string]any:
		for key, item := range v {
			v[key] = normalize(item)
		}
		return v
	case int:
		return int64(v)
	}
	if value != nil && reflect.TypeOf(value).Kind() == reflect.Slice {
		v := reflect.ValueOf(value)
		result := make([]any, v.Len())
		for i := range result {
			result[i] = normalize(v.Index(i).Interface())
		}
		return result
	}
	return value
}

func parseTOML(data []byte, label string) (map[string]any, error) {
	if len(data) > maxFileBytes {
		return nil, invalid(label, "", "is larger than 1 MiB")
	}
	if !utf8.Valid(data) {
		return nil, invalid(label, "", "must be UTF-8 text")
	}
	var document map[string]any
	if _, err := toml.Decode(string(data), &document); err != nil {
		note := "TOML syntax error at the end of the file"
		if position := regexp.MustCompile(`line ([0-9]+)`).FindStringSubmatch(err.Error()); position != nil {
			note = "TOML syntax error at line " + position[1]
		}
		return nil, invalid(label, "", note)
	}
	document = normalize(document).(map[string]any)
	if field, rule := credentialInValue(document); rule != "" {
		return nil, invalid(label, field, "looks like a credential ("+rule+"); configuration files hold secret names, never values")
	}
	if _, ok := document["schema_version"]; !ok {
		return nil, invalid(label, "schema_version", "is required")
	}
	if err := schemaError(label, checkVersion(document["schema_version"], "schema_version")); err != nil {
		return nil, err
	}
	return document, nil
}

type configReader struct {
	dir        *directory
	kind, name string
}

func openConfigReader(name, path, kind string) (*configReader, error) {
	d, err := openDirectory(path, kind+" "+shownName(name))
	if err != nil {
		return nil, err
	}
	return &configReader{d, kind, name}, nil
}
func (r *configReader) label(relative string) string {
	return r.kind + " " + shownName(r.name) + ": " + safePath(relative)
}

func (r *configReader) inside(path, relative string) (*directory, error) {
	d, err := openDirectory(path, r.label(relative))
	if err != nil {
		return nil, err
	}
	chain, _, err := walkUp(d)
	if err == nil && !containsIdentity(chain, r.dir.info) {
		err = invalid(r.kind+" "+shownName(r.name), safePath(relative), "leads outside the "+r.kind+" directory")
	}
	if err != nil {
		d.close()
		return nil, err
	}
	return d, nil
}

func (r *configReader) read(relative string) ([]byte, error) {
	real, err := realPath(r.dir.path + "/" + relative)
	if err != nil {
		return nil, err
	}
	d, err := r.inside(filepath.Dir(real), relative)
	if err != nil {
		return nil, err
	}
	defer d.close()
	return d.read(filepath.Base(real), maxFileBytes+1, r.label(relative))
}
func (r *configReader) list(relative string) ([]string, error) {
	real, err := realPath(r.dir.path + "/" + relative)
	if err != nil {
		return nil, err
	}
	d, err := r.inside(real, relative)
	if err != nil {
		return nil, err
	}
	defer d.close()
	f, err := d.root.Open(".")
	if err != nil {
		return nil, err
	}
	defer f.Close()
	names, err := f.Readdirnames(-1)
	sort.Strings(names)
	return names, err
}

func homePath(variable, fallback string) (string, error) {
	value := os.Getenv(variable)
	if value == "" {
		return fallback, nil
	}
	if !filepath.IsAbs(value) {
		return "", refused("%s must be an absolute path", variable)
	}
	return filepath.Clean(value), nil
}

func bind(o options) (*configuration, *zones, error) {
	userHome, err := os.UserHomeDir()
	if err != nil {
		return nil, nil, refused("cannot determine the user home directory")
	}
	home, err := homePath("LANEBOSS_HOME", filepath.Join(userHome, ".config", program))
	if err != nil {
		return nil, nil, err
	}
	states, err := homePath("LANEBOSS_STATE_HOME", filepath.Join(userHome, ".local", "state", program))
	if err != nil {
		return nil, nil, err
	}
	environment := os.Getenv("LANEBOSS_CONFIG")
	if o.configSet && !namePattern.MatchString(o.config) {
		return nil, nil, refused("the configuration name given by --config must match %s", nameRule)
	}
	if environment != "" && !namePattern.MatchString(environment) {
		return nil, nil, refused("the configuration name in LANEBOSS_CONFIG must match %s", nameRule)
	}
	if o.configSet && environment != "" && o.config != environment {
		return nil, nil, refused("--config %s conflicts with LANEBOSS_CONFIG; a session is bound to exactly one configuration", shownName(o.config))
	}
	name := environment
	if o.configSet {
		name = o.config
	}
	if name == "" {
		return nil, nil, refused("no configuration is bound: pass --config NAME or set LANEBOSS_CONFIG; %s", describeNames(home))
	}
	c, err := loadConfiguration(name, home, states)
	if err != nil {
		return nil, nil, err
	}
	z, err := newZones(c)
	if err != nil {
		return nil, nil, err
	}
	return c, z, nil
}

type configEntry struct{ name, path string }

func otherConfigDirs(home, own string) []configEntry {
	root := filepath.Join(home, "configs")
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil
	}
	var result []configEntry
	for _, entry := range entries {
		if entry.Name() == own || !namePattern.MatchString(entry.Name()) {
			continue
		}
		if entry.IsDir() || entry.Type()&os.ModeSymlink != 0 {
			result = append(result, configEntry{entry.Name(), filepath.Join(root, entry.Name())})
		}
	}
	return result
}

func describeNames(home string) string {
	var names []string
	for _, entry := range otherConfigDirs(home, "") {
		if info, err := os.Stat(filepath.Join(entry.path, "config.toml")); err == nil && info.Mode().IsRegular() {
			names = append(names, shownName(entry.name))
		}
	}
	if len(names) > 0 {
		return "configurations: " + strings.Join(names, ", ")
	}
	return "no configuration exists under " + safePath(filepath.Join(home, "configs"))
}

// Other configurations are read for their name and declared state only. An
// unreadable neighbour is not guessed and never has its settings printed.
func declaredState(name, directoryPath, states string) (string, bool) {
	r, err := openConfigReader(name, directoryPath, "configuration")
	if err != nil {
		return "", false
	}
	defer r.dir.close()
	data, err := r.read("config.toml")
	if err != nil || !utf8.Valid(data) {
		return "", false
	}
	var m map[string]any
	if _, err := toml.Decode(string(data), &m); err != nil || m["name"] != name {
		return "", false
	}
	state, exists := m["state"]
	if !exists {
		return filepath.Join(states, name), true
	}
	table, ok := state.(map[string]any)
	if !ok {
		return "", false
	}
	path, exists := table["path"]
	if !exists {
		return filepath.Join(states, name), true
	}
	if checkAbsolute(path, "state.path") != "" {
		return "", false
	}
	return filepath.Clean(path.(string)), true
}

func loadConfiguration(name, home, states string) (*configuration, error) {
	path := filepath.Join(home, "configs", name)
	if _, err := os.Lstat(filepath.Join(path, "config.toml")); err != nil && errors.Is(err, os.ErrNotExist) {
		return nil, refused("no configuration named %s; %s", shownName(name), describeNames(home))
	}
	r, err := openConfigReader(name, path, "configuration")
	if err != nil {
		return nil, err
	}
	defer r.dir.close()
	label := r.label("config.toml")
	data, err := r.read("config.toml")
	if err != nil {
		return nil, err
	}
	document, err := parseTOML(data, label)
	if err != nil {
		return nil, err
	}
	if err := schemaError(label, configurationSchema()(document, "")); err != nil {
		return nil, err
	}
	if document["name"] != name {
		return nil, invalid(label, "name", "must equal the directory name \""+shownName(name)+"\"")
	}
	for _, value := range tableValue(document["supervisors"]) {
		entry := value.(map[string]any)
		if role, ok := entry["role"]; ok {
			level := int64(4)
			if role == "top" {
				level = 5
			}
			entry["level"] = level
			delete(entry, "role")
		}
	}
	c := &configuration{name: name, home: home, stateHome: states, configDir: path, stateDir: filepath.Join(states, name), data: document, projects: map[string]map[string]any{}, ruleBytes: map[string][]byte{}, organisationBytes: map[string][]byte{}}
	if state, ok := tableValue(document["state"])["path"].(string); ok {
		c.stateDir = filepath.Clean(state)
	}
	if err := c.checkTools(label); err != nil {
		return nil, err
	}
	if _, err := r.dir.root.Lstat("projects"); err == nil {
		names, err := r.list("projects")
		if err != nil {
			return nil, err
		}
		for _, entry := range names {
			if !strings.HasSuffix(entry, ".toml") {
				continue
			}
			stem := strings.TrimSuffix(entry, ".toml")
			if !namePattern.MatchString(stem) {
				return nil, invalid("configuration "+shownName(name), "projects", "a project file name does not match "+nameRule+".toml")
			}
			relative := "projects/" + entry
			projectLabel := r.label(relative)
			data, err := r.read(relative)
			if err != nil {
				return nil, err
			}
			project, err := parseTOML(data, projectLabel)
			if err != nil {
				return nil, err
			}
			if err := schemaError(projectLabel, projectSchema()(project, "")); err != nil {
				return nil, err
			}
			if project["name"] != stem {
				return nil, invalid(projectLabel, "name", "must equal the file name \""+shownName(stem)+"\"")
			}
			c.projects[stem] = project
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, refused("cannot inspect the projects directory")
	}
	if err := c.crossCheck(r, label); err != nil {
		return nil, err
	}
	if listed, ok := document["organisation_rules"]; ok {
		organisation, ok := document["organisation"].(string)
		if !ok {
			return nil, invalid(label, "organisation_rules", "needs the key organisation, which names the organisation whose directory holds these files")
		}
		var org *configReader
		for i, relative := range stringList(listed) {
			field := fmt.Sprintf("organisation_rules[%d]", i)
			if org == nil {
				org, err = openConfigReader(organisation, filepath.Join(home, "orgs", organisation), "organisation")
				if err != nil {
					return nil, invalid(label, field, err.Error())
				}
				defer org.dir.close()
			}
			content, err := org.read(relative)
			if err != nil {
				return nil, invalid(label, field, err.Error())
			}
			if err := checkRulesBytes(content, relative, label, field, maxFileBytes); err != nil {
				return nil, err
			}
			c.organisationBytes[relative] = content
		}
	}
	if relative, ok := tableValue(document["turns"])["idle_message"].(string); ok {
		content, err := r.read(relative)
		if err != nil {
			return nil, invalid(label, "turns.idle_message", err.Error())
		}
		if err := checkRulesBytes(content, relative, label, "turns.idle_message", 64*1024); err != nil {
			return nil, err
		}
	}
	if err := c.checkStateLocation(label); err != nil {
		return nil, err
	}
	own, err := locate(path)
	if err != nil {
		return nil, err
	}
	for _, other := range otherConfigDirs(home, name) {
		location, err := locate(other.path)
		if err != nil {
			return nil, err
		}
		if overlaps(own, location) {
			return nil, invalid("configuration "+shownName(name), "its directory", "overlaps configuration "+shownName(other.name)+"'s directory")
		}
	}
	return c, nil
}

func checkRulesBytes(data []byte, relative, label, field string, maximum int) error {
	if len(data) > maximum {
		return invalid(label, field, fmt.Sprintf("%s is larger than %d bytes", safePath(relative), maximum))
	}
	if !utf8.Valid(data) {
		return invalid(label, field, safePath(relative)+" must be UTF-8 text")
	}
	if f := findCredential(string(data)); f != nil {
		return invalid(label, field, fmt.Sprintf("%s line %d: looks like a credential (%s)", safePath(relative), f.line, f.rule))
	}
	return nil
}

func (c *configuration) crossCheck(r *configReader, label string) error {
	runners, channels := tableValue(c.data["runners"]), tableValue(c.data["owner_channels"])
	environments, supervisors := tableValue(c.data["test_environments"]), tableValue(c.data["supervisors"])
	secrets := stringList(c.data["secrets"])
	accounts := []string{}
	known := func(value any, choices map[string]any, field, what string) error {
		if _, ok := choices[value.(string)]; !ok {
			return invalid(label, field, "names a "+what+" that is not defined")
		}
		return nil
	}
	listed := func(value, field string) error {
		if !hasString(secrets, value) {
			return invalid(label, field, "names a secret that is not listed in the top-level secrets")
		}
		return nil
	}
	for _, group := range []struct {
		name    string
		entries map[string]any
	}{{"runners", runners}, {"test_environments", environments}} {
		for _, name := range sortedKeys(group.entries) {
			entry := group.entries[name].(map[string]any)
			for i, secret := range stringList(entry["secrets"]) {
				if err := listed(secret, fmt.Sprintf("%s.%s.secrets[%d]", group.name, shownName(name), i)); err != nil {
					return err
				}
			}
			if group.name == "runners" {
				accounts = append(accounts, stringList(entry["accounts"])...)
			}
		}
	}
	for _, name := range sortedKeys(channels) {
		entry := channels[name].(map[string]any)
		if secret, ok := entry["token_secret"].(string); ok {
			if err := listed(secret, "owner_channels."+shownName(name)+".token_secret"); err != nil {
				return err
			}
		}
	}
	projects := map[string]any{}
	for name, project := range c.projects {
		projects[name] = project
	}
	for _, name := range sortedKeys(supervisors) {
		entry := supervisors[name].(map[string]any)
		base := "supervisors." + shownName(name)
		if err := known(entry["runner"], runners, base+".runner", "runner"); err != nil {
			return err
		}
		for i, project := range stringList(entry["projects"]) {
			if err := known(project, projects, fmt.Sprintf("%s.projects[%d]", base, i), "project file"); err != nil {
				return err
			}
		}
		if channel, ok := entry["owner_channel"]; ok {
			if err := known(channel, channels, base+".owner_channel", "owner channel"); err != nil {
				return err
			}
		}
	}
	for difficulty, values := range tableValue(c.data["routing"]) {
		for i, value := range values.([]any) {
			if err := known(value.(map[string]any)["runner"], runners, fmt.Sprintf("routing.%s[%d].runner", difficulty, i), "runner"); err != nil {
				return err
			}
		}
	}
	for _, key := range []string{"owner_channel", "test_environment"} {
		if value, ok := c.data[key]; ok {
			choices, noun := channels, "owner channel"
			if key == "test_environment" {
				choices, noun = environments, "test environment"
			}
			if err := known(value, choices, key, noun); err != nil {
				return err
			}
		}
	}
	loadRules := func(values any, fileLabel string) error {
		for i, relative := range stringList(values) {
			if _, ok := c.ruleBytes[relative]; ok {
				continue
			}
			data, err := r.read(relative)
			if err != nil {
				return err
			}
			field := fmt.Sprintf("rules[%d]", i)
			if err := checkRulesBytes(data, relative, fileLabel, field, maxFileBytes); err != nil {
				return err
			}
			c.ruleBytes[relative] = data
		}
		return nil
	}
	if err := loadRules(c.data["rules"], label); err != nil {
		return err
	}
	for _, name := range sortedKeys(projects) {
		project := c.projects[name]
		projectLabel := r.label("projects/" + name + ".toml")
		for _, item := range []struct {
			key     string
			choices map[string]any
			noun    string
		}{{"workers", runners, "runner"}} {
			for i, value := range stringList(project[item.key]) {
				if _, ok := item.choices[value]; !ok {
					return invalid(projectLabel, fmt.Sprintf("%s[%d]", item.key, i), "names a "+item.noun+" that is not defined")
				}
			}
		}
		for i, account := range stringList(project["excluded_accounts"]) {
			if !hasString(accounts, account) {
				return invalid(projectLabel, fmt.Sprintf("excluded_accounts[%d]", i), "names an account no runner lists")
			}
		}
		for _, key := range []string{"test_environment", "owner_channel"} {
			if value, ok := project[key]; ok {
				choices, noun := channels, "owner channel"
				if key == "test_environment" {
					choices, noun = environments, "test environment"
				}
				if _, ok := choices[value.(string)]; !ok {
					return invalid(projectLabel, key, "names a "+noun+" that is not defined")
				}
			}
		}
		if authority, ok := project["landing_authority"].(string); ok {
			entry := tableValue(supervisors[authority])
			if entry["level"] != int64(5) && entry["level"] != int64(6) {
				return invalid(projectLabel, "landing_authority", "must name a supervisor of level 5 or 6")
			}
		}
		if err := loadRules(project["rules"], projectLabel); err != nil {
			return err
		}
	}
	return nil
}

func (c *configuration) checkTools(label string) error {
	organisation, ok := c.data["organisation"].(string)
	if !ok {
		return nil
	}
	root := filepath.Join(c.home, "orgs") + "/"
	for _, group := range []struct {
		name string
		keys []string
	}{{"runners", []string{"command", "resume", "room"}}, {"judges", []string{"command"}}, {"resources", []string{"command"}}} {
		entries := tableValue(c.data[group.name])
		for _, name := range sortedKeys(entries) {
			entry := entries[name].(map[string]any)
			for _, key := range group.keys {
				for i, element := range stringList(entry[key]) {
					if !filepath.IsAbs(element) {
						continue
					}
					path := filepath.Clean(element)
					if strings.HasPrefix(path, root) && strings.Split(strings.TrimPrefix(path, root), "/")[0] != organisation {
						return invalid(label, fmt.Sprintf("%s.%s.%s[%d]", group.name, shownName(name), key, i), "points into the directory of another organisation; tools are not shared between organisations")
					}
				}
			}
		}
	}
	return nil
}

func (c *configuration) checkStateLocation(label string) error {
	state, err := locate(c.stateDir)
	if err != nil {
		return err
	}
	home, err := locate(c.home)
	if err != nil {
		return err
	}
	if overlaps(state, home) {
		return invalid(label, "state.path", "the state directory must not overlap the configuration home")
	}
	if _, custom := tableValue(c.data["state"])["path"]; !custom {
		return nil
	}
	states, err := locate(c.stateHome)
	if err != nil {
		return err
	}
	own, err := locate(filepath.Join(c.stateHome, c.name))
	if err != nil {
		return err
	}
	if inside(states, state) {
		return invalid(label, "state.path", "must not contain the state home, which holds every default state directory")
	}
	if inside(state, states) && !inside(state, own) {
		return invalid(label, "state.path", "must not lie inside another configuration's default state directory")
	}
	return nil
}

func (c *configuration) rules(o options) []ruleFile {
	result := []ruleFile{}
	organisation, _ := c.data["organisation"].(string)
	for _, relative := range stringList(c.data["organisation_rules"]) {
		result = append(result, ruleFile{"orgs/" + organisation + "/" + relative, c.organisationBytes[relative]})
	}
	listed := stringList(c.data["rules"])
	if o.projectSet {
		for _, relative := range stringList(c.projects[o.project]["rules"]) {
			if !hasString(listed, relative) {
				listed = append(listed, relative)
			}
		}
	}
	for _, relative := range listed {
		result = append(result, ruleFile{relative, c.ruleBytes[relative]})
	}
	return result
}
