package judge

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/BurntSushi/toml"
)

type judgeDefinition struct {
	command     []string
	description *string
	seconds     int
}
type zone struct {
	name, kind string
	location   location
}
type configuration struct {
	name, home, states, configDir, statePath                string
	egressLimit                                             int
	data                                                    map[string]any
	projects                                                map[string]map[string]any
	judges                                                  map[string]judgeDefinition
	ownConfig, ownState, ownDefault, configsRoot, stateRoot location
	others                                                  []zone
	known                                                   map[string]bool
}

func configurationHome(variable, fallback string) (string, error) {
	value := os.Getenv(variable)
	if value == "" {
		return fallback, nil
	}
	if !filepath.IsAbs(value) {
		return "", refused(variable + " must be an absolute path")
	}
	return filepath.Clean(value), nil
}
func loadConfiguration(o options) (*configuration, error) {
	bound := os.Getenv("LANEBOSS_CONFIG")
	if o.configSet && !namePattern.MatchString(o.config) {
		return nil, refused("the configuration name given by --config must match [a-z0-9][a-z0-9-]{0,31}")
	}
	if bound != "" && !namePattern.MatchString(bound) {
		return nil, refused("the configuration name in LANEBOSS_CONFIG must match [a-z0-9][a-z0-9-]{0,31}")
	}
	if o.configSet && bound != "" && o.config != bound {
		return nil, refused(fmt.Sprintf("--config %s conflicts with LANEBOSS_CONFIG=%s; a session is bound to exactly one configuration", shown(o.config), shown(bound)))
	}
	name := bound
	if o.configSet {
		name = o.config
	}
	if name == "" {
		return nil, refused("no configuration is bound: pass --config NAME or set LANEBOSS_CONFIG")
	}
	userHome, err := os.UserHomeDir()
	if err != nil {
		return nil, refused("the user home directory cannot be determined")
	}
	home, err := configurationHome("LANEBOSS_HOME", filepath.Join(userHome, ".config", "laneboss"))
	if err != nil {
		return nil, err
	}
	states, err := configurationHome("LANEBOSS_STATE_HOME", filepath.Join(userHome, ".local", "state", "laneboss"))
	if err != nil {
		return nil, err
	}
	c := &configuration{name: name, home: home, states: states, configDir: filepath.Join(home, "configs", name), judges: map[string]judgeDefinition{}, projects: map[string]map[string]any{}, known: map[string]bool{name: true}}
	c.egressLimit = maxEgressBytes
	if value, exists := os.LookupEnv("LANEBOSS_JUDGE_MAX_EGRESS_BYTES"); exists {
		limit, err := strconv.Atoi(value)
		if err != nil || limit < 1 || limit > maxEgressBytes {
			return nil, refused("LANEBOSS_JUDGE_MAX_EGRESS_BYTES must be a positive integer no greater than the 64 MiB log limit")
		}
		c.egressLimit = limit
	}
	c.ownConfig, err = locate(c.configDir)
	if err != nil {
		return nil, err
	}
	if !c.ownConfig.exists() {
		return nil, refused("no configuration named " + shown(name) + " (config.toml does not exist)")
	}
	label := "configuration " + shown(name) + ": config.toml"
	data, err := readInside(c.configDir, "config.toml", label)
	if err != nil {
		return nil, err
	}
	c.data, err = decodeDocument(data, label)
	if err != nil {
		return nil, err
	}
	check := checker{label}
	if err = check.validateConfiguration(c.data); err != nil {
		return nil, err
	}
	if c.data["name"] != name {
		return nil, check.fail("name", "must equal the configuration directory name")
	}
	for _, v := range tableValue(c.data["supervisors"]) {
		s := tableValue(v)
		if role, ok := s["role"].(string); ok {
			level := int64(4)
			if role == "top" {
				level = 5
			}
			s["level"] = level
			delete(s, "role")
		}
	}
	c.statePath = filepath.Join(states, name)
	if path, ok := tableValue(c.data["state"])["path"].(string); ok {
		c.statePath = filepath.Clean(path)
	}
	for name, v := range tableValue(c.data["judges"]) {
		definition := tableValue(v)
		j := judgeDefinition{command: stringValues(definition["command"]), seconds: 10}
		if seconds, ok := definition["timeout_seconds"].(int64); ok {
			j.seconds = int(seconds)
		}
		if text, ok := definition["description"].(string); ok {
			j.description = &text
		}
		c.judges[name] = j
	}
	if err = c.loadProjects(); err != nil {
		return nil, err
	}
	if err = c.crossCheck(); err != nil {
		return nil, err
	}
	if err = c.loadZones(); err != nil {
		return nil, err
	}
	return c, nil
}

func readInside(base, relative, what string) ([]byte, error) {
	root, err := locate(base)
	if err != nil {
		return nil, err
	}
	target, err := realPath(filepath.Join(base, relative))
	if err != nil {
		return nil, refused(what + ": cannot resolve the file")
	}
	parent, err := locate(filepath.Dir(target))
	if err != nil {
		return nil, err
	}
	if !inside(parent, root) {
		return nil, refused(what + " leads outside the configuration directory")
	}
	d, err := openDirectory(filepath.Dir(target))
	if err != nil {
		return nil, refused(what + ": cannot open the directory (" + safeOSMessage(err) + ")")
	}
	defer d.close()
	return d.readFile(filepath.Base(target), what, maxTextBytes)
}
func decodeDocument(data []byte, label string) (map[string]any, error) {
	check := checker{label}
	if len(data) > maxTextBytes {
		return nil, check.fail("(top level)", "is larger than 1 MiB")
	}
	if !utf8.Valid(data) {
		return nil, check.fail("(top level)", "must be UTF-8 text")
	}
	var document map[string]any
	if _, err := toml.Decode(string(data), &document); err != nil {
		return nil, check.fail("(top level)", "TOML syntax error")
	}
	if field, found := credentialField(document, ""); found {
		return nil, check.fail(field, "looks like a credential; configuration files hold secret names, never values")
	}
	return document, nil
}
func (c *configuration) loadProjects() error {
	path := filepath.Join(c.configDir, "projects")
	if _, err := os.Lstat(path); os.IsNotExist(err) {
		return nil
	}
	where, err := locate(path)
	if err != nil {
		return err
	}
	if !inside(where, c.ownConfig) {
		return refused("projects leads outside the configuration directory")
	}
	entries, err := os.ReadDir(path)
	if err != nil {
		return refused("the configuration projects directory cannot be read")
	}
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".toml") {
			continue
		}
		stem := strings.TrimSuffix(entry.Name(), ".toml")
		if !namePattern.MatchString(stem) {
			return refused("a project file name is not a valid name")
		}
		label := "configuration " + shown(c.name) + ": projects/" + stem + ".toml"
		data, err := readInside(c.configDir, "projects/"+entry.Name(), label)
		if err != nil {
			return err
		}
		document, err := decodeDocument(data, label)
		if err != nil {
			return err
		}
		check := checker{label}
		if err = check.validateProject(document); err != nil {
			return err
		}
		if document["name"] != stem {
			return check.fail("name", "must equal the project file name")
		}
		c.projects[stem] = document
	}
	return nil
}
func (c *configuration) checkRules(base string, paths []string, field string, limit int) error {
	for i, path := range paths {
		data, err := readInside(base, path, "standing rules")
		if err != nil {
			return (checker{"configuration " + shown(c.name) + ": config.toml"}).fail(fmt.Sprintf("%s[%d]", field, i), safeFailure(err))
		}
		if len(data) > limit || !utf8.Valid(data) || hasCredential(string(data)) {
			return (checker{"configuration " + shown(c.name) + ": config.toml"}).fail(fmt.Sprintf("%s[%d]", field, i), "the file must be bounded UTF-8 text and hold no credential shape")
		}
	}
	return nil
}
func (c *configuration) crossCheck() error {
	check := checker{"configuration " + shown(c.name) + ": config.toml"}
	runners, channels, environments, supervisors := tableValue(c.data["runners"]), tableValue(c.data["owner_channels"]), tableValue(c.data["test_environments"]), tableValue(c.data["supervisors"])
	secrets := map[string]bool{}
	accounts := map[string]bool{}
	for _, s := range stringValues(c.data["secrets"]) {
		secrets[s] = true
	}
	known := func(value any, choices map[string]any, path, kind string) error {
		s, _ := value.(string)
		if _, ok := choices[s]; !ok {
			return check.fail(path, "names a "+kind+" that is not defined")
		}
		return nil
	}
	for _, group := range []string{"runners", "test_environments"} {
		for name, v := range tableValue(c.data[group]) {
			entry := tableValue(v)
			for i, s := range stringValues(entry["secrets"]) {
				if !secrets[s] {
					return check.fail(fmt.Sprintf("%s.%s.secrets[%d]", group, name, i), "names a secret that is not listed in the top-level secrets")
				}
			}
			if group == "runners" {
				for _, a := range stringValues(entry["accounts"]) {
					accounts[a] = true
				}
			}
		}
	}
	for name, v := range channels {
		if secret, ok := tableValue(v)["token_secret"].(string); ok && !secrets[secret] {
			return check.fail("owner_channels."+name+".token_secret", "names a secret that is not listed in the top-level secrets")
		}
	}
	for name, v := range supervisors {
		s := tableValue(v)
		base := "supervisors." + name
		if err := known(s["runner"], runners, base+".runner", "runner"); err != nil {
			return err
		}
		for i, p := range stringValues(s["projects"]) {
			if _, ok := c.projects[p]; !ok {
				return check.fail(fmt.Sprintf("%s.projects[%d]", base, i), "names a project file that is not defined")
			}
		}
		if v, ok := s["owner_channel"]; ok {
			if err := known(v, channels, base+".owner_channel", "owner channel"); err != nil {
				return err
			}
		}
	}
	for difficulty, v := range tableValue(c.data["routing"]) {
		for i, route := range sliceValues(v) {
			if err := known(tableValue(route)["runner"], runners, fmt.Sprintf("routing.%s[%d].runner", difficulty, i), "runner"); err != nil {
				return err
			}
		}
	}
	for _, field := range []string{"owner_channel", "test_environment"} {
		if v, ok := c.data[field]; ok {
			choices := channels
			kind := "owner channel"
			if field == "test_environment" {
				choices = environments
				kind = "test environment"
			}
			if err := known(v, choices, field, kind); err != nil {
				return err
			}
		}
	}
	if err := c.checkRules(c.configDir, stringValues(c.data["rules"]), "rules", maxTextBytes); err != nil {
		return err
	}
	for name, p := range c.projects {
		pc := checker{"configuration " + shown(c.name) + ": projects/" + name + ".toml"}
		for i, worker := range stringValues(p["workers"]) {
			if _, ok := runners[worker]; !ok {
				return pc.fail(fmt.Sprintf("workers[%d]", i), "names a runner that is not defined")
			}
		}
		for i, a := range stringValues(p["excluded_accounts"]) {
			if !accounts[a] {
				return pc.fail(fmt.Sprintf("excluded_accounts[%d]", i), "names an account no runner lists")
			}
		}
		for _, field := range []string{"owner_channel", "test_environment"} {
			if value, ok := p[field]; ok {
				choices := channels
				if field == "test_environment" {
					choices = environments
				}
				if _, ok := choices[value.(string)]; !ok {
					return pc.fail(field, "names an entry that is not defined")
				}
			}
		}
		if authority, ok := p["landing_authority"].(string); ok {
			s := tableValue(supervisors[authority])
			level, _ := s["level"].(int64)
			if level != 5 && level != 6 {
				return pc.fail("landing_authority", "must name a supervisor of level 5 or 6")
			}
		}
		if err := c.checkRules(c.configDir, stringValues(p["rules"]), "rules", maxTextBytes); err != nil {
			return err
		}
	}
	organisation, _ := c.data["organisation"].(string)
	if len(stringValues(c.data["organisation_rules"])) > 0 && organisation == "" {
		return check.fail("organisation_rules", "requires organisation")
	}
	if organisation != "" {
		if err := c.checkRules(filepath.Join(c.home, "orgs", organisation), stringValues(c.data["organisation_rules"]), "organisation_rules", maxTextBytes); err != nil {
			return err
		}
	}
	if path, ok := tableValue(c.data["turns"])["idle_message"].(string); ok {
		if err := c.checkRules(c.configDir, []string{path}, "turns.idle_message", 65536); err != nil {
			return err
		}
	}
	if organisation != "" {
		root := filepath.Join(c.home, "orgs") + string(filepath.Separator)
		for _, group := range []string{"runners", "judges", "resources"} {
			for name, v := range tableValue(c.data[group]) {
				for _, key := range []string{"command", "resume", "room"} {
					for i, arg := range stringValues(tableValue(v)[key]) {
						if filepath.IsAbs(arg) {
							path := filepath.Clean(arg)
							if strings.HasPrefix(path, root) && strings.Split(strings.TrimPrefix(path, root), string(filepath.Separator))[0] != organisation {
								return check.fail(fmt.Sprintf("%s.%s.%s[%d]", group, name, key, i), "points into another organisation's directory; tools are not shared")
							}
						}
					}
				}
			}
		}
	}
	return nil
}

func (c *configuration) loadZones() error {
	var err error
	c.ownState, err = locate(c.statePath)
	if err != nil {
		return err
	}
	c.ownDefault, err = locate(filepath.Join(c.states, c.name))
	if err != nil {
		return err
	}
	c.configsRoot, err = locate(filepath.Join(c.home, "configs"))
	if err != nil {
		return err
	}
	c.stateRoot, err = locate(c.states)
	if err != nil {
		return err
	}
	home, err := locate(c.home)
	if err != nil {
		return err
	}
	if overlaps(c.ownState, home) {
		return refused("state.path: the state directory must not overlap the configuration home")
	}
	if _, custom := tableValue(c.data["state"])["path"]; custom {
		if inside(c.stateRoot, c.ownState) || inside(c.ownState, c.stateRoot) && !inside(c.ownState, c.ownDefault) {
			return refused("state.path: must not overlap another configuration's default state directory")
		}
	}
	entries, err := os.ReadDir(filepath.Join(c.home, "configs"))
	if err != nil {
		return refused("cannot list the configuration home")
	}
	for _, entry := range entries {
		name := entry.Name()
		if name == c.name || !namePattern.MatchString(name) {
			continue
		}
		info, err := os.Lstat(filepath.Join(c.home, "configs", name))
		if err != nil {
			continue
		}
		if !info.IsDir() && info.Mode()&os.ModeSymlink == 0 {
			continue
		}
		c.known[name] = true
		path := filepath.Join(c.home, "configs", name)
		other, err := locate(path)
		if err != nil {
			return err
		}
		c.others = append(c.others, zone{name, "configuration directory", other})
		if overlaps(c.ownConfig, other) {
			return refused("the configuration directory overlaps configuration " + shown(name) + "'s directory")
		}
		data, err := readInside(path, "config.toml", "another configuration")
		if err != nil {
			continue
		}
		var document map[string]any
		if _, err = toml.Decode(string(data), &document); err != nil || !utf8.Valid(data) || document["name"] != name {
			continue
		}
		state := filepath.Join(c.states, name)
		if value, exists := document["state"]; exists {
			m, ok := value.(map[string]any)
			if !ok {
				continue
			}
			if value, exists := m["path"]; exists {
				s, ok := value.(string)
				if !ok || !validAbsolutePath(s) {
					continue
				}
				state = filepath.Clean(s)
			}
		}
		other, err = locate(state)
		if err != nil {
			return err
		}
		c.others = append(c.others, zone{name, "state directory", other})
	}
	for _, other := range c.others {
		if overlaps(c.ownState, other.location) {
			return refused("the state directory is the same as, inside or around configuration " + shown(other.name) + "'s " + other.kind)
		}
	}
	return nil
}
func (c *configuration) checkMarkers(path, option string, includeSelf bool) error {
	real, err := realPath(path)
	if err != nil {
		return refused(option + ": cannot resolve the checked directory")
	}
	if !includeSelf {
		real = filepath.Dir(real)
	}
	for {
		d, err := openDirectory(real)
		if err != nil {
			return refused(option + ": cannot read a directory above the checked path")
		}
		marker, present, err := d.marker()
		d.close()
		if err != nil {
			return refused(option + " lies below a directory whose ownership marker is unreadable")
		}
		if present && marker["config"] != c.name {
			owner, ok := marker["config"].(string)
			if !ok || !validMarker(marker) || !c.known[owner] {
				return refused(option + " lies inside the state directory of another or an unknown configuration")
			}
			return refused(option + " belongs to configuration " + shown(owner))
		}
		parent := filepath.Dir(real)
		if parent == real {
			return nil
		}
		real = parent
	}
}
func (c *configuration) readExternal(path, option string) (string, error) {
	target, err := locate(path)
	if err != nil {
		return "", err
	}
	for _, other := range c.others {
		if inside(target, other.location) {
			return "", refused(option + " lies inside configuration " + shown(other.name) + "'s " + other.kind)
		}
	}
	real, err := realPath(path)
	if err != nil {
		return "", refused(option + ": cannot resolve the file")
	}
	parent, err := locate(filepath.Dir(real))
	if err != nil {
		return "", err
	}
	if inside(parent, c.configsRoot) && !inside(parent, c.ownConfig) {
		return "", refused(option + " lies inside the configuration home but outside its own directory")
	}
	if inside(parent, c.stateRoot) && !inside(parent, c.ownState) && !inside(parent, c.ownDefault) {
		return "", refused(option + " lies inside the state home but outside its own state directory")
	}
	// A written path cannot enter an own directory and escape through a link.
	written, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	for current := filepath.Dir(written); ; current = filepath.Dir(current) {
		if info, err := os.Stat(current); err == nil {
			for _, own := range []location{c.ownConfig, c.ownState} {
				if own.exists() && identity(info) == own.chain[0] && !containsID(parent.chain, own.chain[0]) {
					return "", refused(option + " passes through its configuration directory and leaves it through a link")
				}
			}
		}
		if filepath.Dir(current) == current {
			break
		}
	}
	if err = c.checkMarkers(filepath.Dir(real), option, true); err != nil {
		return "", err
	}
	d, err := openDirectory(filepath.Dir(real))
	if err != nil {
		return "", refused(option + ": cannot open the file's directory")
	}
	defer d.close()
	data, err := d.readFile(filepath.Base(real), option, maxTextBytes)
	if err != nil {
		return "", err
	}
	if !utf8.Valid(data) {
		return "", refused(option + ": the file must be UTF-8 text")
	}
	return string(data), nil
}
func (c *configuration) openState(create bool) (*directory, error) {
	where, err := locate(c.statePath)
	if err != nil {
		return nil, err
	}
	if !where.exists() {
		if !create {
			return nil, nil
		}
		existing := where.real
		for {
			if info, err := os.Stat(existing); err == nil {
				if !info.IsDir() {
					return nil, refused("the state directory's ancestor is not a directory")
				}
				break
			} else if !os.IsNotExist(err) {
				return nil, refused("the state directory's ancestor cannot be read")
			}
			existing = filepath.Dir(existing)
		}
		if err = c.checkMarkers(existing, "the state directory", true); err != nil {
			return nil, err
		}
		if err = os.MkdirAll(c.statePath, 0700); err != nil {
			return nil, refused("cannot create the state directory (" + safeOSMessage(err) + ")")
		}
	}
	d, err := openDirectory(c.statePath)
	if err != nil {
		return nil, refused("cannot open the state directory (" + safeOSMessage(err) + ")")
	}
	d.logLimit = c.egressLimit
	if err = c.checkMarkers(d.real, "the state directory", true); err != nil {
		d.close()
		return nil, err
	}
	return d, nil
}
