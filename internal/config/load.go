package config

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/BurntSushi/toml"

	"laneboss.io/laneboss/internal/rolepolicy"
)

func sortNames(names []string) { sort.Strings(names) }

// Normalize array-of-table values as well as ordinary arrays to []any.
func normalize(value any) any {
	switch value := value.(type) {
	case map[string]any:
		for key, item := range value {
			value[key] = normalize(item)
		}
		return value
	case []map[string]any:
		result := make([]any, len(value))
		for index, item := range value {
			result[index] = normalize(item)
		}
		return result
	case []any:
		for index, item := range value {
			value[index] = normalize(item)
		}
		return value
	default:
		return value
	}
}

func parseTOML(data []byte, c checker, orderTarget ...*map[string][]string) (map[string]any, error) {
	if len(data) > MaxFileBytes {
		return nil, c.fail("", "is larger than 1 MiB")
	}
	if !utf8.Valid(data) {
		return nil, c.fail("", "must be UTF-8 text")
	}
	// The shared Python TOML reader rejects a BOM; do not let the Go decoder's
	// more permissive BOM handling widen the accepted on-disk format.
	if bytes.HasPrefix(data, []byte{0xef, 0xbb, 0xbf}) {
		return nil, c.fail("", "TOML syntax error at line 1, column 1")
	}
	// The pinned decoder has an opt-in TOML 1.1 mode. It must not silently
	// widen the file format shared with Python's TOML 1.0 reader.
	if _, enabled := os.LookupEnv("BURNTSUSHI_TOML_110"); enabled {
		return nil, c.fail("", "TOML 1.1 parser mode is not supported for shared configuration files; unset BURNTSUSHI_TOML_110")
	}
	var document map[string]any
	metadata, err := toml.Decode(string(data), &document)
	if err != nil {
		var position toml.ParseError
		if errors.As(err, &position) {
			return nil, c.fail("", fmt.Sprintf("TOML syntax error at line %d, column %d", position.Position.Line, position.Position.Col))
		}
		return nil, c.fail("", "TOML syntax error at the end of the file")
	}
	document = normalize(document).(map[string]any)
	if where, rule := detectValue(document); rule != "" {
		return nil, c.fail(where, "looks like a credential ("+rule+"); configuration files hold secret names, never values")
	}
	if _, exists := document["schema_version"]; !exists {
		return nil, c.fail("schema_version", "is required")
	}
	if err := schemaVersion(c, document["schema_version"], "schema_version"); err != nil {
		return nil, err
	}
	if len(orderTarget) > 0 {
		order := map[string][]string{}
		for _, key := range metadata.Keys() {
			for depth, name := range key {
				parent := strings.Join(key[:depth], ".")
				if !contains(order[parent], name) {
					order[parent] = append(order[parent], name)
				}
			}
		}
		*orderTarget[0] = order
	}
	return document, nil
}

// Load reads and validates a configuration, its projects and its rule files.
// It respects the session binding and creates no configuration or state files.
func Load(name string, options ...Options) (*Configuration, error) {
	var err error
	if name == "" {
		name, err = BoundName("")
		if err != nil {
			return nil, err
		}
	}
	if err := GuardNamed(name); err != nil {
		return nil, err
	}
	home, states, err := homes(options)
	if err != nil {
		return nil, err
	}
	return load(name, home, states)
}

func load(name, home, states string) (*Configuration, error) {
	if err := CheckName(name); err != nil {
		return nil, err
	}
	directory := filepath.Join(home, "configs", name)
	if missing(filepath.Join(directory, "config.toml")) {
		description, err := describeNames(home)
		if err != nil {
			return nil, err
		}
		shown := shownName(name)
		return nil, refused("no configuration named " + shown + " (" + safePath(filepath.Join(home, "configs", shown, "config.toml")) + " does not exist); " + description)
	}
	reader, err := newReader(name, directory, "configuration")
	if err != nil {
		return nil, err
	}
	defer reader.close()
	c := checker{"configuration " + shownName(name) + ": config.toml"}
	bytes, err := reader.read("config.toml")
	if err != nil {
		return nil, err
	}
	var order map[string][]string
	data, err := parseTOML(bytes, c, &order)
	if err != nil {
		return nil, err
	}
	if err := configSchema(c, data, ""); err != nil {
		return nil, err
	}
	for supervisorName, supervisor := range tableOf(data["supervisors"]) {
		entry := tableOf(supervisor)
		if role, exists := entry["role"]; exists {
			level := int64(5)
			if role == "mini" {
				level = 4
			}
			entry["level"] = level
			delete(entry, "role")
			for index, key := range order["supervisors."+supervisorName] {
				if key == "role" {
					order["supervisors."+supervisorName][index] = "level"
				}
			}
		}
	}
	if data["name"] != name {
		return nil, c.fail("name", "must equal the directory name \""+shownName(name)+"\"")
	}
	if err := checkTools(c, home, data); err != nil {
		return nil, err
	}
	projects, err := loadProjects(name, reader)
	if err != nil {
		return nil, err
	}
	rules, err := crossCheck(c, name, reader, data, projects)
	if err != nil {
		return nil, err
	}
	organisationBytes, err := loadOrganisationRules(c, home, data)
	if err != nil {
		return nil, err
	}
	idle, err := loadIdleMessage(c, reader, data)
	if err != nil {
		return nil, err
	}
	state := filepath.Join(states, name)
	if custom := stringOf(tableOf(data["state"])["path"]); custom != "" {
		state = filepath.Clean(custom)
	}
	organisation := stringOf(data["organisation"])
	configuration := &Configuration{
		Name: name, Home: home, StateHome: states, ConfigDir: directory, ConfigFile: filepath.Join(directory, "config.toml"),
		StateDir: state, Store: filepath.Join(state, StoreFile), Data: data, Projects: projects, RuleBytes: rules,
		Organisation: organisation, OrganisationBytes: organisationBytes, IdleMessage: idle,
		tableOrder: order,
	}
	folder, err := rolepolicy.ConfigRoot(home, data)
	if err != nil {
		return nil, c.fail("org_dir", err.Error())
	}
	_, explicitOrg := data["org_dir"]
	_, orgErr := os.Lstat(filepath.Join(folder, ".laneboss", "org.toml"))
	if folder != "" && (explicitOrg || !os.IsNotExist(orgErr)) {
		catalog, err := rolepolicy.Load(folder, func(data []byte) error {
			if detectText(string(data)) != nil {
				return c.fail("org_dir", "org role sources look like credentials; output was withheld")
			}
			return nil
		})
		if err != nil {
			return nil, c.fail("org_dir", err.Error())
		}
		if problems := catalog.RunnerProblems(tableOf(data["runners"])); len(problems) > 0 {
			return nil, c.fail("runners", strings.Join(problems, "\n"))
		}
	}
	if organisation != "" {
		configuration.OrganisationTools = filepath.Join(home, "orgs", organisation, "tools")
	}
	if err := checkStateLocation(c, configuration); err != nil {
		return nil, err
	}
	own := locate(directory)
	others, err := configDirectories(home)
	if err != nil {
		return nil, err
	}
	for _, other := range others {
		if other == name || !namePattern.MatchString(other) {
			continue
		}
		if overlap(own, locate(filepath.Join(home, "configs", other))) {
			return nil, invalid("configuration " + shownName(name) + ": its directory overlaps configuration " + shownName(other) + "'s directory")
		}
	}
	return configuration, nil
}

func loadProjects(name string, reader *fileReader) (map[string]map[string]any, error) {
	projects := map[string]map[string]any{}
	names, err := reader.projectNames()
	if err != nil {
		return nil, err
	}
	for _, entry := range names {
		if !strings.HasSuffix(entry, ".toml") {
			continue
		}
		stem := strings.TrimSuffix(entry, ".toml")
		if !namePattern.MatchString(stem) {
			return nil, (checker{"configuration " + shownName(name)}).fail("projects", "a project file name does not match "+NameRule+".toml")
		}
		c := checker{"configuration " + shownName(name) + ": " + safePath("projects/"+entry)}
		bytes, err := reader.read("projects/" + entry)
		if err != nil {
			return nil, err
		}
		document, err := parseTOML(bytes, c)
		if err != nil {
			return nil, err
		}
		if err := projectSchema(c, document, ""); err != nil {
			return nil, err
		}
		if document["name"] != stem {
			return nil, c.fail("name", "must equal the file name \""+shownName(stem)+"\"")
		}
		projects[stem] = document
	}
	return projects, nil
}

func checkRulesBytes(c checker, data []byte, relative, path string) ([]byte, error) {
	if len(data) > MaxFileBytes {
		return nil, c.fail(path, safePath(relative)+" is larger than 1 MiB")
	}
	if !utf8.Valid(data) {
		return nil, c.fail(path, safePath(relative)+" must be UTF-8 text")
	}
	if found := detectText(string(data)); found != nil {
		return nil, c.fail(path, fmt.Sprintf("%s line %d: looks like a credential (%s)", safePath(relative), found.line, found.rule))
	}
	return data, nil
}

func readRules(c checker, reader *fileReader, relative, path string, wrap bool) ([]byte, error) {
	data, err := reader.read(relative)
	if err != nil {
		if wrap {
			return nil, c.fail(path, err.Error())
		}
		return nil, err
	}
	return checkRulesBytes(c, data, relative, path)
}

func loadOrganisationRules(c checker, home string, data map[string]any) (map[string][]byte, error) {
	found := map[string][]byte{}
	listed, exists := data["organisation_rules"]
	if !exists {
		return found, nil
	}
	organisation, exists := data["organisation"]
	if !exists {
		return nil, c.fail("organisation_rules", "needs the key organisation, which names the organisation whose directory holds these files")
	}
	paths := stringsOf(listed)
	if len(paths) == 0 {
		return found, nil
	}
	reader, err := newReader(organisation.(string), filepath.Join(home, "orgs", organisation.(string)), "organisation")
	if err != nil {
		return nil, c.fail("organisation_rules[0]", err.Error())
	}
	defer reader.close()
	for index, relative := range paths {
		bytes, err := readRules(c, reader, relative, fmt.Sprintf("organisation_rules[%d]", index), true)
		if err != nil {
			return nil, err
		}
		found[relative] = bytes
	}
	return found, nil
}

func loadIdleMessage(c checker, reader *fileReader, data map[string]any) (*RuleFile, error) {
	relative := stringOf(tableOf(data["turns"])["idle_message"])
	if relative == "" {
		return nil, nil
	}
	content, err := reader.read(relative)
	if err != nil {
		return nil, c.fail("turns.idle_message", err.Error())
	}
	if len(content) > MaxIdleMessageBytes {
		return nil, c.fail("turns.idle_message", safePath(relative)+" is larger than 64 KiB")
	}
	content, err = checkRulesBytes(c, content, relative, "turns.idle_message")
	if err != nil {
		return nil, err
	}
	return &RuleFile{Path: relative, Bytes: content}, nil
}

func crossCheck(c checker, name string, reader *fileReader, data map[string]any, projects map[string]map[string]any) (map[string][]byte, error) {
	secrets := stringsOf(data["secrets"])
	runners := tableOf(data["runners"])
	channels := tableOf(data["owner_channels"])
	environments := tableOf(data["test_environments"])
	supervisors := tableOf(data["supervisors"])
	accounts := []string{}
	rules := map[string][]byte{}
	known := func(value any, choices map[string]any, path, what string) error {
		if _, exists := choices[stringOf(value)]; !exists {
			return c.fail(path, "names a "+what+" that is not defined")
		}
		return nil
	}
	listed := func(value, path string) error {
		if !contains(secrets, value) {
			return c.fail(path, "names a secret that is not listed in the top-level secrets")
		}
		return nil
	}
	for _, runnerName := range keys(runners) {
		runner := tableOf(runners[runnerName])
		accounts = append(accounts, stringsOf(runner["accounts"])...)
		for index, secret := range stringsOf(runner["secrets"]) {
			if err := listed(secret, fmt.Sprintf("runners.%s.secrets[%d]", runnerName, index)); err != nil {
				return nil, err
			}
		}
	}
	for _, environmentName := range keys(environments) {
		for index, secret := range stringsOf(tableOf(environments[environmentName])["secrets"]) {
			if err := listed(secret, fmt.Sprintf("test_environments.%s.secrets[%d]", environmentName, index)); err != nil {
				return nil, err
			}
		}
	}
	for _, channelName := range keys(channels) {
		if secret, exists := tableOf(channels[channelName])["token_secret"]; exists {
			if err := listed(secret.(string), "owner_channels."+channelName+".token_secret"); err != nil {
				return nil, err
			}
		}
	}
	for _, supervisorName := range keys(supervisors) {
		supervisor := tableOf(supervisors[supervisorName])
		base := "supervisors." + supervisorName
		if err := known(supervisor["runner"], runners, base+".runner", "runner"); err != nil {
			return nil, err
		}
		for index, project := range stringsOf(supervisor["projects"]) {
			if _, exists := projects[project]; !exists {
				return nil, c.fail(fmt.Sprintf("%s.projects[%d]", base, index), "names a project file that is not defined")
			}
		}
		if channel, exists := supervisor["owner_channel"]; exists {
			if err := known(channel, channels, base+".owner_channel", "owner channel"); err != nil {
				return nil, err
			}
		}
	}
	for _, difficulty := range keys(tableOf(data["routing"])) {
		for index, route := range arrayOf(tableOf(data["routing"])[difficulty]) {
			if err := known(tableOf(route)["runner"], runners, fmt.Sprintf("routing.%s[%d].runner", difficulty, index), "runner"); err != nil {
				return nil, err
			}
		}
	}
	if channel, exists := data["owner_channel"]; exists {
		if err := known(channel, channels, "owner_channel", "owner channel"); err != nil {
			return nil, err
		}
	}
	if environment, exists := data["test_environment"]; exists {
		if err := known(environment, environments, "test_environment", "test environment"); err != nil {
			return nil, err
		}
	}
	for index, relative := range stringsOf(data["rules"]) {
		bytes, err := readRules(c, reader, relative, fmt.Sprintf("rules[%d]", index), false)
		if err != nil {
			return nil, err
		}
		rules[relative] = bytes
	}
	for _, projectName := range keys(projects) {
		project := projects[projectName]
		pc := checker{"configuration " + shownName(name) + ": " + safePath("projects/"+projectName+".toml")}
		for index, worker := range stringsOf(project["workers"]) {
			if _, exists := runners[worker]; !exists {
				return nil, pc.fail(fmt.Sprintf("workers[%d]", index), "names a runner that is not defined")
			}
		}
		for index, account := range stringsOf(project["excluded_accounts"]) {
			if !contains(accounts, account) {
				return nil, pc.fail(fmt.Sprintf("excluded_accounts[%d]", index), "names an account no runner lists")
			}
		}
		if environment, exists := project["test_environment"]; exists {
			if _, found := environments[environment.(string)]; !found {
				return nil, pc.fail("test_environment", "names a test environment that is not defined")
			}
		}
		if channel, exists := project["owner_channel"]; exists {
			if _, found := channels[channel.(string)]; !found {
				return nil, pc.fail("owner_channel", "names an owner channel that is not defined")
			}
		}
		if name, exists := project["landing_authority"]; exists {
			authority := tableOf(supervisors[name.(string)])
			if authority["level"] != int64(5) && authority["level"] != int64(6) {
				return nil, pc.fail("landing_authority", "must name a supervisor of level 5 or 6")
			}
		}
		for index, relative := range stringsOf(project["rules"]) {
			if _, exists := rules[relative]; exists {
				continue
			}
			bytes, err := readRules(pc, reader, relative, fmt.Sprintf("rules[%d]", index), false)
			if err != nil {
				return nil, err
			}
			rules[relative] = bytes
		}
	}
	return rules, nil
}

type commandElement struct {
	path     string
	elements []string
}

func commandElements(data map[string]any) []commandElement {
	result := []commandElement{}
	if command, exists := data["archive_command"]; exists {
		result = append(result, commandElement{"archive_command", stringsOf(command)})
	}
	for _, runner := range keys(tableOf(data["runners"])) {
		for _, key := range []string{"command", "resume", "room"} {
			if elements, exists := tableOf(tableOf(data["runners"])[runner])[key]; exists {
				result = append(result, commandElement{"runners." + runner + "." + key, stringsOf(elements)})
			}
		}
	}
	for _, group := range []string{"judges", "resources"} {
		for _, name := range keys(tableOf(data[group])) {
			result = append(result, commandElement{group + "." + name + ".command", stringsOf(tableOf(tableOf(data[group])[name])["command"])})
		}
	}
	return result
}

func checkTools(c checker, home string, data map[string]any) error {
	own := stringOf(data["organisation"])
	if own == "" {
		return nil
	}
	root := filepath.Join(home, "orgs") + string(filepath.Separator)
	for _, command := range commandElements(data) {
		for index, element := range command.elements {
			if !filepath.IsAbs(element) {
				continue
			}
			path := filepath.Clean(element)
			if strings.HasPrefix(path, root) && strings.Split(strings.TrimPrefix(path, root), string(filepath.Separator))[0] != own {
				return c.fail(fmt.Sprintf("%s[%d]", command.path, index), "points into the directory of another organisation; tools are not shared between organisations")
			}
		}
	}
	return nil
}

func checkStateLocation(c checker, configuration *Configuration) error {
	state := locate(configuration.StateDir)
	_, custom := tableOf(configuration.Data["state"])["path"]
	if overlap(state, locate(configuration.Home)) {
		note := ""
		if !custom {
			note = " (it comes from LANEBOSS_STATE_HOME; set it elsewhere)"
		}
		return c.fail("state.path", "the state directory must not overlap the configuration home "+safePath(configuration.Home)+note)
	}
	if !custom {
		return nil
	}
	states := locate(configuration.StateHome)
	if inside(states, state) {
		return c.fail("state.path", "must not contain the state home, which holds every default state directory")
	}
	if inside(state, states) && !inside(state, locate(filepath.Join(configuration.StateHome, configuration.Name))) {
		return c.fail("state.path", "must not lie inside another configuration's default state directory")
	}
	return nil
}

func configDirectories(home string) ([]string, error) {
	root := filepath.Join(home, "configs")
	entries, err := os.ReadDir(root)
	if os.IsNotExist(err) {
		return []string{}, nil
	}
	if err != nil {
		return nil, refused("cannot list " + safePath(root))
	}
	names := []string{}
	for _, entry := range entries {
		info, err := os.Lstat(filepath.Join(root, entry.Name()))
		if err == nil && (info.IsDir() || info.Mode()&os.ModeSymlink != 0) {
			names = append(names, entry.Name())
		}
	}
	return names, nil
}

// ValidateAll validates every configuration directory, including malformed
// names and incomplete configurations, then refuses equal/nested state paths.
// A session bound by LANEBOSS_CONFIG cannot call it.
func ValidateAll(options ...Options) ([]string, error) {
	if os.Getenv(EnvName("CONFIG")) != "" {
		return nil, refused("--all reads every configuration, but LANEBOSS_CONFIG binds this session to one; unset it first")
	}
	home, states, err := homes(options)
	if err != nil {
		return nil, err
	}
	names, err := configDirectories(home)
	if err != nil {
		return nil, err
	}
	problems := []string{}
	loaded := []*Configuration{}
	for _, name := range names {
		if !namePattern.MatchString(name) {
			problems = append(problems, "configs: a configuration directory name does not match "+NameRule)
			continue
		}
		configuration, err := load(name, home, states)
		if err != nil {
			problems = append(problems, err.Error())
			continue
		}
		loaded = append(loaded, configuration)
	}
	for index, first := range loaded {
		for _, second := range loaded[index+1:] {
			one, two := locate(first.StateDir), locate(second.StateDir)
			if overlap(one, two) {
				kind := "nested"
				if inside(one, two) && inside(two, one) {
					kind = "equal"
				}
				problems = append(problems, "configurations "+shownName(first.Name)+" and "+shownName(second.Name)+": state.path: their state directories are "+kind)
			}
		}
	}
	if len(problems) > 0 {
		return nil, invalid(strings.Join(problems, "\n"))
	}
	result := make([]string, 0, len(loaded))
	for _, configuration := range loaded {
		result = append(result, configuration.Name)
	}
	return result, nil
}
