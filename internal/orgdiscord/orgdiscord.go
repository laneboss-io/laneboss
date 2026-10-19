// Package orgdiscord implements owner channels, the shared roles file, and
// channel-aware events. Validation never contacts Discord or opens secrets.
package orgdiscord

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"

	"laneboss.io/laneboss/internal/cliargs"
	"laneboss.io/laneboss/internal/instancename"
)

const rolesPath = ".laneboss/shared/services/discord-roles.toml"

var (
	namePattern   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
	filePattern   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,159}$`)
	idPattern     = regexp.MustCompile(`^[1-9][0-9]{0,19}$`)
	secretPattern = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,63}$`)
	tokenPattern  = regexp.MustCompile(`^[A-Za-z0-9._-]{20,512}$`)
)

func refused(message string) error { return errors.New(message) }

func checkedString(value any, label string, pattern *regexp.Regexp) (string, error) {
	s, ok := value.(string)
	if !ok || !pattern.MatchString(s) {
		if pattern == idPattern {
			return "", refused(label + " must be a positive Discord id written as a string")
		}
		return "", refused(label + " must be a plain name without path separators")
	}
	return s, nil
}

func channelName(value any) (string, error) {
	s, ok := value.(string)
	if !ok || !utf8.ValidString(s) || utf8.RuneCountInString(s) == 0 || utf8.RuneCountInString(s) > 100 {
		return "", refused("Discord channel name is missing or invalid")
	}
	for _, r := range s {
		if r < 32 || r == 127 {
			return "", refused("Discord channel name is missing or invalid")
		}
	}
	return s, nil
}

// Member is an authenticated Discord user or server-role authority.
type Member struct{ Kind, ID, Authority string }

func (m Member) document() map[string]any {
	return map[string]any{m.Kind + "_id": m.ID, "authority": m.Authority}
}

// Role binds one L5/L6 instance to one owner channel.
type Role struct {
	Name, Instance, ChannelID, ChannelName string
	StateFile, EventsFile, FormDoorbell    string
	HelloMessageID                         string
	Members                                []Member
}

func (r Role) document() map[string]any {
	members := make([]any, 0, len(r.Members))
	for _, m := range r.Members {
		members = append(members, m.document())
	}
	value := map[string]any{"instance": r.Instance, "channel_id": r.ChannelID, "channel_name": r.ChannelName,
		"state_file": r.StateFile, "events_file": r.EventsFile, "form_doorbell": r.FormDoorbell, "members": members}
	if r.HelloMessageID != "" {
		value["hello_message_id"] = r.HelloMessageID
	}
	return value
}

type instance struct {
	relative string
	raw      []byte
	level    int64
	channel  string
}

func readInstance(files *orgFiles, name string) (instance, error) {
	var agent instance
	if _, err := checkedString(name, "instance", instancename.Expression); err != nil {
		return agent, err
	}
	agent.relative = ".laneboss/instances/" + name + "/instance.toml"
	raw, err := files.read(agent.relative, "instance.toml")
	if err != nil {
		return agent, err
	}
	value, err := parseTOML(raw, "instance.toml")
	if err != nil {
		return agent, err
	}
	level, ok := value["level"].(int64)
	if !ok || level < 3 || level > 6 {
		return agent, refused("instance.toml level must be an integer from 3 to 6")
	}
	if actual, exists := value["name"]; exists && actual != name {
		return agent, refused("instance.toml name must match its instance directory")
	}
	if channel, exists := value["discord_channel_id"]; exists {
		agent.channel, err = checkedString(channel, "instance.toml discord_channel_id", idPattern)
		if err != nil {
			return agent, err
		}
	}
	agent.raw, agent.level = raw, level
	return agent, nil
}

func exactFields(value map[string]any, required []string, optional string) bool {
	for _, field := range required {
		if _, ok := value[field]; !ok {
			return false
		}
	}
	for field := range value {
		if optional != "" && field == optional {
			continue
		}
		found := false
		for _, allowed := range required {
			if field == allowed {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func sortedNames[T any](values map[string]T) []string {
	names := make([]string, 0, len(values))
	for name := range values {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// ReadRoles validates role bindings and authorities. Partial coverage is allowed;
// use ValidateOrgChannels for the complete org rule.
func ReadRoles(org string, allowMissing bool) (map[string]Role, error) {
	files, err := openOrg(org)
	if err != nil {
		return nil, err
	}
	defer files.close()
	return readRoles(files, allowMissing)
}

func readRoles(files *orgFiles, allowMissing bool) (result map[string]Role, failure error) {
	defer func() {
		if failure != nil && !strings.Contains(failure.Error(), "discord-roles.toml") {
			failure = refused("discord-roles.toml: " + failure.Error())
		}
	}()
	roles := make(map[string]Role)
	if err := files.checkPath(rolesPath); err != nil {
		return nil, err
	}
	if _, err := files.root.Lstat(rolesPath); errors.Is(err, os.ErrNotExist) && allowMissing {
		return roles, nil
	}
	raw, err := files.read(rolesPath, "discord-roles.toml")
	if err != nil {
		return nil, err
	}
	value, err := parseTOML(raw, "discord-roles.toml")
	if err != nil {
		return nil, err
	}
	entries, ok := value["roles"].(map[string]any)
	version, integer := value["schema_version"].(int64)
	if len(value) != 2 || !ok || !integer || version != 1 {
		return nil, refused("discord-roles.toml requires schema_version = 1 and a roles table")
	}
	instances, channels := map[string]bool{}, map[string]bool{}
	fields := []string{"instance", "channel_id", "channel_name", "members", "state_file", "events_file", "form_doorbell"}
	for _, name := range sortedNames(entries) {
		if _, err := checkedString(name, "Discord role", instancename.Expression); err != nil {
			return nil, err
		}
		entry, ok := entries[name].(map[string]any)
		if !ok || !exactFields(entry, fields, "hello_message_id") {
			return nil, refused("each Discord role must have exactly the documented role fields")
		}
		role := Role{Name: name}
		role.Instance, err = checkedString(entry["instance"], "role instance", instancename.Expression)
		if err != nil {
			return nil, err
		}
		agent, err := readInstance(files, role.Instance)
		if err != nil {
			return nil, err
		}
		if agent.level < 5 {
			return nil, refused("Discord roles may belong only to L5 or L6 instances; L3/L4 are refused")
		}
		role.ChannelID, err = checkedString(entry["channel_id"], "role channel_id", idPattern)
		if err != nil {
			return nil, err
		}
		if instances[role.Instance] || channels[role.ChannelID] {
			return nil, refused("each instance and each channel may occur in exactly one Discord role")
		}
		instances[role.Instance], channels[role.ChannelID] = true, true
		role.ChannelName, err = channelName(entry["channel_name"])
		if err != nil {
			return nil, err
		}
		for field, dest := range map[string]*string{"state_file": &role.StateFile, "events_file": &role.EventsFile, "form_doorbell": &role.FormDoorbell} {
			*dest, err = checkedString(entry[field], "role "+field, filePattern)
			if err != nil {
				return nil, err
			}
		}
		if role.StateFile == role.EventsFile {
			return nil, refused("state_file and events_file must be different file names")
		}
		var list []any
		switch members := entry["members"].(type) {
		case []map[string]any:
			for _, member := range members {
				list = append(list, member)
			}
		case []any:
			list = members
		}
		if len(list) == 0 {
			return nil, refused("each Discord role requires at least one member with an authority")
		}
		seen := map[string]bool{}
		for _, item := range list {
			member, ok := item.(map[string]any)
			kind := "user"
			if _, found := member["role_id"]; found {
				kind = "role"
			}
			if !ok || !exactFields(member, []string{kind + "_id", "authority"}, "") {
				return nil, refused("each member requires one user_id or role_id and an authority")
			}
			identifier, err := checkedString(member[kind+"_id"], "member id", idPattern)
			if err != nil {
				return nil, err
			}
			authority, ok := member["authority"].(string)
			if !ok || (authority != "decide" && authority != "inform") {
				return nil, refused("every member authority must be decide or inform")
			}
			key := kind + ":" + identifier
			if seen[key] {
				return nil, refused("a Discord role must not repeat a member")
			}
			seen[key] = true
			role.Members = append(role.Members, Member{kind, identifier, authority})
		}
		if hello, exists := entry["hello_message_id"]; exists {
			role.HelloMessageID, err = checkedString(hello, "role hello_message_id", idPattern)
			if err != nil {
				return nil, err
			}
		}
		roles[name] = role
	}
	return roles, nil
}

func renderRoles(roles map[string]Role) []byte {
	var out bytes.Buffer
	out.WriteString("schema_version = 1\n\n")
	if len(roles) == 0 {
		out.WriteString("roles = {}\n")
	}
	for _, name := range sortedNames(roles) {
		role := roles[name]
		fmt.Fprintf(&out, "[roles.%s]\n", tomlString(name))
		entry := role.document()
		for _, field := range []string{"instance", "channel_id", "channel_name", "state_file", "events_file", "form_doorbell", "hello_message_id"} {
			if value, ok := entry[field]; ok {
				fmt.Fprintf(&out, "%s = %s\n", field, tomlString(value.(string)))
			}
		}
		out.WriteString("members = [\n")
		for _, member := range role.Members {
			fmt.Fprintf(&out, "  { %s_id = %s, authority = %s },\n", member.Kind, tomlString(member.ID), tomlString(member.Authority))
		}
		out.WriteString("]\n\n")
	}
	return []byte(strings.TrimRight(out.String(), "\n") + "\n")
}

// ValidateOrgChannels returns channel-rule failures. L3/L4 never have channels;
// L5/L6 coverage starts when services.discord exists or a role is registered.
// This function never opens the secret store or contacts Discord.
func ValidateOrgChannels(org string) []string {
	files, err := openOrg(org)
	if err != nil {
		return []string{err.Error()}
	}
	defer files.close()
	roles, err := readRoles(files, true)
	if err != nil {
		return []string{err.Error()}
	}
	const directory = ".laneboss/instances"
	if err := files.checkPath(directory); err != nil {
		return []string{err.Error()}
	}
	handle, err := files.root.Open(directory)
	if err != nil {
		return []string{"Discord validation requires the instances directory"}
	}
	defer handle.Close()
	entries, err := handle.ReadDir(-1)
	if err != nil {
		return []string{"cannot read org instances for Discord validation"}
	}
	config, err := files.toml(".laneboss/org.toml", "org.toml")
	if err != nil {
		return []string{err.Error()}
	}
	services, _ := config["services"].(map[string]any)
	_, configured := services["discord"]
	usesDiscord := len(roles) != 0 || configured
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	failures := []string{}
	for _, entry := range entries {
		if entry.Type()&os.ModeSymlink != 0 {
			return []string{"org configuration paths must stay inside the org and must not be symbolic links"}
		}
		if !entry.IsDir() {
			continue
		}
		agent, err := readInstance(files, entry.Name())
		if err != nil {
			return []string{err.Error()}
		}
		var matches []Role
		for _, role := range roles {
			if role.Instance == entry.Name() {
				matches = append(matches, role)
			}
		}
		if agent.level >= 5 {
			if !usesDiscord {
				continue
			}
			if len(matches) != 1 || agent.channel == "" {
				failures = append(failures, entry.Name()+": every L5/L6 instance requires exactly one role and channel")
			} else if matches[0].ChannelID != agent.channel {
				failures = append(failures, entry.Name()+": instance channel and Discord role channel disagree")
			}
		} else if len(matches) != 0 || agent.channel != "" {
			failures = append(failures, entry.Name()+": L3/L4 instances must not have a Discord role or channel")
		}
	}
	return failures
}

type addArguments struct {
	org, instance, channel string
	create, dry            bool
	members, groups        []string
}

// Run executes org channel actions. Test adapters are isolated in tagged builds.
func Run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "usage: laneboss org channel add ORG INSTANCE (--channel-id ID | --create)")
		return 2
	}
	if code, handled := runTestProbe(args, stdout, stderr); handled {
		return code
	}
	if args[0] == "read" {
		return runRead(args[1:], stdout, stderr)
	}
	if args[0] == "-h" || args[0] == "--help" {
		fmt.Fprintln(stdout, "usage: laneboss org channel add ORG INSTANCE (--channel-id ID | --create) [--member ID:AUTHORITY] [--role-id ID:AUTHORITY] [--dry-run]\n       laneboss org channel read ORG --json")
		return 0
	}
	if args[0] != "add" {
		fmt.Fprintln(stderr, "laneboss org channel: error: "+cliargs.Reject("ACTION"))
		return 2
	}
	for _, argument := range args[1:] {
		if argument == "-h" || argument == "--help" {
			fmt.Fprintln(stdout, "usage: laneboss org channel add ORG INSTANCE (--channel-id ID | --create) [--member ID:AUTHORITY] [--role-id ID:AUTHORITY] [--dry-run]")
			return 0
		}
	}
	arguments, err := parseAdd(args[1:])
	if err != nil {
		fmt.Fprintln(stderr, "laneboss org channel add: "+err.Error())
		return 2
	}
	result, err := addChannel(arguments)
	if err != nil {
		fmt.Fprintln(stderr, "laneboss org channel add: "+err.Error())
		return 2
	}
	if err := writeJSON(stdout, result); err != nil {
		fmt.Fprintln(stderr, "cannot write org channel result")
		return 2
	}
	return 0
}

func parseAdd(args []string) (addArguments, error) {
	var result addArguments
	var positional []string
	endOptions, channelSet := false, false
	for index := 0; index < len(args); index++ {
		word := args[index]
		if !endOptions && word == "--" {
			endOptions = true
			continue
		}
		if endOptions || !strings.HasPrefix(word, "-") {
			positional = append(positional, word)
			continue
		}
		key, value, assigned := strings.Cut(word, "=")
		switch key {
		case "--create", "--dry-run":
			if assigned {
				return result, refused(cliargs.Reject(key))
			}
			if key == "--create" {
				result.create = true
			} else {
				result.dry = true
			}
		case "--channel-id", "--member", "--role-id":
			if !assigned {
				index++
				if index == len(args) || strings.HasPrefix(args[index], "--") {
					return result, refused(cliargs.Expected(key))
				}
				value = args[index]
			}
			if key == "--channel-id" {
				result.channel, channelSet = value, true
			} else if key == "--member" {
				result.members = append(result.members, value)
			} else {
				result.groups = append(result.groups, value)
			}
		default:
			return result, refused(cliargs.Reject(""))
		}
	}
	if len(positional) != 2 {
		if len(positional) < 2 {
			labels := []string{"ORG-DIR", "INSTANCE"}
			return result, refused(cliargs.Required(labels[len(positional):]...))
		}
		return result, refused(cliargs.Reject(""))
	}
	if channelSet == result.create {
		if channelSet {
			return result, refused(cliargs.Conflict("--create", "--channel-id"))
		}
		return result, refused(cliargs.Screen("one of the arguments --channel-id --create is required"))
	}
	if channelSet {
		if _, err := checkedString(result.channel, "--channel-id", idPattern); err != nil {
			return result, err
		}
	}
	result.org, result.instance = positional[0], positional[1]
	return result, nil
}

func changes(agent instance, existing *Role, role Role) []any {
	result := []any{}
	var before any
	if existing != nil {
		before = existing.document()
	}
	if !reflect.DeepEqual(before, role.document()) {
		result = append(result, map[string]any{"file": rolesPath, "role": role.Name, "before": before, "after": role.document()})
	}
	if agent.channel != role.ChannelID {
		var beforeChannel any
		if agent.channel != "" {
			beforeChannel = agent.channel
		}
		result = append(result, map[string]any{"file": agent.relative, "field": "discord_channel_id", "before": beforeChannel, "after": role.ChannelID})
	}
	return result
}
