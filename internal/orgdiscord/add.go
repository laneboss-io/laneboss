package orgdiscord

import (
	"encoding/json"
	"fmt"
	"reflect"
	"regexp"
	"strings"
	"syscall"
)

type binding struct {
	agent    instance
	discord  discordSettings
	store    secretStore
	roles    map[string]Role
	existing *Role
	role     Role
	channel  string
}

func memberArguments(values []string, kind string) ([]Member, error) {
	result := []Member{}
	seen := map[string]int{}
	for _, value := range values {
		parts := strings.Split(value, ":")
		if len(parts) != 2 || (parts[1] != "decide" && parts[1] != "inform") {
			return nil, refused("--member and --role-id require ID:decide or ID:inform")
		}
		id, err := checkedString(parts[0], "member id", idPattern)
		if err != nil {
			return nil, err
		}
		if index, exists := seen[id]; exists {
			if result[index].Authority != parts[1] {
				return nil, refused("a member must not be given conflicting authorities in one command")
			}
			continue
		}
		seen[id] = len(result)
		result = append(result, Member{kind, id, parts[1]})
	}
	return result, nil
}

func prepareBinding(files *orgFiles, arguments addArguments) (binding, error) {
	var b binding
	agent, err := readInstance(files, arguments.instance)
	if err != nil {
		return b, err
	}
	if agent.level < 5 {
		return b, refused("owner Discord channels are for L5 or L6 instances only; L3/L4 are refused")
	}
	b.agent = agent
	b.discord, b.store, err = settings(files)
	if err != nil {
		return b, err
	}
	b.roles, err = readRoles(files, true)
	if err != nil {
		return b, err
	}
	b.channel = agent.channel
	for _, role := range b.roles {
		if role.Instance == arguments.instance {
			copy := role
			b.existing, b.channel = &copy, role.ChannelID
			if agent.channel != "" && agent.channel != b.channel {
				return b, refused("instance channel and Discord role channel disagree; resolve the binding before adding")
			}
		}
	}
	if arguments.channel != "" {
		if b.channel != "" && b.channel != arguments.channel {
			return b, refused("this instance already has another channel; channel add will not rebind it")
		}
		b.channel = arguments.channel
	}
	for _, role := range b.roles {
		if role.ChannelID == b.channel && (b.existing == nil || role.Name != b.existing.Name) {
			return b, refused("this channel is already registered to another instance")
		}
	}
	members := []Member{}
	if b.existing != nil {
		members = append(members, b.existing.Members...)
	}
	users, err := memberArguments(arguments.members, "user")
	if err != nil {
		return b, err
	}
	groups, err := memberArguments(arguments.groups, "role")
	if err != nil {
		return b, err
	}
	merge := func(member Member) {
		for i, existing := range members {
			if existing.Kind == member.Kind && existing.ID == member.ID {
				members[i] = member
				return
			}
		}
		members = append(members, member)
	}
	for _, member := range append(users, groups...) {
		if member.Kind == "user" && member.ID == b.discord.owner && member.Authority != "decide" {
			return b, refused("the configured owner must keep decide authority in every channel")
		}
		merge(member)
	}
	if b.discord.owner != "" {
		merge(Member{"user", b.discord.owner, "decide"})
	}
	if len(members) == 0 {
		return b, refused("add at least one --member or --role-id, or configure services.discord.owner_id")
	}
	if b.existing != nil {
		b.role = *b.existing
		b.role.Members = members
	} else {
		if _, exists := b.roles[arguments.instance]; exists {
			return b, refused("the default role name is already used by another instance")
		}
		channel := b.channel
		if channel == "" {
			channel = "<created-channel-id>"
		}
		b.role = Role{Name: arguments.instance, Instance: arguments.instance, ChannelID: channel,
			ChannelName: regexp.MustCompile(`[^a-z0-9_-]`).ReplaceAllString(strings.ToLower(arguments.instance), "-"),
			Members:     members, StateFile: "owner-discord." + arguments.instance + ".state.json",
			EventsFile: "owner-discord.events." + arguments.instance + ".jsonl", FormDoorbell: "owner-form." + arguments.instance}
	}
	return b, nil
}

func hello(role Role, level int64) string {
	return fmt.Sprintf("laneboss: owner channel ready for %s (L%d).", role.Instance, level)
}

func verifyMessage(reply map[string]any, role Role, text, messageID string) (string, error) {
	id, err := checkedString(reply["id"], "hello message id", idPattern)
	if err != nil {
		return "", err
	}
	author, ok := reply["author"].(map[string]any)
	if reply["channel_id"] != role.ChannelID || reply["content"] != text || (messageID != "" && id != messageID) || !ok || author["bot"] != true {
		return "", refused("Discord hello verification failed: message id, channel, text or bot author did not match")
	}
	return id, nil
}

func addChannel(arguments addArguments) (map[string]any, error) {
	files, err := openOrg(arguments.org)
	if err != nil {
		return nil, err
	}
	defer files.close()
	if arguments.dry {
		b, err := prepareBinding(files, arguments)
		if err != nil {
			return nil, err
		}
		requests := []any{}
		if b.channel != "" {
			requests = append(requests, map[string]any{"method": "GET", "path": "/channels/" + b.channel})
		} else {
			requests = append(requests, map[string]any{"method": "POST", "path": "/guilds/" + b.discord.guild + "/channels", "body": map[string]any{"name": b.role.ChannelName, "type": 0}})
		}
		if b.role.HelloMessageID == "" {
			b.role.HelloMessageID = "<posted-message-id>"
			requests = append(requests, map[string]any{"method": "POST", "path": "/channels/" + b.role.ChannelID + "/messages", "body": map[string]any{"content": hello(b.role, b.agent.level), "allowed_mentions": map[string]any{"parse": []string{}}}})
		}
		requests = append(requests, map[string]any{"method": "GET", "path": "/channels/" + b.role.ChannelID + "/messages/" + b.role.HelloMessageID})
		return map[string]any{"dry_run": true, "instance": b.role.Instance, "reused": b.channel != "", "changes": changes(b.agent, b.existing, b.role), "requests": requests, "note": "channel name and new ids are resolved by REST during the real run"}, nil
	}
	// Refuse lower-level instances before the lock fallback can create a file.
	agent, err := readInstance(files, arguments.instance)
	if err != nil {
		return nil, err
	}
	if agent.level < 5 {
		return nil, refused("owner Discord channels are for L5 or L6 instances only; L3/L4 are refused")
	}
	lock, err := files.lock()
	if err != nil {
		return nil, err
	}
	defer lock.Close()
	defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	b, err := prepareBinding(files, arguments)
	if err != nil {
		return nil, err
	}
	token, err := loadToken(b.discord, b.store)
	if err != nil {
		return nil, err
	}
	if bytesContainToken(b.agent.raw, token) || bytesContainToken(renderRoles(b.roles), token) {
		return nil, refused("instance.toml or discord-roles.toml contains credential material; registration refused")
	}
	api, err := newREST(token)
	if err != nil {
		return nil, err
	}
	defer api.client.CloseIdleConnections()
	var metadata map[string]any
	if b.channel != "" {
		metadata, err = api.request("GET", "/channels/"+b.channel, nil, false)
	} else {
		metadata, err = api.request("POST", "/guilds/"+b.discord.guild+"/channels", map[string]any{"name": b.role.ChannelName, "type": 0}, true)
	}
	if err != nil {
		return nil, err
	}
	id, err := checkedString(metadata["id"], "Discord channel id", idPattern)
	if err != nil {
		return nil, err
	}
	typeNumber, integer := metadata["type"].(json.Number)
	if metadata["guild_id"] != b.discord.guild || !integer || (typeNumber != "0" && typeNumber != "5") || (b.channel != "" && id != b.channel) {
		return nil, refused("Discord channel is not a text channel in the configured org server")
	}
	for _, role := range b.roles {
		if role.ChannelID == id && (b.existing == nil || role.Name != b.existing.Name) {
			return nil, refused("Discord returned a channel already registered to another instance")
		}
	}
	name, err := channelName(metadata["name"])
	if err != nil {
		return nil, err
	}
	b.role.ChannelID, b.role.ChannelName = id, name
	// Check every persisted role field, including IDs, before writing. This also
	// catches a numeric token reflected as an otherwise valid snowflake.
	encoded, err := json.Marshal(b.role.document())
	if err != nil || bytesContainToken(encoded, token) {
		return nil, refused("Discord channel metadata contains credential material; registration refused")
	}
	b.roles[b.role.Name] = b.role
	if b.existing == nil || !reflect.DeepEqual(b.role, *b.existing) {
		if err := files.write(rolesPath, renderRoles(b.roles)); err != nil {
			return nil, err
		}
	}
	if b.agent.channel == "" {
		data := append([]byte("discord_channel_id = "+tomlString(id)+"\n"), b.agent.raw...)
		if err := files.write(b.agent.relative, data); err != nil {
			return nil, err
		}
	}
	text := hello(b.role, b.agent.level)
	if b.role.HelloMessageID == "" {
		posted, err := api.request("POST", "/channels/"+id+"/messages", map[string]any{"content": text, "allowed_mentions": map[string]any{"parse": []string{}}}, false)
		if err != nil {
			return nil, err
		}
		messageID, err := verifyMessage(posted, b.role, text, "")
		if err != nil {
			return nil, err
		}
		if strings.Contains(messageID, token) {
			return nil, refused("Discord hello verification failed: message id contains credential material")
		}
		b.role.HelloMessageID = messageID
		b.roles[b.role.Name] = b.role
		if err := files.write(rolesPath, renderRoles(b.roles)); err != nil {
			return nil, err
		}
	}
	readBack, err := api.request("GET", "/channels/"+id+"/messages/"+b.role.HelloMessageID, nil, false)
	if err != nil {
		return nil, err
	}
	if _, err := verifyMessage(readBack, b.role, text, b.role.HelloMessageID); err != nil {
		return nil, err
	}
	result := map[string]any{"dry_run": false, "instance": b.role.Instance, "role": b.role.Name, "channel_id": id, "channel_name": name, "hello_message_id": b.role.HelloMessageID, "verified": true, "reused": b.channel != "", "changes": changes(b.agent, b.existing, b.role)}
	// The before-state is untrusted too. Fail closed instead of printing any
	// credential embedded in a previously edited configuration document.
	encoded, err = json.Marshal(result)
	if err != nil || bytesContainToken(encoded, token) {
		return nil, refused("org channel result contains credential material; output refused")
	}
	return result, nil
}

func bytesContainToken(data []byte, token string) bool { return strings.Contains(string(data), token) }
