package orgdiscord

import (
	"encoding/json"
	"fmt"
	"io"
)

func truthy(value any) bool {
	switch v := value.(type) {
	case nil:
		return false
	case bool:
		return v
	case string:
		return v != ""
	case json.Number:
		number, err := v.Float64()
		return err != nil || number != 0
	case []any:
		return len(v) != 0
	case map[string]any:
		return len(v) != 0
	default:
		return true
	}
}

// MessageToEvent converts an authenticated MESSAGE_CREATE payload. Explicit user
// authority wins over server roles; decide wins among matching server roles.
// Dropped messages log only a fixed reason and never their text or metadata.
func MessageToEvent(message any, roles map[string]Role, channelNames map[string]any, logger io.Writer) any {
	drop := func(reason string) any {
		if logger != nil {
			fmt.Fprintln(logger, "drop Discord message: "+reason)
		}
		return "drop"
	}
	payload, ok := message.(map[string]any)
	if !ok {
		return drop("message is not an object")
	}
	var role *Role
	for _, name := range sortedNames(roles) {
		entry := roles[name]
		if payload["channel_id"] == entry.ChannelID {
			role = &entry
			break
		}
	}
	if role == nil {
		return drop("channel is not registered")
	}
	author, ok := payload["author"].(map[string]any)
	if !ok || truthy(author["bot"]) || truthy(payload["webhook_id"]) {
		return drop("sender is not a human member")
	}
	authorID, err := checkedString(author["id"], "author id", idPattern)
	if err != nil {
		return drop("author or message id is invalid")
	}
	messageID, err := checkedString(payload["id"], "message id", idPattern)
	if err != nil {
		return drop("author or message id is invalid")
	}
	member := map[string]any{}
	if value, exists := payload["member"]; exists {
		member, ok = value.(map[string]any)
		if !ok {
			return drop("Discord member metadata is invalid")
		}
	}
	authority := ""
	for _, entry := range role.Members {
		if entry.Kind == "user" && entry.ID == authorID {
			authority = entry.Authority
			break
		}
	}
	if authority == "" {
		groupIDs := []any{}
		if value, exists := member["roles"]; exists {
			groupIDs, ok = value.([]any)
			if !ok {
				return drop("Discord server role metadata is invalid")
			}
		}
		groups := map[string]bool{}
		for _, value := range groupIDs {
			id, err := checkedString(value, "Discord server role id", idPattern)
			if err != nil {
				return drop("Discord server role metadata is invalid")
			}
			groups[id] = true
		}
		for _, entry := range role.Members {
			if entry.Kind == "role" && groups[entry.ID] {
				if entry.Authority == "decide" {
					authority = "decide"
				} else if authority == "" {
					authority = "inform"
				}
			}
		}
	}
	if authority == "" {
		return drop("sender is not listed for this channel")
	}
	display := ""
	for _, value := range []any{member["nick"], author["global_name"], author["username"]} {
		if name, ok := value.(string); ok && name != "" {
			display = name
			break
		}
	}
	text, textOK := payload["content"].(string)
	reference := map[string]any{}
	if value := payload["message_reference"]; value != nil {
		reference, ok = value.(map[string]any)
		if !ok {
			return drop("message text, display name or reply metadata is invalid")
		}
	}
	if display == "" || !textOK {
		return drop("message text, display name or reply metadata is invalid")
	}
	var replyTo any
	if value := reference["message_id"]; value != nil {
		id, err := checkedString(value, "reply message id", idPattern)
		if err != nil {
			return drop("reply message id is invalid")
		}
		replyTo = id
	}
	var name any = role.ChannelName
	if cached, exists := channelNames[role.ChannelID]; exists {
		name = cached
	}
	channel, err := channelName(name)
	if err != nil {
		return drop("channel name is unavailable")
	}
	return map[string]any{"role": role.Name, "instance": role.Instance,
		"channel":    map[string]any{"id": role.ChannelID, "name": channel},
		"author":     map[string]any{"id": authorID, "display_name": display, "authority": authority},
		"message_id": messageID, "text": text, "reply_to": replyTo}
}

// EventJSONLine returns the single line a gateway appends, or "drop".
func EventJSONLine(message any, roles map[string]Role, channelNames map[string]any, logger io.Writer) (string, error) {
	event := MessageToEvent(message, roles, channelNames, logger)
	if event == "drop" {
		return "drop", nil
	}
	data, err := json.Marshal(event)
	if err != nil {
		return "", refused("cannot encode Discord event")
	}
	return string(data) + "\n", nil
}
