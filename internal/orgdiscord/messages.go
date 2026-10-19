package orgdiscord

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strconv"
	"time"
	"unicode/utf8"
)

// ReadMessages opens only each registered role's events file in its instance's
// laneboss state directory. The CLI's role/file readers pin the org and refuse
// escaping links. No messaging tool's home, credentials or settings are read.
func ReadMessages(org string) ([]map[string]any, error) {
	return ReadMessagesContext(context.Background(), org)
}

func ReadMessagesContext(ctx context.Context, org string) ([]map[string]any, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	files, err := openOrg(org)
	if err != nil {
		return nil, err
	}
	defer files.close()
	roles, err := readRoles(files, true)
	if err != nil {
		return nil, err
	}
	result := []map[string]any{}
	for _, name := range sortedNames(roles) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		role := roles[name]
		path := filepath.Join(".laneboss", "instances", role.Instance, "state", role.EventsFile)
		if _, err := files.root.Lstat(path); os.IsNotExist(err) {
			continue
		} else if err != nil {
			return nil, refused("the registered message log cannot be inspected")
		}
		data, err := files.readContext(ctx, path, "the registered message log")
		if err != nil {
			return nil, err
		}
		if !utf8.Valid(data) {
			return nil, refused("the registered message log must be UTF-8")
		}
		for _, line := range bytes.Split(data, []byte{'\n'}) {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			if len(bytes.TrimSpace(line)) == 0 {
				continue
			}
			value, err := parseJSON(line, "the registered message event")
			record, objectOK := value.(map[string]any)
			if err != nil || !objectOK || record["role"] != role.Name || record["instance"] != role.Instance {
				return nil, refused("the registered message log holds an invalid channel event")
			}
			text, ok := record["text"].(string)
			author, authorOK := record["author"].(map[string]any)
			channel, channelOK := record["channel"].(map[string]any)
			if !ok || !authorOK || !channelOK || channel["id"] != role.ChannelID {
				return nil, refused("the registered message log holds an invalid channel event")
			}
			if _, err := checkedString(record["message_id"], "message id", idPattern); err != nil {
				return nil, err
			}
			if _, err := checkedString(author["id"], "author id", idPattern); err != nil {
				return nil, err
			}
			if _, ok := author["display_name"].(string); !ok || author["authority"] != "decide" && author["authority"] != "inform" {
				return nil, refused("the registered message log holds invalid author metadata")
			}
			var at any
			// The converter preserves a Discord snowflake, whose timestamp is
			// intrinsic to the stored ID; never substitute a file's mtime.
			if id, ok := record["message_id"].(string); ok {
				if number, err := strconv.ParseUint(id, 10, 64); err == nil {
					at = time.UnixMilli(int64(number>>22) + 1420070400000).UTC().Format(time.RFC3339Nano)
				}
			}
			result = append(result, map[string]any{"id": record["message_id"], "time": at, "direction": "inbound", "sender_role": "human", "authority": author["authority"], "from": author["display_name"], "to": role.Instance, "text": text, "kind": "orgdiscord.message"})
		}
	}
	return result, nil
}
