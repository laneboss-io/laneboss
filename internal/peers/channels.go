package peers

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"laneboss.io/laneboss/internal/caller"
	"laneboss.io/laneboss/internal/config"
	"laneboss.io/laneboss/internal/orgdiscord"
)

// Channels reports installation from existing settings, never from a level guess.
// The report command independently records the result of actual delivery.
func Channels(c *config.Configuration, target string) (map[string]bool, error) {
	if target == "" {
		target = "human"
	}
	result := map[string]bool{"dashboard": true, "discord": false, "file": false, "terminal": false}
	channelName, _ := c.Data["owner_channel"].(string)
	if strings.HasPrefix(target, "supervisor:") {
		supervisors, _ := c.Data["supervisors"].(map[string]any)
		entry, _ := supervisors[strings.TrimPrefix(target, "supervisor:")].(map[string]any)
		if name, ok := entry["owner_channel"].(string); ok {
			channelName = name
		}
	}
	channels, _ := c.Data["owner_channels"].(map[string]any)
	channel, _ := channels[channelName].(map[string]any)
	result["file"] = target == "human" && channel["kind"] == "file"
	result["discord"] = channel["kind"] == "chat" && channel["service"] == "discord"
	if !result["discord"] {
		if org := caller.ConfiguredOrgRoot(c); org != "" {
			name := target
			if _, after, ok := strings.Cut(target, ":"); ok {
				name = after
			}
			installed, err := orgdiscord.Installed(org, name)
			if err != nil {
				return nil, fmt.Errorf("the report's Discord installation cannot be checked: %s", err)
			}
			result["discord"] = installed
		}
	}
	if strings.HasPrefix(target, "lane:") {
		all, err := caller.Lanes(c)
		if err != nil {
			return nil, err
		}
		if r, ok := all[strings.TrimPrefix(target, "lane:")]; ok {
			_, hasMail := r.Payload["mail"]
			_, adopted := r.Payload["idle_seconds"]
			result["terminal"] = hasMail || adopted
		}
	} else {
		live, err := terminalInstalled(c, target)
		if err != nil {
			return nil, err
		}
		result["terminal"] = live
	}
	return result, nil
}

func terminalInstalled(c *config.Configuration, target string) (bool, error) {
	root, err := os.OpenRoot(c.StateDir)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("the report's terminal installation cannot be checked")
	}
	defer root.Close()
	path := "reports/terminals/" + target
	info, err := root.Stat(path + ".fifo")
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("the report's terminal FIFO cannot be checked")
	}
	if info.Mode()&os.ModeNamedPipe == 0 {
		return false, fmt.Errorf("the report's terminal is not a FIFO")
	}
	data, err := root.ReadFile(path + ".json")
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil || len(data) > 1<<20 {
		return false, fmt.Errorf("the report's terminal identity cannot be read")
	}
	var ticket struct {
		Target  string         `json:"target"`
		Process map[string]any `json:"process"`
	}
	if json.Unmarshal(data, &ticket) != nil || ticket.Target != target {
		return false, fmt.Errorf("the report's terminal identity is invalid")
	}
	return caller.ProcessAlive(ticket.Process)
}
