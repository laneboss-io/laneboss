package report

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"

	"laneboss.io/laneboss/internal/caller"
	"laneboss.io/laneboss/internal/config"
	"laneboss.io/laneboss/internal/eventstore"
	"laneboss.io/laneboss/internal/orgdiscord"
)

var discordChannelID = regexp.MustCompile(`^[1-9][0-9]{0,19}$`)

func ownerChannel(c *config.Configuration, to string) map[string]any {
	name := text(c.Data["owner_channel"])
	if strings.HasPrefix(to, "supervisor:") {
		row := table(table(c.Data["supervisors"])[strings.TrimPrefix(to, "supervisor:")])
		if value := text(row["owner_channel"]); value != "" {
			name = value
		}
	}
	return table(table(c.Data["owner_channels"])[name])
}

func orgDirectory(c *config.Configuration) string {
	return caller.ConfiguredOrgRoot(c)
}

func discordChannel(org, to string, owner map[string]any) (string, bool, error) {
	if text(owner["kind"]) == "chat" && text(owner["service"]) == "discord" {
		return text(owner["target"]), true, nil
	}
	if org == "" {
		return "", false, nil
	}
	roles, err := orgdiscord.ReadRoles(org, true)
	if err != nil {
		return "", true, err
	}
	name := to
	if _, suffix, found := strings.Cut(to, ":"); found {
		name = suffix
	}
	for key, role := range roles {
		if key == name || role.Instance == name {
			return role.ChannelID, true, nil
		}
	}
	return "", false, nil
}

func laneTerminalInstalled(store *eventstore.Configuration, lane string) (bool, error) {
	d, err := store.OpenDirectory(false)
	if err != nil || d == nil {
		return false, err
	}
	defer d.Close()
	s, err := eventstore.Open(d, false)
	if err != nil || s == nil {
		return false, err
	}
	defer s.Close()
	row, err := s.Lane(lane)
	if err != nil {
		return false, err
	}
	turns, _ := table(row["mail"])["turn_based"].(bool)
	return turns, nil
}

func installedChannels(c *config.Configuration, store *eventstore.Configuration, from caller.Principal, to caller.Principal, payload eventstore.Object, data []byte, sendLane LaneSender) []channel {
	owner := ownerChannel(c, to.ID)
	org := orgDirectory(c)
	discordID, discordInstalled, discordErr := discordChannel(org, to.ID, owner)
	terminalInstalled := false
	var terminalErr error
	if strings.HasPrefix(to.ID, "lane:") {
		terminalInstalled, terminalErr = laneTerminalInstalled(store, strings.TrimPrefix(to.ID, "lane:"))
	} else {
		terminalInstalled, terminalErr = terminalLive(c.StateDir, to.ID)
	}
	return []channel{
		{"dashboard", true, func() error { return appendRecord(store, from.ID, "report.sent", payload) }},
		{"discord", discordInstalled, func() error {
			if discordErr != nil {
				return discordErr
			}
			if !discordChannelID.MatchString(discordID) {
				return fmt.Errorf("the Discord target must be a positive channel ID")
			}
			if org == "" {
				return fmt.Errorf("Discord org configuration is unavailable")
			}
			client, err := orgdiscord.OpenReportClient(org)
			if err != nil {
				return err
			}
			defer client.Close()
			content := discordText(payload, data)
			reply, err := client.Request("POST", "/channels/"+discordID+"/messages", map[string]any{"content": content, "allowed_mentions": map[string]any{"parse": []string{}}})
			if err != nil {
				return err
			}
			id, err := client.VerifyMessage(reply, discordID, content, "")
			if err != nil {
				return err
			}
			read, err := client.Request("GET", "/channels/"+discordID+"/messages/"+id, nil)
			if err != nil {
				return err
			}
			_, err = client.VerifyMessage(read, discordID, content, id)
			return err
		}},
		{"file", to.ID == "human" && text(owner["kind"]) == "file", func() error { return appendFile(c.StateDir, text(owner["path"]), payload) }},
		{"terminal", terminalInstalled || terminalErr != nil, func() error {
			if terminalErr != nil {
				return terminalErr
			}
			if strings.HasPrefix(to.ID, "lane:") {
				if sendLane == nil {
					return fmt.Errorf("the lane mail adapter is unavailable")
				}
				return sendLane(c.Name, from, strings.TrimPrefix(to.ID, "lane:"), data)
			}
			return sendTerminal(c.StateDir, to.ID, payload)
		}},
	}
}

func discordText(payload eventstore.Object, data []byte) string {
	if payload["legacy_relationship"] == true {
		return "[legacy_relationship: true]\n\n" + string(data)
	}
	return string(data)
}

// Installed exposes the same channel discovery to the launcher's report-line
// section. It performs no delivery and does not expose credentials.
func Installed(configName, targetID string) (map[string]bool, error) {
	c, err := config.Load(configName)
	if err != nil {
		return nil, err
	}
	store, err := eventstore.Bind(c.Name)
	if err != nil {
		return nil, err
	}
	owner := ownerChannel(c, targetID)
	_, discord, discordErr := discordChannel(orgDirectory(c), targetID, owner)
	if discordErr != nil {
		return nil, discordErr
	}
	terminal := false
	if strings.HasPrefix(targetID, "lane:") {
		terminal, err = laneTerminalInstalled(store, strings.TrimPrefix(targetID, "lane:"))
	} else {
		terminal, err = terminalLive(c.StateDir, targetID)
	}
	if err != nil {
		return nil, err
	}
	return map[string]bool{"dashboard": true, "discord": discord, "file": targetID == "human" && text(owner["kind"]) == "file", "terminal": terminal}, nil
}

// checkComponents rejects every symbolic link, including links that stay
// inside the pinned root. Reads and writes additionally use os.Root and
// O_NOFOLLOW, so a replaced final component is refused.
func checkComponents(root *os.Root, relative string, createParents bool) error {
	if !filepath.IsLocal(relative) || strings.Contains(relative, "\\") {
		return fmt.Errorf("the channel path must stay inside its root")
	}
	parts := strings.Split(filepath.Clean(relative), string(filepath.Separator))
	current := ""
	for i, part := range parts {
		current = filepath.Join(current, part)
		info, err := root.Lstat(current)
		if errors.Is(err, os.ErrNotExist) {
			if i == len(parts)-1 || !createParents {
				return nil
			}
			if err = root.Mkdir(current, 0700); err != nil && !errors.Is(err, os.ErrExist) {
				return fmt.Errorf("cannot create channel directory")
			}
			info, err = root.Lstat(current)
		}
		if err != nil {
			return fmt.Errorf("cannot inspect channel path")
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("channel paths must not contain symbolic links")
		}
		if i < len(parts)-1 && !info.IsDir() {
			return fmt.Errorf("channel parent must be a directory")
		}
	}
	return nil
}

func appendFile(directory, relative string, payload eventstore.Object) error {
	root, err := os.OpenRoot(directory)
	if err != nil {
		return fmt.Errorf("cannot open the file channel root")
	}
	defer root.Close()
	if err = checkComponents(root, relative, true); err != nil {
		return err
	}
	file, err := root.OpenFile(relative, os.O_WRONLY|os.O_CREATE|os.O_APPEND|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0600)
	if err != nil {
		return fmt.Errorf("cannot open the file channel")
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return fmt.Errorf("the file channel must be a regular file")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Nlink != 1 {
		return fmt.Errorf("the file channel must not have multiple links")
	}
	if err = syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return fmt.Errorf("the file channel is busy")
	}
	defer syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
	data, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("cannot encode file channel report")
	}
	data = append(data, '\n')
	if n, err := file.Write(data); err != nil || n != len(data) {
		return fmt.Errorf("cannot append the complete report to the file channel")
	}
	if err = file.Sync(); err != nil {
		return fmt.Errorf("cannot sync the file channel")
	}
	if err = file.Close(); err != nil {
		return fmt.Errorf("cannot close the file channel")
	}
	return nil
}
