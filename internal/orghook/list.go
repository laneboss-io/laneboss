package orghook

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"laneboss.io/laneboss/internal/caller"
	"laneboss.io/laneboss/internal/config"
	"laneboss.io/laneboss/internal/rolepolicy"
	"laneboss.io/laneboss/internal/settings"
)

const listUsage = "usage: laneboss org blacklist list [--config NAME] [--format {text,json}]"

type listedBlacklistEntry struct {
	ID          string `json:"id"`
	Band        string `json:"band"`
	Description string `json:"description"`
	Instead     string `json:"instead"`
	Source      string `json:"source"`
}

type listedBuiltin struct {
	ID          string `json:"id"`
	Description string `json:"description"`
	Instead     string `json:"instead"`
}

type blacklistList struct {
	Config   string                 `json:"config"`
	Caller   string                 `json:"caller"`
	Level    int                    `json:"level"`
	Role     string                 `json:"role"`
	Instance string                 `json:"instance"`
	Sources  []string               `json:"sources"`
	Entries  []listedBlacklistEntry `json:"entries"`
	Builtins []listedBuiltin        `json:"builtins"`
	Notes    []string               `json:"notes"`
}

// listCallerInstance uses the same process-authenticated start record as the
// hook. CLI options cannot select a different level, role or instance.
func listCallerInstance(c *config.Configuration) (*instance, caller.Principal, error) {
	principal, record, err := caller.ResolveWithLane(c)
	if err != nil {
		return nil, principal, err
	}
	root, err := rolepolicy.ConfigRoot(c.Home, c.Data)
	if err != nil || root == "" {
		return nil, principal, invalid("blacklist list requires a configured org folder")
	}
	root, err = filepath.EvalSymlinks(root)
	if err != nil {
		return nil, principal, invalid("the configured org folder cannot be opened")
	}
	home := filepath.Join(root, ".laneboss")
	name, role := "", ""
	if record != nil {
		role, _ = record.Payload["role"].(string)
		if context, ok := record.Payload["role_context"].(map[string]any); ok {
			previous, _ := context["org_dir"].(string)
			previous, err = filepath.EvalSymlinks(previous)
			if err != nil || previous != root {
				return nil, principal, invalid("the lane's recorded org and configured org disagree")
			}
		}
		if record.Payload["settings"] != nil {
			snapshot, err := settings.Decode(record.Payload["settings"])
			if err != nil {
				return nil, principal, err
			}
			name = snapshot.Instance
		}
	} else if strings.HasPrefix(principal.ID, "instance:") {
		name = strings.TrimPrefix(principal.ID, "instance:")
	} else {
		return nil, principal, invalid("blacklist list requires an authenticated lane or org instance\nInstead: run laneboss org blacklist list inside the lane or instance session")
	}

	var inst *instance
	cwd, err := currentDirectory()
	if err != nil {
		return nil, principal, err
	}
	if name != "" {
		inst, err = findInstance(cwd, filepath.Join(home, "instances", name))
	} else {
		if os.Getenv("LANEBOSS_INSTANCE") != "" || instanceFromDirectory(cwd) != "" {
			inst, err = findInstance(cwd, "")
		} else {
			// A role-only lane has no instance-local rows. Its org and role
			// rows still come from the hook's effective-list loader.
			if rolepolicy.CheckName(role) != nil {
				return nil, principal, invalid("the lane has no recorded org role or selected hook instance")
			}
			policy, policyErr := parseHookBlacklist(home)
			if policyErr != nil {
				return nil, principal, policyErr
			}
			inst = &instance{home: home, directory: home, role: role, level: principal.Level,
				data: map[string]any{"role": role}, hookMode: policy.mode}
			inst.worktree, err = recordedLaneWorktree(record)
			if err == nil {
				inst.writableRepos = []string{inst.worktree}
				inst.blacklist, inst.blacklistSources, err = effectiveHookBlacklist(home, inst.level, role, policy.blacklist)
			}
		}
	}
	if err != nil {
		return nil, principal, err
	}
	if inst.home != home || inst.level != principal.Level || role != "" && inst.role != role {
		return nil, principal, invalid("the lane's recorded org, level or role and selected hook instance disagree")
	}
	return inst, principal, nil
}

func effectiveBlacklistList(inst *instance, principal caller.Principal, name string) (blacklistList, error) {
	result := blacklistList{Config: name, Caller: principal.ID, Level: inst.level, Role: inst.role,
		Instance: inst.name, Sources: inst.blacklistSources, Entries: []listedBlacklistEntry{}}
	rows, err := blacklistGuardRows(inst)
	if err != nil {
		return result, err
	}
	for _, row := range rows {
		if blacklistScopeApplies(row, inst) {
			result.Entries = append(result.Entries, listedBlacklistEntry{
				ID: row.id, Band: row.band, Description: row.description, Instead: row.instead, Source: row.source})
		}
	}
	result.Builtins = []listedBuiltin{
		{ID: "laneboss-files", Description: "Protected Laneboss policy files and state must not be edited directly.", Instead: "Use the checked Laneboss command; report policy changes to the supervisor."},
		{ID: "lane-network", Description: "Every lane is refused raw network clients and dashboard-port requests.", Instead: "Use laneboss report or laneboss lane send for permitted communication."},
		{ID: "lane-identity", Description: "Every lane is refused detached process identities and identity overrides.", Instead: "Keep the recorded lane identity and use the Laneboss lifecycle commands."},
		{ID: "lane-tmux", Description: "Every lane is refused direct access to lane tmux sockets.", Instead: "Use laneboss lane start, stop or attach."},
		{ID: "laneboss-obscured", Description: "Obscured forms in laneboss calls are refused when their effects cannot be inspected.", Instead: "Use a direct laneboss call with literal arguments."},
	}
	if inst.level == 3 {
		result.Builtins = append(result.Builtins, listedBuiltin{ID: "lane-worktree",
			Description: "L3 worktree boundary: writes must stay inside the recorded worktree, subject to an explicit org boundary grant; shared messages require the checked message route.",
			Instead:     "Write inside the lane worktree, or use laneboss report or laneboss lane send."})
	}
	result.Notes = []string{"Secret-file reads are refused only when an applicable org rule says so."}
	return result, nil
}

func runBlacklistList(args []string, stdout, stderr io.Writer) int {
	name, format := "", "text"
	seen := map[string]bool{}
	for i := 0; i < len(args); i++ {
		key, value, inline := strings.Cut(args[i], "=")
		if key != "--config" && key != "--format" || seen[key] {
			fmt.Fprintln(stderr, listUsage)
			return 2
		}
		if !inline {
			i++
			if i == len(args) {
				fmt.Fprintln(stderr, listUsage)
				return 2
			}
			value = args[i]
		}
		if value == "" || key == "--format" && value != "text" && value != "json" {
			fmt.Fprintln(stderr, listUsage)
			return 2
		}
		seen[key] = true
		if key == "--config" {
			name = value
		} else {
			format = value
		}
	}
	c, err := config.Load(name)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	inst, principal, err := listCallerInstance(c)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	result, err := effectiveBlacklistList(inst, principal, c.Name)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	if format == "json" {
		if err := json.NewEncoder(stdout).Encode(result); err != nil {
			return 1
		}
		return 0
	}
	var output bytes.Buffer
	fmt.Fprintf(&output, "Org hook rules for %s (L%d, %s)\n\nBlacklist entries (current sources):\n", result.Caller, result.Level, result.Role)
	if len(result.Entries) == 0 {
		output.WriteString("No applicable blacklist entries.\n")
	}
	for _, row := range result.Entries {
		label := "Refuses"
		if row.Band == "warn" {
			label = "Warns"
		}
		fmt.Fprintf(&output, "\n[%s] Band: %s\n%s: %s\nInstead: %s\nSource: %s\n", row.ID, row.Band, label, row.Description, row.Instead, row.Source)
	}
	output.WriteString("\nBuilt-in refusals (not blacklist entries):\n")
	for _, row := range result.Builtins {
		fmt.Fprintf(&output, "- %s\n  Instead: %s\n", row.Description, row.Instead)
	}
	for _, note := range result.Notes {
		fmt.Fprintln(&output, note)
	}
	output.WriteString("\nBlacklist source files, in hook order:\n")
	for _, source := range result.Sources {
		fmt.Fprintf(&output, "- %s\n", source)
	}
	if _, err := io.Copy(stdout, &output); err != nil {
		return 1
	}
	return 0
}
