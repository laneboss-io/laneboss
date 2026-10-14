package hookconfig

import (
	"errors"
	"strconv"
	"strings"
	"unicode"

	"github.com/BurntSushi/toml"
)

func vetOverride(value string) error {
	key, raw, ok := strings.Cut(value, "=")
	key = strings.TrimFunc(key, unicode.IsSpace)
	raw = strings.TrimFunc(raw, unicode.IsSpace)
	if !ok || key == "" {
		return errors.New("Codex command config is incomplete")
	}
	if key+"="+raw == CodexEnable {
		return nil
	}
	document := map[string]any{}
	if _, err := toml.Decode("value="+raw, &document); err != nil {
		if strings.ContainsAny(raw, "{[") {
			return errors.New("Codex command config contains an unparsed table or array")
		}
		// Codex retains an unparsable right-hand value as a plain string.
		document["value"] = raw
	}
	for _, part := range strings.Split(key, ".") {
		part = strings.Trim(part, " \t\"'")
		var partValue any
		if part == "approval_policy" {
			partValue = document["value"]
		}
		if part == "" || strings.EqualFold(part, "plugins") || overrideKeys(map[string]any{part: partValue}) {
			return errors.New("Codex command config changes an unvetted hook, permission or project key " + strconv.Quote(part))
		}
	}
	if overrideKeys(document) {
		return errors.New("Codex command config changes an unvetted hook or permission key " + blockedKey(document, ""))
	}
	return nil
}

func vetConfigArgs(args []string) error {
	if err := vetSandboxArgs(args); err != nil {
		return err
	}
	for i := 0; i < len(args); i++ {
		word := args[i]
		if word == "--" {
			break
		}
		if (word == "--enable" || word == "--disable") && i+1 < len(args) && permissionFeature(args[i+1]) {
			return errors.New("Codex permission or approval feature switches cannot carry hook trust")
		}
		if (strings.HasPrefix(word, "--enable=") || strings.HasPrefix(word, "--disable=")) && permissionFeature(strings.SplitN(word, "=", 2)[1]) {
			return errors.New("Codex permission or approval feature switches cannot carry hook trust")
		}
		if word == "--enable" && i+1 < len(args) && pluginFeature(args[i+1]) {
			return errors.New("Codex enabled plugins cannot be granted hook trust")
		}
		if strings.HasPrefix(word, "--enable=") && pluginFeature(strings.TrimPrefix(word, "--enable=")) {
			return errors.New("Codex enabled plugins cannot be granted hook trust")
		}
		if word == "-C" || strings.HasPrefix(word, "--cd") || (strings.HasPrefix(word, "-C") && len(word) > 2) {
			return errors.New("Codex directory overrides cannot be vetted; use the lane worktree")
		}
		if word == "-c" || word == "--config" {
			i++
			if i >= len(args) {
				return errors.New("Codex command config is incomplete")
			}
			if err := vetOverride(args[i]); err != nil {
				return err
			}
		} else if strings.HasPrefix(word, "--config=") || (strings.HasPrefix(word, "-c") && len(word) > 2) {
			value := strings.TrimPrefix(word, "--config=")
			if strings.HasPrefix(word, "-c") {
				value = strings.TrimPrefix(word[2:], "=")
			}
			if err := vetOverride(value); err != nil {
				return err
			}
		}
	}
	return nil
}

func overrideKeys(value any) bool {
	switch node := value.(type) {
	case map[string]any:
		for key, child := range node {
			if key == "plugins" && enabledPlugins(child) {
				return true
			}
			if strings.Contains(strings.ToLower(key), "hook") || key == "managed_dir" || key == "project_root_markers" || sandboxKey(key) ||
				permissionKey(key) || key == "agents" || agentFeature(key) || (key == "approval_policy" && child != "never") {
				return true
			}
			if overrideKeys(child) {
				return true
			}
		}
	case []any:
		for _, child := range node {
			if overrideKeys(child) {
				return true
			}
		}
	case []map[string]any:
		for _, child := range node {
			if overrideKeys(child) {
				return true
			}
		}
	}
	return false
}

func pluginFeature(value string) bool {
	for _, name := range strings.Split(value, ",") {
		if strings.Contains(strings.ToLower(strings.TrimSpace(name)), "plugin") {
			return true
		}
	}
	return false
}

func permissionFeature(value string) bool {
	for _, name := range strings.Split(value, ",") {
		name = strings.TrimSpace(name)
		if permissionKey(name) || sandboxKey(name) || agentFeature(name) || name == "agents" || name == "approval_policy" || name == "auto_review" {
			return true
		}
	}
	return false
}

func enabledPlugins(value any) bool {
	entries, ok := value.(map[string]any)
	if !ok {
		return value != false && value != nil
	}
	for _, entry := range entries {
		if table, ok := entry.(map[string]any); ok {
			if disabled, known := table["enabled"].(bool); known && !disabled {
				continue
			}
			return true
		}
		if enabled, known := entry.(bool); !known || enabled {
			return true
		}
	}
	return false
}
