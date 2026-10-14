package hookconfig

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"syscall"

	"github.com/BurntSushi/toml"
	"laneboss.io/laneboss/internal/hookpaths"
)

const CodexTrustBypass = "--dangerously-bypass-hook-trust"
const CodexTrustRefusal = "Codex hook trust vetting refused: re-render the instance hooks and remove repository or system hook sources"

type RenderedHooks struct {
	Home             string `json:"home"`
	Instance         string `json:"instance"`
	SHA256           string `json:"sha256"`
	Command          string `json:"command"`
	Executable       string `json:"executable"`
	ExecutableSHA256 string `json:"executable_sha256"`
}

func RenderMarkerPath(home string) string {
	return filepath.Join(filepath.Dir(home), "hooks", "codex-render.json")
}

func trustError(path, rule string) error {
	return fmt.Errorf("Codex hook trust vetting refused: %s: %s", path, rule)
}

func containsPath(directory, target string) (bool, error) {
	container, err := os.Stat(directory)
	if err != nil || !container.IsDir() {
		return false, trustError(directory, "working directory cannot be inspected")
	}
	paths := []string{target}
	resolved, err := filepath.EvalSymlinks(target)
	if err == nil && resolved != target {
		paths = append(paths, resolved)
	} else if err != nil && !os.IsNotExist(err) {
		return false, trustError(target, "vetted path cannot be resolved")
	}
	for _, path := range paths {
		for current := filepath.Clean(path); ; current = filepath.Dir(current) {
			info, err := os.Stat(current)
			if err != nil && !os.IsNotExist(err) {
				return false, trustError(current, "path ancestor cannot be inspected")
			}
			if err == nil && os.SameFile(container, info) {
				return true, nil
			}
			if filepath.Dir(current) == current {
				break
			}
		}
	}
	return false, nil
}

func vetCwd(home, cwd string, extra ...string) error {
	if inside, err := containsPath(home, cwd); err != nil {
		return err
	} else if inside {
		return trustError(cwd, "working directory must not be at or below vetted Codex home "+home)
	}
	paths := []string{home, filepath.Join(filepath.Dir(home), "instance.toml"), RenderMarkerPath(home),
		filepath.Join(home, "hooks.json"), filepath.Join(home, "config.toml")}
	paths = append(paths, extra...)
	// First find every enclosing protected directory, regardless of list order.
	for _, path := range paths {
		if info, err := os.Stat(path); err == nil && info.IsDir() {
			if inside, err := containsPath(path, cwd); err != nil {
				return err
			} else if inside {
				return trustError(cwd, "working directory must not be inside protected policy input "+path)
			}
		}
	}
	for _, path := range paths {
		if contains, err := containsPath(cwd, path); err != nil {
			return err
		} else if contains {
			return trustError(cwd, "working directory must not contain vetted Codex input "+path)
		}
	}
	return nil
}

func regularBytes(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, trustError(path, "file cannot be inspected")
	}
	if !info.Mode().IsRegular() {
		return nil, trustError(path, "file must be regular without a symbolic link")
	}
	if info.Size() > 2*1024*1024 {
		return nil, trustError(path, "file exceeds the configuration size limit")
	}
	metadata, ok := info.Sys().(*syscall.Stat_t)
	if !ok || metadata.Nlink != 1 {
		return nil, trustError(path, "file must have exactly one hard link")
	}
	parent, err := filepath.EvalSymlinks(filepath.Dir(path))
	if err != nil || parent != filepath.Dir(path) {
		return nil, trustError(path, "parent path must have no symbolic alias")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, trustError(path, "file cannot be opened")
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return nil, trustError(path, "file identity changed while opening")
	}
	data, err := io.ReadAll(io.LimitReader(file, 2*1024*1024+1))
	if err != nil || len(data) > 2*1024*1024 {
		return nil, trustError(path, "file cannot be read within the configuration size limit")
	}
	return data, nil
}

func foreignHooks(document map[string]any, parent string) bool {
	for key, value := range document {
		if parent == "projects" {
			// Project table keys are path names, not configuration directives.
			child, ok := value.(map[string]any)
			if !ok || foreignHooks(child, "project") {
				return true
			}
			continue
		}
		if permissionKey(key) || (key == "approval_policy" && value != "never") {
			return true
		}
		if (key == "agents" && !agentsSafe(value)) || (agentFeature(key) && value != false) {
			return true
		}
		if key == "writable_roots" || (key == "sandbox_workspace_write" && !sandboxSafe(value)) ||
			((key == "exclude_slash_tmp" || key == "exclude_tmpdir_env_var") && value != true) ||
			(key == "sandbox_mode" && value != "workspace-write" && value != "read-only") {
			return true
		}
		if key == "plugins" && enabledPlugins(value) {
			return true
		}
		if parent == "features" && pluginFeature(key) && value != false {
			return true
		}
		if strings.Contains(strings.ToLower(key), "hook") && !(parent == "features" && key == "hooks") {
			return true
		}
		if key == "managed_dir" || key == "project_root_markers" {
			return true
		}
		if child, ok := value.(map[string]any); ok && foreignHooks(child, key) {
			return true
		}
		if children, ok := value.([]map[string]any); ok {
			for _, child := range children {
				if foreignHooks(child, key) {
					return true
				}
			}
		}
		if children, ok := value.([]any); ok {
			for _, child := range children {
				if foreignValue(child, key) {
					return true
				}
			}
		}
	}
	return false
}

func foreignValue(value any, parent string) bool {
	switch node := value.(type) {
	case map[string]any:
		return foreignHooks(node, parent)
	case []any:
		for _, child := range node {
			if foreignValue(child, parent) {
				return true
			}
		}
	case []map[string]any:
		for _, child := range node {
			if foreignHooks(child, parent) {
				return true
			}
		}
	}
	return false
}

// blockedKey locates a refusal through the same semantic predicate, without values.
func blockedKey(document map[string]any, parent string) string {
	keys := make([]string, 0, len(document))
	for key := range document {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		value := document[key]
		if !foreignHooks(map[string]any{key: value}, parent) {
			continue
		}
		name := strconv.Quote(key)
		if key == "agents" {
			if table, ok := value.(map[string]any); ok {
				if table["enabled"] != false {
					return name + "." + strconv.Quote("enabled")
				}
				roles := make([]string, 0, len(table))
				for role := range table {
					if role != "enabled" {
						roles = append(roles, role)
					}
				}
				sort.Strings(roles)
				if len(roles) > 0 {
					return name + "." + strconv.Quote(roles[0])
				}
			}
			return name
		}
		context := key
		switch parent {
		case "projects":
			context = "project"
		}
		if child := blockedValue(value, context); child != "" {
			name += "." + child
		}
		return name
	}
	return ""
}

func blockedValue(value any, parent string) string {
	switch node := value.(type) {
	case map[string]any:
		return blockedKey(node, parent)
	case []any:
		for index, child := range node {
			if key := blockedValue(child, parent); key != "" {
				return fmt.Sprintf("[%d].%s", index, key)
			}
		}
	case []map[string]any:
		for index, child := range node {
			if key := blockedKey(child, parent); key != "" {
				return fmt.Sprintf("[%d].%s", index, key)
			}
		}
	}
	return ""
}

func checkConfig(path string) error {
	if _, err := os.Lstat(path); os.IsNotExist(err) {
		return nil
	}
	data, err := regularBytes(path)
	if err != nil {
		return err
	}
	document := map[string]any{}
	if _, err := toml.Decode(string(data), &document); err != nil {
		return trustError(path, "configuration is not valid TOML")
	}
	if foreignHooks(document, "") {
		return trustError(path, "unvetted hook or plugin key "+blockedKey(document, ""))
	}
	return nil
}

func checkSystemHooks(systemHome string) error {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		return trustError("system configuration", "Codex system hook sources cannot be vetted on this OS")
	}
	for _, path := range []string{"/etc/codex/config.toml", "/etc/codex/requirements.toml", "/etc/codex/managed_config.toml"} {
		if err := checkConfig(path); err != nil {
			return fmt.Errorf("Codex system configuration has hooks or cannot be vetted: %w", err)
		}
	}
	paths := []string{"/etc/codex/hooks.json", "/etc/codex/managed"}
	if runtime.GOOS == "darwin" {
		if systemHome == "" || !filepath.IsAbs(systemHome) {
			return trustError("user preference home", "Codex user preference layer cannot be vetted")
		}
		paths = append(paths, "/Library/Managed Preferences/com.openai.codex.plist", "/Library/Preferences/com.openai.codex.plist")
		identity, err := user.LookupId(strconv.Itoa(os.Geteuid()))
		if err != nil {
			return trustError("account preference home", "account identity cannot be resolved")
		}
		if err := vetPrefs(systemHome, identity.HomeDir); err != nil {
			return err
		}
		if err := inspectPlist("/Library/Preferences/.GlobalPreferences.plist"); err != nil {
			return err
		}
		paths = append(paths, filepath.Join("/Library/Managed Preferences", identity.Username, "com.openai.codex.plist"))
	}
	for _, path := range paths {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			return trustError(path, "Codex system hook source exists or cannot be vetted")
		}
	}
	return nil
}

func systemPrefs(home string) error {
	if err := prefDirectory(home); err != nil {
		return fmt.Errorf("Codex user preference source exists or cannot be vetted: %w", err)
	}
	return nil
}

// VetCodex checks every supported configuration layer before granting invocation-local trust.
func VetCodex(home, cwd string, userHomes ...string) error {
	if !filepath.IsAbs(home) || filepath.Base(home) != ".codex" {
		return trustError("CODEX_HOME", "must name an absolute instance .codex directory")
	}
	if !filepath.IsAbs(cwd) {
		return trustError("worktree", "must name an absolute directory")
	}
	actual, err := filepath.EvalSymlinks(cwd)
	if err != nil {
		return trustError(cwd, "Codex working directory cannot be vetted")
	}
	markerPath := RenderMarkerPath(home)
	markerBytes, err := regularBytes(markerPath)
	if err != nil {
		return err
	}
	var marker RenderedHooks
	if json.Unmarshal(markerBytes, &marker) != nil {
		return trustError(markerPath, "render marker is not valid JSON")
	}
	if marker.Home != home || marker.Instance != filepath.Join(filepath.Dir(home), "instance.toml") {
		return trustError(markerPath, "render marker home or instance does not match")
	}
	if !filepath.IsAbs(marker.Executable) {
		return trustError(markerPath, "executable must name an absolute readable file")
	}
	orgHome := filepath.Dir(filepath.Dir(filepath.Dir(home)))
	if filepath.Base(filepath.Dir(filepath.Dir(home))) != "instances" || filepath.Base(orgHome) != ".laneboss" {
		return trustError(home, "instance org policy directory cannot be determined")
	}
	protected, err := hookpaths.List(orgHome, marker.Executable)
	if err != nil {
		return trustError(orgHome, err.Error())
	}
	roots, err := writableRoots(filepath.Join(home, "config.toml"), actual)
	if err != nil {
		return err
	}
	if err := vetWriteRoots(home, roots, protected); err != nil {
		return err
	}
	hooksPath := filepath.Join(home, "hooks.json")
	data, err := regularBytes(hooksPath)
	if err != nil {
		return err
	}
	if hash(data) != marker.SHA256 {
		return trustError(hooksPath, "Codex instance hooks.json differs from its laneboss render; re-render before launching")
	}
	var document map[string]any
	if json.Unmarshal(data, &document) != nil {
		return trustError(hooksPath, "hooks document is not valid JSON")
	}
	if err := CodexKeys(document); err != nil {
		return trustError(hooksPath, err.Error())
	}
	hooks, _ := document["hooks"].(map[string]any)
	rows, _ := hooks["PreToolUse"].([]any)
	if len(hooks) != 1 || len(rows) != 1 {
		return trustError(hooksPath, "hooks.PreToolUse must contain only laneboss's rendered org hook")
	}
	row, _ := rows[0].(map[string]any)
	commands, _ := row["hooks"].([]any)
	if len(row) != 2 || row["matcher"] != "" || len(commands) != 1 {
		return trustError(hooksPath, "hooks.PreToolUse matcher or command count differs from the render")
	}
	command, _ := commands[0].(map[string]any)
	if len(command) != 2 || command["type"] != "command" || command["command"] != marker.Command {
		return trustError(hooksPath, "hooks.PreToolUse command differs from the render")
	}
	file, err := os.Open(marker.Executable)
	if err != nil || !filepath.IsAbs(marker.Executable) {
		if file != nil {
			file.Close()
		}
		return trustError(markerPath, "executable must name an absolute readable file")
	}
	sum := sha256.New()
	_, err = io.Copy(sum, file)
	file.Close()
	if err != nil || hex.EncodeToString(sum.Sum(nil)) != marker.ExecutableSHA256 {
		return trustError(markerPath, "laneboss org-hook executable changed; re-render before launching")
	}
	if err := checkConfig(filepath.Join(home, "config.toml")); err != nil {
		return err
	}
	if err := vetRepository(actual, home); err != nil {
		return err
	}
	systemHome, _ := os.UserHomeDir()
	if len(userHomes) > 0 {
		systemHome = userHomes[0]
	}
	return checkSystemHooks(systemHome)
}

func vetRepository(cwd, home string) error {
	instance, err := os.Stat(filepath.Dir(home))
	if err != nil {
		return trustError(filepath.Dir(home), "instance directory cannot be inspected")
	}
	owned, err := os.Stat(home)
	if err != nil {
		return trustError(home, "vetted home cannot be inspected")
	}
	// Inspect repository ancestors through the closest Git root, or the filesystem root.
	for directory := filepath.Clean(cwd); ; directory = filepath.Dir(directory) {
		info, err := os.Stat(directory)
		if err != nil {
			return trustError(directory, "repository ancestor cannot be inspected")
		}
		candidate := filepath.Join(directory, ".codex")
		source, sourceErr := os.Lstat(candidate)
		vettedHome := os.SameFile(instance, info) && sourceErr == nil && source.IsDir() && os.SameFile(owned, source)
		if !vettedHome {
			path := filepath.Join(candidate, "hooks.json")
			if _, err := os.Lstat(path); !os.IsNotExist(err) {
				return trustError(path, "repository must not inject hooks into a Codex bypass run")
			}
			if err := checkConfig(filepath.Join(candidate, "config.toml")); err != nil {
				return fmt.Errorf("repository must not inject hooks into a Codex bypass run: %w", err)
			}
		}
		if filepath.Dir(directory) == directory {
			break
		}
		main, found, err := gitMain(directory)
		if err != nil {
			return err
		}
		if found {
			if main != directory {
				return vetMainSources(cwd, directory, main)
			}
			break
		}
	}
	return nil
}
