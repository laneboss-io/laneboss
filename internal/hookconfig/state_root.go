package hookconfig

import (
	"bytes"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"syscall"

	"github.com/BurntSushi/toml"
	"laneboss.io/laneboss/internal/config"
	"laneboss.io/laneboss/internal/rolepolicy"
)

const stateRootRefusal = "unvetted hook or plugin key \"sandbox_workspace_write\".\"writable_roots\""

func launcherScope(environment map[string]string) map[string]string {
	return map[string]string{"LANEBOSS_CONFIG": environment["LANEBOSS_CONFIG"],
		"LANEBOSS_HOME": environment["LANEBOSS_HOME"], "LANEBOSS_STATE_HOME": environment["LANEBOSS_STATE_HOME"]}
}

func vetLauncherScope(scope, environment map[string]string) error {
	for name, value := range scope {
		if environment[name] != value {
			return trustError("runner environment", "Codex cannot change the launcher state scope: "+strconv.Quote(name))
		}
	}
	return nil
}

// Derive authority from the bound launcher's configuration, never the Codex
// document or its render marker. StateHome would grant other configurations too.
func stateBinding(environment map[string]string) string {
	if environment != nil {
		return environment["LANEBOSS_CONFIG"]
	}
	return os.Getenv("LANEBOSS_CONFIG")
}

func instanceState(home string, environment map[string]string) (string, error) {
	state, err := boundInstanceState(home, environment)
	if err != nil {
		return "", err
	}
	if state == "" {
		return "", trustError(home, stateRootRefusal)
	}
	return state, nil
}

// An unrelated, otherwise vetted hook home receives no automatic state grant.
// Explicit writable_roots still require instanceState's matching binding.
func boundInstanceState(home string, environment map[string]string) (string, error) {
	name := stateBinding(environment)
	if name == "" {
		return "", nil
	}
	var options []config.Options
	if environment != nil {
		user := environment["HOME"]
		if !filepath.IsAbs(user) {
			return "", trustError(home, stateRootRefusal)
		}
		configuration, states := environment["LANEBOSS_HOME"], environment["LANEBOSS_STATE_HOME"]
		if configuration == "" {
			configuration = filepath.Join(user, ".config", "laneboss")
		}
		if states == "" {
			states = filepath.Join(user, ".local", "state", "laneboss")
		}
		options = []config.Options{{Home: configuration, StateHome: states}}
	}
	c, err := config.Load(name, options...)
	if err != nil {
		return "", trustError(home, stateRootRefusal)
	}
	org, err := rolepolicy.ConfigRoot(c.Home, c.Data)
	if err != nil {
		return "", trustError(home, stateRootRefusal)
	}
	actual, err := filepath.EvalSymlinks(org)
	if err != nil {
		return "", trustError(home, stateRootRefusal)
	}
	if actual != filepath.Dir(filepath.Dir(filepath.Dir(filepath.Dir(home)))) {
		return "", nil
	}
	state, err := filepath.EvalSymlinks(c.StateDir)
	if err != nil {
		return "", trustError(home, stateRootRefusal)
	}
	if contains, err := containsPath(state, home); err != nil || contains {
		return "", trustError(home, stateRootRefusal)
	}
	return state, nil
}

// Check every component before inspecting identity. Cleaning first would hide
// '..' and following the final component would accept a symlink or bind alias.
func vetStateRoot(entry, state string) error {
	refuse := func() error { return trustError("writable_roots", stateRootRefusal) }
	if !filepath.IsAbs(entry) || filepath.Clean(entry) != entry || entry != state {
		return refuse()
	}
	for current := entry; ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || filepath.Base(current) == ".git" {
			return refuse()
		}
		if err := stateMount(current); err != nil {
			return refuse()
		}
		if current == filepath.Dir(current) {
			break
		}
	}
	owned, err := os.Stat(state)
	if err != nil {
		return refuse()
	}
	info, err := os.Lstat(entry)
	if err != nil || !os.SameFile(owned, info) {
		return refuse()
	}
	// No link, mount or Git metadata may make the grant reach outside the store.
	// Reject hard-linked files as well: a store entry must not alias a policy file.
	return filepath.WalkDir(entry, func(path string, item fs.DirEntry, err error) error {
		if err != nil || item.Name() == ".git" || item.Type()&os.ModeSymlink != 0 {
			return refuse()
		}
		info, err := item.Info()
		if err != nil {
			return refuse()
		}
		if err := stateMount(path); err != nil {
			return refuse()
		}
		if info.Mode().IsRegular() {
			metadata, ok := info.Sys().(*syscall.Stat_t)
			if !ok || metadata.Nlink != 1 {
				return refuse()
			}
		} else if !info.IsDir() {
			return refuse()
		}
		return nil
	})
}

func instanceDocument(path string, environment map[string]string) (map[string]any, error) {
	data, err := regularBytes(path)
	if err != nil {
		return nil, err
	}
	document := map[string]any{}
	if _, err := toml.Decode(string(data), &document); err != nil {
		return nil, trustError(path, "configuration is not valid TOML")
	}
	sandbox, _ := document["sandbox_workspace_write"].(map[string]any)
	if roots, present := sandbox["writable_roots"]; present {
		state, err := instanceState(filepath.Dir(path), environment)
		entries, ok := roots.([]any)
		if err != nil || !ok || len(entries) != 1 {
			return nil, trustError(path, stateRootRefusal)
		}
		entry, ok := entries[0].(string)
		if !ok || vetStateRoot(entry, state) != nil {
			return nil, trustError(path, stateRootRefusal)
		}
		// Only this one top-level key has authority. Recursive/profile/system
		// keys still go through the original fail-closed semantic predicate.
		delete(sandbox, "writable_roots")
	}
	if foreignHooks(document, "") {
		return nil, trustError(path, "unvetted hook or plugin key "+blockedKey(document, ""))
	}
	return document, nil
}

// Called only after full hook vetting, before the feature probes and exec.
// An existing root is vetted, never repaired or broadened by this renderer.
func renderStateRoot(home string, environment map[string]string) error {
	if stateBinding(environment) == "" {
		return nil // Standalone hook probes do not select a launcher store.
	}
	path := filepath.Join(home, "config.toml")
	document, err := instanceDocument(path, environment)
	if err != nil {
		return err
	}
	state, err := boundInstanceState(home, environment)
	if err != nil {
		return err
	}
	if state == "" {
		return nil
	}
	if err := vetStateRoot(state, state); err != nil {
		return err
	}
	sandbox, _ := document["sandbox_workspace_write"].(map[string]any)
	if sandbox == nil {
		return trustError(path, "sandbox_workspace_write must be a table")
	}
	sandbox["writable_roots"] = []string{state}
	var output bytes.Buffer
	if err := toml.NewEncoder(&output).Encode(document); err != nil {
		return trustError(path, "state root cannot be rendered")
	}
	current, err := regularBytes(path)
	if err != nil {
		return err
	}
	// Preserve ordinary user text, comments and notices when already rendered.
	var parsed map[string]any
	if _, err := toml.Decode(string(current), &parsed); err == nil {
		if table, ok := parsed["sandbox_workspace_write"].(map[string]any); ok {
			if _, present := table["writable_roots"]; present {
				return nil
			}
		}
	}
	file, err := os.CreateTemp(home, ".state-root-*")
	if err != nil {
		return trustError(path, "state root cannot be staged")
	}
	defer os.Remove(file.Name())
	if _, err := file.Write(output.Bytes()); err != nil {
		file.Close()
		return trustError(path, "state root cannot be written")
	}
	if err := file.Chmod(0444); err != nil {
		file.Close()
		return trustError(path, "state root cannot be protected")
	}
	if err := file.Close(); err != nil {
		return trustError(path, "state root cannot be closed")
	}
	if err := os.Rename(file.Name(), path); err != nil {
		return trustError(path, "state root cannot be installed")
	}
	return nil
}
