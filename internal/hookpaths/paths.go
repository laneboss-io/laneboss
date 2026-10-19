// Package hookpaths supplies the protected org policy inputs to both gates.
package hookpaths

import (
	"fmt"
	"os"
	"path/filepath"

	"laneboss.io/laneboss/internal/config"
	"laneboss.io/laneboss/internal/faults"
)

func List(home, executable string) ([]string, error) {
	// The decision guard reads three things from shared/services (docs/decisions.md, "Guiding agents"): guide.toml holds
	// its dial, history.toml says where the decision store is and which launcher configuration defines the judge, and
	// the store is what the guard reads, with the -wal, -shm and -journal files that SQLite keeps beside it. They are
	// policy like the hook rules: an agent that could remove, move or replace one of them could switch the guard off
	// without a word. The whole directory is protected, so no such file is left out, and a write to one of its parents
	// is refused as well. This only adds to what was protected before.
	services := filepath.Join(home, "shared", "services")
	if faults.Get("guide-services-unprotected").Point != "" {
		// The mutant: only guide.toml is protected, as it was; the store and history.toml are not.
		_ = faults.Reach("guide-services-unprotected")
		services = filepath.Join(services, "guide.toml")
	}
	paths := []string{filepath.Join(home, "org.toml"), filepath.Join(home, "hooks"), filepath.Join(home, "shared", "hooks"),
		filepath.Join(home, "shared", "refusals"), services, executable}
	if faults.Get("orghook-bl-state-unprotected").Point == "" {
		paths = append(paths, filepath.Join(home, "shared", "state"))
	} else {
		_ = faults.Reach("orghook-bl-state-unprotected")
	}
	// Neither the whole home nor the instances container is a protected subtree here: agents write ordinary state in
	// their own instance folder (layered settings row test_settings_protected's control, R26) and in unprotected
	// shared files (decision-guide G10). Each instance's policy files are protected one by one below. Residual: a
	// not-yet-rendered instance folder can be pre-created by an agent; the macOS sandbox profile protects the whole home.
	state, err := StateDir()
	if err != nil {
		return nil, err
	}
	if state != "" {
		paths = append(paths, state)
	}
	settingsProtected := faults.Get("settings-paths-unprotected").Point == ""
	if settingsProtected {
		paths = append(paths, filepath.Join(home, "settings.toml"))
	} else if err := faults.Reach("settings-paths-unprotected"); err != nil {
		return nil, err
	}
	definitions, err := judgeDefinition(home)
	if err != nil {
		return nil, err
	}
	paths = append(paths, definitions...)
	for level := 3; level <= 6; level++ {
		directory := filepath.Join(home, fmt.Sprintf("L%d", level))
		paths = append(paths, directory, filepath.Join(directory, "hooks"), filepath.Join(directory, "refusals"))
	}
	entries, err := os.ReadDir(filepath.Join(home, "instances"))
	if err != nil {
		return nil, fmt.Errorf("the instances directory is unreadable")
	}
	for _, entry := range entries {
		directory := filepath.Join(home, "instances", entry.Name())
		if settingsProtected {
			paths = append(paths, filepath.Join(directory, "settings.toml"))
		}
		// Keep the whole rendered vendor homes protected. The lane sandbox may
		// grant explicit runner-data exceptions, never the policy files themselves.
		// Instance containers stay in lanesandbox; hook denies also cover subpaths.
		for _, part := range []string{"instance.toml", ".claude", ".codex", ".claude/settings.json", ".codex/hooks.json", ".codex/config.toml", "hooks", "refusals"} {
			paths = append(paths, filepath.Join(directory, part))
		}
	}
	return paths, nil
}

// State records, journals, reports and other lanes' files are protected as a
// subtree. Only the CLI adapter may declare managed effects on this root.
func StateDir() (string, error) {
	if os.Getenv("LANEBOSS_CONFIG") == "" {
		return "", nil
	}
	c, err := config.Load("")
	if err != nil {
		return "", fmt.Errorf("the bound configuration state directory cannot be determined")
	}
	return c.StateDir, nil
}
