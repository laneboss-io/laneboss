package plugin

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"sort"
	"syscall"
)

// Inventory is shared by plugin list and the dashboard. It inspects only assets
// installed beside this launcher, never another tool's private plugin registry.
func Inventory() ([]map[string]any, error) {
	root, err := resourceRoot()
	if err != nil {
		return nil, err
	}
	directory, err := os.OpenRoot(filepath.Join(root, "plugins"))
	if os.IsNotExist(err) {
		return []map[string]any{}, nil
	}
	if err != nil {
		return nil, err
	}
	defer directory.Close()
	listing, err := directory.Open(".")
	if err != nil {
		return nil, err
	}
	entries, err := listing.ReadDir(-1)
	listing.Close()
	if err != nil {
		return nil, err
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	result := []map[string]any{}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		row := map[string]any{"agent": entry.Name(), "name": entry.Name(), "version": nil, "enabled": nil, "default_enabled": nil, "health": "error", "last_error": nil}
		manifest, err := directory.OpenFile(filepath.Join(entry.Name(), ".claude-plugin", "plugin.json"), os.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOFOLLOW, 0)
		if err != nil {
			row["last_error"] = "the installed manifest cannot be read"
		} else {
			info, statErr := manifest.Stat()
			data, readErr := io.ReadAll(io.LimitReader(manifest, 65537))
			manifest.Close()
			var document map[string]any
			if statErr != nil || !info.Mode().IsRegular() || readErr != nil || len(data) > 65536 || json.Unmarshal(data, &document) != nil {
				row["last_error"] = "the installed manifest is not a bounded JSON object"
			} else {
				name, nameOK := document["name"].(string)
				version, versionOK := document["version"].(string)
				if !nameOK || !versionOK || name == "" || version == "" {
					row["last_error"] = "the installed manifest needs a name and version"
				} else {
					row["name"], row["version"], row["health"] = name, version, "ok"
					if enabled, ok := document["defaultEnabled"].(bool); ok {
						row["default_enabled"] = enabled
					}
					// Agent enablement is not recorded by this CLI. A publisher
					// default does not establish the user's enabled state.
				}
			}
		}
		result = append(result, row)
	}
	return result, nil
}
