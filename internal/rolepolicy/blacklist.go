package rolepolicy

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/BurntSushi/toml"
	"laneboss.io/laneboss/internal/faults"
	"laneboss.io/laneboss/internal/hookblacklist"
)

// BlacklistSource retains the defining pair even when a lower level inherits it.
type BlacklistSource struct {
	Level int
	Role  string
	Path  string
	Bytes []byte
	Rows  []hookblacklist.Rule
}

func roleBlacklist(data []byte, filename string) ([]hookblacklist.Rule, error) {
	var document map[string]any
	if _, err := toml.Decode(string(data), &document); err != nil {
		return nil, fmt.Errorf("%s must be valid role TOML", filename)
	}
	return hookblacklist.Parse(document["blacklist"], filename+" blacklist")
}

// EffectiveBlacklist includes the selected pair and every higher level's roles.
// Empty org-owned sources are retained so agents can read every applicable
// source. Built-in fallbacks have no source file. Scope is applied by the hook.
func (c *Catalog) EffectiveBlacklist(level int, role string) ([]BlacklistSource, error) {
	upwards := faults.Get("roles-blacklist-upwards").Point != ""
	sameRole := faults.Get("roles-blacklist-same-role").Point != ""
	for _, point := range []string{"roles-blacklist-upwards", "roles-blacklist-same-role"} {
		if faults.Get(point).Point != "" {
			if err := faults.Reach(point); err != nil {
				return nil, err
			}
		}
	}
	result := []BlacklistSource{}
	for sourceLevel := 3; sourceLevel <= 6; sourceLevel++ {
		higher := sourceLevel > level
		if upwards {
			higher = sourceLevel < level
		}
		if sourceLevel != level && !higher {
			continue
		}
		for _, sourceRole := range c.Roles(sourceLevel) {
			if (sourceLevel == level || sameRole) && sourceRole != role {
				continue
			}
			template := c.Levels[sourceLevel].Roles[sourceRole]
			if !strings.HasPrefix(template.Path, ".laneboss/") {
				continue
			}
			result = append(result, BlacklistSource{Level: sourceLevel, Role: sourceRole,
				Path: filepath.Join(c.Root, template.DriverPath), Bytes: template.DriverBytes, Rows: template.Blacklist})
		}
	}
	return result, nil
}

// BlacklistSourcePaths projects the same ordered sources used by the hook.
// org.toml is required by both catalog and hook loading, even without entries.
func BlacklistSourcePaths(root string, sources []BlacklistSource) []string {
	paths := []string{filepath.Join(root, ".laneboss", "org.toml")}
	for _, source := range sources {
		paths = append(paths, source.Path)
	}
	return paths
}
