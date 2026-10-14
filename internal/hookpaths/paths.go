// Package hookpaths supplies the protected org policy inputs to both gates.
package hookpaths

import (
	"fmt"
	"os"
	"path/filepath"
)

func List(home, executable string) ([]string, error) {
	paths := []string{filepath.Join(home, "org.toml"), filepath.Join(home, "shared", "hooks"),
		filepath.Join(home, "shared", "refusals"), executable}
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
		for _, part := range []string{"instance.toml", ".claude", ".codex", "hooks", "refusals"} {
			paths = append(paths, filepath.Join(directory, part))
		}
	}
	return paths, nil
}
