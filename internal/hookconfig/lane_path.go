package hookconfig

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const lanePathInstead = "Instead: remove that entry from the runner's PATH (set PATH in the runner command's env prefix to directories the lane cannot write) and start again."

// Run after parsing every env prefix, before executing even a provider probe.
// Only bound org-instance runs receive the state grant and this PATH contract.
func vetLanePath(home, cwd string, environment map[string]string) error {
	if stateBinding(environment) == "" {
		return nil
	}
	state, err := boundInstanceState(home, environment)
	if err != nil {
		return err
	}
	if state == "" {
		return nil
	}
	roots, err := writableRootsIn(filepath.Join(home, "config.toml"), cwd, false, environment)
	if err != nil {
		return err
	}
	roots = append(roots, state)
	for _, entry := range strings.Split(environment["PATH"], string(os.PathListSeparator)) {
		refused := func() error {
			return fmt.Errorf("the Codex lane's PATH contains a directory the lane can write: %s\n%s", strconv.Quote(entry), lanePathInstead)
		}
		if entry == "" || !filepath.IsAbs(entry) {
			return refused()
		}
		resolved, err := filepath.EvalSymlinks(entry)
		if err != nil {
			return fmt.Errorf("the Codex lane's PATH entry cannot be resolved: %s\n%s", strconv.Quote(entry), lanePathInstead)
		}
		resolved, err = filepath.Abs(resolved)
		if err != nil {
			return refused()
		}
		for _, root := range roots {
			for _, candidate := range []string{filepath.Clean(entry), filepath.Clean(resolved)} {
				inside, err := containsPath(root, candidate)
				if err != nil {
					return err
				}
				if inside {
					return refused()
				}
			}
		}
	}
	return nil
}
