// Package lanesandbox prepares a runner-only policy protecting Laneboss files.
// It does not define a worktree, read, network, tool or package-manager boundary.
package lanesandbox

import (
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"unicode/utf8"

	"laneboss.io/laneboss/internal/faults"
	"laneboss.io/laneboss/internal/hookpaths"
	"laneboss.io/laneboss/internal/rolepolicy"
)

const Mode = "laneboss-files"

const RunnerReplaced = "runner sandbox: replaced by laneboss lane sandbox"

// Enabled reads the configuration-owned opt-in without changing defaults.
func Enabled(data map[string]any) bool {
	lanes, _ := data["lanes"].(map[string]any)
	return lanes["sandbox"] == Mode
}

// ValidateEvent checks the optional execution-policy record on historic runs.
func ValidateEvent(payload map[string]any) error {
	if value, exists := payload["runner_sandbox"]; exists && value != RunnerReplaced {
		return errors.New("runner_sandbox must name the recorded Laneboss replacement")
	}
	return nil
}

// Configuration contains launcher-owned locations, never runner-supplied paths.
// ServiceSocketDir is supplied by the service integration when it is present;
// it is not a new configuration-file key on the 0.7.0 line.
type Configuration struct {
	Home, StateHome, Directory, StateDir, Executable, ServiceSocketDir string
	Data                                                               map[string]any
}

// ProtectedPaths reuses the org hook's policy inputs and protects both whole
// launcher roots, relocated configuration/state and the socket directory. Missing
// leaves stay exact leaves: an existing ancestor is never protected instead.
func ProtectedPaths(c Configuration) ([]string, error) {
	for _, root := range []string{c.Home, c.StateHome} {
		if !validPath(root) {
			return nil, errors.New("launcher home and state root must be nonempty absolute directories")
		}
		resolved, err := filepath.EvalSymlinks(root)
		if err != nil || !validPath(resolved) {
			return nil, errors.New("launcher home or state root cannot be resolved")
		}
		info, err := os.Stat(resolved)
		if err != nil || !info.IsDir() {
			return nil, errors.New("launcher home and state root must exist as directories")
		}
	}
	if c.Directory == "" || c.StateDir == "" {
		return nil, errors.New("configuration and state locations are required")
	}
	paths := []string{c.Directory, c.StateDir}
	if faults.Get("sandbox-drop-home").Point != "" {
		if err := faults.Reach("sandbox-drop-home"); err != nil {
			return nil, err
		}
	} else {
		paths = append(paths, c.Home, c.StateHome)
	}
	lanes, _ := c.Data["lanes"].(map[string]any)
	if extra, exists := lanes["sandbox_deny_extra"]; exists {
		items, ok := extra.([]any)
		if !ok {
			return nil, errors.New("sandbox_deny_extra must be an array of absolute paths")
		}
		for _, item := range items {
			path, ok := item.(string)
			if !ok || !validPath(path) {
				return nil, errors.New("sandbox_deny_extra must contain absolute non-root paths")
			}
			paths = append(paths, path)
		}
	}
	if c.ServiceSocketDir != "" {
		paths = append(paths, c.ServiceSocketDir)
	}
	if c.Executable != "" {
		paths = append(paths, c.Executable)
	}
	org, err := rolepolicy.ConfigRoot(c.Home, c.Data)
	if err != nil {
		return nil, errors.New("the configured org location is invalid")
	}
	if org != "" {
		// Include the org and instance containers, so an external org's policy
		// leaves and future instances inherit subpath protection as well.
		orgPaths, err := hookpaths.List(filepath.Join(org, ".laneboss"), c.Executable)
		if err != nil {
			return nil, err
		}
		// The whole org home is protected here, in the sandbox profile, and not in hookpaths.List: the org hook reads
		// that list as subtrees, and the whole home there would refuse ordinary writes to unprotected shared files
		// (decision-guide row G10's control, R26). The instances container is in both.
		orgPaths = append(orgPaths, filepath.Join(org, ".laneboss"))
		for _, path := range orgPaths {
			if path != "" {
				paths = append(paths, path)
			}
		}
	}
	return normalizePaths(paths)
}

func validPath(path string) bool {
	return utf8.ValidString(path) && filepath.IsAbs(path) && filepath.Clean(path) != string(filepath.Separator) &&
		strings.IndexFunc(path, func(r rune) bool { return r < 32 || r == 127 }) < 0
}

// resolveMissing resolves existing links while retaining the names of every
// missing component, including profiles generated before a service starts.
func resolveMissing(path string) (string, error) {
	resolved, err := filepath.EvalSymlinks(path)
	if err == nil {
		return resolved, nil
	}
	if !os.IsNotExist(err) {
		return "", errors.New("a protected location cannot be resolved")
	}
	// A dangling link is not a missing name: its future target cannot be guessed.
	if info, linkErr := os.Lstat(path); linkErr == nil && info.Mode()&os.ModeSymlink != 0 {
		return "", errors.New("a protected location is a dangling link")
	} else if linkErr != nil && !os.IsNotExist(linkErr) {
		return "", errors.New("a protected location cannot be inspected")
	}
	parent := filepath.Dir(path)
	if parent == path {
		return "", errors.New("a protected location has no resolvable ancestor")
	}
	resolved, err = resolveMissing(parent)
	if err != nil {
		return "", err
	}
	return filepath.Join(resolved, filepath.Base(path)), nil
}

func normalizePaths(paths []string) ([]string, error) {
	set := make(map[string]bool, len(paths)*2)
	for _, path := range paths {
		if !validPath(path) {
			return nil, errors.New("protected locations must be absolute non-root paths without controls")
		}
		path = filepath.Clean(path)
		resolved, err := resolveMissing(path)
		if err != nil {
			return nil, err
		}
		if !validPath(resolved) {
			return nil, errors.New("a protected location resolves to an invalid path")
		}
		set[path] = true
		set[resolved] = true
	}
	result := make([]string, 0, len(set))
	for path := range set {
		result = append(result, path)
	}
	sort.Strings(result)
	return result, nil
}
