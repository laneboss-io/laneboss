package lanesandbox

import (
	"errors"
	"sort"
	"strings"

	"laneboss.io/laneboss/internal/faults"
)

// DarwinProfile generates the complete sandbox-exec policy. File-write rules
// do not constrain reads, process creation, networking or connecting to an
// existing Unix socket. Paths are quoted as literal Scheme strings, not regexes.
func DarwinProfile(paths []string) (string, error) {
	return darwinProfile(paths, nil)
}

type writeAllowance struct {
	path      string
	recursive bool
}

func normalizeAllowances(allowed []writeAllowance) ([]writeAllowance, error) {
	set := map[string]bool{}
	for _, permit := range allowed {
		paths, err := normalizePaths([]string{permit.path})
		if err != nil {
			return nil, err
		}
		for _, path := range paths {
			set[path] = set[path] || permit.recursive
		}
	}
	paths := make([]string, 0, len(set))
	for path := range set {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	result := make([]writeAllowance, 0, len(paths))
	for _, path := range paths {
		result = append(result, writeAllowance{path: path, recursive: set[path]})
	}
	return result, nil
}

func pathPredicate(path string, recursive bool) string {
	quoted := strings.NewReplacer("\\", "\\\\", "\"", "\\\"").Replace(path)
	literal := "(literal \"" + quoted + "\")"
	if !recursive {
		return literal
	}
	return "(require-any " + literal + " (subpath \"" + quoted + "\"))"
}

func darwinProfile(paths []string, allowed []writeAllowance) (string, error) {
	if len(paths) == 0 {
		return "", errors.New("a sandbox profile needs a protected location")
	}
	paths, err := normalizePaths(paths)
	if err != nil {
		return "", err
	}
	if len(allowed) > 0 {
		allowed, err = normalizeAllowances(allowed)
		if err != nil {
			return "", err
		}
	}
	var profile strings.Builder
	profile.WriteString("(version 1)\n(allow default)\n")
	if faults.Get("sandbox-drop-denies").Point != "" {
		if err := faults.Reach("sandbox-drop-denies"); err != nil {
			return "", err
		}
		return profile.String(), nil
	}
	for _, path := range paths {
		quoted := strings.NewReplacer("\\", "\\\\", "\"", "\\\"").Replace(path)
		exceptions := []writeAllowance{}
		for _, permit := range allowed {
			if strings.HasPrefix(permit.path, path+"/") {
				exceptions = append(exceptions, permit)
			}
		}
		if len(exceptions) > 0 {
			profile.WriteString("(deny file-write* (require-all (require-any (literal \"" + quoted + "\") (subpath \"" + quoted + "\"))")
			for _, permit := range exceptions {
				profile.WriteString(" (require-not " + pathPredicate(permit.path, permit.recursive) + ")")
			}
			profile.WriteString("))\n")
			continue
		}
		profile.WriteString("(deny file-write* (literal \"")
		profile.WriteString(quoted)
		profile.WriteString("\") (subpath \"")
		profile.WriteString(quoted)
		profile.WriteString("\"))\n")
	}
	for _, permit := range allowed {
		profile.WriteString("(allow file-write* " + pathPredicate(permit.path, permit.recursive) + ")\n")
	}
	return profile.String(), nil
}
