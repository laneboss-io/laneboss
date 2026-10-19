// Package worktreepath compares the directory scopes handed to lanes.
package worktreepath

import (
	"os"
	"path/filepath"
	"strings"
)

// Overlap reports whether either directory contains the other after resolving
// symlinks. Resolve existing parents too, since a recorded directory or a new
// Git worktree may not exist yet.
func Overlap(a, b string) bool {
	a, b = resolve(a), resolve(b)
	if x, err := os.Stat(a); err == nil {
		if y, err := os.Stat(b); err == nil && os.SameFile(x, y) {
			return true
		}
	}
	return contains(a, b) || contains(b, a)
}

func contains(parent, child string) bool {
	rel, err := filepath.Rel(parent, child)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

func resolve(path string) string {
	abs, _ := filepath.Abs(path)
	if resolved, err := filepath.EvalSymlinks(abs); err == nil {
		return resolved
	}
	parent := filepath.Dir(abs)
	if parent == abs {
		return abs
	}
	return filepath.Join(resolve(parent), filepath.Base(abs))
}
