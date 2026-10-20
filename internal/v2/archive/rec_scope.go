package archive

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	"laneboss.io/laneboss/internal/v2/api"
)

// Walk each component through an already held directory. OpenRoot confines a
// racing link; comparing the opened inode also refuses links within that root.
func restoreChild(parent *os.Root, name string) (*os.Root, error) {
	before, err := parent.Lstat(name)
	if err != nil || !before.IsDir() || before.Mode()&os.ModeSymlink != 0 {
		return nil, restoreFault(api.CodeForbidden, "restore_target_scope")
	}
	child, err := parent.OpenRoot(name)
	if err != nil {
		return nil, restoreFault(api.CodeForbidden, "restore_target_scope")
	}
	after, err := child.Stat(".")
	if err != nil || !os.SameFile(before, after) {
		child.Close()
		return nil, restoreFault(api.CodeForbidden, "restore_target_scope")
	}
	return child, nil
}

func restoreParent(target string, roots []string) (*os.Root, error) {
	if gitAdmin(filepath.Base(target)) {
		return nil, restoreFault(api.CodeForbidden, "restore_target_git")
	}
	if !filepath.IsAbs(target) || filepath.Clean(target) != target || target == string(filepath.Separator) {
		return nil, restoreFault(api.CodeForbidden, "restore_target_scope")
	}
	for _, allowed := range roots {
		if !filepath.IsAbs(allowed) || filepath.Clean(allowed) != allowed || allowed == string(filepath.Separator) {
			continue
		}
		rel, err := filepath.Rel(allowed, target)
		if err != nil || rel == "." || !filepath.IsLocal(rel) {
			continue
		}
		root, err := os.OpenRoot(string(filepath.Separator))
		if err != nil {
			return nil, err
		}
		parts := strings.Split(strings.TrimPrefix(allowed, string(filepath.Separator)), string(filepath.Separator))
		parent := filepath.Dir(rel)
		if parent != "." {
			parts = append(parts, strings.Split(parent, string(filepath.Separator))...)
		}
		for _, part := range parts {
			child, openErr := restoreChild(root, part)
			root.Close()
			if openErr != nil {
				return nil, openErr
			}
			root = child
		}
		return root, nil
	}
	return nil, restoreFault(api.CodeForbidden, "restore_target_scope")
}

// RestoreDestination is used only by the installed native publisher with roots
// selected from its protected allocation journal.
func RestoreDestination(target string, roots []string) (*os.Root, error) {
	return restoreParent(target, roots)
}

// EmptyRestoreTarget refuses links, files and nonempty directories. The native
// publisher also uses a kernel directory rename, which refuses a racing fill.
func EmptyRestoreTarget(parent *os.Root, base string) (bool, error) {
	info, err := parent.Lstat(base)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, restoreFault(api.CodeForbidden, "restore_target_unreadable")
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return false, restoreFault(api.CodeConflict, "restore_target_exists")
	}
	child, err := restoreChild(parent, base)
	if err != nil {
		return false, err
	}
	defer child.Close()
	file, err := child.Open(".")
	if err != nil {
		return false, err
	}
	items, readErr := file.ReadDir(1)
	closeErr := file.Close()
	if readErr != nil && !errors.Is(readErr, io.EOF) || closeErr != nil {
		return false, restoreFault(api.CodeForbidden, "restore_target_unreadable")
	}
	if len(items) != 0 {
		return false, restoreFault(api.CodeConflict, "restore_target_exists")
	}
	return true, nil
}
