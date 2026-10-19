//go:build linux

package linux

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// resolvePath resolves existing ancestors even when the last component does
// not exist. A dangling link is followed to its target, never silently treated
// as an absent ordinary name. The bound also refuses loops through absent paths.
func resolvePath(input string) (string, error) {
	if !filepath.IsAbs(input) || strings.ContainsRune(input, 0) {
		return "", errors.New("protected path must be absolute")
	}
	current := filepath.Clean(input)
	for attempts := 0; attempts < 40; attempts++ {
		parts := strings.Split(strings.TrimPrefix(current, "/"), "/")
		resolved := "/"
		restart := false
		for index, part := range parts {
			if part == "" {
				continue
			}
			candidate := filepath.Join(resolved, part)
			info, err := os.Lstat(candidate)
			if errors.Is(err, fs.ErrNotExist) {
				return filepath.Join(append([]string{candidate}, parts[index+1:]...)...), nil
			}
			if err != nil {
				return "", err
			}
			if info.Mode()&os.ModeSymlink != 0 {
				target, err := os.Readlink(candidate)
				if err != nil {
					return "", err
				}
				if !filepath.IsAbs(target) {
					target = filepath.Join(resolved, target)
				}
				current = filepath.Join(append([]string{target}, parts[index+1:]...)...)
				restart = true
				break
			}
			resolved = candidate
		}
		if !restart {
			return resolved, nil
		}
	}
	return "", errors.New("too many links in protected path")
}

func protectedRoots(extra []string) ([]string, error) {
	if len(extra) == 0 {
		return nil, errors.New("explicit configuration state roots are required")
	}
	roots := append([]string{}, extra...)
	roots = append(roots, "/var/lib/laneboss", "/etc/laneboss")
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("resolve conventional home roots: %w", err)
	}
	roots = append(roots, filepath.Join(home, ".local/state/laneboss"),
		filepath.Join(home, ".config/laneboss"))
	for _, name := range []string{"LANEBOSS_HOME", "LANEBOSS_STATE_HOME"} {
		if value, ok := os.LookupEnv(name); ok && value != "" {
			roots = append(roots, value)
		}
	}
	for _, item := range []struct{ name, suffix string }{
		{"XDG_STATE_HOME", "laneboss"}, {"XDG_CONFIG_HOME", "laneboss"},
	} {
		if value, ok := os.LookupEnv(item.name); ok && value != "" {
			roots = append(roots, filepath.Join(value, item.suffix))
		}
	}
	for index, root := range roots {
		resolved, err := resolvePath(root)
		if err != nil {
			// A protected root may originate in a variable. Keep its cause,
			// without printing that variable's path value in a diagnostic.
			var pathErr *fs.PathError
			if errors.As(err, &pathErr) {
				err = pathErr.Err
			}
			return nil, fmt.Errorf("resolve protected root %d: %w", index, err)
		}
		roots[index] = resolved
	}
	return roots, nil
}
