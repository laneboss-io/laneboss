package orghook

import (
	"io"
	"os"
	"path/filepath"
)

const maxSearchEntries = 20000
const narrowSearchPath = "narrow path to a folder or file without secrets"

type contentSearch struct{ path string }

func contentSearchInput(data map[string]any, cwd string) (contentSearch, error) {
	search := contentSearch{path: cwd}
	if value, exists := data["path"]; exists && value != nil {
		text, ok := value.(string)
		if !ok || hasControl(text) {
			return search, invalid("a content search needs a literal text path")
		}
		if text != "" {
			search.path = text
		}
	}
	if follow, exists := data["follow"]; exists && follow != false {
		return search, invalid("a content search's follow override cannot be inspected")
	}
	return search, nil
}

// Filters never narrow this metadata walk: every descendant name is checked
// independently of the search engine's glob, type or other selection semantics.
func secretSearch(search contentSearch, directory string, names []string, inst *instance) (bool, error) {
	path, err := pathAt(search.path, directory)
	if err != nil {
		return false, err
	}
	matched, err := secretNameMatch(search.path, path, names, inst)
	if matched || err != nil {
		return matched, err
	}
	info, err := os.Stat(path)
	if err != nil {
		return false, invalid("a content search path cannot be inspected")
	}
	if !info.IsDir() {
		if !info.Mode().IsRegular() {
			return false, invalid("a content search path is not a regular file or directory")
		}
		return false, nil
	}
	seen := 0
	var walk func(string) (bool, error)
	walk = func(root string) (bool, error) {
		stream, err := os.Open(root)
		if err != nil {
			return false, invalid("a content search directory cannot be inspected")
		}
		defer stream.Close()
		for {
			entries, readErr := stream.ReadDir(128)
			if readErr != nil && readErr != io.EOF {
				return false, invalid("a content search directory cannot be inspected")
			}
			for _, entry := range entries {
				seen++
				if seen > maxSearchEntries {
					return false, invalid("a content search exceeds the inspection limit")
				}
				child := filepath.Join(root, entry.Name())
				resolved, err := resolvePath(child, directory)
				if err != nil {
					return false, err
				}
				if entry.Type()&os.ModeSymlink != 0 && isDirectory(resolved) {
					return false, invalid("a content search contains a symlink directory")
				}
				matched, err := secretNameMatch(child, resolved, names, inst)
				if matched || err != nil {
					return matched, err
				}
				if entry.IsDir() {
					matched, err := walk(child)
					if matched || err != nil {
						return matched, err
					}
				}
			}
			if readErr == io.EOF {
				return false, nil
			}
		}
	}
	return walk(path)
}
