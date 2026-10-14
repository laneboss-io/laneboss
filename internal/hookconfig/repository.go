package hookconfig

import (
	"os"
	"path/filepath"
	"strings"
)

func gitMain(directory string) (string, bool, error) {
	path := filepath.Join(directory, ".git")
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return "", false, nil
	}
	if err != nil || info.Mode()&os.ModeSymlink != 0 {
		return "", false, trustError(path, "Codex project root cannot be vetted through a .git symlink or unreadable source")
	}
	if info.IsDir() {
		if _, err := os.Stat(filepath.Join(path, "HEAD")); os.IsNotExist(err) {
			return "", false, nil
		} else if err != nil {
			return "", false, trustError(path, "Git HEAD cannot be inspected")
		}
		return directory, true, nil
	}
	data, err := regularBytes(path)
	if err != nil || !strings.HasPrefix(string(data), "gitdir: ") {
		return "", false, trustError(path, "linked worktree main checkout cannot be determined")
	}
	gitdir := strings.TrimSpace(strings.TrimPrefix(string(data), "gitdir: "))
	if !filepath.IsAbs(gitdir) {
		gitdir = filepath.Join(directory, gitdir)
	}
	gitdir = filepath.Clean(gitdir)
	commonBytes, err := regularBytes(filepath.Join(gitdir, "commondir"))
	if err != nil {
		return "", false, trustError(path, "linked worktree main checkout cannot be determined")
	}
	common := strings.TrimSpace(string(commonBytes))
	if !filepath.IsAbs(common) {
		common = filepath.Join(gitdir, common)
	}
	common, err = filepath.EvalSymlinks(common)
	if err != nil || filepath.Base(common) != ".git" {
		return "", false, trustError(path, "linked worktree main checkout cannot be determined")
	}
	if _, err := os.Stat(filepath.Join(common, "HEAD")); err != nil {
		return "", false, trustError(path, "linked worktree main checkout cannot be determined")
	}
	configuration, err := regularBytes(filepath.Join(common, "config"))
	if err != nil {
		return "", false, trustError(path, "linked worktree main checkout cannot be determined")
	}
	section := ""
	for _, line := range strings.Split(string(configuration), "\n") {
		line = strings.ToLower(strings.TrimSpace(line))
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") {
			section = line
			if strings.HasPrefix(line, "[include") {
				return "", false, trustError(path, "linked worktree main checkout cannot be determined through included Git configuration")
			}
		}
		key, value, _ := strings.Cut(line, "=")
		if section == "[core]" && (strings.TrimSpace(key) == "worktree" || (strings.TrimSpace(key) == "bare" && strings.TrimSpace(value) != "false")) {
			return "", false, trustError(path, "linked worktree main checkout cannot be determined for alternate or bare layouts")
		}
	}
	main := filepath.Dir(common)
	if _, err := os.Stat(main); err != nil {
		return "", false, trustError(path, "linked worktree main checkout cannot be determined")
	}
	return main, true, nil
}

func vetMainSources(cwd, root, main string) error {
	for directory := cwd; ; directory = filepath.Dir(directory) {
		relative, err := filepath.Rel(root, directory)
		if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
			return trustError(root, "linked worktree relative source cannot be determined")
		}
		source := filepath.Join(main, relative, ".codex")
		path := filepath.Join(source, "hooks.json")
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			return trustError(path, "main checkout must not inject hooks into a Codex bypass run")
		}
		if err := checkConfig(filepath.Join(source, "config.toml")); err != nil {
			return err
		}
		if directory == root {
			return nil
		}
	}
}
