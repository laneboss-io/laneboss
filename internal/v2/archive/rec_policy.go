package archive

import (
	"path"
	"sort"
	"strings"
	"unicode"

	"laneboss.io/laneboss/internal/v2/api"
)

// Compare portable Git names without changing the retained path spelling.
// HFS ignores format/variation characters; NTFS ignores trailing dots/spaces,
// streams and the short-name alias used for .git.
func gitName(name string) string {
	name = strings.Map(func(c rune) rune {
		if unicode.Is(unicode.Cf, c) || c >= 0xfe00 && c <= 0xfe0f || c >= 0xe0100 && c <= 0xe01ef {
			return -1
		}
		return unicode.ToLower(c)
	}, name)
	name, _, _ = strings.Cut(name, ":")
	return strings.TrimRight(name, " .")
}

func shortGit(name, prefix string) bool {
	if !strings.HasPrefix(name, prefix+"~") {
		return false
	}
	tail := strings.TrimPrefix(name, prefix+"~")
	if tail == "" {
		return false
	}
	for _, c := range tail {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

func gitAdmin(name string) bool {
	name = gitName(name)
	return name == ".git" || shortGit(name, "git")
}

func gitModules(name string) bool {
	name = gitName(name)
	return name == ".gitmodules" || shortGit(name, "gitmod") || shortGit(name, "gi7eba")
}

// Follow the original manifest graph one component at a time. Cleaning a
// complete target first would miss an escape through an intermediate link.
func linkOutside(name string, entries map[string]api.ObjectEntry) bool {
	pending := strings.Split(name, "/")
	stack := []string{}
	links := 0
	for len(pending) != 0 {
		part := pending[0]
		pending = pending[1:]
		if part == "." {
			continue
		}
		if part == ".." {
			if len(stack) == 0 {
				return true
			}
			stack = stack[:len(stack)-1]
			continue
		}
		if part == "" {
			return true
		}
		current := strings.Join(append(append([]string{}, stack...), part), "/")
		entry, found := entries[current]
		if found && entry.Kind == "symlink" {
			links++
			if links > 40 || path.IsAbs(entry.LinkTarget) || strings.ContainsAny(entry.LinkTarget, "\\\x00") {
				return true
			}
			pending = append(strings.Split(entry.LinkTarget, "/"), pending...)
			continue
		}
		stack = append(stack, part)
	}
	return false
}

func gitControl(name string) string {
	name = gitName(name)
	base, _, _ := strings.Cut(name, ".")
	for _, control := range []string{"config", "config.worktree", "hooks", "commondir", "gitdir", "head", "objects", "refs"} {
		stem, _, _ := strings.Cut(control, ".")
		if name == control || shortGit(base, stem[:min(6, len(stem))]) {
			return control
		}
	}
	return ""
}

func gitHex(name string, size int) bool {
	if len(name) != size {
		return false
	}
	for _, c := range name {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

func gitObject(parts []string, kind string) bool {
	if len(parts) == 0 {
		return kind == "directory"
	}
	pack := gitName(parts[0]) == "pack"
	if len(parts) == 1 {
		return kind == "directory" && (pack || gitHex(parts[0], 2))
	}
	if len(parts) != 2 || kind != "file" {
		return false
	}
	if !pack {
		return gitHex(parts[0], 2) && gitHex(parts[1], 38)
	}
	ext := path.Ext(parts[1])
	if ext != ".pack" && ext != ".idx" && ext != ".rev" {
		return false
	}
	stem := strings.TrimSuffix(parts[1], ext)
	return strings.HasPrefix(stem, "pack-") && len(stem) > len("pack-")
}

// Retain only complete leaf shapes and the directories needed to reach them.
func gitRetained(parts []string, kind string) bool {
	if len(parts) == 0 {
		return kind == "directory"
	}
	switch gitName(parts[0]) {
	case "head", "packed-refs":
		return len(parts) == 1 && kind == "file"
	case "refs", "logs":
		if gitName(parts[0]) == "logs" && len(parts) >= 2 {
			if gitName(parts[1]) == "head" && len(parts) == 2 {
				return kind == "file"
			}
			if gitName(parts[1]) == "refs" {
				return gitRetained(parts[1:], kind)
			}
		}
		if len(parts) == 1 {
			return kind == "directory"
		}
		if kind != "file" && kind != "directory" {
			return false
		}
		for _, part := range parts[1:] {
			if gitControl(part) != "" || gitAdmin(part) {
				return false
			}
		}
		return true
	case "objects":
		return gitObject(parts[1:], kind)
	default:
		return false
	}
}

// Inspect the original graph, before filtering could hide a gitdir signature.
// The explicitly allowed administrative root is exempt; its descendants are not.
func gitBareDirs(entries map[string]api.ObjectEntry) map[string]bool {
	masks := map[string]uint8{}
	for name, entry := range entries {
		parent := path.Dir(name)
		switch gitControl(path.Base(name)) {
		case "head":
			if entry.Kind == "file" || entry.Kind == "symlink" {
				masks[parent] |= 1
			}
		case "objects":
			if entry.Kind == "directory" {
				masks[parent] |= 2
			}
		case "refs":
			if entry.Kind == "directory" {
				masks[parent] |= 4
			}
		}
	}
	result := map[string]bool{}
	for name, mask := range masks {
		if mask != 7 || entries[name].Kind != "directory" {
			continue
		}
		if !gitAdmin(path.Base(name)) {
			result[name] = true
		}
	}
	return result
}

// RestorePolicy inspects the complete original workspace before any write.
// Its sole Git refusal lists every affected path. An owner may retain nested
// Git directories as inert data; only allowlisted repository data is copied.
func RestorePolicy(tree api.ObjectManifest, allow bool) (map[string]bool, error) {
	entries := map[string]api.ObjectEntry{}
	for _, entry := range tree.Entries {
		if entry.Path == "workspace" {
			entries["."] = entry
		}
		if strings.HasPrefix(entry.Path, "workspace/") {
			entries[strings.TrimPrefix(entry.Path, "workspace/")] = entry
		}
	}
	denied, skipped := []string{}, map[string]bool{}
	bare := gitBareDirs(entries)
	for name, entry := range entries {
		parts := strings.Split(name, "/")
		bad := false
		for i, part := range parts {
			if gitAdmin(part) {
				admin := strings.Join(parts[:i+1], "/")
				if !allow || i == 0 || entries[admin].Kind != "directory" {
					bad = true
				}
				if allow && !gitRetained(parts[i+1:], entry.Kind) {
					skipped[entry.Path] = true
				}
			}
		}
		for current := name; ; current = path.Dir(current) {
			if bare[current] {
				skipped[entry.Path] = true
				break
			}
			if current == "." {
				break
			}
		}
		if entry.Kind == "symlink" && (gitModules(parts[len(parts)-1]) || linkOutside(name, entries)) {
			bad = true
		}
		if bad {
			denied = append(denied, name)
		}
	}
	if len(denied) != 0 {
		sort.Strings(denied)
		return nil, restoreFault(api.CodeIntegrity, "restore_git_unsafe: "+strings.Join(denied, ", "))
	}
	return skipped, nil
}
