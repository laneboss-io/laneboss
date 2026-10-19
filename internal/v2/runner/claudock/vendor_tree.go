package claudock

import (
	"io/fs"
	"os"
	"strings"

	"laneboss.io/laneboss/internal/v2/api"
)

// The vendor tree is owned data. Ordinary tool state elsewhere in HOME is
// still reported only. Configuration assets must come from protected seeding.
func auditVendor(root *os.Root, record *homeRecord) error {
	for name, recorded := range record.Directories {
		if !recorded || !relative(name) {
			return ownedError(ErrOwnedType)
		}
		if err := ownedDirectory(root, name); err != nil {
			return err
		}
	}
	for _, name := range []string{"projects", "sessions", "plugins", "agents", "skills", "hooks", "cache", "debug", "todos", "session-env"} {
		if err := ownedDirectory(root, ".claude/"+name); err != nil {
			return err
		}
	}
	if err := ownedFile(root, ".claude/history.jsonl", false); err != nil {
		return err
	}
	count := 0
	return fs.WalkDir(root.FS(), ".claude", func(name string, entry fs.DirEntry, walkErr error) error {
		count++
		if walkErr != nil || count > 100000 {
			return ownedError(ErrOwnedRead)
		}
		if entry.IsDir() {
			if err := ownedDirectory(root, name); err != nil {
				return err
			}
		} else if err := ownedFile(root, name, false); err != nil {
			return err
		}
		for _, directory := range []string{".claude/hooks", ".claude/plugins", ".claude/agents", ".claude/skills"} {
			if !strings.HasPrefix(name, directory+"/") {
				continue
			}
			if entry.IsDir() {
				if !record.Directories[name] {
					return failure(api.CodeIntegrity, "vendor configuration directory is not in the protected generation")
				}
			} else {
				if !digest(record.Generated[name]) {
					return failure(api.CodeIntegrity, "vendor configuration asset is not in the protected generation")
				}
				info, err := entry.Info()
				if err != nil {
					return ownedError(ErrOwnedRead)
				}
				if info.Mode().Perm()&0222 != 0 {
					return ownedError(ErrOwnedMode)
				}
			}
		}
		return nil
	})
}

func recordDirectories(record *homeRecord, directories map[string]bool) {
	for name := range directories {
		record.Directories[name] = true
	}
}
