package claudock

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"laneboss.io/laneboss/internal/v2/api"
)

// Seed imports explicit generated configuration/assets from a trusted worker.
// It is not a lane RPC or a renderer. Every copied file is private, read-only
// and digest-bound in the service's protected records. Runtime/auth/history
// destinations are blacklisted, never imported as configuration assets.
func (h *Home) Seed(source, destination string) (result error) {
	if h == nil {
		return failure(api.CodeInvalid, "private home is required")
	}
	if !absolute(source) || !relative(destination) {
		return failure(api.CodeInvalid, "generated import needs explicit source and relative destination")
	}
	for _, blocked := range []string{".runnerhome-runtime", ".config/claudock", ".claude/.credentials.json",
		".claude/projects", ".claude/sessions", ".claude/history.jsonl", "tmp"} {
		if destination == blocked || strings.HasPrefix(destination, blocked+"/") || strings.HasPrefix(blocked, destination+"/") {
			return failure(api.CodeForbidden, "generated import cannot replace runtime, auth or history paths")
		}
	}
	canonical, err := filepath.EvalSymlinks(source)
	if err != nil || canonical != source {
		return ownedError(ErrOwnedType)
	}
	if err := h.records.check(); err != nil {
		return err
	}
	claim, err := h.records.acquireLease("home/" + h.key)
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, claim.close()) }()
	if err := h.AuditOwned(); err != nil {
		return err
	}
	if err := h.verifyGenerated(); err != nil {
		return err
	}
	from, err := os.OpenRoot(filepath.Dir(source))
	if err != nil {
		return ownedError(ErrOwnedRead)
	}
	defer from.Close()
	to, err := h.open()
	if err != nil {
		return err
	}
	defer to.Close()
	// Poison the protected generation BEFORE changing any destination. Failed
	// imports remain stopped even if their new files were not yet in a manifest.
	if err := h.records.transaction(h.key, func(record *homeRecord) error { record.Incomplete = true; return nil }, nil); err != nil {
		return err
	}
	generated := map[string]api.Digest{}
	directories := map[string]bool{}
	count := 0
	base := filepath.Base(source)
	err = fs.WalkDir(from.FS(), base, func(path string, entry fs.DirEntry, walkErr error) error {
		count++
		if walkErr != nil || count > 4096 {
			return ownedError(ErrOwnedRead)
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return ownedError(ErrOwnedType)
		}
		suffix, err := filepath.Rel(base, path)
		if err != nil {
			return ownedError(ErrOwnedType)
		}
		name := filepath.Join(destination, suffix)
		if !relative(name) {
			return ownedError(ErrOwnedType)
		}
		if entry.IsDir() {
			rememberDirectories(directories, name)
			return makeOwnedDirectories(to, name)
		}
		data, err := readRegular(from, path, maxRecordBytes, false)
		if err != nil {
			return err
		}
		info, err := entry.Info()
		if err != nil {
			return ownedError(ErrOwnedRead)
		}
		if name == ".claude/settings.json" {
			document, err := decodeRecord(data)
			if err != nil || object(document["sandbox"])["enabled"] != false {
				return failure(api.CodeInvalid, "generated settings must disable the inner sandbox")
			}
			for _, field := range []string{"env", "apiKeyHelper", "forceLoginMethod"} {
				if _, exists := document[field]; exists {
					return failure(api.CodeForbidden, "generated settings cannot change headless authentication")
				}
			}
		}
		if err := makeOwnedDirectories(to, filepath.Dir(name)); err != nil {
			return err
		}
		rememberDirectories(directories, filepath.Dir(name))
		mode := fs.FileMode(0400)
		if info.Mode().Perm()&0111 != 0 {
			mode = 0500
		}
		if err := replacePrivate(to, ".runnerhome-runtime", name, data, mode); err != nil {
			return err
		}
		generated[name] = contentDigest(data)
		return nil
	})
	if err != nil {
		return dependency(err)
	}
	return h.records.transaction(h.key, func(record *homeRecord) error {
		for name, digest := range generated {
			record.Generated[name] = digest
		}
		recordDirectories(record, directories)
		record.Incomplete = false
		return nil
	}, nil)
}

func rememberDirectories(directories map[string]bool, name string) {
	for name != "." {
		directories[name] = true
		name = filepath.Dir(name)
	}
}

func makeOwnedDirectories(root *os.Root, name string) error {
	if name == "." {
		return nil
	}
	parts := strings.Split(filepath.ToSlash(name), "/")
	for i := range parts {
		path := filepath.Join(parts[:i+1]...)
		if err := root.Mkdir(path, 0700); err != nil && !os.IsExist(err) {
			return ownedError(ErrOwnedRead)
		}
		if err := ownedDirectory(root, path); err != nil {
			return err
		}
	}
	return nil
}
