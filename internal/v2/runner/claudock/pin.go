package claudock

import (
	"encoding/json"
	"errors"
	"os"
	"syscall"

	"laneboss.io/laneboss/internal/v2/api"
)

const preferencePath = ".config/claudock/preferences.json"

// The caller verifies the declared executable bytes before this transaction.
// Installed callers also check the namespace path against the helper's pinned
// manifest. The generated file is hashed and overmounted read-only at exec.
func (h *Home) pinClaude(vendor api.Executable, path string) error {
	data, err := json.Marshal(struct {
		Claude string `json:"claudeExecutable"`
	}{path})
	if err != nil {
		return failure(api.CodeIntegrity, "executable preference cannot be encoded")
	}
	root, err := h.open()
	if err != nil {
		return err
	}
	defer root.Close()
	return h.records.transaction(h.key, func(record *homeRecord) error {
		sum := contentDigest(data)
		if record.Claude.ID != "" {
			if record.Claude != vendor || record.ClaudePath != path || record.Generated[preferencePath] != sum {
				return failure(api.CodeIntegrity, "declared CLI differs from the protected home pin")
			}
			info, err := root.Lstat(preferencePath)
			if err != nil || info.Mode().Perm() != 0400 {
				return failure(api.CodeIntegrity, "executable preference is not protected read-only")
			}
			return nil
		}
		if _, err := root.Lstat(preferencePath); !os.IsNotExist(err) {
			return failure(api.CodeIntegrity, "unrecorded executable preference must be preserved for recovery")
		}
		if err := createPrivate(root, preferencePath, data, 0400); err != nil {
			return err
		}
		owner, ok := h.identity.Sys().(*syscall.Stat_t)
		if !ok {
			return ownedError(ErrOwnedMode)
		}
		if err := root.Chown(preferencePath, int(owner.Uid), int(owner.Gid)); err != nil {
			return ownedError(ErrOwnedMode)
		}
		dir, err := root.Open(".config/claudock")
		if err != nil {
			return ownedError(ErrOwnedRead)
		}
		if err := errors.Join(dir.Sync(), dir.Close()); err != nil {
			return ownedError(ErrPublish)
		}
		record.Generated[preferencePath] = sum
		record.Claude, record.ClaudePath = vendor, path
		return nil
	}, nil)
}
