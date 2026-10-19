package claudock

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"

	"laneboss.io/laneboss/internal/v2/api"
)

func identifier(value api.ID) bool {
	if len(value) == 0 || len(value) > 128 {
		return false
	}
	for _, c := range value {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

func digest(value api.Digest) bool {
	if len(value) != 64 {
		return false
	}
	for _, c := range value {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

func label(value string) bool {
	return value != "" && len(value) <= 256 && utf8.ValidString(value) && !strings.HasPrefix(value, "-") &&
		strings.IndexFunc(value, func(r rune) bool { return r <= 32 || r == 127 }) < 0
}

func absolute(path string) bool {
	return filepath.IsAbs(path) && filepath.Clean(path) == path && path != "/" && utf8.ValidString(path) &&
		strings.IndexFunc(path, func(r rune) bool { return r < 32 || r == 127 }) < 0
}

func relative(path string) bool {
	return path != "" && path != "." && !filepath.IsAbs(path) && filepath.Clean(path) == path &&
		path != ".." && !strings.HasPrefix(path, ".."+string(filepath.Separator)) &&
		utf8.ValidString(path) && strings.IndexFunc(path, func(r rune) bool { return r < 32 || r == 127 }) < 0
}

func uuid(value string) bool {
	if len(value) != 36 {
		return false
	}
	for i, c := range value {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if c != '-' {
				return false
			}
		} else if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

func timestamp(value api.Timestamp) (time.Time, bool) {
	t, err := time.Parse(time.RFC3339Nano, string(value))
	return t, err == nil && strings.HasSuffix(string(value), "Z")
}

func executable(value api.Executable) bool {
	return identifier(value.ID) && digest(value.SHA256) && label(value.Version)
}

func blob(value api.BlobRef) bool {
	return identifier(value.ID) && digest(value.SHA256) && value.Bytes > 0 &&
		value.Bytes <= api.MaxObjectBytes && label(value.Class)
}

// This checks the frozen terminal-record shape, not kernel provenance. The
// credential/lifecycle worker must still supply the canonical outside record
// for the exact reservation and reject stale/forged process generations.
func terminalObservation(observation api.ProcessObservation) bool {
	handle := observation.Handle
	if observation.State != "exited" || observation.Survivors == nil || *observation.Survivors != 0 ||
		!identifier(handle.ID) || !identifier(handle.ContainmentID) || !label(handle.Generation) ||
		!identifier(handle.Target.LifeID) || handle.Target.Run == 0 || uint64(handle.Target.Run) > 1<<53-1 {
		return false
	}
	if _, valid := timestamp(observation.ObservedAt); !valid {
		return false
	}
	switch observation.PromptStatus {
	case "not_written", "written", "cut", "unknown", "completed":
	default:
		return false
	}
	if (observation.ExitCode == nil) == (observation.Signal == nil) {
		return false
	}
	if observation.ExitCode != nil {
		return int64(*observation.ExitCode) >= -1<<31 && int64(*observation.ExitCode) <= 1<<31-1
	}
	return *observation.Signal > 0 && int64(*observation.Signal) <= 1<<31-1
}

func validateRequest(r api.RunnerRequest) error {
	if !identifier(r.Target.LifeID) || r.Target.Run == 0 || uint64(r.Target.Run) > 1<<53-1 ||
		!identifier(r.LogicalTurnID) || !identifier(r.Session.ID) || r.Session.Driver != api.DriverClaudock ||
		!uuid(r.Session.VendorID) || !label(r.Session.VendorVersion) || r.Session.HomeID != r.Home.ID ||
		!identifier(r.Session.HistoryID) || r.Session.HistoryID != r.Home.HistoryID ||
		!absolute(r.Session.LogicalCWD) || !identifier(r.Home.ID) || !identifier(r.Home.WorkspaceID) ||
		!identifier(r.Home.HistoryID) || r.Home.VendorDirectory != PrivateVendorDirectory ||
		!identifier(r.Slot.ID) || !identifier(r.Slot.ProfileGrantID) || !identifier(r.Slot.ProfileID) ||
		!identifier(r.Slot.LeaseID) || !executable(r.Executable) || !blob(r.Prompt) || !label(r.Model) {
		return failure(api.CodeInvalid, "runner identity, prompt, private home and explicit session are required")
	}
	if _, valid := timestamp(r.Slot.ExpiresAt); !valid {
		return failure(api.CodeInvalid, "credential expiry is invalid")
	}
	switch r.Slot.Mode {
	case "claudock-headless", "claude-api-key", "claudock-helper", "claudock-api":
	default:
		return failure(api.CodeUnsupported, "credential mode is outside the frozen Claudock contract")
	}
	switch r.Effort {
	case "low", "medium", "high", "max":
	default:
		return failure(api.CodeUnsupported, "effort needs a pinned vendor mapping")
	}
	if r.Budget.WallMS <= 0 || r.Budget.MemoryBytes == 0 || r.Budget.Processes == 0 || r.Budget.DiskBytes == 0 ||
		r.Budget.SpendMicros < 0 || !label(r.Budget.Currency) || r.Budget.WallMS > 1<<53-1 ||
		r.Budget.SpendMicros > 1<<53-1 || r.Budget.CPUSeconds > 1<<53-1 ||
		r.Budget.MemoryBytes > 1<<53-1 || r.Budget.DiskBytes > 1<<53-1 {
		return failure(api.CodeBudget, "runner launch budget is invalid")
	}
	return nil
}

func verifyExecutable(path string, pinned api.Executable) error {
	return verifyPinnedFile(path, pinned, false)
}

func (d Dependencies) verifyExecutables() error {
	projected := d.RuntimePath != ""
	if err := verifyPinnedFile(d.ExecutablePath, d.Executable, projected); err != nil {
		return err
	}
	return verifyPinnedFile(d.ClaudePath, d.Claude, projected)
}

func verifyPinnedFile(path string, pinned api.Executable, projected bool) error {
	if !absolute(path) || !executable(pinned) {
		return failure(api.CodeInvalid, "pinned executable path and identity are required")
	}
	canonical, err := filepath.EvalSymlinks(path)
	if err != nil || canonical != path {
		return failure(api.CodeIntegrity, "pinned executable path is missing or linked")
	}
	root, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		return failure(api.CodeIntegrity, "pinned executable directory is unavailable")
	}
	defer root.Close()
	f, info, err := openRegular(root, filepath.Base(path))
	if err != nil {
		return err
	}
	defer f.Close()
	if info.Mode().Perm()&0111 == 0 || info.Mode().Perm()&0022 != 0 || info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 ||
		projected && info.Mode().Perm() != 0555 {
		return failure(api.CodeIntegrity, "pinned executable permissions are unsafe")
	}
	if info.Size() < 1 || info.Size() > api.MaxVendorBytes {
		return failure(api.CodeIntegrity, "pinned vendor executable exceeds its file bound")
	}
	hash := sha256.New()
	if n, err := io.Copy(hash, io.LimitReader(f, api.MaxVendorBytes+1)); err != nil || n != info.Size() {
		return failure(api.CodeIntegrity, "pinned executable could not be hashed")
	}
	after, err := f.Stat()
	if err != nil || info.Size() != after.Size() || info.ModTime() != after.ModTime() || info.Mode() != after.Mode() || linked(after) ||
		hex.EncodeToString(hash.Sum(nil)) != string(pinned.SHA256) {
		return failure(api.CodeIntegrity, "pinned executable digest differs from retained bytes")
	}
	return nil
}
