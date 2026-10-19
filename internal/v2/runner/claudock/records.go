package claudock

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"syscall"

	"laneboss.io/laneboss/internal/v2/api"
)

// Records must be service-owned and outside EVERY lane mount. Path separation
// here is a necessary check; the launcher's mount/UID gate enforces that fact.
// Home identity is device/inode, so a rename cannot create another controller.
type Records struct {
	path string
	root *os.Root
	info fs.FileInfo
	mu   sync.Mutex
	// Private per-instance writer seam. Production always uses the fixed private
	// publisher; tests can exercise a real failed filesystem publication.
	publish func(*os.Root, string, []byte) error
}

type homeRecord struct {
	Launches    map[api.ID]api.Digest `json:"launch_inputs"`
	Directories map[string]bool       `json:"generated_directories"`
	Driver      api.Driver            `json:"driver"`
	Adapter     string                `json:"adapter"`
	Generated   map[string]api.Digest `json:"generated"`
	Registry    json.RawMessage       `json:"registry"`
	Session     api.Session           `json:"session"`
	Home        api.PrivateHome       `json:"home"`
	Model       string                `json:"model"`
	Mode        string                `json:"mode,omitempty"`
	Incomplete  bool                  `json:"incomplete"`
	Claude      api.Executable        `json:"claude,omitzero"`
	ClaudePath  string                `json:"claude_path,omitempty"`
}

type GeneratedProjection struct {
	Path   string
	SHA256 api.Digest
}

// GeneratedProjections returns only paths and protected digests. The helper
// opens their actual inodes and mounts them read-only over the lane home.
func (h *Home) GeneratedProjections() ([]GeneratedProjection, error) {
	if err := h.verifyGenerated(); err != nil {
		return nil, err
	}
	result := []GeneratedProjection{}
	err := h.records.transaction(h.key, func(record *homeRecord) error {
		for path, sum := range record.Generated {
			result = append(result, GeneratedProjection{Path: path, SHA256: sum})
		}
		return nil
	}, nil)
	sort.Slice(result, func(i, j int) bool { return result[i].Path < result[j].Path })
	return result, err
}

func NewRecords(directory string) (*Records, error) {
	r, info, err := openProtectedDirectory(directory)
	if err != nil {
		return nil, err
	}
	return &Records{path: directory, root: r, info: info, publish: publishRecord}, nil
}

func publishRecord(root *os.Root, name string, data []byte) error {
	return replacePrivate(root, ".", name, data, 0600)
}

func openProtectedDirectory(directory string) (*os.Root, fs.FileInfo, error) {
	if !absolute(directory) {
		return nil, nil, failure(api.CodeInvalid, "service records require an absolute protected directory")
	}
	canonical, err := filepath.EvalSymlinks(directory)
	info, statErr := os.Lstat(directory)
	if err != nil || canonical != directory || statErr != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return nil, nil, failure(api.CodeIntegrity, "service records directory must be real and private")
	}
	native, ok := info.Sys().(*syscall.Stat_t)
	if !ok || uint32(os.Geteuid()) != native.Uid {
		return nil, nil, failure(api.CodeIntegrity, "service records directory has the wrong owner")
	}
	r, err := os.OpenRoot(directory)
	if err != nil {
		return nil, nil, failure(api.CodeIntegrity, "service records directory cannot be opened")
	}
	after, err := r.Stat(".")
	if err != nil || !os.SameFile(info, after) {
		r.Close()
		return nil, nil, failure(api.CodeIntegrity, "service records directory changed while opening")
	}
	return r, info, nil
}

func (r *Records) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.root == nil {
		return nil
	}
	err := r.root.Close()
	r.root = nil
	if err != nil {
		return failure(api.CodeIntegrity, "service records handle could not be closed")
	}
	return nil
}

func (r *Records) check() error {
	if r == nil {
		return failure(api.CodePrerequisite, "protected home records are unavailable")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.checkLocked()
}

// checkLocked and every root operation below run under the same mutex as Close.
func (r *Records) checkLocked() error {
	if r == nil || r.root == nil {
		return failure(api.CodePrerequisite, "protected home records are unavailable")
	}
	info, err := os.Lstat(r.path)
	after, rootErr := r.root.Stat(".")
	if err != nil || rootErr != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 ||
		!os.SameFile(info, r.info) || !os.SameFile(info, after) {
		return failure(api.CodeIntegrity, "protected home records identity changed")
	}
	return nil
}

func (r *Records) withRoot(action func(*os.Root) error) error {
	if r == nil {
		return failure(api.CodePrerequisite, "protected home records are unavailable")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.checkLocked(); err != nil {
		return err
	}
	return action(r.root)
}

func (r *Records) acquireLease(identity string) (claim *lease, err error) {
	err = r.withRoot(func(root *os.Root) error {
		var acquireErr error
		claim, acquireErr = acquire(root, identity)
		return acquireErr
	})
	return claim, err
}

func (r *Records) rotationAbsent(login string) error {
	return r.withRoot(func(root *os.Root) error {
		_, err := root.Lstat(rotationName(login))
		if os.IsNotExist(err) {
			return nil
		}
		if err != nil {
			return ownedError(ErrOwnedRead)
		}
		return failure(api.CodeForbidden, "canonical login requires credential rotation before reuse")
	})
}

func (r *Records) markRotation(login string) error {
	return r.withRoot(func(root *os.Root) error {
		data, err := json.Marshal(struct {
			Login    string `json:"login_handle"`
			Rotation bool   `json:"rotation_required"`
		}{login, true})
		if err != nil {
			return ownedError(ErrPublish)
		}
		return replacePrivate(root, ".", rotationName(login), data, 0600)
	})
}

func homeKey(info fs.FileInfo) (string, error) {
	native, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return "", failure(api.CodeUnsupported, "private home filesystem identity is unavailable")
	}
	return fmt.Sprintf("%d-%d", native.Dev, native.Ino), nil
}

// transaction holds a permanent kernel lock as well as the in-process mutex.
// Never remove the lock file: doing so would create a second lock domain.
func (r *Records) transaction(key string, update func(*homeRecord) error, create *homeRecord) (result error) {
	if r == nil {
		return failure(api.CodePrerequisite, "protected home records are unavailable")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.checkLocked(); err != nil {
		return err
	}
	lock, err := acquire(r.root, "record/"+key)
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, lock.close()) }()
	name := key + ".json"
	var record homeRecord
	if create != nil {
		if _, err := r.root.Lstat(name); !os.IsNotExist(err) {
			return failure(api.CodeConflict, "private home already has protected records")
		}
		record = *create
	} else {
		data, err := readPrivate(r.root, name, maxRecordBytes)
		if err != nil {
			return err
		}
		if err := decodeExact(data, &record); err != nil || record.Launches == nil || record.Directories == nil || record.Driver != api.DriverClaudock ||
			record.Adapter != AdapterVersion || !digest(record.Generated[".claude/settings.json"]) ||
			!digest(record.Generated[".config/claudock/profiles.json"]) ||
			contentDigest(record.Registry) != record.Generated[".config/claudock/profiles.json"] {
			return failure(api.CodeIntegrity, "protected home record is invalid")
		}
	}
	if err := update(&record); err != nil {
		return err
	}
	data, err := json.Marshal(record)
	if err != nil {
		return failure(api.CodeIntegrity, "protected home record cannot be encoded")
	}
	return r.publish(r.root, name, data)
}

func (h *Home) checkLaunch(id api.ID, digest api.Digest) (replayed bool, err error) {
	err = h.records.transaction(h.key, func(record *homeRecord) error {
		retained, exists := record.Launches[id]
		if exists && digest != retained {
			return failure(api.CodeIntegrity, "launch replay changed its immutable inputs")
		}
		replayed = exists
		return nil
	}, nil)
	return replayed, err
}

func (h *Home) retainLaunch(id api.ID, digest api.Digest) error {
	return h.records.transaction(h.key, func(record *homeRecord) error {
		if retained, exists := record.Launches[id]; exists && retained != digest {
			return failure(api.CodeIntegrity, "launch replay changed its immutable inputs")
		}
		record.Launches[id] = digest
		return nil
	}, nil)
}

// bindAndSeal is the only Start publication. The record mutex and per-home
// flock cover the foreign-reservation check, binding and seal together.
func (h *Home) bindAndSeal(request api.RunnerRequest, id api.ID, digest api.Digest) error {
	return h.records.transaction(h.key, func(record *homeRecord) error {
		retained, exists := record.Launches[id]
		if !exists && len(record.Launches) != 0 {
			return failure(api.CodeConflict, "private home is sealed for another start reservation")
		}
		if exists && retained != digest {
			return failure(api.CodeIntegrity, "launch replay changed its immutable inputs")
		}
		same := record.Session == request.Session && record.Home == request.Home && record.Model == request.Model
		if record.Session.ID != "" && !same {
			return failure(api.CodeConflict, "private home already has a different protected binding")
		}
		if exists && record.Session.ID == "" {
			return failure(api.CodeIntegrity, "sealed start lost its protected binding")
		}
		record.Session, record.Home, record.Model = request.Session, request.Home, request.Model
		record.Launches[id] = digest
		return nil
	}, nil)
}

func contentDigest(data []byte) api.Digest {
	hash := sha256.Sum256(data)
	return api.Digest(hex.EncodeToString(hash[:]))
}

func (h *Home) verifyGenerated() error {
	return h.records.transaction(h.key, func(record *homeRecord) error {
		if record.Incomplete {
			return failure(api.CodeIntegrity, "generated configuration publication is incomplete")
		}
		r, err := h.open()
		if err != nil {
			return err
		}
		defer r.Close()
		if err := auditVendor(r, record); err != nil {
			return err
		}
		for name, expected := range record.Generated {
			if !relative(name) || !digest(expected) {
				return failure(api.CodeIntegrity, "protected generated manifest is invalid")
			}
			if name == ".config/claudock/profiles.json" {
				if _, err := r.Lstat(name); os.IsNotExist(err) {
					continue
				}
			}
			if err := ownedFile(r, name, false); err != nil {
				return err
			}
			data, err := readPrivate(r, name, maxRecordBytes)
			if err != nil {
				return err
			}
			if contentDigest(data) != expected {
				return failure(api.CodeIntegrity, "generated configuration differs from its protected digest")
			}
		}
		return nil
	}, nil)
}

func (h *Home) bind(request api.RunnerRequest, start bool) error {
	return h.records.transaction(h.key, func(record *homeRecord) error {
		if start {
			if record.Session.ID != "" {
				return failure(api.CodeConflict, "private home already has a protected session binding")
			}
			record.Session, record.Home, record.Model = request.Session, request.Home, request.Model
			return nil
		}
		if record.Session != request.Session || record.Home != request.Home || record.Model != request.Model {
			return failure(api.CodeIntegrity, "continuation differs from the protected session, home or model")
		}
		return nil
	}, nil)
}

func within(parent, child string) bool {
	relative, err := filepath.Rel(parent, child)
	return err == nil && (relative == "." || relative != ".." && !filepath.IsAbs(relative) &&
		len(relative) > 0 && !(len(relative) >= 3 && relative[:3] == ".."+string(filepath.Separator)))
}
