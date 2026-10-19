package claudock

import (
	"bufio"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"laneboss.io/laneboss/internal/v2/api"
)

// Home contains only this life's data. It is not a credential store or an OS
// boundary. The service-owned parent and launcher must prevent replacement and
// concurrent modification while these quiescent-tree checks run.
type Home struct {
	path     string
	identity fs.FileInfo
	records  *Records
	key      string
}

type Finding struct {
	Path string `json:"path"`
	Kind string `json:"kind"`
}

var (
	ErrOwnedType   = errors.New("owned entry has the wrong type")
	ErrOwnedLink   = errors.New("owned file has another link")
	ErrOwnedMode   = errors.New("owned entry is not private")
	ErrRootChanged = errors.New("open home root changed")
	ErrOwnedRead   = errors.New("owned entry cannot be inspected")
)

func ownedError(reason error) error {
	return fmt.Errorf("%w: %w", failure(api.CodeIntegrity, "private owned-entry check failed"), reason)
}

func (h *Home) Path() string { return h.path }

// CredentialPaths identifies known runtime exclusions. Archive explicitly
// selected conversation data, never the entire home or unknown runtime files.
func (h *Home) CredentialPaths() []string {
	return []string{".claude/.credentials.json", ".config/claudock", ".runnerhome-runtime", "tmp"}
}

// CreateHome ports the private Claudock layout from wave-0 without importing a
// human profile, file login, shared history, symlink or ambient environment.
// Its skeleton is NOT a compatibility receipt and cannot enable a live mode.
func CreateHome(path string, records *Records) (*Home, error) {
	if !absolute(path) {
		return nil, failure(api.CodeInvalid, "a new absolute private home path is required")
	}
	if records == nil {
		return nil, failure(api.CodePrerequisite, "protected home records are required")
	}
	if err := records.check(); err != nil {
		return nil, err
	}
	if within(path, records.path) || within(records.path, path) {
		return nil, failure(api.CodeIntegrity, "protected home records must be outside the lane home")
	}
	parent, err := filepath.EvalSymlinks(filepath.Dir(path))
	if err != nil {
		return nil, failure(api.CodePrerequisite, "private home parent is unavailable")
	}
	path = filepath.Join(parent, filepath.Base(path))
	if within(path, records.path) || within(records.path, path) {
		return nil, failure(api.CodeIntegrity, "resolved home and protected records overlap")
	}
	r, err := os.OpenRoot(parent)
	if err != nil {
		return nil, failure(api.CodePrerequisite, "private home parent cannot be opened")
	}
	defer r.Close()
	info, err := r.Stat(".")
	if err != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return nil, failure(api.CodeIntegrity, "private home parent must be protected")
	}
	if err := r.Mkdir(filepath.Base(path), 0700); err != nil {
		return nil, failure(api.CodeConflict, "private home must be new; preserve existing data")
	}
	path = filepath.Join(parent, filepath.Base(path))
	root, err := os.OpenRoot(path)
	if err != nil {
		return nil, failure(api.CodeIntegrity, "new private home cannot be opened")
	}
	defer root.Close()
	return initializeHome(path, root, records, false)
}

// InitializeAllocatedHome is used only by the helper credential worker after
// its native journal has authenticated the home's owner, inode and quiescence.
// A missing record can initialize only the materializer's empty .claude root;
// existing configuration or partial setup is preserved and refused.
func InitializeAllocatedHome(path string, records *Records) error {
	canonical, err := filepath.EvalSymlinks(path)
	if err != nil || canonical != path || records == nil || within(path, records.path) || within(records.path, path) {
		return failure(api.CodeIntegrity, "allocated home is linked or overlaps protected records")
	}
	root, err := os.OpenRoot(path)
	if err != nil {
		return ownedError(ErrOwnedRead)
	}
	defer root.Close()
	info, err := root.Stat(".")
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0700 {
		return ownedError(ErrOwnedMode)
	}
	key, err := homeKey(info)
	if err != nil {
		return err
	}
	missing := false
	if err := records.withRoot(func(r *os.Root) error {
		_, err := r.Lstat(key + ".json")
		if os.IsNotExist(err) {
			missing = true
			return nil
		}
		return err
	}); err != nil {
		return err
	}
	if !missing {
		_, err := OpenHome(path, records)
		return err
	}
	for _, name := range []string{".", ".claude"} {
		file, err := root.Open(name)
		if err != nil {
			return ownedError(ErrOwnedRead)
		}
		entries, readErr := file.ReadDir(-1)
		closeErr := file.Close()
		if readErr != nil || closeErr != nil || name == "." && (len(entries) != 1 || entries[0].Name() != ".claude" || !entries[0].IsDir()) || name == ".claude" && len(entries) != 0 {
			return failure(api.CodeConflict, "unrecorded allocated home is not an empty vendor skeleton")
		}
	}
	if err := ownedDirectory(root, ".claude"); err != nil {
		return err
	}
	_, err = initializeHome(path, root, records, true)
	return err
}

func initializeHome(path string, root *os.Root, records *Records, allocated bool) (*Home, error) {
	info, err := root.Stat(".")
	if err != nil {
		return nil, ownedError(ErrOwnedRead)
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return nil, failure(api.CodeUnsupported, "private home native owner is unavailable")
	}
	for _, dir := range []string{".runnerhome-runtime", ".config", ".config/claudock", ".cache", ".local", ".local/state", "tmp",
		".claude", ".claude/projects", ".claude/sessions", ".claude/plugins", ".claude/agents",
		".claude/skills", ".claude/hooks", ".claude/cache", ".claude/debug", ".claude/todos", ".claude/session-env"} {
		if allocated && dir == ".claude" {
			continue
		}
		if err := root.Mkdir(dir, 0700); err != nil {
			return nil, failure(api.CodeIntegrity, "private layout creation failed; retain the incomplete home")
		}
		if err := root.Chown(dir, int(owner.Uid), int(owner.Gid)); err != nil {
			return nil, ownedError(ErrOwnedMode)
		}
	}
	registryID, err := newUUID()
	if err != nil {
		return nil, err
	}
	registry := registryProjection{Version: 1, Profiles: []registryProfile{{
		Command: "claude", ConfigDirectory: VendorDirectory, RegistryID: registryID}},
		SuppressedCommands: []string{}, SuppressedDirectories: []string{}, SubscriptionOnlyMigration: 1}
	encoded, err := json.Marshal(registry)
	if err != nil {
		return nil, failure(api.CodeIntegrity, "private profile projection cannot be encoded")
	}
	files := []struct {
		name string
		data []byte
		mode fs.FileMode
	}{
		{".claude/settings.json", []byte("{\"sandbox\":{\"enabled\":false}}\n"), 0400},
		{".claude/history.jsonl", nil, 0600},
		{".config/claudock/profiles.json", encoded, 0400},
		{".config/claudock/credential-store.json", []byte("{}\n"), 0600},
	}
	generated := map[string]api.Digest{}
	for _, file := range files {
		if err := createPrivate(root, file.name, file.data, file.mode); err != nil {
			return nil, err
		}
		if err := root.Chown(file.name, int(owner.Uid), int(owner.Gid)); err != nil {
			return nil, ownedError(ErrOwnedMode)
		}
		if file.mode == 0400 {
			generated[file.name] = contentDigest(file.data)
		}
	}
	info, err = root.Stat(".")
	if err != nil {
		return nil, ownedError(ErrOwnedRead)
	}
	key, err := homeKey(info)
	if err != nil {
		return nil, err
	}
	record := homeRecord{Launches: map[api.ID]api.Digest{}, Directories: map[string]bool{}, Driver: api.DriverClaudock, Adapter: AdapterVersion, Generated: generated, Registry: encoded}
	if err := records.transaction(key, func(r *homeRecord) error { return nil }, &record); err != nil {
		return nil, err
	}
	return OpenHome(path, records)
}

func OpenHome(path string, records *Records) (*Home, error) {
	if !absolute(path) {
		return nil, failure(api.CodeInvalid, "private home path is invalid")
	}
	canonical, err := filepath.EvalSymlinks(path)
	if err != nil || canonical != path {
		return nil, failure(api.CodeIntegrity, "private home path is missing or linked")
	}
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return nil, failure(api.CodeIntegrity, "private home must remain an ordinary protected directory")
	}
	if records == nil || within(path, records.path) || within(records.path, path) {
		return nil, failure(api.CodeIntegrity, "protected home records must be outside the lane home")
	}
	key, err := homeKey(info)
	if err != nil {
		return nil, err
	}
	h := &Home{path: path, identity: info, records: records, key: key}
	if err := h.AuditOwned(); err != nil {
		return nil, err
	}
	if err := h.verifyGenerated(); err != nil {
		return nil, err
	}
	return h, nil
}

func (h *Home) open() (*os.Root, error) {
	if h == nil || h.identity == nil {
		return nil, failure(api.CodeInvalid, "private home is required")
	}
	info, err := os.Lstat(h.path)
	if err != nil || !info.IsDir() || !os.SameFile(info, h.identity) || info.Mode().Perm()&0077 != 0 {
		return nil, ownedError(ErrRootChanged)
	}
	r, err := os.OpenRoot(h.path)
	if err != nil {
		return nil, failure(api.CodeIntegrity, "private home cannot be opened")
	}
	after, err := r.Stat(".")
	if err != nil || !os.SameFile(info, after) {
		r.Close()
		return nil, ownedError(ErrRootChanged)
	}
	return r, nil
}

// AuditOwned hard-checks ONLY library-owned entries. In particular every
// intermediate component is Lstat'ed: os.Root alone follows internal links.
func (h *Home) AuditOwned() error {
	r, err := h.open()
	if err != nil {
		return err
	}
	defer r.Close()
	return h.auditRoot(r)
}

func (h *Home) auditRoot(r *os.Root) error {
	info, err := os.Lstat(h.path)
	after, rootErr := r.Stat(".")
	if err != nil || rootErr != nil || !info.IsDir() || !os.SameFile(info, after) || !os.SameFile(info, h.identity) {
		return ownedError(ErrRootChanged)
	}
	if info.Mode().Perm()&0077 != 0 {
		return ownedError(ErrOwnedMode)
	}
	for _, name := range []string{".runnerhome-runtime", ".config", ".config/claudock", ".claude"} {
		if err := ownedDirectory(r, name); err != nil {
			return err
		}
	}
	for _, item := range []struct {
		name     string
		optional bool
	}{
		{".claude/settings.json", false}, {".claude/.credentials.json", true},
		{".config/claudock/profiles.json", true}, {".config/claudock/credential-store.json", true},
	} {
		if err := ownedFile(r, item.name, item.optional); err != nil {
			return err
		}
	}
	for _, directory := range []string{".runnerhome-runtime", ".config/claudock"} {
		f, err := r.Open(directory)
		if err != nil {
			return ownedError(ErrOwnedRead)
		}
		entries, readErr := f.ReadDir(-1)
		closeErr := f.Close()
		if readErr != nil || closeErr != nil {
			return ownedError(ErrOwnedRead)
		}
		for _, entry := range entries {
			if directory == ".runnerhome-runtime" && !strings.HasPrefix(entry.Name(), ".runnerhome-") {
				continue
			}
			if err := ownedFile(r, filepath.Join(directory, entry.Name()), false); err != nil {
				return err
			}
		}
	}
	return h.records.transaction(h.key, func(record *homeRecord) error {
		for name := range record.Generated {
			if !relative(name) {
				return ownedError(ErrOwnedType)
			}
			if err := ownedFile(r, name, name == ".config/claudock/profiles.json"); err != nil {
				return err
			}
		}
		return auditVendor(r, record)
	}, nil)
}

func ownedDirectory(r *os.Root, name string) error {
	parts := strings.Split(filepath.ToSlash(name), "/")
	for i := range parts {
		info, err := r.Lstat(filepath.Join(parts[:i+1]...))
		if err != nil {
			return ownedError(ErrOwnedRead)
		}
		if !info.IsDir() {
			return ownedError(ErrOwnedType)
		}
		if info.Mode().Perm()&0077 != 0 {
			return ownedError(ErrOwnedMode)
		}
	}
	return nil
}

func ownedFile(r *os.Root, name string, optional bool) error {
	if err := ownedDirectory(r, filepath.Dir(name)); err != nil {
		return err
	}
	info, err := r.Lstat(name)
	if optional && os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return ownedError(ErrOwnedRead)
	}
	if !info.Mode().IsRegular() {
		return ownedError(ErrOwnedType)
	}
	if linked(info) {
		return ownedError(ErrOwnedLink)
	}
	if info.Mode().Perm()&0077 != 0 {
		return ownedError(ErrOwnedMode)
	}
	return nil
}

// Inspect reports ordinary tool state without making sockets, venv links,
// rustup/git hardlinks or browser lock links a barrier to another turn.
func (h *Home) Inspect() ([]Finding, error) {
	if err := h.AuditOwned(); err != nil {
		return nil, err
	}
	r, err := h.open()
	if err != nil {
		return nil, err
	}
	defer r.Close()
	return inspectFiles(r.FS(), 100000)
}

func inspectFiles(files fs.FS, limit int) ([]Finding, error) {
	findings := []Finding{}
	count := 0
	err := fs.WalkDir(files, ".", func(name string, entry fs.DirEntry, walkErr error) error {
		count++
		if count > limit {
			findings = append(findings, Finding{Path: name, Kind: "unreadable-or-bounded"})
			return fs.SkipAll
		}
		if walkErr != nil {
			findings = append(findings, Finding{Path: name, Kind: "unreadable-or-bounded"})
			return fs.SkipDir
		}
		info, err := entry.Info()
		if err != nil {
			findings = append(findings, Finding{Path: name, Kind: "unreadable"})
			return nil
		}
		kind := ""
		if info.Mode()&os.ModeSymlink != 0 {
			kind = "link"
		} else if info.Mode().IsRegular() && linked(info) {
			kind = "hardlink"
		} else if !info.IsDir() && !info.Mode().IsRegular() {
			kind = "special"
		}
		if kind != "" {
			findings = append(findings, Finding{Path: name, Kind: kind})
		}
		return nil
	})
	if err != nil {
		return findings, ownedError(ErrOwnedRead)
	}
	return findings, nil
}

type registryProjection struct {
	Version                   int               `json:"version"`
	Profiles                  []registryProfile `json:"profiles"`
	SuppressedCommands        []string          `json:"suppressedCommands"`
	SuppressedDirectories     []string          `json:"suppressedDirectories"`
	SubscriptionOnlyMigration int               `json:"subscriptionOnlyMigration"`
}

type registryProfile struct {
	Command         string `json:"command"`
	AuthKind        string `json:"authKind,omitempty"`
	ConfigDirectory string `json:"configDirectory"`
	RegistryID      string `json:"registryID"`
	IsVertex        bool   `json:"isVertex"`
	Managed         bool   `json:"managed"`
}

func (h *Home) checkProjection(mode string) error {
	r, err := h.open()
	if err != nil {
		return err
	}
	defer r.Close()
	data, err := readPrivate(r, ".config/claudock/profiles.json", maxRecordBytes)
	if err != nil {
		return err
	}
	var registry registryProjection
	version, count := 1, 1
	if mode == "claude-api-key" {
		version, count = 2, 2
	}
	if err := decodeExact(data, &registry); err != nil || registry.Version != version || len(registry.Profiles) != count ||
		registry.SubscriptionOnlyMigration != 1 || registry.SuppressedCommands == nil || registry.SuppressedDirectories == nil {
		return failure(api.CodeIntegrity, "Claudock requires the complete private mode registry")
	}
	shape, err := decodeRecord(data)
	if err != nil {
		return err
	}
	profiles, ok := shape["profiles"].([]any)
	if !ok || len(profiles) != count || object(profiles[0])["managed"] != false || object(profiles[0])["isVertex"] != false {
		return failure(api.CodeIntegrity, "Claudock registry is missing its explicit private mode fields")
	}
	profile := registry.Profiles[0]
	if profile.Command != "claude" || profile.ConfigDirectory != VendorDirectory || !uuid(profile.RegistryID) ||
		profile.AuthKind != "" || profile.Managed || profile.IsVertex || len(registry.SuppressedCommands) != 0 || len(registry.SuppressedDirectories) != 0 {
		return failure(api.CodeIntegrity, "Claudock profile changes the private home or authentication mode")
	}
	if mode == "claude-api-key" {
		key := registry.Profiles[1]
		if key.Command != "claude-"+KeyProfile || key.ConfigDirectory != VendorDirectory || !uuid(key.RegistryID) ||
			key.RegistryID == profile.RegistryID || key.AuthKind != "apiKey" || !key.Managed || key.IsVertex ||
			object(profiles[1])["managed"] != true || object(profiles[1])["isVertex"] != false {
			return failure(api.CodeIntegrity, "private API key profile differs from the selected slot mode")
		}
	}
	if _, err := r.Lstat(KeyStorePath); !os.IsNotExist(err) {
		return failure(api.CodeIntegrity, "private API key store survived its previous projection")
	}
	settings, err := readPrivate(r, ".claude/settings.json", maxRecordBytes)
	if err != nil {
		return err
	}
	document, err := decodeRecord(settings)
	if err != nil || object(document["sandbox"])["enabled"] != false {
		return failure(api.CodeIntegrity, "generated settings must record the disabled inner sandbox")
	}
	for _, key := range []string{"env", "apiKeyHelper", "forceLoginMethod"} {
		if _, exists := document[key]; exists {
			return failure(api.CodeIntegrity, "headless settings cannot override credentials or the environment")
		}
	}
	for _, name := range []string{".claude/settings.json", ".config/claudock/profiles.json"} {
		info, err := r.Lstat(name)
		if err != nil || info.Mode().Perm()&0222 != 0 {
			return failure(api.CodeIntegrity, "generated settings and registry must be read-only projections")
		}
	}
	store, err := readPrivate(r, ".config/claudock/credential-store.json", maxRecordBytes)
	if err != nil {
		return err
	}
	entries, err := decodeRecord(store)
	if err != nil || len(entries) != 0 {
		return failure(api.CodeIntegrity, "headless wrapper store must not contain another credential")
	}
	if _, err := r.Lstat(".claude/.credentials.json"); !os.IsNotExist(err) {
		return failure(api.CodeIntegrity, "headless mode cannot inherit a file login")
	}
	return nil
}

func (h *Home) conversation(session api.Session) (bool, error) {
	r, err := h.open()
	if err != nil {
		return false, err
	}
	defer r.Close()
	container, err := r.Lstat(".claude/projects")
	if err != nil || !container.IsDir() {
		return false, failure(api.CodeIntegrity, "required conversation container is missing or linked")
	}
	name := ""
	count := 0
	err = fs.WalkDir(r.FS(), ".claude/projects", func(path string, entry fs.DirEntry, walkErr error) error {
		count++
		if walkErr != nil || count > 100000 {
			return failure(api.CodeIntegrity, "private conversation inventory is incomplete")
		}
		if entry.IsDir() {
			if err := ownedDirectory(r, path); err != nil {
				return err
			}
		} else if err := ownedFile(r, path, false); err != nil {
			return err
		}
		if entry.Name() == session.VendorID+".jsonl" {
			if name != "" || !entry.Type().IsRegular() {
				return failure(api.CodeIntegrity, "private conversation identity is ambiguous or linked")
			}
			name = path
		}
		return nil
	})
	if err != nil || name == "" {
		return false, dependency(err)
	}
	if err := ownedDirectory(r, filepath.Dir(name)); err != nil {
		return false, err
	}
	f, info, err := openRegular(r, name)
	if err != nil {
		return false, err
	}
	defer f.Close()
	if info.Mode().Perm()&0077 != 0 || linked(info) || info.Size() > api.MaxObjectBytes {
		return false, failure(api.CodeIntegrity, "private conversation exceeds the bounded adapter reader")
	}
	found := false
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 4096), maxRecordBytes)
	for scanner.Scan() {
		event, err := decodeRecord(scanner.Bytes())
		if err != nil {
			return false, err
		}
		if id, exists := event["sessionId"]; exists && id != session.VendorID {
			return false, failure(api.CodeIntegrity, "private conversation belongs to another session")
		}
		if event["type"] == "user" || event["type"] == "assistant" {
			if event["sessionId"] != session.VendorID || event["cwd"] != session.LogicalCWD {
				return false, failure(api.CodeIntegrity, "private conversation lost its session or cwd binding")
			}
			found = true
		}
	}
	if scanner.Err() != nil {
		return false, failure(api.CodeIntegrity, "private conversation could not be read completely")
	}
	if !found {
		return false, failure(api.CodeIntegrity, "private conversation has no bound message records")
	}
	return true, nil
}

func newUUID() (string, error) {
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return "", failure(api.CodeUnavailable, "private registry identity could not be generated")
	}
	id[6] = id[6]&0x0f | 0x40
	id[8] = id[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", id[:4], id[4:6], id[6:8], id[8:10], id[10:]), nil
}
