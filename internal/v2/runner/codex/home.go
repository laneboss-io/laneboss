package codex

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"laneboss.io/laneboss/internal/v2/api"
)

type assetRecord struct {
	Name   string     `json:"name"`
	SHA256 api.Digest `json:"sha256"`
}

type homeRecord struct {
	Driver  api.Driver      `json:"driver"`
	Home    api.PrivateHome `json:"home"`
	Assets  []assetRecord   `json:"assets"`
	Session api.Session     `json:"session"`
	Model   string          `json:"model"`
	Slot    slotRecord      `json:"slot"`
}

// Home's records live outside lane mounts; no lane-side file is authority.
// Audit is a quiescent file check, not containment or concurrent tamper proof.
type Home struct {
	mu      sync.Mutex
	path    string
	root    *os.Root
	records *Records
	key     string
	record  homeRecord
}

func (h *Home) Format(state fmt.State, verb rune) {
	io.WriteString(state, "codex-home(values withheld)")
}
func (h *Home) MarshalJSON() ([]byte, error) { return []byte(`{"codex_home":"values withheld"}`), nil }
func (h *Home) Descriptor() api.PrivateHome  { h.mu.Lock(); defer h.mu.Unlock(); return h.record.Home }

// Create requires an existing PRIVATE parent. It imports no ambient home and
// exclusively creates the lane home. The caller must keep records outside all
// lane mounts and give this tree to only the lane's isolated OS identity.
func Create(path string, descriptor api.PrivateHome, records *Records) (*Home, error) {
	if !absolute(path) || !privateHome(descriptor) || records == nil || descriptor.VendorDirectory != ".codex" && descriptor.VendorDirectory != filepath.Join(path, ".codex") {
		return nil, problem(api.CodeInvalid, "Codex home needs an explicit descriptor and protected records")
	}
	if err := records.check(); err != nil {
		return nil, wrap("create Codex home", err)
	}
	parent, root, err := openControlDirectory(filepath.Dir(path))
	if err != nil {
		return nil, wrap("check Codex home parent", err)
	}
	defer root.Close()
	path = filepath.Join(parent, filepath.Base(path))
	if descriptor.VendorDirectory != ".codex" && descriptor.VendorDirectory != filepath.Join(path, ".codex") || within(path, records.path) || within(records.path, path) {
		return nil, problem(api.CodeIntegrity, "Codex records must be separate from the lane home")
	}
	if err := root.Mkdir(filepath.Base(path), 0700); err != nil {
		return nil, problem(api.CodeConflict, "Codex home must be new and exclusively creatable")
	}
	homeRoot, err := os.OpenRoot(path)
	if err != nil {
		return nil, problem(api.CodeUnavailable, "Codex new home cannot be opened")
	}
	key, err := homeKey(homeRoot)
	if err != nil {
		homeRoot.Close()
		return nil, err
	}
	h := &Home{path: path, root: homeRoot, records: records, key: key, record: homeRecord{
		Driver: api.DriverCodex, Home: descriptor, Assets: []assetRecord{}, Slot: slotRecord{Logins: []api.ID{}},
	}}
	for _, name := range []string{".runnerhome-runtime", ".config", ".cache", ".local", ".local/state", "tmp",
		".codex", ".codex/sessions", ".codex/log", ".codex/tmp", ".codex/cache", ".codex/skills"} {
		if err := h.root.Mkdir(name, 0700); err != nil {
			h.root.Close()
			return nil, problem(api.CodeUnavailable, "Codex private directory creation is incomplete")
		}
	}
	if err := writePrivate(h.root, ".codex/config.toml", ".runnerhome-runtime", []byte("cli_auth_credentials_store = \"file\"\napproval_policy = \"never\"\nsandbox_mode = \"danger-full-access\"\n"), 0400); err != nil {
		h.root.Close()
		return nil, err
	}
	if err := writePrivate(h.root, ".codex/history.jsonl", ".runnerhome-runtime", nil, 0600); err != nil {
		h.root.Close()
		return nil, err
	}
	if err := h.seal(".codex/config.toml"); err != nil {
		h.root.Close()
		return nil, err
	}
	if err := writePrivate(h.root, ".codex/hooks.json", ".runnerhome-runtime", []byte("{}\n"), 0400); err != nil {
		h.root.Close()
		return nil, err
	}
	if err := h.seal(".codex/hooks.json"); err != nil {
		h.root.Close()
		return nil, err
	}
	if err := h.save(); err != nil {
		h.root.Close()
		return nil, err
	}
	return h, nil
}

func Open(path string, records *Records) (*Home, error) {
	if !absolute(path) || records == nil || within(path, records.path) || within(records.path, path) {
		return nil, problem(api.CodeInvalid, "Codex existing home needs a separate protected records directory")
	}
	root, err := os.OpenRoot(path)
	if err != nil {
		return nil, problem(api.CodeUnavailable, "Codex existing home cannot be opened")
	}
	if err := sameRoot(path, root); err != nil {
		root.Close()
		return nil, wrap("open Codex home", err)
	}
	key, err := homeKey(root)
	if err != nil {
		root.Close()
		return nil, err
	}
	h := &Home{path: path, root: root, records: records, key: key}
	if err := h.reload(); err != nil {
		root.Close()
		return nil, err
	}
	if h.record.Driver != api.DriverCodex || !privateHome(h.record.Home) || h.record.Home.VendorDirectory != ".codex" && h.record.Home.VendorDirectory != filepath.Join(path, ".codex") {
		root.Close()
		return nil, problem(api.CodeIntegrity, "Codex protected home descriptor is invalid")
	}
	if _, err := h.Audit(); err != nil {
		root.Close()
		return nil, err
	}
	return h, nil
}

func (h *Home) Close() error { return closeResult(h.root.Close()) }

// PreparedSession reloads protected worker state. The worker reserves the
// service-issued session before asking the adapter to build argv.
func (h *Home) PreparedSession() (api.Session, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if err := h.reload(); err != nil {
		return api.Session{}, err
	}
	if h.record.Session.ID == "" {
		return api.Session{}, problem(api.CodeConflict, "Codex private home has no prepared session")
	}
	return h.record.Session, nil
}

func (h *Home) save() error {
	if err := h.records.check(); err != nil {
		return wrap("save Codex home record", err)
	}
	data, err := json.Marshal(h.record)
	if err != nil {
		return problem(api.CodeIntegrity, "Codex home record cannot be encoded")
	}
	return writePrivate(h.records.root, h.key+".json", ".", data, 0600)
}

func (h *Home) reload() error {
	if err := h.records.check(); err != nil {
		return wrap("read Codex home record", err)
	}
	data, err := readPrivate(h.records.root, h.key+".json", maxRecordBytes)
	if err != nil {
		return wrap("read Codex protected home record", err)
	}
	if err := decode(data, &h.record); err != nil {
		return wrap("decode Codex protected home record", err)
	}
	session := h.record.Session
	if session != (api.Session{}) && (!id(session.ID) || session.Driver != api.DriverCodex ||
		!id(session.HistoryID) || session.HistoryID != h.record.Home.HistoryID || session.HomeID != h.record.Home.ID ||
		!absolute(session.LogicalCWD) || !label(session.VendorVersion) || !label(h.record.Model) ||
		(session.VendorID != "" && !uuid(session.VendorID))) {
		return problem(api.CodeIntegrity, "Codex protected session differs from its private history binding")
	}
	return nil
}

func (h *Home) seal(name string) error {
	data, err := readPrivate(h.root, name, 16*1024*1024)
	if err != nil {
		return wrap("seal Codex generated asset", err)
	}
	hash := sha256.Sum256(data)
	for i := range h.record.Assets {
		if h.record.Assets[i].Name == name {
			h.record.Assets[i].SHA256 = api.Digest(hex.EncodeToString(hash[:]))
			return nil
		}
	}
	h.record.Assets = append(h.record.Assets, assetRecord{Name: name, SHA256: api.Digest(hex.EncodeToString(hash[:]))})
	return nil
}

// Observation names a non-owned entry and its shape; it carries no file bytes.
// Ordinary sockets, links and hard links cannot prevent a later turn or swap.
type Observation struct {
	Path string
	Kind string
}
type AuditReport struct{ Observations []Observation }

func (h *Home) Audit() (AuditReport, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.audit()
}

func (h *Home) audit() (AuditReport, error) {
	report := AuditReport{Observations: []Observation{}}
	if err := h.records.check(); err != nil {
		return report, wrap("audit Codex records", err)
	}
	if err := sameRoot(h.path, h.root); err != nil {
		return report, wrap("audit Codex home", err)
	}
	for _, name := range []string{".runnerhome-runtime", ".codex"} {
		info, err := h.root.Lstat(name)
		if err != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
			return report, problem(api.CodeIntegrity, "Codex owned container must be a real private directory")
		}
	}
	for _, asset := range h.record.Assets {
		data, err := readPrivate(h.root, asset.Name, 16*1024*1024)
		if err != nil {
			return report, wrap("audit Codex generated asset", err)
		}
		info, err := h.root.Lstat(asset.Name)
		if err != nil || info.Mode().Perm() != 0400 {
			return report, problem(api.CodeIntegrity, "Codex generated asset is no longer read-only")
		}
		hash := sha256.Sum256(data)
		if api.Digest(hex.EncodeToString(hash[:])) != asset.SHA256 {
			return report, problem(api.CodeIntegrity, "Codex generated asset differs from its protected digest")
		}
	}
	if _, err := h.root.Lstat(".codex/auth.json"); err == nil {
		if _, err := readPrivate(h.root, ".codex/auth.json", maxAuthBytes); err != nil {
			return report, wrap("audit Codex auth slot", err)
		}
	} else if !os.IsNotExist(err) {
		return report, problem(api.CodeUnavailable, "Codex auth slot cannot be inspected")
	} else if h.record.Slot.Ready {
		return report, problem(api.CodeIntegrity, "Codex selected native auth slot is absent")
	}
	directory, err := h.root.Open(".runnerhome-runtime")
	if err != nil {
		return report, problem(api.CodeUnavailable, "Codex owned runtime directory cannot be read")
	}
	entries, readErr := directory.ReadDir(-1)
	closeErr := directory.Close()
	if readErr != nil || closeErr != nil {
		return report, problem(api.CodeUnavailable, "Codex owned runtime entries cannot be inspected completely")
	}
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), ".runnerhome-") {
			continue
		}
		name := filepath.Join(".runnerhome-runtime", entry.Name())
		info, err := h.root.Lstat(name)
		if err != nil || !info.Mode().IsRegular() || linked(info) || info.Mode().Perm()&0077 != 0 {
			return report, problem(api.CodeIntegrity, "Codex owned runtime entry must be a private single-linked regular file")
		}
	}
	err = fs.WalkDir(h.root.FS(), ".", func(name string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			report.Observations = append(report.Observations, Observation{Path: name, Kind: "unreadable"})
			return fs.SkipDir
		}
		if name == "." {
			return nil
		}
		owned := name == ".codex/auth.json"
		for _, asset := range h.record.Assets {
			owned = owned || name == asset.Name
		}
		owned = owned || filepath.Dir(name) == ".runnerhome-runtime" && strings.HasPrefix(filepath.Base(name), ".runnerhome-")
		if owned {
			if err := ownedAncestors(h.root, name); err != nil {
				return wrap("audit Codex owned entry", err)
			}
			info, err := h.root.Lstat(name)
			if err != nil || !info.Mode().IsRegular() || linked(info) || info.Mode().Perm()&0077 != 0 {
				return problem(api.CodeIntegrity, "Codex owned entry must be a private single-linked regular file")
			}
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			report.Observations = append(report.Observations, Observation{Path: name, Kind: "unreadable"})
			return nil
		}
		kind := ""
		switch {
		case info.Mode()&os.ModeSymlink != 0:
			kind = "symlink"
		case !info.IsDir() && !info.Mode().IsRegular():
			kind = "special"
		case info.Mode().IsRegular() && linked(info):
			kind = "hardlink"
		case filepath.Dir(name) == ".runnerhome-runtime":
			kind = "unexpected-runtime-entry"
		case info.IsDir():
			kind = "directory"
		default:
			kind = "file"
		}
		if kind != "" {
			report.Observations = append(report.Observations, Observation{Path: name, Kind: kind})
		}
		return nil
	})
	if err != nil {
		return report, wrap("audit Codex owned paths", err)
	}
	return report, nil
}

// Seed copies only explicitly selected non-runtime assets. Runtime/auth/history
// imports are refused. Config/hooks are sealed in the protected service record;
// they may not redirect login, provider, home, helpers, sandbox or policy.
func (h *Home) Seed(source, destination string) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if !absolute(source) || filepath.ToSlash(filepath.Clean(destination)) != destination ||
		!(destination == ".codex/config.toml" || destination == ".codex/hooks.json" || destination == ".codex/skills" || strings.HasPrefix(destination, ".codex/skills/")) {
		return problem(api.CodeInvalid, "Codex seed destination is not a selected non-runtime asset")
	}
	if err := h.reload(); err != nil {
		return err
	}
	if h.record.Session.ID != "" || len(h.record.Slot.Logins) != 0 {
		return problem(api.CodeConflict, "Codex configuration assets must be seeded before issuing any credential slot")
	}
	if _, err := h.audit(); err != nil {
		return err
	}
	for path := source; ; path = filepath.Dir(path) {
		info, err := os.Lstat(path)
		if err != nil || info.Mode()&os.ModeSymlink != 0 {
			return problem(api.CodeIntegrity, "Codex asset source has a linked or absent ancestor")
		}
		if filepath.Dir(path) == path {
			break
		}
	}
	sourceRoot, err := os.OpenRoot(filepath.Dir(source))
	if err != nil {
		return problem(api.CodeUnavailable, "Codex asset source cannot be opened")
	}
	defer sourceRoot.Close()
	base := filepath.Base(source)
	err = fs.WalkDir(sourceRoot.FS(), base, func(name string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return problem(api.CodeUnavailable, "Codex asset source cannot be walked")
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return problem(api.CodeIntegrity, "Codex asset source contains a link")
		}
		suffix, err := filepath.Rel(base, name)
		if err != nil {
			return problem(api.CodeIntegrity, "Codex asset destination cannot be resolved")
		}
		target := filepath.Join(destination, suffix)
		if entry.IsDir() {
			if err := h.root.Mkdir(target, 0700); err != nil {
				info, statErr := h.root.Lstat(target)
				if !os.IsExist(err) || statErr != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
					return problem(api.CodeIntegrity, "Codex asset directory cannot be created safely")
				}
			}
			return nil
		}
		data, err := readRegular(sourceRoot, name, 16*1024*1024, false)
		if err != nil {
			return wrap("read Codex seed asset", err)
		}
		info, err := entry.Info()
		if err != nil {
			return problem(api.CodeUnavailable, "Codex asset metadata cannot be read")
		}
		mode := fs.FileMode(0600)
		if info.Mode().Perm()&0111 != 0 {
			mode = 0700
		}
		if target == ".codex/config.toml" || target == ".codex/hooks.json" {
			if err := checkConfig(target, data); err != nil {
				return err
			}
			mode = 0400
		}
		if err := writePrivate(h.root, target, ".runnerhome-runtime", data, mode); err != nil {
			return err
		}
		if mode == 0400 {
			return h.seal(target)
		}
		return nil
	})
	if err != nil {
		return wrap("copy Codex selected assets", err)
	}
	return h.save()
}

// Archive selected history only; these names are mandatory exclusions, not a
// claim that every vendor-generated file is credential-free.
func (h *Home) CredentialPaths() []string { return []string{".codex/auth.json", ".runnerhome-runtime"} }
