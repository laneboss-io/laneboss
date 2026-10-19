//go:build linux

package linux

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
	"laneboss.io/laneboss/internal/v2/api"
)

const (
	bwrapPath   = "/usr/bin/bwrap"
	helperPath  = "/.lb-v2-bootstrap"
	helperFlag  = "--laneboss-linux-bootstrap"
	privateHome = "/home/lane"
	privateRun  = "/run/lane"
)

// sandboxSpec is a resolved trusted bootstrap input, not a public RPC or
// api.LaunchSpec adapter. Its caller must already have switched to the leased
// lane UID, cleared groups and joined the cgroup. No service code calls the
// diagnostic start path until the missing frozen control contract is amended.
type sandboxSpec struct {
	Worktree     string
	CWD          string
	MainReadOnly bool
	Grants       []exportSpec
	Home         string
	Tmp          string
	StatePaths   []string
	Helper       string
	HelperSHA256 api.Digest
	UIDPool      []IDRange
	GIDPool      []IDRange
	Environment  []string // already selected protected values; never os.Environ
	Network      bool
	Argv         []string
	Stdin        io.Reader
	Stdout       io.Writer
	Stderr       io.Writer
}

type exportSpec struct {
	Source string
	Target string
	Access Access
}

type launchPayload struct {
	Mode        string       `json:"mode"`
	CWD         string       `json:"cwd"`
	Nonce       string       `json:"nonce,omitempty"`
	Argv        []string     `json:"argv,omitempty"`
	Environment []string     `json:"environment,omitempty"`
	Paths       []PathAccess `json:"paths"`
}

type launchPlan struct {
	runtime []*pinnedMount
	data    []*pinnedMount
	helper  *pinnedMount
	links   [][2]string
	home    bool
	tmp     bool
	cwd     string
}

func (plan *launchPlan) close() error {
	var failures []error
	items := append(append([]*pinnedMount{}, plan.runtime...), plan.data...)
	if plan.helper != nil {
		items = append(items, plan.helper)
	}
	for _, item := range items {
		failures = append(failures, item.file.Close())
	}
	return errors.Join(failures...)
}

func hashPinned(item *pinnedMount) (api.Digest, error) {
	fd, err := unix.Open("/proc/self/fd/"+strconv.Itoa(int(item.file.Fd())), unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return "", err
	}
	file := os.NewFile(uintptr(fd), "pinned-executable")
	hash := sha256.New()
	_, readErr := io.Copy(hash, file)
	closeErr := file.Close()
	if readErr != nil || closeErr != nil {
		return "", errors.Join(readErr, closeErr)
	}
	return api.Digest(hex.EncodeToString(hash.Sum(nil))), nil
}

func pinRuntime(source, target string, policy runtimePathPolicy) (*pinnedMount, error) {
	resolved, err := safeSystemPath(source)
	if err != nil {
		return nil, fmt.Errorf("runtime %s: %w", target, err)
	}
	item, err := pinPath(resolved, target, true)
	if err != nil {
		return nil, err
	}
	if err := checkPinnedMounts(item); err != nil {
		return nil, errors.Join(fmt.Errorf("runtime %s mount: %w", target, err), item.file.Close())
	}
	// An administrator-owned parent alone does not make a user-owned subtree
	// safe to project into every lane. Check through the same pinned inode.
	err = walkPinned(item, func(_ string, identity objectIdentity) error {
		if !policy.systemUID(identity.UID) || !policy.systemGID(identity.GID) {
			return errors.New("runtime tree owner/group is outside administrator inventory")
		}
		if identity.Mode&unix.S_IFMT == unix.S_IFLNK {
			return nil // links resolve only within the final minimal mount view
		}
		if identity.Mode&0022 != 0 {
			return errors.New("runtime tree contains a group/other writable object")
		}
		return nil
	})
	if err != nil {
		return nil, errors.Join(fmt.Errorf("runtime %s: %w", target, err), item.file.Close())
	}
	return item, nil
}

func runtimePlan(helper string, digest api.Digest, uidPool, gidPool []IDRange) (_ launchPlan, resultErr error) {
	var plan launchPlan
	defer func() {
		if resultErr != nil {
			resultErr = errors.Join(resultErr, plan.close())
		}
	}()
	if !validDigest(digest) {
		return plan, errors.New("installed helper digest is required")
	}
	resolved, err := safeSystemPath(helper)
	if err != nil {
		return plan, fmt.Errorf("installed helper ownership: %w", err)
	}
	plan.helper, err = pinPath(resolved, helperPath, true)
	if err != nil {
		return plan, err
	}
	if plan.helper.identity.Mode&unix.S_IFMT != unix.S_IFREG ||
		plan.helper.identity.Mode&(unix.S_ISUID|unix.S_ISGID) != 0 {
		return plan, errors.New("installed helper must be a root-owned non-setuid regular file")
	}
	if plan.helper.identity.UID != 0 || plan.helper.identity.GID != 0 {
		allowAndLog("helper_root_owner")
	}
	actual, err := hashPinned(plan.helper)
	if err != nil {
		return plan, fmt.Errorf("hash pinned helper: %w", err)
	}
	if actual != digest {
		return plan, errors.New("installed helper digest mismatch")
	}
	if err := checkPinnedMounts(plan.helper); err != nil {
		return plan, err
	}
	limits, err := hostSystemIDLimits()
	if err != nil {
		return plan, err
	}
	policy := runtimePathPolicy{limits: limits, laneUID: uint32(os.Geteuid()),
		laneGID: uint32(os.Getegid()), uidPool: uidPool, gidPool: gidPool}
	for _, name := range []string{"/usr", "/bin", "/sbin", "/lib", "/lib64"} {
		info, err := os.Lstat(name)
		if errors.Is(err, fs.ErrNotExist) && name != "/usr" {
			continue
		}
		if err != nil {
			return plan, err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			resolved, err := safeSystemPath(name)
			if err != nil {
				return plan, err
			}
			if !within(resolved, "/usr") {
				return plan, errors.New("runtime symlink must resolve into the usr projection")
			}
			target, err := os.Readlink(name)
			if err != nil {
				return plan, err
			}
			plan.links = append(plan.links, [2]string{target, name})
			continue
		}
		item, err := pinRuntime(name, name, policy)
		if err != nil {
			return plan, err
		}
		plan.runtime = append(plan.runtime, item)
	}
	for _, name := range []string{"/etc/ld.so.cache", "/etc/ssl/certs"} {
		if _, err := os.Stat(name); errors.Is(err, fs.ErrNotExist) {
			continue
		} else if err != nil {
			return plan, err
		}
		item, err := pinRuntime(name, name, policy)
		if err != nil {
			return plan, err
		}
		plan.runtime = append(plan.runtime, item)
	}
	return plan, nil
}

func checkExportOverlaps(plan launchPlan, protected []string) error {
	for _, item := range append(append([]*pinnedMount{}, plan.runtime...), plan.helper) {
		for _, root := range protected {
			if overlaps(item.source, root) {
				return fmt.Errorf("runtime %s overlaps protected state", item.target)
			}
		}
	}
	for index, item := range plan.data {
		if overlaps(item.source, plan.helper.source) {
			return fmt.Errorf("export %s overlaps the installed helper", item.target)
		}
		for _, runtime := range plan.runtime {
			if overlaps(item.source, runtime.source) {
				return fmt.Errorf("export %s overlaps runtime %s", item.target, runtime.target)
			}
		}
		for _, other := range plan.data[:index] {
			if overlaps(item.source, other.source) || overlaps(item.target, other.target) ||
				item.identity.Device == other.identity.Device && item.identity.Inode == other.identity.Inode {
				return fmt.Errorf("export %s aliases another export", item.target)
			}
		}
	}
	return nil
}

func prepareSandbox(spec sandboxSpec) (_ launchPlan, _ launchPayload, resultErr error) {
	var plan launchPlan
	var payload launchPayload
	if spec.Network {
		return plan, payload, &PrerequisiteError{Check: "controlled_egress",
			Err: errors.New("networked launch requires a provisioned private network lease")}
	}
	if len(spec.Argv) == 0 || !canonical(spec.Argv[0]) || spec.Argv[0] == "/" {
		return plan, payload, errors.New("command requires an absolute lane executable")
	}
	if spec.CWD == "" {
		spec.CWD = "/work/main"
	}
	if !canonical(spec.CWD) || !within(spec.CWD, "/work/main") {
		return plan, payload, errors.New("cwd must be beneath the main lane workspace")
	}
	for _, argument := range spec.Argv {
		if strings.ContainsRune(argument, 0) {
			return plan, payload, errors.New("NUL in command argument")
		}
	}
	var err error
	plan, err = runtimePlan(spec.Helper, spec.HelperSHA256, spec.UIDPool, spec.GIDPool)
	if err != nil {
		return plan, payload, err
	}
	plan.cwd = spec.CWD
	defer func() {
		if resultErr != nil {
			resultErr = errors.Join(resultErr, plan.close())
		}
	}()
	roots, err := protectedRoots(spec.StatePaths)
	if err != nil {
		return plan, payload, err
	}
	addExport := func(source, target string, access Access, private bool) error {
		if access != ReadOnly && access != ReadWrite {
			return fmt.Errorf("export %s has unknown access", target)
		}
		item, err := pinPath(source, target, access == ReadOnly)
		if err != nil {
			return err
		}
		plan.data = append(plan.data, item)
		if err := checkPinnedMounts(item); err != nil {
			return fmt.Errorf("export %s mount: %w", target, err)
		}
		return validatePinnedExport(item, private, uint32(os.Geteuid()), roots)
	}
	access := ReadWrite
	if spec.MainReadOnly {
		access = ReadOnly
	}
	if err := addExport(spec.Worktree, "/work/main", access, false); err != nil {
		return plan, payload, err
	}
	for _, grant := range spec.Grants {
		parent := filepath.Dir(grant.Target)
		if !canonical(grant.Target) || grant.Target == "/work/main" ||
			(parent != "/work" && parent != "/data") {
			return plan, payload, errors.New("grant target must be a distinct direct child of work or data")
		}
		if err := addExport(grant.Source, grant.Target, grant.Access, false); err != nil {
			return plan, payload, err
		}
	}
	for _, item := range []struct{ source, target string }{{spec.Home, privateHome}, {spec.Tmp, "/tmp"}} {
		if item.source == "" {
			continue
		}
		if err := addExport(item.source, item.target, ReadWrite, true); err != nil {
			return plan, payload, err
		}
		if item.target == privateHome {
			plan.home = true
		} else {
			plan.tmp = true
		}
	}
	if err := checkExportOverlaps(plan, roots); err != nil {
		return plan, payload, err
	}
	payload.Mode, payload.CWD, payload.Argv = "run", spec.CWD, append([]string{}, spec.Argv...)
	payload.Environment, err = selectedEnvironment(spec.Environment)
	if err != nil {
		return plan, payload, err
	}
	for _, item := range append(append([]*pinnedMount{}, plan.runtime...), plan.helper) {
		payload.Paths = append(payload.Paths, PathAccess{Path: item.target, Directory: item.directory,
			Executable: true, Access: ReadOnly})
	}
	for _, item := range plan.data {
		access := ReadWrite
		if item.readOnly {
			access = ReadOnly
		}
		payload.Paths = append(payload.Paths, PathAccess{Path: item.target, Directory: item.directory,
			Executable: true, Access: access})
	}
	for _, dir := range []string{"/proc", "/dev/shm", "/dev/pts", privateRun} {
		access := ReadWrite
		if dir == "/proc" {
			access = ReadOnly
		}
		payload.Paths = append(payload.Paths, PathAccess{Path: dir, Directory: true, Access: access})
	}
	if !plan.home {
		payload.Paths = append(payload.Paths, PathAccess{Path: privateHome, Directory: true, Access: ReadWrite, Executable: true})
	}
	if !plan.tmp {
		payload.Paths = append(payload.Paths, PathAccess{Path: "/tmp", Directory: true, Access: ReadWrite, Executable: true})
	}
	for _, device := range []string{"null", "zero", "full", "random", "urandom", "tty"} {
		payload.Paths = append(payload.Paths, PathAccess{Path: "/dev/" + device, Access: ReadWrite})
	}
	sort.Slice(plan.data, func(i, j int) bool { return plan.data[i].target < plan.data[j].target })
	return plan, payload, nil
}

func selectedEnvironment(selected []string) ([]string, error) {
	result := []string{"PATH=/usr/bin:/bin", "HOME=" + privateHome,
		"TMPDIR=/tmp", "XDG_RUNTIME_DIR=" + privateRun}
	var names []string
	for _, entry := range selected {
		name, _, found := strings.Cut(entry, "=")
		if !found || strings.ContainsRune(entry, 0) {
			return nil, errors.New("invalid selected environment entry")
		}
		names = append(names, name)
	}
	if err := validateEnvironmentNames(names); err != nil {
		return nil, err
	}
	return append(result, selected...), nil
}

// Descriptor 3 is the sealed payload; descriptor 4 holds the seccomp program.
// Every source, including the helper, is bound by fd. No host path is used as
// a mount source after validation. --unshare-net is unconditional.
func buildArgs(plan launchPlan) ([]string, []*os.File) {
	args := []string{"--die-with-parent", "--new-session", "--unshare-user", "--unshare-pid",
		"--unshare-ipc", "--unshare-uts", "--unshare-net",
		"--cap-drop", "ALL", "--clearenv"}
	var files []*os.File
	bind := func(item *pinnedMount) {
		flag := "--bind"
		if item.readOnly {
			flag = "--ro-bind"
		}
		args = append(args, flag, "/proc/self/fd/"+strconv.Itoa(5+len(files)), item.target)
		files = append(files, item.file)
	}
	for _, item := range plan.runtime {
		bind(item)
	}
	for _, link := range plan.links {
		args = append(args, "--symlink", link[0], link[1])
	}
	args = append(args, "--proc", "/proc", "--dev", "/dev", "--perms", "0700", "--tmpfs", "/dev/shm",
		"--dir", "/home", "--dir", "/run", "--perms", "0700", "--tmpfs", privateRun,
		"--dir", "/work", "--dir", "/data")
	if !plan.home {
		args = append(args, "--perms", "0700", "--tmpfs", privateHome)
	}
	if !plan.tmp {
		args = append(args, "--perms", "0700", "--tmpfs", "/tmp")
	}
	for _, item := range plan.data {
		bind(item)
	}
	bind(plan.helper)
	cwd := plan.cwd
	if cwd == "" {
		cwd = "/work/main"
	}
	// denyFilter blocks nested user namespaces before the bootstrap executes;
	// no sysctl write is needed under the installed kernel-tunable protection.
	args = append(args, "--seccomp", "4", "--chdir", cwd, "--remount-ro", "/proc", "--remount-ro", "/",
		"--", helperPath, helperFlag, "3")
	return args, files
}
