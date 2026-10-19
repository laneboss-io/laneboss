//go:build linux

package admin

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/sys/unix"
	"laneboss.io/laneboss/internal/v2/api"
)

type executableStamp struct {
	Device   uint64
	Inode    uint64
	Size     int64
	Modified unix.Timespec
	Changed  unix.Timespec
	Digest   api.Digest
}

var verifiedExecutables sync.Map

// The helper selects this fixed system tool once, measures its actual bytes,
// and retains the pin before invoking it. A retry never selects new Git bytes.
func pinWorkspaceGit() (api.ReleaseArtifact, error) {
	const path = "/usr/bin/git"
	if err := protectedPath(path, false); err != nil {
		return api.ReleaseArtifact{}, err
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return api.ReleaseArtifact{}, failure(api.CodePrerequisite, "native workspace Git is unavailable")
	}
	file := os.NewFile(uintptr(fd), "workspace-git")
	defer file.Close()
	var info unix.Stat_t
	if unix.Fstat(fd, &info) != nil || info.Size <= 0 || info.Size > api.MaxObjectBytes {
		return api.ReleaseArtifact{}, failure(api.CodeIntegrity, "native workspace Git has invalid metadata")
	}
	digest := sha256.New()
	if n, err := io.Copy(digest, io.LimitReader(file, info.Size+1)); err != nil || n != info.Size {
		return api.ReleaseArtifact{}, failure(api.CodeIntegrity, "native workspace Git could not be measured")
	}
	artifact := api.ReleaseArtifact{Bytes: info.Size, SHA256: api.Digest(hex.EncodeToString(digest.Sum(nil)))}
	if err := verifyExecutableFile(file, artifact); err != nil {
		return api.ReleaseArtifact{}, err
	}
	return artifact, nil
}

func stampExecutable(info unix.Stat_t, artifact api.ReleaseArtifact) executableStamp {
	return executableStamp{Device: uint64(info.Dev), Inode: info.Ino, Size: info.Size, Modified: info.Mtim, Changed: info.Ctim, Digest: artifact.SHA256}
}

func protectedPath(path string, directory bool) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return failure(api.CodeIntegrity, "installed helper path is not canonical")
	}
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	current := "/"
	for index, part := range parts {
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if err != nil {
			return failure(api.CodePrerequisite, "installed helper path is missing or unreadable")
		}
		fd, err := unix.Open(current, unix.O_PATH|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if err != nil {
			return failure(api.CodeIntegrity, "cannot pin installed helper path")
		}
		var native unix.Stat_t
		err = unix.Fstat(fd, &native)
		closeErr := unix.Close(fd)
		if err != nil || closeErr != nil || native.Uid != 0 || native.Mode&0022 != 0 || info.Mode()&os.ModeSymlink != 0 {
			return failure(api.CodeIntegrity, "installed helper path must be root-owned, unlinked and not group/world writable")
		}
		if index < len(parts)-1 || directory {
			if !info.IsDir() {
				return failure(api.CodeIntegrity, "installed helper parent is not a directory")
			}
		}
	}
	return nil
}

func readProtected(path string, max int64) ([]byte, error) {
	return readProtectedMode(path, max, 0)
}

func readProtectedMode(path string, max int64, mode uint32) ([]byte, error) {
	if err := protectedPath(path, false); err != nil {
		return nil, err
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, failure(api.CodePrerequisite, "cannot open installed helper data")
	}
	f := os.NewFile(uintptr(fd), "installed-data")
	defer f.Close()
	return readProtectedDescriptor(f, max, mode, 0)
}

// Production always selects owner zero. Package component tests may read their
// own actual descriptors; ownership is never a helper or public request field.
func readProtectedDescriptor(f *os.File, max int64, mode, owner uint32) ([]byte, error) {
	fd := int(f.Fd())
	var info unix.Stat_t
	if err := unix.Fstat(fd, &info); err != nil || info.Mode&unix.S_IFMT != unix.S_IFREG ||
		info.Uid != owner || info.Mode&0022 != 0 || info.Nlink != 1 || info.Size < 0 || info.Size > max {
		return nil, failure(api.CodeIntegrity, "installed helper data has unsafe ownership, links, mode or size")
	}
	if mode != 0 && info.Mode&07777 != mode {
		return nil, failure(api.CodeIntegrity, "initial publication input must be an immutable root-owned file")
	}
	data, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil || int64(len(data)) > max {
		return nil, failure(api.CodeIntegrity, "cannot read bounded installed helper data")
	}
	return data, nil
}

func loadInstallation(config string) (installation, error) {
	if !validConfig(config) {
		return installation{}, failure(api.CodeInvalid, "invalid helper configuration name")
	}
	data, err := readProtected(bindingPath(config), api.MaxFrameBytes)
	if err != nil {
		return installation{}, err
	}
	var b installation
	if err := decodeStrict(data, &b); err != nil {
		return b, err
	}
	if err := b.validate(); err != nil {
		return b, err
	}
	if b.Config != config {
		return b, failure(api.CodeIntegrity, "installed helper configuration name differs")
	}
	if err := verifyExecutable(b.binaryPath(), b.Artifact); err != nil {
		return b, err
	}
	return b, nil
}

func verifyExecutable(path string, artifact api.ReleaseArtifact) error {
	if err := protectedPath(path, false); err != nil {
		return err
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return failure(api.CodeIntegrity, "cannot open the installed executable")
	}
	f := os.NewFile(uintptr(fd), "installed-executable")
	defer f.Close()
	return verifyExecutableFile(f, artifact)
}

func verifyExecutableFile(f *os.File, artifact api.ReleaseArtifact) error {
	return verifyExecutableFileRead(f, artifact, nil)
}

// The optional process-local observer sees real reads without replacing their
// bytes or verdict. Native canaries use it to order an RPC during hash proof.
func verifyExecutableFileRead(f *os.File, artifact api.ReleaseArtifact, observed func(int)) error {
	var st unix.Stat_t
	if err := unix.Fstat(int(f.Fd()), &st); err != nil {
		return failure(api.CodeIntegrity, "cannot stat pinned helper executable")
	}
	if err := verifyArtifactStat(st, artifact); err != nil {
		return err
	}
	_, err := unix.Fgetxattr(int(f.Fd()), "security.capability", nil)
	if err == nil || !errors.Is(err, unix.ENODATA) && !errors.Is(err, unix.ENOTSUP) {
		return failure(api.CodeIntegrity, "helper executable has capabilities or unverifiable capability metadata")
	}
	stamp := stampExecutable(st, artifact)
	if _, verified := verifiedExecutables.Load(stamp); verified {
		return nil
	}
	hash := sha256.New()
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return failure(api.CodeIntegrity, "cannot seek pinned helper executable")
	}
	var reader io.Reader = f
	if observed != nil {
		reader = &executableReadObserver{file: f, observed: observed}
	}
	n, err := io.Copy(hash, io.LimitReader(reader, artifact.Bytes+1))
	if err != nil || n != artifact.Bytes || hex.EncodeToString(hash.Sum(nil)) != string(artifact.SHA256) {
		return failure(api.CodeIntegrity, "helper executable digest differs from its installed release")
	}
	var after unix.Stat_t
	if unix.Fstat(int(f.Fd()), &after) != nil || stampExecutable(after, artifact) != stamp || verifyArtifactStat(after, artifact) != nil {
		return failure(api.CodeIntegrity, "executable metadata changed while verifying bytes")
	}
	verifiedExecutables.Store(stamp, struct{}{})
	return nil
}

type executableReadObserver struct {
	file     *os.File
	observed func(int)
}

func (r *executableReadObserver) Read(data []byte) (int, error) {
	n, err := r.file.Read(data)
	if n > 0 {
		r.observed(n)
	}
	return n, err
}

func verifyArtifactStat(st unix.Stat_t, artifact api.ReleaseArtifact) error {
	if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Uid != 0 || st.Mode&07022 != 0 ||
		st.Mode&0111 == 0 || st.Nlink != 1 || st.Size != artifact.Bytes {
		return failure(api.CodeIntegrity, "helper executable is changed, linked, writable, setuid or setgid")
	}
	return nil
}

func checkAccount(a account) error {
	u, err := user.Lookup(a.Name)
	if err != nil || u.Uid != strconv.FormatUint(uint64(a.UID), 10) || u.Gid != strconv.FormatUint(uint64(a.GID), 10) {
		return failure(api.CodeIntegrity, "installed account UID or primary group changed")
	}
	groups, err := u.GroupIds()
	if err != nil {
		return failure(api.CodeIntegrity, "installed account groups cannot be verified")
	}
	for _, group := range groups {
		if group != u.Gid {
			return failure(api.CodeIntegrity, "installed account has supplementary groups")
		}
	}
	// Require a locked system account with no interactive shell. These are OS
	// installation facts; a request cannot select an account by name.
	data, err := os.ReadFile("/etc/passwd")
	if err != nil {
		return failure(api.CodePrerequisite, "cannot verify installed account shell")
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Split(line, ":")
		if len(fields) == 7 && fields[0] == a.Name {
			if fields[6] != "/usr/sbin/nologin" && fields[6] != "/sbin/nologin" {
				return failure(api.CodeIntegrity, "installed account permits an interactive shell")
			}
			return checkAccountLock(a.Name)
		}
	}
	return failure(api.CodeIntegrity, "installed account has no local passwd record")
}

func checkAccountLock(name string) error {
	// Inspect only in privileged helper memory. No shadow byte, hash, password
	// or account lookup result is returned, copied to an event or printed.
	data, err := readProtected("/etc/shadow", api.MaxFrameBytes)
	if err != nil {
		return failure(api.CodePrerequisite, "cannot verify that installed service/lane accounts are locked")
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Split(line, ":")
		if len(fields) == 9 && fields[0] == name {
			if strings.HasPrefix(fields[1], "!") || strings.HasPrefix(fields[1], "*") {
				return nil
			}
			return failure(api.CodeIntegrity, "installed service/lane account is not password locked")
		}
	}
	return failure(api.CodeIntegrity, "installed service/lane account has no local lock record")
}
