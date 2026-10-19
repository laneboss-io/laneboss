//go:build linux

package admin

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
	"laneboss.io/laneboss/internal/v2/api"
)

// The installed unit already gives the whole helper process a private mount
// namespace. Use that namespace, rather than unshare on one Go thread while
// other executor threads retain a different view. Refuse a host namespace or
// mixed thread views before touching any mount.
func helperMountNamespace() error {
	self, err := os.Stat("/proc/self/ns/mnt")
	host, hostErr := os.Stat("/proc/1/ns/mnt")
	if err != nil || hostErr != nil || os.SameFile(self, host) {
		return failure(api.CodeContainmentUnknown, "helper requires its own installed mount namespace")
	}
	threads, err := os.ReadDir("/proc/self/task")
	if err != nil || len(threads) == 0 {
		return failure(api.CodeContainmentUnknown, "helper mount namespace thread inventory is unavailable")
	}
	for _, thread := range threads {
		actual, err := os.Stat(filepath.Join("/proc/self/task", thread.Name(), "ns/mnt"))
		if errors.Is(err, os.ErrNotExist) || errors.Is(err, unix.ESRCH) {
			continue
		}
		if err != nil || !os.SameFile(self, actual) {
			return failure(api.CodeContainmentUnknown, "helper threads do not share its private mount namespace")
		}
	}
	return nil
}

// NSpid is relative to the procfs mount's PID namespace. Exactly one mapping
// must name the visible process, including self and PID 1. An ancestor/host
// proc bind reveals an extra mapping for this sandbox's own process. Reading
// status avoids ptrace-dependent ns links on a nondumpable bwrap PID 1.
func lanePrivateProc() error {
	self, err := os.ReadFile("/proc/self/status")
	if err != nil || !procSinglePID(self, strconv.Itoa(os.Getpid())) {
		return failure(api.CodeIntegrity, "lane procfs does not use its own PID namespace")
	}
	init, err := os.ReadFile("/proc/1/status")
	if err != nil || !procSinglePID(init, "1") {
		return failure(api.CodeIntegrity, "lane procfs has no private namespace init")
	}
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return failure(api.CodeContainmentUnknown, "lane procfs inventory is unavailable")
	}
	visible := 0
	for _, entry := range entries {
		if _, err := strconv.ParseUint(entry.Name(), 10, 32); err != nil {
			continue
		}
		actual, err := os.ReadFile(filepath.Join("/proc", entry.Name(), "status"))
		if errors.Is(err, os.ErrNotExist) || errors.Is(err, unix.ESRCH) {
			continue
		}
		if err != nil || !procSinglePID(actual, entry.Name()) {
			return failure(api.CodeIntegrity, "lane procfs exposes a foreign process namespace")
		}
		visible++
	}
	if visible == 0 {
		return failure(api.CodeContainmentUnknown, "lane procfs inventory is empty")
	}
	return nil
}

func procSinglePID(status []byte, visible string) bool {
	found := false
	for _, line := range strings.Split(string(status), "\n") {
		value, ok := strings.CutPrefix(line, "NSpid:")
		if !ok {
			continue
		}
		fields := strings.Fields(value)
		if found || len(fields) != 1 || fields[0] != visible {
			return false
		}
		found = true
	}
	return found
}

func mountHelperProc(runtimePath string) (func() error, error) {
	if err := helperMountNamespace(); err != nil {
		return nil, err
	}
	// Prevent mount propagation out of this already private unit namespace.
	if err := unix.Mount("", "/", "", unix.MS_REC|unix.MS_PRIVATE, ""); err != nil {
		return nil, failure(api.CodePrerequisite, "cannot make helper mounts private")
	}
	path := filepath.Join(runtimePath, "proc")
	if err := os.Mkdir(path, 0700); err != nil && !errors.Is(err, os.ErrExist) {
		return nil, failure(api.CodePrerequisite, "cannot reserve helper-private procfs mountpoint")
	}
	if err := privateDirectory(path, 0, 0700); err != nil {
		return nil, err
	}
	// Match the approved pristine subset=pid witness. It is private to this
	// helper namespace and has no sys subtree. The original /proc/sys stays
	// read-only, and bwrap remounts the lane's separate /proc read-only.
	flags := uintptr(unix.MS_NOSUID | unix.MS_NODEV | unix.MS_NOEXEC)
	if err := unix.Mount("proc", path, "proc", flags, "subset=pid"); err != nil {
		return nil, failure(api.CodePrerequisite, "cannot mount pristine helper-private pid procfs")
	}
	closeMount := func() error {
		if err := unix.Unmount(path, 0); err != nil {
			return failure(api.CodeContainmentUnknown, "helper-private procfs could not be collected")
		}
		return nil
	}
	if err := verifyHelperProcAtSpawn(runtimePath); err != nil {
		return nil, errors.Join(err, closeMount())
	}
	return closeMount, nil
}

// Called on the locked creator after joining the retained netns and directly
// before Start. The child must inherit this verified mount namespace; neither
// a parent-only setup check nor a retained FD from a foreign view is enough.
func verifyHelperProcAtSpawn(runtimePath string) error {
	leader, err := os.Stat("/proc/self/ns/mnt")
	creator, creatorErr := os.Stat("/proc/thread-self/ns/mnt")
	host, hostErr := os.Stat("/proc/1/ns/mnt")
	// Credential-view workers may intentionally occupy another namespace on
	// retired private threads. Only this locked creator can supply the child.
	if err != nil || creatorErr != nil || hostErr != nil || os.SameFile(creator, host) || !os.SameFile(leader, creator) {
		return failure(api.CodeContainmentUnknown, "gate creator does not share the helper mount namespace")
	}
	var sys unix.Statfs_t
	if unix.Statfs("/proc/sys", &sys) != nil || uint64(sys.Flags)&unix.MS_RDONLY == 0 {
		return failure(api.CodeContainmentUnknown, "helper kernel tunables are not mounted read-only")
	}
	path := filepath.Join(runtimePath, "proc")
	file, err := os.OpenFile(path, os.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return failure(api.CodeContainmentUnknown, "gate creator has no pristine helper procfs")
	}
	checkErr := verifyPristineProc(file, path)
	closeErr := file.Close()
	if checkErr != nil || closeErr != nil {
		return errors.Join(checkErr, failureIfClose(closeErr))
	}
	return nil
}

func failureIfClose(err error) error {
	if err != nil {
		return failure(api.CodeContainmentUnknown, "cannot close pristine procfs verification descriptor")
	}
	return nil
}

func verifyPristineProc(file *os.File, path string) error {
	var fs unix.Statfs_t
	var info unix.Stat_t
	flags := uint64(unix.MS_NOSUID | unix.MS_NODEV | unix.MS_NOEXEC)
	if unix.Fstatfs(int(file.Fd()), &fs) != nil || fs.Type != unix.PROC_SUPER_MAGIC || uint64(fs.Flags)&flags != flags ||
		uint64(fs.Flags)&unix.MS_RDONLY != 0 || !errors.Is(unix.Fstatat(int(file.Fd()), "sys", &info, unix.AT_SYMLINK_NOFOLLOW), unix.ENOENT) {
		return failure(api.CodeContainmentUnknown, "gate creator pristine pid procfs restrictions differ")
	}
	var root unix.Statx_t
	if unix.Statx(int(file.Fd()), "", unix.AT_EMPTY_PATH|unix.AT_SYMLINK_NOFOLLOW, unix.STATX_MNT_ID, &root) != nil || root.Mask&unix.STATX_MNT_ID == 0 {
		return failure(api.CodeContainmentUnknown, "gate creator pristine procfs mount identity is unavailable")
	}
	inventory, err := os.Open("/proc/thread-self/mountinfo")
	if err != nil {
		return failure(api.CodeContainmentUnknown, "gate creator mount inventory is unavailable")
	}
	data, readErr := io.ReadAll(io.LimitReader(inventory, (4<<20)+1))
	closeErr := inventory.Close()
	if readErr != nil || closeErr != nil || len(data) > 4<<20 || !pristineProcMount(data, strconv.FormatUint(root.Mnt_id, 10), path) {
		return failure(api.CodeContainmentUnknown, "gate creator pristine procfs is absent or overmounted")
	}
	return nil
}

func pristineProcMount(data []byte, id, path string) bool {
	found := false
	unescape := strings.NewReplacer(`\040`, " ", `\011`, "\t", `\012`, "\n", `\134`, `\`)
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 10 || fields[1] == id {
			return false
		}
		if fields[0] == id {
			if found || fields[3] != "/" || unescape.Replace(fields[4]) != path || !strings.Contains(line, " - proc ") {
				return false
			}
			found = true
		}
	}
	return found
}
