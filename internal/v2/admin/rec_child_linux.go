//go:build linux

package admin

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
	"laneboss.io/laneboss/internal/v2/api"
	archivejob "laneboss.io/laneboss/internal/v2/archive"
	"laneboss.io/laneboss/internal/v2/grants/manifest"
)

const restoreChildEntry = "--restore-child"

type restoreChildInput struct {
	Tree     api.ObjectManifest
	UID, GID uint32
	RootDev  uint64
	RootIno  uint64
	Allow    bool
	Ceiling  uint64
}

type restoreRuleError struct {
	slot int
	err  error
}

func (e *restoreRuleError) Error() string { return "restore confinement setup failed" }
func (e *restoreRuleError) Unwrap() error { return e.err }

func restoreRefs(tree api.ObjectManifest) (map[api.ID]api.BlobRef, []api.ID) {
	refs := map[api.ID]api.BlobRef{}
	for _, entry := range tree.Entries {
		for _, ref := range manifest.ContentRefs(entry) {
			refs[ref.ID] = ref
		}
	}
	ids := make([]api.ID, 0, len(refs))
	for id := range refs {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	return refs, ids
}

func sealedRestore(file *os.File, limit int64) (unix.Stat_t, error) {
	var info unix.Stat_t
	seals, err := unix.FcntlInt(file.Fd(), unix.F_GET_SEALS, 0)
	if err != nil || seals&bootstrapSeals != bootstrapSeals || unix.Fstat(int(file.Fd()), &info) != nil || info.Mode&unix.S_IFMT != unix.S_IFREG || info.Size < 0 || info.Size > limit {
		return info, failure(api.CodeIntegrity, "restore input is not exactly sealed")
	}
	return info, nil
}

// The fixed namespace entry drops groups, UID/GID and capabilities before
// reading any archive input. It has no service socket, host target path or
// inherited credential environment.
func runRestoreChild(ctx context.Context, identity []string) int {
	runtime.LockOSThread()
	uid, uidErr := strconv.ParseUint(identity[0], 10, 32)
	gid, gidErr := strconv.ParseUint(identity[1], 10, 32)
	if uidErr != nil || gidErr != nil || uid == 0 || gid == 0 {
		return 92
	}
	if os.Geteuid() == 0 {
		// This fixed entry performs no input read before the privilege drop.
		// syscall's credential setters synchronize all Go runtime threads.
		if syscall.Setgroups([]int{}) != nil || syscall.Setresgid(int(gid), int(gid), int(gid)) != nil || syscall.Setresuid(int(uid), int(uid), int(uid)) != nil {
			return 92
		}
		// A fresh unprivileged image replaces every runtime thread. Clear the
		// calling thread's inherited/ambient sets first; only FDs 3-5 survive.
		header := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
		caps := [2]unix.CapUserData{}
		if unix.Capset(&header, &caps[0]) != nil || unix.Prctl(unix.PR_CAP_AMBIENT, unix.PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0) != nil ||
			unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != nil || unix.CloseRange(6, ^uint(0), unix.CLOSE_RANGE_CLOEXEC) != nil {
			return 92
		}
		if err := unix.Exec("/runtime/restore", []string{"/runtime/restore", restoreChildEntry, identity[0], identity[1]}, []string{"GOMAXPROCS=1"}); err != nil {
			return 92
		}
	}
	input, bodies := os.NewFile(3, "restore-input"), os.NewFile(4, "restore-bytes")
	defer input.Close()
	defer bodies.Close()
	if _, err := sealedRestore(input, api.MaxFrameBytes); err != nil {
		return 90
	}
	raw, err := io.ReadAll(io.LimitReader(input, api.MaxFrameBytes+1))
	var q restoreChildInput
	if err != nil || decodeStrict(raw, &q) != nil || q.Ceiling > 128<<20 {
		return 91
	}
	if q.UID == 0 || q.GID == 0 || os.Getuid() != int(q.UID) || os.Geteuid() != int(q.UID) || os.Getgid() != int(q.GID) || os.Getegid() != int(q.GID) {
		return 92
	}
	groups, err := os.Getgroups()
	if err != nil || len(groups) != 0 || unix.Prctl(unix.PR_CAP_AMBIENT, unix.PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0) != nil {
		return 92
	}
	header := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	caps := [2]unix.CapUserData{}
	if unix.Capget(&header, &caps[0]) != nil || caps != [2]unix.CapUserData{} {
		return 92
	}
	if unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0) != nil || unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != nil || unix.CloseRange(3, ^uint(0), unix.CLOSE_RANGE_CLOEXEC) != nil {
		return 93
	}
	unix.Umask(0077)
	workFD, err := unix.Open("/work", unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return 96
	}
	directory := os.NewFile(uintptr(workFD), "restore-root")
	defer directory.Close()
	var inode unix.Stat_t
	if unix.Fstat(workFD, &inode) != nil || inode.Dev != q.RootDev || inode.Ino != q.RootIno || inode.Uid != q.UID || inode.Gid != q.GID {
		return 96
	}
	if err := restoreLandlock(directory); err != nil {
		var rule *restoreRuleError
		if errors.As(err, &rule) {
			return 180 + rule.slot
		}
		var native unix.Errno
		if errors.As(err, &native) && native > 0 && native < 150 {
			return 100 + int(native)
		}
		return 94
	}
	refs, ids := restoreRefs(q.Tree)
	offsets := map[api.ID]int64{}
	var total int64
	for _, id := range ids {
		offsets[id] = total
		if refs[id].Bytes < 0 || uint64(refs[id].Bytes) > q.Ceiling-uint64(total) {
			return 95
		}
		total += refs[id].Bytes
	}
	info, err := sealedRestore(bodies, int64(q.Ceiling))
	if err != nil || info.Size != total {
		return 95
	}
	root, err := os.OpenRoot("/work")
	if err != nil {
		return 96
	}
	defer root.Close()
	held, heldErr := directory.Stat()
	mounted, mountErr := root.Stat(".")
	if heldErr != nil || mountErr != nil || !os.SameFile(held, mounted) {
		return 96
	}
	read := func(ctx context.Context, r api.BlobReadRequest) (api.BlobChunk, error) {
		ref, ok := refs[r.ObjectID]
		if !ok || r.Offset < 0 || r.Offset > ref.Bytes || r.Limit < 1 || r.Limit > api.MaxChunkBytes {
			return api.BlobChunk{}, failure(api.CodeForbidden, "restore read escaped its inventory")
		}
		data := make([]byte, min(int64(r.Limit), ref.Bytes-r.Offset))
		if _, err := bodies.ReadAt(data, offsets[r.ObjectID]+r.Offset); err != nil {
			return api.BlobChunk{}, err
		}
		return api.BlobChunk{ObjectID: r.ObjectID, Offset: r.Offset, Data: data, SHA256: digestBytes(data)}, nil
	}
	var report api.RestoreReceipt
	report.Head, err = archivejob.RestoreRoot(ctx, root, q.Tree, read, q.Ceiling, archivejob.RestoreOptions{AllowNestedGit: q.Allow, Report: &report})
	if err != nil {
		return 97
	}
	encoded, err := EncodeWire(report)
	if err != nil {
		return 98
	}
	if n, err := os.Stdout.Write(encoded); err != nil || n != len(encoded) {
		return 98
	}
	return 0
}

// Only the held result inode is writable. Executables/libraries and proc are
// read-only; no lane home, credential source or service state is granted.
func restoreLandlock(directory *os.File) error {
	abi, _, errno := unix.Syscall(unix.SYS_LANDLOCK_CREATE_RULESET, 0, 0, unix.LANDLOCK_CREATE_RULESET_VERSION)
	if errno != 0 || abi < 3 {
		return failure(api.CodePrerequisite, "restore requires Landlock ABI 3")
	}
	handled := uint64((1 << 15) - 1)
	if abi >= 5 {
		handled |= unix.LANDLOCK_ACCESS_FS_IOCTL_DEV
	}
	fd, _, errno := unix.Syscall(unix.SYS_LANDLOCK_CREATE_RULESET, uintptr(unsafe.Pointer(&handled)), 8, 0)
	if errno != 0 {
		return errno
	}
	defer unix.Close(int(fd))
	add := func(file *os.File, access uint64) error {
		attr := unix.LandlockPathBeneathAttr{Allowed_access: access, Parent_fd: int32(file.Fd())}
		_, _, errno := unix.Syscall6(unix.SYS_LANDLOCK_ADD_RULE, fd, unix.LANDLOCK_RULE_PATH_BENEATH, uintptr(unsafe.Pointer(&attr)), 0, 0, 0)
		runtime.KeepAlive(file)
		if errno != 0 {
			return errno
		}
		return nil
	}
	workFD, err := unix.Open("/work", unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	work := os.NewFile(uintptr(workFD), "restore-work-rule")
	defer work.Close()
	held, heldErr := directory.Stat()
	mounted, mountErr := work.Stat()
	if heldErr != nil || mountErr != nil || !os.SameFile(held, mounted) {
		return failure(api.CodeIntegrity, "restore mount differs from its held inode")
	}
	if err := add(work, handled&^unix.LANDLOCK_ACCESS_FS_EXECUTE); err != nil {
		return err
	}
	for slot, name := range []string{"/usr", "/lib", "/lib64", "/proc", "/dev/null", "/etc/ld.so.cache", "/dev/urandom", "/dev/random"} {
		opened, err := unix.Open(name, unix.O_PATH|unix.O_CLOEXEC, 0)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return &restoreRuleError{slot: slot + 1, err: err}
		}
		file := os.NewFile(uintptr(opened), "restore-read-rule")
		access := uint64(unix.LANDLOCK_ACCESS_FS_READ_FILE)
		info, err := file.Stat()
		if err == nil && info.IsDir() {
			access |= unix.LANDLOCK_ACCESS_FS_READ_DIR | unix.LANDLOCK_ACCESS_FS_EXECUTE
		}
		if name == "/dev/null" {
			access |= unix.LANDLOCK_ACCESS_FS_WRITE_FILE
		}
		if err == nil {
			err = add(file, access)
		}
		if err := errors.Join(err, file.Close()); err != nil {
			return &restoreRuleError{slot: slot + 11, err: err}
		}
	}
	_, _, errno = unix.Syscall(unix.SYS_LANDLOCK_RESTRICT_SELF, fd, 0, 0)
	if errno != 0 {
		return errno
	}
	return nil
}

func (m *leaseManager) runRestore(ctx context.Context, r leaseRecord, job *nativeRestore) (report api.RestoreReceipt, resultErr error) {
	result := filepath.Join(job.Stage, "result")
	if err := os.Mkdir(result, 0700); err != nil {
		return report, err
	}
	if err := os.Chown(result, int(r.Lease.UID), int(r.Lease.GID)); err != nil {
		return report, err
	}
	directory, err := archiveRoot(result)
	if err != nil {
		return report, err
	}
	defer directory.Close()
	var inode unix.Stat_t
	if err := unix.Fstat(int(directory.Fd()), &inode); err != nil {
		return report, err
	}
	input, err := sealedBootstrap(restoreChildInput{Tree: job.Input.Tree, UID: r.Lease.UID, GID: r.Lease.GID, RootDev: inode.Dev, RootIno: inode.Ino, Allow: job.Input.Request.AllowNestedGit, Ceiling: job.Input.Ceiling})
	if err != nil {
		return report, err
	}
	defer input.Close()
	fd, err := unix.MemfdCreate("restore-bytes", unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING)
	if err != nil {
		return report, err
	}
	bodies := os.NewFile(uintptr(fd), "restore-bytes")
	defer bodies.Close()
	_, ids := restoreRefs(job.Input.Tree)
	for _, id := range ids {
		body := job.Bodies[id]
		if n, err := bodies.Write(body); err != nil || n != len(body) {
			return report, failure(api.CodeIntegrity, "cannot retain exact restore input bytes")
		}
	}
	if _, err := unix.FcntlInt(bodies.Fd(), unix.F_ADD_SEALS, bootstrapSeals); err != nil {
		return report, err
	}
	selfFD, err := unix.Open("/proc/self/exe", unix.O_PATH|unix.O_CLOEXEC, 0)
	if err != nil {
		return report, err
	}
	self := os.NewFile(uintptr(selfFD), "restore-executable")
	defer self.Close()
	mountFD, err := unix.Openat(int(directory.Fd()), ".", unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return report, err
	}
	mount := os.NewFile(uintptr(mountFD), "restore-mount")
	defer mount.Close()
	id, err := randomID("rc-")
	if err != nil {
		return report, err
	}
	groupPath := filepath.Join(m.binding.cgroupPath(), string(id))
	if err := os.Mkdir(groupPath, 0755); err != nil {
		return report, err
	}
	group, err := os.OpenRoot(groupPath)
	if err != nil {
		return report, errors.Join(err, os.Remove(groupPath))
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		killErr := writeControl(group, "cgroup.kill", "1")
		waitErr := waitCgroupEvent(cleanup, group, "populated", "0")
		closeErr := group.Close()
		removeErr := os.Remove(groupPath)
		resultErr = errors.Join(resultErr, killErr, waitErr, closeErr, removeErr)
	}()
	for _, limit := range [][2]string{{"pids.max", "32"}, {"memory.max", "536870912"}, {"memory.swap.max", "0"}, {"cgroup.max.depth", "0"}, {"cgroup.max.descendants", "0"}} {
		if err := writeControl(group, limit[0], limit[1]); err != nil {
			return report, err
		}
	}
	groupFD, err := group.Open(".")
	if err != nil {
		return report, err
	}
	defer groupFD.Close()
	childCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	args := []string{"--die-with-parent", "--new-session", "--unshare-pid", "--unshare-ipc", "--unshare-uts", "--unshare-net",
		"--cap-drop", "ALL", "--cap-add", "CAP_SETUID", "--cap-add", "CAP_SETGID",
		"--clearenv", "--setenv", "GOMAXPROCS", "1", "--proc", "/proc", "--dev", "/dev", "--dir", "/runtime", "--dir", "/etc"}
	for _, name := range []string{"/usr", "/lib", "/lib64", "/etc/ld.so.cache"} {
		if _, err := os.Stat(name); errors.Is(err, os.ErrNotExist) {
			continue
		} else if err != nil {
			return report, err
		}
		args = append(args, "--ro-bind", name, name)
	}
	// A bind of the held inode gives Git a usable absolute path while the
	// host stage parent stays root 0700. Only /work is a writable host mount.
	args = append(args, "--bind-fd", "7", "/work", "--ro-bind-fd", "6", "/runtime/restore", "--chdir", "/",
		"--remount-ro", "/proc", "--remount-ro", "/", "--", "/runtime/restore", restoreChildEntry,
		strconv.FormatUint(uint64(r.Lease.UID), 10), strconv.FormatUint(uint64(r.Lease.GID), 10))
	command := exec.CommandContext(childCtx, "/usr/bin/bwrap", args...)
	command.Env, command.ExtraFiles = []string{}, []*os.File{input, bodies, input, self, mount}
	// Only namespace/mount setup stays privileged: resolving a private stage
	// must not require making its host parent traversable by the lane. Bwrap
	// The fixed entry drops the destination UID/GID and every capability before
	// reading either sealed input or running Git. Only SETUID/SETGID survive
	// namespace setup; these are already required by the installed helper.
	command.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Groups: []uint32{}}, UseCgroupFD: true, CgroupFD: int(groupFD.Fd()), Pdeathsig: syscall.SIGKILL}
	diagnostic := &bootstrapStderr{destination: io.Discard, binds: bootstrapBindRequests(command.Args)}
	command.Stderr = diagnostic
	var output archivePackOutput
	output.limit = api.MaxFrameBytes
	command.Stdout = &output
	if err := command.Run(); err != nil {
		code := -1
		if command.ProcessState != nil {
			code = command.ProcessState.ExitCode()
		}
		return report, failure(api.CodeIntegrity, "restore child failed (exit "+strconv.Itoa(code)+"); "+diagnostic.diagnosticFacts())
	}
	quiet, cancelQuiet := context.WithTimeout(childCtx, time.Second)
	defer cancelQuiet()
	if err := waitCgroupEvent(quiet, group, "populated", "0"); err != nil {
		return report, err
	}
	if processes, err := readControl(group, "cgroup.procs"); err != nil || processes != "" {
		return report, failure(api.CodeContainmentUnknown, "restore child left surviving tasks")
	}
	if err := decodeStrict(output.Bytes(), &report); err != nil {
		return report, err
	}
	return report, nil
}
