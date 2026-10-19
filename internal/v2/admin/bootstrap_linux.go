//go:build linux

package admin

import (
	"context"
	"crypto/subtle"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"unsafe"

	"golang.org/x/sys/unix"
	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client/wire"
	"laneboss.io/laneboss/internal/v2/fdpath"
)

func readBootstrapInput() (gatePayload, error) {
	var payload gatePayload
	seals, err := unix.FcntlInt(3, unix.F_GET_SEALS, 0)
	var info unix.Stat_t
	if err != nil || seals&bootstrapSeals != bootstrapSeals || unix.Fstat(3, &info) != nil ||
		info.Mode&unix.S_IFMT != unix.S_IFREG || info.Size < 1 || info.Size > api.MaxFrameBytes {
		return payload, failure(api.CodeForbidden, "fixed bootstrap requires sealed inherited descriptor 3")
	}
	file := os.NewFile(3, "sealed-fixed-input")
	data, readErr := io.ReadAll(io.LimitReader(file, api.MaxFrameBytes+1))
	closeErr := file.Close()
	if readErr != nil || closeErr != nil || int64(len(data)) != info.Size {
		return payload, failure(api.CodeIntegrity, "cannot read exact fixed bootstrap input")
	}
	if err := api.DecodeObjectFrame(data, &payload, api.JSONFrameGateInput); err != nil {
		return payload, errors.Join(failure(api.CodeInvalid, "fixed bootstrap input could not be decoded"), err)
	}
	return payload, nil
}

// This entry never elevates credentials. The installed root helper has already
// selected the UID, cgroup and descriptor-only mount view. A command-line word
// or caller-created sealed memfd cannot acquire any helper authority here.
func runFixedBootstrap(ctx context.Context, config, mode string) error {
	return withBootstrapRoute(func() error { return executeFixedBootstrap(ctx, config, mode) })
}

func executeFixedBootstrap(ctx context.Context, config, mode string) error {
	if err := contextError(ctx); err != nil {
		return errors.Join(failure(api.CodeDeadline, "fixed bootstrap context ended"), err)
	}
	payload, err := readBootstrapInput()
	if err != nil {
		return err
	}
	if os.Getuid() == 0 || os.Getuid() != os.Geteuid() || os.Getgid() != os.Getegid() ||
		uint32(os.Getuid()) != payload.UID || uint32(os.Getgid()) != payload.GID || payload.Config != config ||
		payload.Mode != mode || !validID(payload.GateID) || !validID(api.ID(payload.Token)) || len(payload.Token) < 32 {
		return failure(api.CodeForbidden, "fixed bootstrap identity or sealed mode differs")
	}
	groups, err := os.Getgroups()
	if err != nil || len(groups) != 0 {
		return failure(api.CodeForbidden, "fixed bootstrap retained supplementary groups")
	}
	peer, err := unix.GetsockoptUcred(5, unix.SOL_SOCKET, unix.SO_PEERCRED)
	if err != nil || peer.Pid != 0 {
		// The helper is outside this private PID namespace. Its socket peer
		// has no PID mapping here. The helper verifies our host SCM credential.
		return failure(api.CodeForbidden, "bootstrap control socket is not inherited from outside its PID namespace")
	}
	var releaseInfo unix.Stat_t
	if unix.Fstat(4, &releaseInfo) != nil || releaseInfo.Mode&unix.S_IFMT != unix.S_IFIFO {
		return failure(api.CodeForbidden, "bootstrap release is not its inherited pipe")
	}
	status, err := os.ReadFile("/proc/thread-self/status")
	if err != nil {
		return failure(api.CodeContainmentUnknown, "bootstrap cannot observe native privilege state")
	}
	capsFound := false
	for _, line := range strings.Split(string(status), "\n") {
		if !strings.HasPrefix(line, "CapEff:") {
			continue
		}
		caps, parseErr := strconv.ParseUint(strings.TrimSpace(strings.TrimPrefix(line, "CapEff:")), 16, 64)
		if parseErr != nil || caps != 0 {
			return failure(api.CodeForbidden, "bootstrap retained effective capabilities")
		}
		capsFound = true
	}
	if !capsFound {
		return failure(api.CodeContainmentUnknown, "bootstrap capability observation is absent")
	}
	if mode != "prepared-gate" && mode != "credential-probe" {
		return runCaptureBootstrap(payload)
	}
	if err := establishCredentialUmask(); err != nil {
		return err
	}
	if payload.Prompt != nil {
		if err := verifyPromptFD(ctx, 0, *payload.Prompt); err != nil {
			return err
		}
	}
	if len(payload.Argv) == 0 || !filepath.IsAbs(payload.Argv[0]) || filepath.Clean(payload.Argv[0]) != payload.Argv[0] ||
		!filepath.IsAbs(payload.CWD) || filepath.Clean(payload.CWD) != payload.CWD {
		return failure(api.CodeInvalid, "fixed gate lacks its sealed executable and cwd")
	}
	for _, argument := range payload.Argv {
		if strings.ContainsRune(argument, 0) {
			return failure(api.CodeInvalid, "NUL in fixed executable input")
		}
	}
	// Never return to an unrestricted Go executor thread after installing
	// thread-scoped Landlock. Errors terminate this internal process at the CLI.
	runtime.LockOSThread()
	if err := confineBootstrap(payload); err != nil {
		return err
	}
	payload.IsolationReady = true
	if err := unix.Chdir(payload.CWD); err != nil {
		return failure(api.CodeContainmentUnknown, "sealed runner cwd is unavailable")
	}
	ack, err := attestGateReadiness(payload)
	if err != nil {
		return err
	}
	if ack >= 0 {
		defer refuseExecProof(ack) // Only successful exec may close it without data.
	}
	if mode == "credential-probe" {
		return waitForGateRelease(payload.Token)
	}
	return executePreparedGate(payload)
}

func executePreparedGate(payload gatePayload) error {
	if err := unix.CloseRange(3, ^uint(0), unix.CLOSE_RANGE_CLOEXEC); err != nil {
		return failure(api.CodePrerequisite, "cannot close inherited descriptors at vendor exec")
	}
	if err := waitForGateRelease(payload.Token); err != nil {
		return err
	}
	environment := payload.Environment
	if payload.CredentialRequired {
		var err error
		environment, err = finalCredentialEnvironment(payload)
		if err != nil {
			return err
		}
	} else if err := unix.Close(5); err != nil {
		return failure(api.CodeContainmentUnknown, "cannot close ready channel before vendor exec")
	}
	if err := retainBootstrapDescriptors(payload.Inherited); err != nil {
		return err
	}
	// The first vendor instruction occurs only after the exact one-use pipe
	// token, pipe EOF, and close of every helper control descriptor.
	if err := unix.Exec(payload.Argv[0], payload.Argv, environment); err != nil {
		return failure(api.CodeUnavailable, "sealed vendor executable could not start")
	}
	return nil
}

// Only fixed sealed immutable inputs and pinned lane/worker sockets survive vendor
// exec. All helper control, storage and runtime mount descriptors stay CLOEXEC.
func retainBootstrapDescriptors(descriptors []bootstrapDescriptor) error {
	seen := map[int]bool{}
	targets := map[string]bool{}
	for _, descriptor := range descriptors {
		input := descriptor.Target == isolationDescriptorPath || descriptor.Target == workerInputPath || descriptor.Target == "/runtime/laneboss-worker.json" || descriptor.Target == wire.LaneBindingPath
		socket := descriptor.Target == "/runtime/laneboss-worker.sock" || descriptor.Target == wire.LaneSocketPath
		if descriptor.FD < 6 || seen[descriptor.FD] || targets[descriptor.Target] ||
			descriptor.Socket && !socket || !descriptor.Socket && !input {
			return failure(api.CodeIntegrity, "invalid fixed inherited descriptor inventory")
		}
		seen[descriptor.FD], targets[descriptor.Target] = true, true
		var info unix.Stat_t
		if unix.Fstat(descriptor.FD, &info) != nil {
			return failure(api.CodeContainmentUnknown, "fixed inherited descriptor is unavailable")
		}
		if descriptor.Socket {
			flags, err := unix.FcntlInt(uintptr(descriptor.FD), unix.F_GETFL, 0)
			if err != nil || flags&unix.O_PATH == 0 || info.Mode&unix.S_IFMT != unix.S_IFSOCK {
				return failure(api.CodeIntegrity, "fixed worker socket descriptor type changed")
			}
		} else {
			seals, err := unix.FcntlInt(uintptr(descriptor.FD), unix.F_GET_SEALS, 0)
			if err != nil || seals&bootstrapSeals != bootstrapSeals || info.Mode&unix.S_IFMT != unix.S_IFREG || info.Mode&07777 != 0444 || info.Size < 1 || info.Size > api.MaxFrameBytes {
				return failure(api.CodeIntegrity, "fixed inherited input is not exactly sealed")
			}
		}
		link, err := os.Readlink(descriptor.Target)
		if err != nil || link != "/proc/self/fd/"+strconv.Itoa(descriptor.FD) {
			return failure(api.CodeIntegrity, "fixed inherited descriptor projection changed")
		}
		if _, err := unix.FcntlInt(uintptr(descriptor.FD), unix.F_SETFD, 0); err != nil {
			return failure(api.CodeContainmentUnknown, "cannot retain fixed vendor descriptor")
		}
	}
	return nil
}

func waitForGateRelease(token string) error {
	file := os.NewFile(4, "one-use-gate-release")
	defer file.Close()
	actual := make([]byte, len(token))
	if _, err := io.ReadFull(file, actual); err != nil || subtle.ConstantTimeCompare(actual, []byte(token)) != 1 {
		return failure(api.CodeContainmentUnknown, "gate owner disappeared or supplied a foreign release")
	}
	var extra [1]byte
	n, err := file.Read(extra[:])
	if n != 0 || err != io.EOF {
		return failure(api.CodeIntegrity, "gate release was not a single closed token")
	}
	return nil
}

const bootstrapOpenFileLimit = 1024

func confineBootstrap(payload gatePayload) error {
	if err := unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0); err != nil {
		return failure(api.CodePrerequisite, "cannot protect bootstrap control descriptors")
	}
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return failure(api.CodePrerequisite, "cannot install no-new-privileges")
	}
	if payload.Budget.CPUSeconds > 0 {
		if err := unix.Setrlimit(unix.RLIMIT_CPU, &unix.Rlimit{Cur: payload.Budget.CPUSeconds, Max: payload.Budget.CPUSeconds}); err != nil {
			return failure(api.CodePrerequisite, "cannot install native CPU limit")
		}
	}
	if err := unix.Setrlimit(unix.RLIMIT_CORE, &unix.Rlimit{}); err != nil {
		return failure(api.CodePrerequisite, "cannot disable bootstrap core dumps")
	}
	var files unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_NOFILE, &files); err != nil {
		return failure(api.CodePrerequisite, "cannot observe bootstrap descriptor limits")
	}
	files.Cur, files.Max = min(files.Cur, bootstrapOpenFileLimit), min(files.Max, bootstrapOpenFileLimit)
	if err := unix.Setrlimit(unix.RLIMIT_NOFILE, &files); err != nil {
		return failure(api.CodePrerequisite, "cannot bound bootstrap descriptor inventory")
	}
	var retained unix.Rlimit
	if unix.Getrlimit(unix.RLIMIT_NOFILE, &retained) != nil || retained != files {
		return failure(api.CodeContainmentUnknown, "bootstrap descriptor limit did not read back")
	}
	if err := bootstrapLandlock(payload.Paths); err != nil {
		return err
	}
	return bootstrapSeccomp()
}

func bootstrapLandlock(paths []bootstrapPath) error {
	abi, _, errno := unix.Syscall(unix.SYS_LANDLOCK_CREATE_RULESET, 0, 0, unix.LANDLOCK_CREATE_RULESET_VERSION)
	if errno != 0 || abi < 3 {
		return failure(api.CodePrerequisite, "prepared gate requires Landlock ABI 3 or newer")
	}
	// Handle the complete ABI-3 filesystem set, including REFER/TRUNCATE.
	// Newer kernel rights are deliberately not claimed as installed here.
	handled := uint64((1 << 15) - 1)
	if abi >= 5 {
		handled |= unix.LANDLOCK_ACCESS_FS_IOCTL_DEV
	}
	raw, _, errno := unix.Syscall(unix.SYS_LANDLOCK_CREATE_RULESET, uintptr(unsafe.Pointer(&handled)), 8, 0)
	runtime.KeepAlive(&handled)
	if errno != 0 {
		return failure(api.CodePrerequisite, "kernel refused fixed Landlock ruleset")
	}
	fd := int(raw)
	defer unix.Close(fd)
	seen := map[string]bool{}
	for _, path := range paths {
		if !filepath.IsAbs(path.Path) || filepath.Clean(path.Path) != path.Path || path.Path == "/" || seen[path.Path] {
			return failure(api.CodeIntegrity, "ambiguous fixed Landlock path")
		}
		seen[path.Path] = true
		access := uint64(unix.LANDLOCK_ACCESS_FS_READ_FILE)
		if path.Directory {
			access |= unix.LANDLOCK_ACCESS_FS_READ_DIR
		}
		if path.Executable {
			access |= unix.LANDLOCK_ACCESS_FS_EXECUTE
		}
		if path.Writable {
			access |= unix.LANDLOCK_ACCESS_FS_WRITE_FILE | unix.LANDLOCK_ACCESS_FS_TRUNCATE
			if path.Directory {
				access |= unix.LANDLOCK_ACCESS_FS_REMOVE_DIR | unix.LANDLOCK_ACCESS_FS_REMOVE_FILE |
					unix.LANDLOCK_ACCESS_FS_MAKE_DIR | unix.LANDLOCK_ACCESS_FS_MAKE_REG |
					unix.LANDLOCK_ACCESS_FS_MAKE_SOCK | unix.LANDLOCK_ACCESS_FS_MAKE_FIFO |
					unix.LANDLOCK_ACCESS_FS_MAKE_SYM | unix.LANDLOCK_ACCESS_FS_REFER
			}
			if abi >= 5 {
				access |= unix.LANDLOCK_ACCESS_FS_IOCTL_DEV
			}
		}
		parent, err := fdpath.Open(unix.AT_FDCWD, path.Path, &unix.OpenHow{Flags: unix.O_PATH | unix.O_NOFOLLOW | unix.O_CLOEXEC, Resolve: unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS})
		if err != nil {
			return failure(api.CodeContainmentUnknown, "fixed Landlock resource is unavailable")
		}
		var info unix.Stat_t
		if unix.Fstat(parent, &info) != nil || path.Directory != (info.Mode&unix.S_IFMT == unix.S_IFDIR) {
			unix.Close(parent)
			return failure(api.CodeIntegrity, "Landlock resource type changed")
		}
		attr := unix.LandlockPathBeneathAttr{Allowed_access: access, Parent_fd: int32(parent)}
		_, _, errno = unix.Syscall6(unix.SYS_LANDLOCK_ADD_RULE, uintptr(fd), unix.LANDLOCK_RULE_PATH_BENEATH, uintptr(unsafe.Pointer(&attr)), 0, 0, 0)
		runtime.KeepAlive(&attr)
		closeErr := unix.Close(parent)
		if errno != 0 || closeErr != nil {
			return failure(api.CodePrerequisite, "kernel refused a fixed Landlock path rule")
		}
	}
	_, _, errno = unix.Syscall(unix.SYS_LANDLOCK_RESTRICT_SELF, uintptr(fd), 0, 0)
	if errno != 0 {
		return failure(api.CodePrerequisite, "kernel refused fixed Landlock restriction")
	}
	return nil
}

// This filter replaces bwrap's sysctl-based nested-userns disabling under the
// installed read-only /proc/sys. It denies every unshare/setns, clone's user
// namespace bit, and clone3's opaque flags, on every bootstrap thread.
func bootstrapSeccompFilter() ([]unix.SockFilter, error) {
	architecture := uint32(0)
	switch runtime.GOARCH {
	case "amd64":
		architecture = unix.AUDIT_ARCH_X86_64
	case "arm64":
		architecture = unix.AUDIT_ARCH_AARCH64
	default:
		return nil, failure(api.CodeUnsupported, "fixed gate has no seccomp architecture")
	}
	load, jump, ret := uint16(unix.BPF_LD|unix.BPF_W|unix.BPF_ABS), uint16(unix.BPF_JMP|unix.BPF_JEQ|unix.BPF_K), uint16(unix.BPF_RET|unix.BPF_K)
	filter := []unix.SockFilter{{Code: load, K: 4}, {Code: jump, Jt: 1, K: architecture}, {Code: ret, K: unix.SECCOMP_RET_KILL_PROCESS}, {Code: load, K: 0}}
	if runtime.GOARCH == "amd64" {
		filter = append(filter, unix.SockFilter{Code: unix.BPF_JMP | unix.BPF_JGE | unix.BPF_K, Jf: 1, K: 0x40000000}, unix.SockFilter{Code: ret, K: unix.SECCOMP_RET_KILL_PROCESS})
	}
	for _, number := range []uint32{unix.SYS_MOUNT, unix.SYS_UMOUNT2, unix.SYS_PIVOT_ROOT, unix.SYS_CHROOT, unix.SYS_OPEN_TREE, unix.SYS_MOVE_MOUNT, unix.SYS_MOUNT_SETATTR,
		unix.SYS_FSOPEN, unix.SYS_FSCONFIG, unix.SYS_FSMOUNT, unix.SYS_FSPICK, unix.SYS_SETNS, unix.SYS_UNSHARE, unix.SYS_PTRACE,
		unix.SYS_PROCESS_VM_READV, unix.SYS_PROCESS_VM_WRITEV, unix.SYS_BPF, unix.SYS_PERF_EVENT_OPEN, unix.SYS_USERFAULTFD,
		unix.SYS_OPEN_BY_HANDLE_AT, unix.SYS_NAME_TO_HANDLE_AT, unix.SYS_KEYCTL, unix.SYS_ADD_KEY, unix.SYS_REQUEST_KEY,
		unix.SYS_KEXEC_LOAD, unix.SYS_KEXEC_FILE_LOAD, unix.SYS_REBOOT, unix.SYS_INIT_MODULE, unix.SYS_FINIT_MODULE, unix.SYS_DELETE_MODULE, unix.SYS_SWAPON, unix.SYS_SWAPOFF,
		unix.SYS_IO_URING_SETUP} {
		filter = append(filter, unix.SockFilter{Code: jump, Jf: 1, K: number}, unix.SockFilter{Code: ret, K: unix.SECCOMP_RET_ERRNO | uint32(unix.EPERM)})
	}
	filter = append(filter, unix.SockFilter{Code: jump, Jf: 1, K: unix.SYS_CLONE3}, unix.SockFilter{Code: ret, K: unix.SECCOMP_RET_ERRNO | uint32(unix.ENOSYS)},
		unix.SockFilter{Code: jump, Jf: 3, K: unix.SYS_CLONE}, unix.SockFilter{Code: load, K: 16},
		unix.SockFilter{Code: unix.BPF_JMP | unix.BPF_JSET | unix.BPF_K, Jf: 1, K: unix.CLONE_NEWUSER | unix.CLONE_NEWNS | unix.CLONE_NEWNET | unix.CLONE_NEWIPC | unix.CLONE_NEWUTS | unix.CLONE_NEWPID | unix.CLONE_NEWCGROUP | unix.CLONE_PTRACE},
		unix.SockFilter{Code: ret, K: unix.SECCOMP_RET_ERRNO | uint32(unix.EPERM)}, unix.SockFilter{Code: ret, K: unix.SECCOMP_RET_ALLOW})
	return filter, nil
}

func bootstrapSeccomp() error {
	filter, err := bootstrapSeccompFilter()
	if err != nil {
		return err
	}
	program := unix.SockFprog{Len: uint16(len(filter)), Filter: &filter[0]}
	result, _, errno := unix.Syscall(unix.SYS_SECCOMP, unix.SECCOMP_SET_MODE_FILTER, unix.SECCOMP_FILTER_FLAG_TSYNC, uintptr(unsafe.Pointer(&program)))
	runtime.KeepAlive(filter)
	if errno != 0 || result != 0 {
		return failure(api.CodePrerequisite, "kernel refused fixed seccomp filter on all bootstrap threads")
	}
	return nil
}
