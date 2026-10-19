//go:build linux

package admin

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"runtime"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
	"laneboss.io/laneboss/internal/v2/api"
)

const isolationInputPath = "/runtime/laneboss-isolation.json"
const isolationDescriptorPath = "/runtime/laneboss-isolation-input.fd"

type isolationInput struct {
	Config string
	Nonce  api.ID
	UID    uint32
	GID    uint32
	Port   int
}

func isolationDenials(c isolationCanary) bool {
	return c.UnshareErrno == int(unix.EPERM) && (c.RuntimeErrno == int(unix.EROFS) || c.RuntimeErrno == int(unix.EACCES) || c.RuntimeErrno == int(unix.EPERM)) &&
		c.LandlockErrno == int(unix.EACCES) && (c.NetworkErrno == int(unix.ENETUNREACH) || c.NetworkErrno == int(unix.EHOSTUNREACH) || c.NetworkErrno == int(unix.ECONNREFUSED))
}

func isolationErrno(err error) int {
	if err == nil {
		return 0
	}
	var errno unix.Errno
	if errors.As(err, &errno) {
		return int(errno)
	}
	return -1
}

func verifyIsolationHost(p isolationProof) error {
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	kernel, kernelErr := os.ReadFile("/proc/sys/kernel/osrelease")
	abi, _, errno := unix.Syscall(unix.SYS_LANDLOCK_CREATE_RULESET, 0, 0, unix.LANDLOCK_CREATE_RULESET_VERSION)
	if err != nil || kernelErr != nil || errno != 0 || strings.TrimSpace(string(boot)) != p.BootID || strings.TrimSpace(string(kernel)) != p.Kernel || int(abi) != p.LandlockABI {
		return failure(api.CodeIntegrity, "isolation evidence differs from the current kernel boot")
	}
	return nil
}

// This fixed entry has no destination, command, URL or environment selector.
// Only the helper's pinned production bootstrap can produce accepted evidence.
func runIsolationCanary(ctx context.Context, config string) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	file, err := inheritedIsolationInput()
	if err != nil {
		return failure(api.CodePrerequisite, "isolation canary lacks its fixed immutable input")
	}
	var st unix.Stat_t
	seals, sealErr := unix.FcntlInt(file.Fd(), unix.F_GET_SEALS, 0)
	raw, readErr := io.ReadAll(io.LimitReader(file, api.MaxFrameBytes+1))
	statErr, closeErr := unix.Fstat(int(file.Fd()), &st), file.Close()
	if sealErr != nil || seals&bootstrapSeals != bootstrapSeals || readErr != nil || statErr != nil || closeErr != nil || st.Mode&07777 != 0444 || st.Mode&unix.S_IFMT != unix.S_IFREG || int64(len(raw)) != st.Size {
		return failure(api.CodeIntegrity, "isolation canary input is not its exact sealed projection")
	}
	var input isolationInput
	if err := decodeStrict(raw, &input); err != nil {
		return err
	}
	projected, err := os.ReadFile(isolationInputPath)
	if err != nil || digestBytes(projected) != digestBytes(raw) {
		return failure(api.CodeIntegrity, "canary read probe differs from its inherited input")
	}
	if input.Config != config || !validID(input.Nonce) || len(input.Nonce) < 32 || input.Port < 1 || input.Port > 65535 ||
		os.Getuid() == 0 || uint32(os.Getuid()) != input.UID || uint32(os.Geteuid()) != input.UID || uint32(os.Getgid()) != input.GID || uint32(os.Getegid()) != input.GID {
		return failure(api.CodeForbidden, "isolation canary native identity differs from its sealed input")
	}
	groups, err := os.Getgroups()
	if err != nil || len(groups) != 0 {
		return failure(api.CodeForbidden, "isolation canary retained supplementary groups")
	}
	// As in the production bootstrap, never return this restricted thread to
	// Go's executor pool. The internal entry exits its process on return.
	runtime.LockOSThread()
	observed := isolationCanary{Nonce: input.Nonce, UID: uint32(os.Getuid()), GID: uint32(os.Getgid()), InputSHA256: digestBytes(raw)}
	observed.PrivateProc = lanePrivateProc() == nil
	observed.NoNewPrivileges, err = unix.PrctlRetInt(unix.PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0)
	if err != nil {
		return failure(api.CodeContainmentUnknown, "cannot measure canary privilege restriction")
	}
	status, err := os.ReadFile("/proc/thread-self/status")
	if err != nil {
		return failure(api.CodeContainmentUnknown, "cannot measure canary syscall filter")
	}
	for _, line := range strings.Split(string(status), "\n") {
		if value, ok := strings.CutPrefix(line, "Seccomp:"); ok {
			observed.Seccomp, err = strconv.Atoi(strings.TrimSpace(value))
			if err != nil {
				return failure(api.CodeIntegrity, "canary syscall filter observation is malformed")
			}
		}
	}
	// unshare(0) has no side effect and succeeds in the outside positive
	// control. The production seccomp filter must change it to EPERM here.
	observed.UnshareErrno = isolationErrno(unix.Unshare(0))
	fd, writeErr := unix.Open(isolationInputPath, unix.O_WRONLY|unix.O_CLOEXEC, 0)
	if writeErr == nil {
		unix.Close(fd)
	}
	observed.RuntimeErrno = isolationErrno(writeErr)
	value := []byte(input.Nonce)
	if err := os.WriteFile("/work/main/canary", value, 0600); err != nil {
		return failure(api.CodeContainmentUnknown, "canary granted write control failed")
	}
	actual, err := os.ReadFile("/work/main/canary")
	if err != nil || digestBytes(actual) != digestBytes(value) {
		return failure(api.CodeIntegrity, "canary granted write did not read back")
	}
	observed.WrittenSHA256 = digestBytes(actual)
	socket, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return failure(api.CodePrerequisite, "canary network positive socket control failed")
	}
	observed.NetworkErrno = isolationErrno(unix.Connect(socket, &unix.SockaddrInet4{Addr: [4]byte{127, 0, 0, 1}, Port: input.Port}))
	if err := unix.Close(socket); err != nil {
		return failure(api.CodeContainmentUnknown, "cannot close canary network control")
	}
	// The same file was successfully read above. Apply the actual production
	// Landlock routine again with that path omitted and require read denial.
	if err := bootstrapLandlock([]bootstrapPath{{Path: "/work/main", Directory: true, Writable: true}}); err != nil {
		return err
	}
	_, denied := os.ReadFile(isolationInputPath)
	observed.LandlockErrno = isolationErrno(denied)
	if !isolationDenials(observed) || !observed.PrivateProc || observed.NoNewPrivileges != 1 || observed.Seccomp != 2 {
		return failure(api.CodeIntegrity, "installed canary did not observe its enforced boundaries")
	}
	if _, err := os.Stderr.WriteString(string(input.Nonce) + "\n"); err != nil {
		return failure(api.CodeUnavailable, "cannot retain canary error-pipe marker")
	}
	if err := json.NewEncoder(os.Stdout).Encode(observed); err != nil {
		return failure(api.CodeUnavailable, "cannot retain canary output-pipe measurements")
	}
	return nil
}

func inheritedIsolationInput() (*os.File, error) {
	link, err := os.Readlink(isolationDescriptorPath)
	word := strings.TrimPrefix(link, "/proc/self/fd/")
	fd, parseErr := strconv.Atoi(word)
	if err != nil || parseErr != nil || fd < 6 || link != "/proc/self/fd/"+strconv.Itoa(fd) {
		return nil, failure(api.CodeIntegrity, "isolation input is not its fixed inherited descriptor")
	}
	copyFD, err := unix.FcntlInt(uintptr(fd), unix.F_DUPFD_CLOEXEC, 3)
	if err != nil {
		return nil, failure(api.CodeContainmentUnknown, "cannot retain inherited isolation input")
	}
	return os.NewFile(uintptr(copyFD), "inherited-isolation-input"), nil
}
