//go:build linux

package linux

import (
	"errors"
	"fmt"
	"runtime"
	"unsafe"

	"golang.org/x/sys/unix"
	"laneboss.io/laneboss/internal/v2/fdpath"
)

func landlockABI() (int, error) {
	abi, _, failure := unix.Syscall(unix.SYS_LANDLOCK_CREATE_RULESET, 0, 0,
		unix.LANDLOCK_CREATE_RULESET_VERSION)
	if failure != 0 {
		return 0, failure
	}
	if abi < MinLaunchABI {
		return int(abi), fmt.Errorf("Landlock ABI is below %d", MinLaunchABI)
	}
	return int(abi), nil
}

// applyLandlock runs only on a permanently locked bootstrap thread. The
// caller must terminate the entire bootstrap on failure; it never returns to
// an unrestricted executor thread. Only the eight-byte ABI-1 struct is passed
// so that kernels at the ABI-3 floor do not receive unknown trailing fields.
func applyLandlock(rules Ruleset) error {
	attribute := rules.HandledAccessFS
	raw, _, failure := unix.Syscall(unix.SYS_LANDLOCK_CREATE_RULESET,
		uintptr(unsafe.Pointer(&attribute)), 8, 0)
	runtime.KeepAlive(&attribute)
	if failure != 0 {
		return fmt.Errorf("landlock_create_ruleset: %w", failure)
	}
	fd := int(raw)
	defer unix.Close(fd)
	for _, rule := range rules.Rules {
		flags := unix.O_PATH | unix.O_CLOEXEC | unix.O_NOFOLLOW
		if rule.Directory {
			flags |= unix.O_DIRECTORY
		}
		parent, err := fdpath.Open(unix.AT_FDCWD, rule.Path, &unix.OpenHow{
			Flags: uint64(flags), Resolve: unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS})
		if err != nil {
			return fmt.Errorf("open Landlock resource: %w", err)
		}
		var stat unix.Stat_t
		statErr := unix.Fstat(parent, &stat)
		if statErr != nil || stat.Mode&unix.S_IFMT == unix.S_IFLNK ||
			(!rule.Directory && stat.Mode&unix.S_IFMT == unix.S_IFDIR) {
			closeErr := unix.Close(parent)
			return errors.Join(errors.New("Landlock resource changed type"), statErr, closeErr)
		}
		attr := unix.LandlockPathBeneathAttr{Allowed_access: rule.AllowedAccess, Parent_fd: int32(parent)}
		_, _, failure = unix.Syscall6(unix.SYS_LANDLOCK_ADD_RULE, uintptr(fd),
			unix.LANDLOCK_RULE_PATH_BENEATH, uintptr(unsafe.Pointer(&attr)), 0, 0, 0)
		runtime.KeepAlive(&attr)
		closeErr := unix.Close(parent)
		if failure != 0 || closeErr != nil {
			if failure != 0 {
				return errors.Join(fmt.Errorf("landlock_add_rule: %w", failure), closeErr)
			}
			return closeErr
		}
	}
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return fmt.Errorf("PR_SET_NO_NEW_PRIVS: %w", err)
	}
	_, _, failure = unix.Syscall(unix.SYS_LANDLOCK_RESTRICT_SELF, uintptr(fd), 0, 0)
	if failure != 0 {
		return fmt.Errorf("landlock_restrict_self: %w", failure)
	}
	return nil
}
