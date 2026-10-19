//go:build linux

package service

import (
	"context"
	"errors"
	"path/filepath"
	"strconv"

	"golang.org/x/sys/unix"
	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client/wire"
	"laneboss.io/laneboss/internal/v2/fdpath"
)

// Only the per-launch endpoint can recover automatically. The private parent
// and socket are pinned without following links. A nonblocking connect to that
// exact inode must report ECONNREFUSED; a live or uncertain endpoint is retained.
func recoverLaneSocket(ctx context.Context, binding api.InstalledBinding) (resultErr error) {
	if err := ctx.Err(); err != nil {
		return contextError(err)
	}
	base, name := filepath.Dir(binding.Socket), filepath.Base(binding.Socket)
	if binding.Class != api.EndpointLane || !wire.ValidID(string(binding.LaunchID)) ||
		filepath.Base(base) != "lanes" || name != string(binding.LaunchID)+".sock" {
		return serviceError(api.CodeForbidden, "socket recovery requires its exact per-launch path")
	}
	if err := runtimeDirectory(base, binding.ServiceUID); err != nil {
		return err
	}
	parent, err := fdpath.Open(unix.AT_FDCWD, base, &unix.OpenHow{
		Flags:   unix.O_PATH | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC,
		Resolve: unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS})
	if err != nil {
		return serviceError(api.CodeIntegrity, "lane recovery parent is missing or linked")
	}
	defer func() { resultErr = errors.Join(resultErr, unix.Close(parent)) }()
	var directory unix.Stat_t
	if unix.Fstat(parent, &directory) != nil || directory.Mode&unix.S_IFMT != unix.S_IFDIR ||
		directory.Mode&07777 != 0700 || directory.Uid != binding.ServiceUID || directory.Gid != binding.ServiceGID {
		return serviceError(api.CodeIntegrity, "lane recovery parent is not private to its service")
	}
	fd, err := fdpath.Open(parent, name, &unix.OpenHow{
		Flags:   unix.O_PATH | unix.O_NOFOLLOW | unix.O_CLOEXEC,
		Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS | unix.RESOLVE_NO_XDEV})
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	if err != nil {
		return serviceError(api.CodeConflict, "existing lane endpoint cannot be safely inspected")
	}
	defer func() { resultErr = errors.Join(resultErr, unix.Close(fd)) }()
	var inode unix.Stat_t
	if unix.Fstat(fd, &inode) != nil || !ownedLaneSocket(inode, binding) {
		return serviceError(api.CodeConflict, "existing lane endpoint is not its service-owned socket")
	}
	probe, err := unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return err
	}
	connectErr := unix.Connect(probe, &unix.SockaddrUnix{Name: "/proc/self/fd/" + strconv.Itoa(fd)})
	if err := unix.Close(probe); err != nil {
		return err
	}
	if !errors.Is(connectErr, unix.ECONNREFUSED) {
		return serviceError(api.CodeConflict, "existing lane endpoint is live or its state is uncertain")
	}
	if err := ctx.Err(); err != nil {
		return contextError(err)
	}
	// Recheck the named parent too: a replacement directory never authorizes
	// removal from the retained one. Only trusted service/root can write here.
	var current unix.Stat_t
	if unix.Fstatat(unix.AT_FDCWD, base, &current, unix.AT_SYMLINK_NOFOLLOW) != nil ||
		current.Dev != directory.Dev || current.Ino != directory.Ino || current.Mode != directory.Mode ||
		current.Uid != directory.Uid || current.Gid != directory.Gid {
		return serviceError(api.CodeConflict, "lane recovery parent changed during inspection")
	}
	return unlinkStaleLaneSocket(parent, name, inode, binding)
}

func ownedLaneSocket(inode unix.Stat_t, binding api.InstalledBinding) bool {
	return inode.Mode&unix.S_IFMT == unix.S_IFSOCK && inode.Mode&07777 == 0666 && inode.Nlink == 1 &&
		inode.Uid == binding.ServiceUID && inode.Gid == binding.ServiceGID
}

func unlinkStaleLaneSocket(parent int, name string, retained unix.Stat_t, binding api.InstalledBinding) error {
	var current unix.Stat_t
	if name != string(binding.LaunchID)+".sock" || !ownedLaneSocket(retained, binding) ||
		unix.Fstatat(parent, name, &current, unix.AT_SYMLINK_NOFOLLOW) != nil || !ownedLaneSocket(current, binding) ||
		current.Dev != retained.Dev || current.Ino != retained.Ino {
		return serviceError(api.CodeConflict, "lane endpoint changed during stale recovery")
	}
	return unix.Unlinkat(parent, name, 0)
}
