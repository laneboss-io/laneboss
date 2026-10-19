//go:build linux

package dataworker

import (
	"errors"
	"fmt"
	"os"
	"strconv"

	"golang.org/x/sys/unix"
	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/fdpath"
	"laneboss.io/laneboss/internal/v2/grants/lstate"
)

// Only the fixed native entry selects these paths, after obtaining its real
// private endpoint principal and verifying the inherited job input. The input
// supplies inode identities, never a host pathname or a descriptor number.
func openNativeMaterializationRoots(p api.WorkerPrincipal, projection api.StorageProjection) (roots [3]*os.Root, resultErr error) {
	if os.Getuid() == 0 || os.Getuid() != os.Geteuid() || os.Getgid() != os.Getegid() ||
		uint32(os.Geteuid()) != p.Peer.HostUID || uint32(os.Getegid()) != p.Peer.HostGID {
		return roots, lstate.Error(api.CodeForbidden, "materialization process differs from its native worker principal")
	}
	groups, err := os.Getgroups()
	if err != nil || len(groups) != 0 {
		return roots, lstate.Error(api.CodeForbidden, "materialization worker retained supplementary groups")
	}
	defer func() {
		if resultErr != nil {
			for i, root := range roots {
				if root != nil {
					resultErr = errors.Join(resultErr, root.Close())
					roots[i] = nil
				}
			}
		}
	}()
	identities := [3]string{projection.SourceIdentity, projection.WorkspaceIdentity, projection.HomeIdentity}
	for i, path := range [3]string{"/job/source", "/job/workspace", "/job/home"} {
		roots[i], err = openMaterializationRoot(path, identities[i], p.Peer.HostUID, p.Peer.HostGID)
		if err != nil {
			return roots, err
		}
	}
	return roots, nil
}

func openMaterializationRoot(path, identity string, uid, gid uint32) (_ *os.Root, resultErr error) {
	fd, err := fdpath.Open(unix.AT_FDCWD, path, &unix.OpenHow{Flags: unix.O_PATH | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC,
		Resolve: unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS})
	if err != nil {
		return nil, lstate.Error(api.CodeContainmentUnknown, "fixed materialization projection is unavailable or linked")
	}
	defer func() { resultErr = errors.Join(resultErr, unix.Close(fd)) }()
	var info unix.Stat_t
	if unix.Fstat(fd, &info) != nil || info.Mode&unix.S_IFMT != unix.S_IFDIR || info.Mode&07777 != 0700 ||
		info.Uid != uid || info.Gid != gid || fmt.Sprintf("%d:%d", info.Dev, info.Ino) != identity {
		return nil, lstate.Error(api.CodeIntegrity, "fixed materialization projection differs from its helper-held root")
	}
	// This is the sole deliberate magic-link open, after the no-link walk has
	// pinned the exact inode. os.Root owns an independent directory descriptor.
	root, err := os.OpenRoot("/proc/self/fd/" + strconv.Itoa(fd))
	if err != nil {
		return nil, lstate.Error(api.CodeContainmentUnknown, "cannot retain fixed materialization root")
	}
	actual, _, err := rootIdentity(root)
	if err != nil || actual != identity {
		return nil, errors.Join(lstate.Error(api.CodeIntegrity, "materialization root changed during descriptor handoff"), root.Close())
	}
	return root, nil
}

func openNativeMaterializationCopies(p api.WorkerPrincipal, projection api.StorageProjection) (_ map[api.ID]MaterializationCopyRoots, resultErr error) {
	entries, err := api.DecodeDataCopyProjections(projection.Copies)
	if err != nil {
		return nil, err
	}
	result := map[api.ID]MaterializationCopyRoots{}
	defer func() {
		if resultErr != nil {
			for _, roots := range result {
				resultErr = errors.Join(resultErr, roots.Source.Close(), roots.Destination.Close())
			}
		}
	}()
	for _, entry := range entries {
		source, err := openMaterializationRoot("/job/source-"+string(entry.Grant.ID), entry.SourceIdentity, p.Peer.HostUID, p.Peer.HostGID)
		if err != nil {
			return nil, err
		}
		destination, err := openMaterializationRoot("/job/copy-"+string(entry.Grant.ID), entry.DestinationIdentity, p.Peer.HostUID, p.Peer.HostGID)
		if err != nil {
			return nil, errors.Join(err, source.Close())
		}
		result[entry.Grant.ID] = MaterializationCopyRoots{Source: source, Destination: destination}
	}
	return result, nil
}
