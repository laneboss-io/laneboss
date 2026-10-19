//go:build linux

package admin

import (
	"crypto/sha256"
	"fmt"
	"sort"

	"golang.org/x/sys/unix"
	"laneboss.io/laneboss/internal/v2/api"
)

// Include ctime as well as mtime: an in-place edit with restored size/mtime,
// chmod/chown, links, xattrs, deletion or atomic replacement must invalidate.
// Atime is deliberately excluded because ordinary journal reads can change it.
type leaseObjectGeneration struct {
	device, inode, links uint64
	mode, uid, gid       uint32
	size                 int64
	modified, changed    unix.Timespec
}

func leaseGeneration(stat unix.Stat_t) leaseObjectGeneration {
	return leaseObjectGeneration{device: uint64(stat.Dev), inode: stat.Ino, links: uint64(stat.Nlink),
		mode: stat.Mode, uid: stat.Uid, gid: stat.Gid, size: stat.Size, modified: stat.Mtim, changed: stat.Ctim}
}

// The same pinned root and operationMu protect full inventories and generation
// checks. A new name, unsafe object or changed record forces the existing full
// Inventory/validateRecords path; a failure never falls back to stale records.
func (s *fileLeaseStore) ContainmentGeneration() ([32]byte, error) {
	var empty [32]byte
	directory, err := s.root.Open(".")
	if err != nil {
		return empty, failure(api.CodeIntegrity, "cannot pin helper journal generation")
	}
	defer directory.Close()
	var before, after unix.Stat_t
	if err := unix.Fstat(int(directory.Fd()), &before); err != nil {
		return empty, failure(api.CodeIntegrity, "cannot measure helper journal generation")
	}
	entries, err := directory.ReadDir(-1)
	if err != nil {
		return empty, failure(api.CodeIntegrity, "cannot enumerate helper journal generation")
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	hash := sha256.New()
	if _, err := fmt.Fprintf(hash, "%q %v\n", ".", leaseGeneration(before)); err != nil {
		return empty, err
	}
	for _, entry := range entries {
		var stat unix.Stat_t
		if err := unix.Fstatat(int(directory.Fd()), entry.Name(), &stat, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			return empty, failure(api.CodeIntegrity, "helper journal entry changed during generation check")
		}
		if entry.Name() == "proofs" {
			// Inventory also checks nested proof contents. Their changes need
			// not change this top directory, so retain that check on every hit.
			if err := checkIsolationReservations(s.root, s.owner); err != nil {
				return empty, err
			}
		}
		if _, err := fmt.Fprintf(hash, "%q %v\n", entry.Name(), leaseGeneration(stat)); err != nil {
			return empty, err
		}
	}
	if err := unix.Fstat(int(directory.Fd()), &after); err != nil || leaseGeneration(before) != leaseGeneration(after) {
		return empty, failure(api.CodeIntegrity, "helper journal directory changed during generation check")
	}
	var generation [32]byte
	copy(generation[:], hash.Sum(nil))
	return generation, nil
}
