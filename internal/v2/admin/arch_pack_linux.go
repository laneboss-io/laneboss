//go:build linux

package admin

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"strconv"

	"golang.org/x/sys/unix"
	"laneboss.io/laneboss/internal/v2/api"
)

// Capture Git bytes into a helper-owned physical root before inventory. Every
// manifest member then has a real inode in the unchanged native journal gate.
// Frozen reads never regenerate a pack from the producer repository.
func (m *leaseManager) stageArchiveGit(ctx context.Context, r leaseRecord) (leaseRecord, error) {
	if r.Archive != nil || r.Storage == nil || r.Storage.Workspace == nil {
		return r, nil // Historical archives keep their exact original tree.
	}
	git, pack, err := archiveGitPack(ctx, r)
	if err != nil {
		return r, err
	}
	parent, err := archiveRoot(storageBase(m.binding, r))
	if err != nil {
		return r, err
	}
	defer parent.Close()
	identity, _, err := dataIdentity(parent)
	if err != nil || identity != r.Storage.Workspace.Enrollment.Workspace.RootIdentity {
		return r, failure(api.CodeIntegrity, "archive Git parent differs from its protected workspace")
	}
	const name = "archive-git"
	root, err := dataDirectory(parent, name)
	if err != nil {
		return r, err
	}
	defer root.Close()
	fd, err := unix.Openat(int(root.Fd()), "pack", unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0400)
	if err == nil {
		file := os.NewFile(uintptr(fd), "archive-git-pack")
		n, writeErr := file.Write(pack)
		if writeErr == nil && n != len(pack) {
			writeErr = io.ErrShortWrite
		}
		if err := errors.Join(writeErr, unix.Fchown(fd, 0, 0), unix.Fchmod(fd, 0400), file.Sync(), file.Close()); err != nil {
			return r, err
		}
	} else if !errors.Is(err, unix.EEXIST) {
		return r, err
	}
	file, err := archFile(root, "pack", false)
	if err != nil {
		return r, err
	}
	actual, readErr := readProtectedDescriptor(file, int64(len(pack)), 0400, 0)
	closeErr := file.Close()
	if readErr != nil || closeErr != nil || !bytes.Equal(actual, pack) {
		return r, failure(api.CodeIntegrity, "archive Git capture differs from its recorded producer")
	}
	if err := root.Sync(); err != nil {
		return r, err
	}
	_, info, err := dataIdentity(root)
	if err != nil {
		return r, err
	}
	r.Archive = &archiveJournal{SourceOperationID: r.ArchiveOperation(), Phase: "inventory", Tree: api.ObjectManifest{Git: git},
		GitRoot: &storageIdentity{ID: name, Device: strconv.FormatUint(uint64(info.Dev), 10), Inode: strconv.FormatUint(info.Ino, 10)}}
	return r, nil
}
