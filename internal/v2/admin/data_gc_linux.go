//go:build linux

package admin

import (
	"context"
	"errors"
	"os"
	"strconv"

	"golang.org/x/sys/unix"
	"laneboss.io/laneboss/internal/v2/api"
)

// Reopening for collection is permitted only after durable token invalidation.
// It never restores the token registry or authorizes another projection.
func (m *leaseManager) collectDataSource(ctx context.Context, parent leaseRecord, job dataJob) error {
	if job.State != "revoked" || job.Result == nil || m.dataPins[job.Projection.OpenToken] != nil {
		return failure(api.CodeContainmentUnknown, "data collection requires closed revoked roots and measured output")
	}
	base := laneStagePath(m.binding, job.Reg.Request.StageID)
	stage, err := dataLaneParent(base, job.Lease.GID)
	if err != nil {
		return err
	}
	defer stage.Close()
	copies, err := api.ValidateDataCopyProjections(job.Reg.Inputs, job.Projection)
	if err != nil {
		return err
	}
	names, identities := []string{"source"}, []string{job.Projection.SourceIdentity}
	for _, copy := range copies {
		names = append(names, "source-"+string(copy.WorkspaceID))
		identities = append(identities, copy.SourceIdentity)
	}
	var sources []*os.File
	defer func() {
		for _, file := range sources {
			file.Close()
		}
	}()
	view := leaseRecord{Lease: job.Lease, Storage: &launchStorageRecord{}}
	for index, name := range names {
		source, err := openStorageDirectory(stage, name)
		if err != nil {
			return err
		}
		sources = append(sources, source)
		identity, info, err := dataIdentity(source)
		if err != nil {
			return err
		}
		if identity != identities[index] || info.Uid != job.Lease.UID || info.Gid != job.Lease.GID || info.Mode&07777 != 0700 {
			return failure(api.CodeContainmentUnknown, "data collection source differs from its original inode")
		}
		view.Storage.Directories = append(view.Storage.Directories, storageIdentity{ID: api.ID(name),
			Device: strconv.FormatUint(uint64(info.Dev), 10), Inode: strconv.FormatUint(info.Ino, 10)})
	}
	root, err := os.OpenRoot(dataFD(stage))
	if err != nil {
		return err
	}
	defer root.Close()
	inventory, err := inventoryStorage(ctx, root, view)
	if err != nil {
		return err
	}
	// Exactly these helper-owned source descriptors are allowed during removal.
	// Every other actual fd, mount or retained namespace remains a stopped gate.
	self, _, err := descriptorReferences(ctx, os.Getpid(), inventory)
	if err != nil {
		return err
	}
	references, err := scanStorageReferences(ctx, base, inventory)
	if err != nil {
		return err
	}
	if self != uint64(len(sources)) || references != self {
		return failure(api.CodeContainmentUnknown, "data source still has descriptors, mounts or writable exports")
	}
	for index, name := range names {
		if err := checkOpenedStorageDirectory(sources[index], stage, name); err != nil {
			return err
		}
	}
	for index, name := range names {
		if err := root.RemoveAll(name); err != nil {
			return failure(api.CodeContainmentUnknown, "cannot collect revoked data source")
		}
		var named unix.Stat_t
		if err := unix.Fstatat(int(stage.Fd()), name, &named, unix.AT_SYMLINK_NOFOLLOW); !errors.Is(err, unix.ENOENT) {
			return failure(api.CodeContainmentUnknown, "data source name remains after collection")
		}
		if err := sources[index].Close(); err != nil {
			return err
		}
	}
	return withdrawStageTraversal(stage, job.Lease.GID)
}
