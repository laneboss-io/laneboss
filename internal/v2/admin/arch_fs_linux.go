//go:build linux

package admin

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"time"

	"golang.org/x/sys/unix"
	"laneboss.io/laneboss/internal/v2/api"
	archivejob "laneboss.io/laneboss/internal/v2/archive"
	"laneboss.io/laneboss/internal/v2/fdpath"
	"laneboss.io/laneboss/internal/v2/grants/manifest"
)

type archiveCostKey struct{}

func archiveNativeCost(ctx context.Context, stage string, elapsed time.Duration) {
	journalHelperTurn(os.Stderr, "archive_check", stage, 0, elapsed)
	archiveScanCost(ctx, stage, elapsed)
}

func archiveScanCost(ctx context.Context, stage string, elapsed time.Duration) {
	if observe, ok := ctx.Value(archiveCostKey{}).(func(string, time.Duration)); ok {
		observe(stage, elapsed)
	}
}

func archiveObjectID(operation api.ID, name string) api.ID {
	return api.ID("archive-" + string(digestBytes([]byte(string(operation) + "\x00" + name)))[:32])
}

func archFile(root *os.File, name string, directory bool) (*os.File, error) {
	if err := manifest.Relative(name); err != nil && name != ".git" {
		return nil, err
	}
	flags := uint64(unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NOFOLLOW | unix.O_NONBLOCK)
	if directory {
		flags |= unix.O_DIRECTORY
	}
	fd, err := fdpath.Open(int(root.Fd()), name, &unix.OpenHow{Flags: flags, Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS | unix.RESOLVE_NO_XDEV})
	if err != nil {
		return nil, failure(api.CodeContainmentUnknown, "archive inode is linked, mounted or unreadable")
	}
	return os.NewFile(uintptr(fd), "archive-inode"), nil
}

func (m *leaseManager) archiveRoots(record leaseRecord) (map[string]string, error) {
	if record.Storage == nil || !record.Storage.Ready || record.Storage.Collected || record.Storage.Collecting || len(record.Storage.Directories) != 3 {
		return nil, failure(api.CodeContainmentUnknown, "archive has no current retained storage")
	}
	roots := map[string]string{}
	for i, name := range []string{"workspace", "home", "history"} {
		roots[name] = filepath.Join(storageBase(m.binding, record), string(record.Storage.Directories[i].ID))
	}
	for _, capture := range record.Captures {
		if capture.Native == nil {
			continue
		}
		roots["captures/"+string(capture.Binding.ID)] = filepath.Join(m.binding.statePath(), "spools", string(capture.Binding.ID))
	}
	return roots, nil
}

// The protected parent is helper-owned even before withdrawal. A root path
// always comes from the retained allocation, never from Workspace.LogicalCWD.
func archiveRoot(name string) (*os.File, error) {
	if err := protectedPath(filepath.Dir(name), true); err != nil {
		return nil, err
	}
	fd, err := fdpath.Open(unix.AT_FDCWD, name, &unix.OpenHow{Flags: unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC | unix.O_NOFOLLOW, Resolve: unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS})
	if err != nil {
		return nil, failure(api.CodeContainmentUnknown, "archive storage root is unavailable")
	}
	return os.NewFile(uintptr(fd), "archive-root"), nil
}

// walkArchive measures the complete current namespace and exact file bytes.
// freeze changes owner/modes only after matching the retained original tree.
// frozen reads keep original archive modes while checking withdrawn OS modes.
func walkArchive(ctx context.Context, root *os.File, prefix string, operation api.ID, prior map[string]api.ObjectEntry, freeze, frozen bool, ceiling *uint64) ([]api.ObjectEntry, []archiveSource, []storageInode, error) {
	_, rootInfo, err := dataIdentity(root)
	if err != nil {
		return nil, nil, nil, err
	}
	var entries []api.ObjectEntry
	var objects []archiveSource
	var inventory []storageInode
	var walk func(string, int) error
	walk = func(name string, depth int) error {
		if err := contextError(ctx); err != nil {
			return err
		}
		if depth > 64 || len(entries) >= 4096 {
			return failure(api.CodeBudget, "archive inventory exceeds its complete bound")
		}
		parent, err := archFile(root, path.Dir(name), true)
		if err != nil {
			return err
		}
		defer parent.Close()
		base := path.Base(name)
		var st unix.Stat_t
		if unix.Fstatat(int(parent.Fd()), base, &st, unix.AT_SYMLINK_NOFOLLOW) != nil || st.Dev != rootInfo.Dev || st.Mode&unix.S_IFMT != unix.S_IFDIR && st.Nlink != 1 {
			return failure(api.CodeIntegrity, "archive inode is replaced, aliased or crosses a filesystem")
		}
		logical := prefix
		if name != "." {
			logical += "/" + name
		}
		entry := api.ObjectEntry{Path: logical, Mode: st.Mode & 0777}
		old, known := prior[logical]
		if prior != nil {
			if !known {
				return failure(api.CodeIntegrity, "archive namespace gained an unmeasured entry")
			}
			entry.Mode = old.Mode
		}
		if frozen && (st.Uid != 0 || st.Gid != 0 || st.Mode&unix.S_IFMT != unix.S_IFLNK && st.Mode&07777 != entry.Mode&0555) {
			return failure(api.CodeIntegrity, "archive writable access was restored")
		}
		inventory = append(inventory, storageInode{Device: uint64(st.Dev), Inode: st.Ino})
		if st.Mode&unix.S_IFMT == unix.S_IFLNK {
			entry.Kind = "symlink"
			buf := make([]byte, 4097)
			n, e := unix.Readlinkat(int(parent.Fd()), base, buf)
			if e != nil || n >= len(buf) {
				return failure(api.CodeIntegrity, "archive symlink is unreadable")
			}
			entry.LinkTarget = string(buf[:n])
			if err := dataLinkAttributes(parent, base, st); err != nil {
				return err
			}
			if prior != nil && !reflect.DeepEqual(entry, old) {
				return failure(api.CodeIntegrity, "archive symlink changed")
			}
			if freeze {
				if err := unix.Fchownat(int(parent.Fd()), base, 0, 0, unix.AT_SYMLINK_NOFOLLOW); err != nil {
					return err
				}
			}
			entries = append(entries, entry)
			return nil
		}
		directory := st.Mode&unix.S_IFMT == unix.S_IFDIR
		if !directory && st.Mode&unix.S_IFMT != unix.S_IFREG {
			return failure(api.CodeIntegrity, "archive contains a special inode")
		}
		file, err := archFile(parent, base, directory)
		if err != nil {
			return err
		}
		defer file.Close()
		var opened unix.Stat_t
		if unix.Fstat(int(file.Fd()), &opened) != nil || opened.Dev != st.Dev || opened.Ino != st.Ino || opened.Ctim != st.Ctim {
			return failure(api.CodeIntegrity, "archive inode changed while opening")
		}
		if err := dataNoAttributes(file); err != nil {
			return err
		}
		if directory {
			entry.Kind = "directory"
		} else {
			entry.Kind = "file"
			if st.Size < 0 || st.Size > api.MaxObjectBytes || uint64(st.Size) > *ceiling {
				return failure(api.CodeBudget, "archive bytes exceed the retained storage budget")
			}
			body, err := io.ReadAll(io.LimitReader(dataReader{ctx, file}, st.Size+1))
			if err != nil || int64(len(body)) != st.Size {
				return failure(api.CodeIntegrity, "archive content was not read completely")
			}
			*ceiling -= uint64(len(body))
			ref := api.BlobRef{ID: archiveObjectID(operation, logical), Class: "artifact", Bytes: int64(len(body)), SHA256: digestBytes(body)}
			entry.Content = &ref
			objects = append(objects, archiveSource{Ref: ref, Root: prefix, Name: name})
		}
		if prior != nil && !reflect.DeepEqual(entry, old) {
			return failure(api.CodeIntegrity, "archive current bytes or mode changed")
		}
		var after unix.Stat_t
		if unix.Fstat(int(file.Fd()), &after) != nil || after.Ino != st.Ino || after.Dev != st.Dev || after.Ctim != st.Ctim || after.Mtim != st.Mtim || after.Size != st.Size {
			return failure(api.CodeIntegrity, "archive inode changed during measurement")
		}
		entries = append(entries, entry)
		if directory {
			items, err := file.ReadDir(4097)
			if err != nil && !errors.Is(err, io.EOF) || len(items) > 4096 {
				return failure(api.CodeContainmentUnknown, "archive directory is unreadable or oversized")
			}
			sort.Slice(items, func(i, j int) bool { return items[i].Name() < items[j].Name() })
			for _, item := range items {
				if prefix == "workspace" && name == "." && item.Name() == ".git" {
					continue
				} // Independently authenticated administrative pointer, not workspace data.
				child := item.Name()
				if name != "." {
					child = name + "/" + child
				}
				if err := walk(child, depth+1); err != nil {
					return err
				}
			}
		}
		if freeze {
			if unix.Fchown(int(file.Fd()), 0, 0) != nil || unix.Fchmod(int(file.Fd()), entry.Mode&0555) != nil {
				return failure(api.CodeIntegrity, "cannot withdraw archive storage writes")
			}
		}
		return file.Sync()
	}
	err = walk(".", 0)
	return entries, objects, inventory, err
}

func (m *leaseManager) archiveTree(ctx context.Context, record leaseRecord, freeze, frozen bool) (api.ObjectManifest, []archiveSource, []storageInode, error) {
	roots, err := m.archiveRoots(record)
	if err != nil {
		return api.ObjectManifest{}, nil, nil, err
	}
	return m.measureArchiveRoots(ctx, record, roots, freeze, frozen)
}

// Roots are selected exclusively by archiveRoots from protected native state.
// Keeping the descriptor measurement separate permits filesystem canaries
// without installing a helper or fabricating an archive receipt.
func (m *leaseManager) measureArchiveRoots(ctx context.Context, record leaseRecord, roots map[string]string, freeze, frozen bool) (api.ObjectManifest, []archiveSource, []storageInode, error) {
	tree := api.ObjectManifest{Schema: "laneboss.objects.v2", Entries: []api.ObjectEntry{}}
	var prior map[string]api.ObjectEntry
	if record.Archive != nil {
		prior = map[string]api.ObjectEntry{}
		for _, e := range record.Archive.Tree.Entries {
			prior[e.Path] = e
		}
	}
	names := make([]string, 0, len(roots))
	for name := range roots {
		names = append(names, name)
	}
	sort.Strings(names)
	var objects []archiveSource
	var inventory []storageInode
	ceiling := min(record.Request.Budget.DiskBytes, uint64(128<<20))
	for _, name := range names {
		root, err := archiveRoot(roots[name])
		if err != nil {
			return tree, nil, nil, err
		}
		// Match the physical root to the allocation's protected inode journal.
		identity, _, err := dataIdentity(root)
		if err == nil {
			for i, key := range []string{"workspace", "home", "history"} {
				if key == name {
					item := record.Storage.Directories[i]
					if identity != item.Device+":"+item.Inode {
						err = failure(api.CodeIntegrity, "archive root differs from its protected allocation")
					}
				}
			}
		}
		if err != nil {
			root.Close()
			return tree, nil, nil, err
		}
		if name == "workspace" {
			if err := m.checkWorkspacePointer(record, root); err != nil {
				root.Close()
				return tree, nil, nil, err
			}
		}
		entries, refs, inodes, walkErr := walkArchive(ctx, root, name, record.ArchiveOperation(), prior, freeze, frozen, &ceiling)
		if walkErr == nil {
			walkErr = restoreArchiveModes(record, name, entries, inodes, prior == nil)
		}
		if name == "workspace" && walkErr == nil {
			var pointer unix.Stat_t
			if err := unix.Fstatat(int(root.Fd()), ".git", &pointer, unix.AT_SYMLINK_NOFOLLOW); err == nil {
				if frozen && (pointer.Uid != 0 || pointer.Gid != 0 || pointer.Mode&07777 != 0400) {
					walkErr = failure(api.CodeIntegrity, "archive Git pointer regained writable access")
				}
				if freeze {
					file, err := archFile(root, ".git", false)
					if err != nil {
						walkErr = err
					} else {
						if unix.Fchown(int(file.Fd()), 0, 0) != nil || unix.Fchmod(int(file.Fd()), 0400) != nil {
							walkErr = failure(api.CodeIntegrity, "cannot withdraw Git pointer writes")
						}
						walkErr = errors.Join(walkErr, file.Sync(), file.Close())
					}
				}
				inodes = append(inodes, storageInode{Device: uint64(pointer.Dev), Inode: pointer.Ino})
			} else if !errors.Is(err, unix.ENOENT) {
				walkErr = failure(api.CodeContainmentUnknown, "archive Git pointer inventory is unreadable")
			}
		}
		closeErr := root.Close()
		if walkErr != nil {
			return tree, nil, nil, walkErr
		}
		if closeErr != nil {
			return tree, nil, nil, closeErr
		}
		tree.Entries = append(tree.Entries, entries...)
		objects = append(objects, refs...)
		inventory = append(inventory, inodes...)
	}
	if len(tree.Entries) > 4096 || len(objects) >= 4096 {
		return tree, nil, nil, failure(api.CodeBudget, "archive inventory requires reconciliation")
	}
	if err := manifest.Object(tree); err != nil {
		return tree, nil, nil, err
	}
	if prior != nil && !reflect.DeepEqual(tree, record.Archive.Tree) {
		return tree, nil, nil, failure(api.CodeIntegrity, "archive lost a required current entry")
	}
	return tree, objects, inventory, nil
}

func (r leaseRecord) ArchiveOperation() api.ID {
	if r.Archive != nil && r.Archive.SourceOperationID != "" {
		return r.Archive.SourceOperationID
	}
	if r.Archive != nil {
		return r.Archive.Intent.OperationID
	}
	return r.Request.Cause.CauseOperationID
}

func (m *leaseManager) archiveReferenceFence(ctx context.Context, record leaseRecord, inventory []storageInode) error {
	if err := m.resources.Quiescent(ctx, record); err != nil {
		return err
	}
	roots, err := m.archiveRoots(record)
	if err != nil {
		return err
	}
	bases := make([]string, 0, len(roots))
	for _, base := range roots {
		bases = append(bases, base)
	}
	sort.Strings(bases)
	count, err := scanStorageRoots(ctx, bases, inventory, nil)
	if err != nil {
		return err
	}
	return archiveNoReferences(count)
}

func archiveNoReferences(count uint64) error {
	if count != 0 {
		return archiveWriterRefusal(count)
	}
	return nil
}

// Revocation permanently fences launch acquisition. Archive may only retain
// read access to that same stopped allocation after credential withdrawal and
// native release have both completed. No caller flag or phase label alone is
// authority, and this check never changes the revoked record.
func stoppedArchiveOwner(record leaseRecord, intent archivejob.Intent) error {
	storage, gate, credentials := record.Storage, record.Gate, record.Credentials
	if record.Phase != "released" || record.Release == nil || record.Receipt == nil ||
		storage == nil || !storage.Ready || !storage.Withdrawn || storage.Withdrawing || storage.Collecting || storage.Collected || len(storage.OriginalModes) == 0 ||
		gate == nil || gate.State != "ended" || gate.Permit == nil || gate.Observation == nil ||
		credentials == nil || credentials.State != "withdrawn" || credentials.Stop == nil || credentials.Record == nil {
		return failure(api.CodeContainmentUnknown, "revoked archive requires its completed stopped storage owner")
	}
	stop, projection := credentials.Stop, credentials.Record
	releaseCause := stop.Cause
	if record.ArchiveEpoch != nil && record.ArchiveEpoch.Stop != nil {
		// An observe operation may own the immutable end/release, while the
		// native and credential stop journals retain the original stop cause.
		releaseCause = record.ArchiveEpoch.Stop.Release
	}
	normalExit := stop.Reason == "release" && gate.Stop != nil && *gate.Stop == stop.Cause
	if !normalExit && stop.Reason != api.CredentialStopReason || projection.Revoked || projection.Authority.Revoked ||
		stop.Cause.Kind != api.InternalHelperStop || stop.Cause.Target != intent.Request.Target ||
		intent.CancellationEpoch < stop.Cause.CancellationEpoch || record.Release.Cause.Target != intent.Request.Target ||
		record.Release.Cause.CancellationEpoch != stop.Cause.CancellationEpoch ||
		record.Release.Cause.CauseOperationID != releaseCause.CauseOperationID || record.Release.Cause.CauseRequestID != releaseCause.CauseRequestID ||
		projection.Fence == nil || projection.Fence.Reason != stop.Reason || projection.Fence.Cause != stop.Cause || projection.Withdrawal == nil ||
		projection.Withdrawal.AgentExecuted == nil || !*projection.Withdrawal.AgentExecuted || !projection.Withdrawal.RotationRequired ||
		record.Receipt.Quiescence.Handle != gateHandle(record) || record.Receipt.Quiescence.Handle.Target != intent.Request.Target {
		return failure(api.CodeContainmentUnknown, "revoked archive differs from its original stop, withdrawal or terminal release")
	}
	withdrawn, released, ended := projection.Withdrawal.Observation, record.Receipt.Quiescence, *gate.Observation
	// Independent native reads have fresh timestamps. Their entire process,
	// wait, prompt and survivor facts must still name the same measured end.
	withdrawn.ObservedAt, released.ObservedAt, ended.ObservedAt = "", "", ""
	if !reflect.DeepEqual(withdrawn, released) || !reflect.DeepEqual(ended, released) {
		return failure(api.CodeContainmentUnknown, "revoked archive withdrawal and release observed different native ends")
	}
	return validateReceipt(record, *record.Release, *record.Receipt)
}

func archiveNativeEpoch(record leaseRecord, intent archivejob.Intent) error {
	if len(record.LaunchAllocations) != 0 {
		allocation := record.LaunchAllocations[len(record.LaunchAllocations)-1]
		epoch := allocation.Reservation.CancellationEpoch
		if record.ArchiveEpoch != nil {
			if record.ArchiveEpoch.Intent != intent {
				return failure(api.CodeConflict, "archive native cancellation epoch changed")
			}
			if record.ArchiveEpoch.Stop != nil {
				if err := archiveStopPin(record, *record.ArchiveEpoch.Stop); err != nil {
					return err
				}
			}
			epoch = record.ArchiveEpoch.Intent.CancellationEpoch
		}
		if !record.Revoked && epoch != intent.CancellationEpoch ||
			record.Revoked && allocation.Reservation.CancellationEpoch > record.Credentials.Stop.Cause.CancellationEpoch {
			return failure(api.CodeConflict, "archive native cancellation epoch changed")
		}
	}
	return nil
}

func (m *leaseManager) archiveParent(intent archivejob.Intent) (leaseRecord, error) {
	if !validID(intent.OperationID) || !validID(intent.EndEventID) || intent.EndSeq == 0 {
		return leaseRecord{}, failure(api.CodeInvalid, "archive lacks its retained original intent")
	}
	records, err := m.records()
	if err != nil {
		return leaseRecord{}, err
	}
	for _, record := range records {
		if record.Request.LifeID == intent.Request.Target.LifeID {
			if record.BootID != m.bootID || record.Storage == nil {
				return record, failure(api.CodeContainmentUnknown, "archive lost its current native storage owner")
			}
			if record.Revoked {
				if err := stoppedArchiveOwner(record, intent); err != nil {
					return record, err
				}
			}
			latest := record.Storage.Binding.Target
			if len(record.LaunchAllocations) > 0 {
				allocation := record.LaunchAllocations[len(record.LaunchAllocations)-1]
				latest = allocation.Reservation.Target
				// Stop and a later terminal decision advance the service epoch.
				// The writer fences the current archive intent before/after freeze;
				// this retained native owner cannot predate its original stop.
				if err := archiveNativeEpoch(record, intent); err != nil {
					return record, err
				}
			}
			if latest != intent.Request.Target {
				return record, failure(api.CodeConflict, "archive native run changed")
			}
			if record.Archive != nil && record.Archive.Intent != intent {
				return record, failure(api.CodeConflict, "archive retry changed its original frozen operation")
			}
			return record, nil
		}
	}
	return leaseRecord{}, failure(api.CodeNotFound, "archive has no retained native allocation")
}

func (m *leaseManager) freezeArchive(ctx context.Context, q archiveQuery) (archiveHeader, error) {
	if q.Epoch != nil {
		if err := m.retainArchiveEpoch(ctx, q); err != nil {
			return archiveHeader{}, err
		}
	}
	r, err := m.archiveParent(q.Intent)
	if err != nil {
		return archiveHeader{}, err
	}
	if r.Archive != nil && r.Archive.Phase == "frozen" {
		q.Freeze = r.Archive.Freeze
		return m.checkArchive(ctx, q)
	}
	if q.Lane.LaunchID == "" || q.Lane.LifeID != q.Intent.Request.Target.LifeID || q.Lane.Run != q.Intent.Request.Target.Run || q.Lane.Generation != q.Intent.Request.ExpectedGeneration || q.Lane.CancellationEpoch != q.Intent.CancellationEpoch || q.Lane.Workspace.ID != r.Storage.Binding.WorkspaceID {
		return archiveHeader{}, failure(api.CodeForbidden, "archive lane differs from protected storage")
	}
	if len(r.LaunchAllocations) == 0 || r.LaunchAllocations[len(r.LaunchAllocations)-1].Reservation.LaunchID != q.Lane.LaunchID {
		return archiveHeader{}, failure(api.CodeForbidden, "archive launch differs from the actual retained native allocation")
	}
	if err := m.retainPrivateStorage(ctx, &r); err != nil {
		return archiveHeader{}, err
	}
	if r.Archive == nil {
		r.Archive = &archiveJournal{Intent: q.Intent, LaunchID: q.Lane.LaunchID, Phase: "inventory"}
		// The first inventory is current, after native write access withdrawal.
		current := r
		current.Archive = nil
		tree, objects, inventory, err := m.archiveTree(ctx, current, false, false)
		if err != nil {
			return archiveHeader{}, err
		}
		// Object IDs belong to the archive operation, not the launch operation.
		for i := range objects {
			objects[i].Ref.ID = archiveObjectID(q.Intent.OperationID, objects[i].Root+"/"+objects[i].Name)
			for j := range tree.Entries {
				e := &tree.Entries[j]
				if e.Content != nil && e.Path == objects[i].Root+"/"+objects[i].Name {
					*e.Content = objects[i].Ref
				}
			}
		}
		r.Archive.Tree, r.Archive.Objects, r.Archive.Inventory = tree, objects, inventory
		if err := m.archiveReferenceFence(ctx, r, inventory); err != nil {
			return archiveHeader{}, err
		}
		r.Archive.Phase = "withdrawing"
		if err := m.save(r); err != nil {
			return archiveHeader{}, err
		}
	}
	if r.Archive.Phase != "withdrawing" {
		return archiveHeader{}, failure(api.CodeContainmentUnknown, "archive storage withdrawal is uncertain")
	}
	_, objects, inventory, err := m.archiveTree(ctx, r, true, false)
	if err != nil {
		return archiveHeader{}, err
	}
	if !reflect.DeepEqual(objects, r.Archive.Objects) || !reflect.DeepEqual(inventory, r.Archive.Inventory) {
		return archiveHeader{}, failure(api.CodeIntegrity, "archive protected namespace changed during withdrawal")
	}
	if err := m.archiveReferenceFence(ctx, r, inventory); err != nil {
		return archiveHeader{}, err
	}
	body, err := canonicalValue(r.Archive.Tree)
	if err != nil {
		return archiveHeader{}, err
	}
	ref := api.BlobRef{ID: archiveObjectID(q.Intent.OperationID, "manifest"), Class: "manifest", Bytes: int64(len(body)), SHA256: digestBytes(body)}
	zero := uint64(0) // Both complete native reference scans above succeeded.
	r.Archive.Freeze = archivejob.Freeze{Target: q.Intent.Request.Target, LaunchID: r.Archive.LaunchID, CancellationEpoch: q.Intent.CancellationEpoch, Snapshot: ref, Writers: &zero, WritableExports: &zero, ObservedAt: gateTimestamp()}
	r.Archive.Phase = "frozen"
	if err := m.save(r); err != nil {
		return archiveHeader{}, err
	}
	q.Freeze = r.Archive.Freeze
	return m.checkArchive(ctx, q)
}

func (m *leaseManager) retainArchiveEpoch(ctx context.Context, q archiveQuery) error {
	if q.Epoch == nil || q.Epoch.Intent != q.Intent || q.Epoch.LaunchID != q.Lane.LaunchID ||
		q.Lane.CancellationEpoch != q.Intent.CancellationEpoch || q.Lane.Generation != q.Intent.Request.ExpectedGeneration ||
		q.Lane.LifeID != q.Intent.Request.Target.LifeID || q.Lane.Run != q.Intent.Request.Target.Run {
		return failure(api.CodeForbidden, "archive epoch handoff differs from its current writer lane")
	}
	state, err := archiveEpochState(*q.Epoch)
	if err != nil || state.To != q.Lane.State {
		return failure(api.CodeForbidden, "archive epoch handoff differs from its committed decision state")
	}
	records, err := m.records()
	if err != nil {
		return err
	}
	for _, record := range records {
		if record.Request.LifeID != q.Intent.Request.Target.LifeID {
			continue
		}
		if record.BootID != m.bootID || record.Storage == nil || record.Storage.Binding.WorkspaceID != q.Lane.Workspace.ID {
			return failure(api.CodeContainmentUnknown, "archive epoch handoff lost its native storage owner")
		}
		if record.ArchiveEpoch != nil {
			if !reflect.DeepEqual(record.ArchiveEpoch, q.Epoch) {
				return failure(api.CodeConflict, "archive epoch handoff replaced its original decision")
			}
			return nil
		}
		record.ArchiveEpoch = q.Epoch
		if record.Storage.Collecting || record.Storage.Collected {
			return failure(api.CodeConflict, "archive epoch handoff cannot replace collected storage")
		}
		if err := validateArchiveEpoch(record); err != nil {
			return err
		}
		if err := m.resources.Quiescent(ctx, record); err != nil {
			return err
		}
		return m.save(record)
	}
	return failure(api.CodeNotFound, "archive epoch handoff has no native allocation")
}

func archiveRefs(j *archiveJournal) []api.BlobRef {
	refs := []api.BlobRef{j.Freeze.Snapshot}
	for _, o := range j.Objects {
		refs = append(refs, o.Ref)
	}
	return refs
}

func (m *leaseManager) checkArchive(ctx context.Context, q archiveQuery) (archiveHeader, error) {
	r, err := m.archiveParent(q.Intent)
	if err != nil {
		return archiveHeader{}, err
	}
	if r.Archive == nil || r.Archive.Phase != "frozen" || !reflect.DeepEqual(q.Freeze, r.Archive.Freeze) {
		return archiveHeader{}, failure(api.CodeIntegrity, "archive freeze differs from its durable native fence")
	}
	started := time.Now()
	_, objects, inventory, err := m.archiveTree(ctx, r, false, true)
	archiveNativeCost(ctx, "tree", time.Since(started))
	if err != nil {
		return archiveHeader{}, err
	}
	if !reflect.DeepEqual(objects, r.Archive.Objects) || !reflect.DeepEqual(inventory, r.Archive.Inventory) {
		return archiveHeader{}, failure(api.CodeIntegrity, "archive frozen inventory changed")
	}
	started = time.Now()
	err = m.archiveReferenceFence(ctx, r, inventory)
	archiveNativeCost(ctx, "references", time.Since(started))
	if err != nil {
		return archiveHeader{}, err
	}
	return archiveHeader{Freeze: r.Archive.Freeze, Objects: archiveRefs(r.Archive)}, nil
}

func (m *leaseManager) archiveBytes(ctx context.Context, q archiveQuery) (api.BlobChunk, error) {
	r, err := m.archiveParent(q.Intent)
	if err != nil {
		return api.BlobChunk{}, err
	}
	if r.Archive == nil || r.Archive.Phase != "frozen" || !reflect.DeepEqual(q.Freeze, r.Archive.Freeze) || q.Index < 0 || q.Index > len(r.Archive.Objects) || q.Offset < 0 || q.Limit < 1 || q.Limit > api.MaxChunkBytes {
		return api.BlobChunk{}, failure(api.CodeForbidden, "archive byte selector escaped its original frozen inventory")
	}
	ref := r.Archive.Freeze.Snapshot
	var body []byte
	if q.Index == 0 {
		body, err = canonicalValue(r.Archive.Tree)
	} else {
		source := r.Archive.Objects[q.Index-1]
		ref = source.Ref
		roots, e := m.archiveRoots(r)
		if e != nil {
			return api.BlobChunk{}, e
		}
		root, e := archiveRoot(roots[source.Root])
		if e != nil {
			return api.BlobChunk{}, e
		}
		defer root.Close()
		file, e := archFile(root, source.Name, false)
		if e != nil {
			return api.BlobChunk{}, e
		}
		defer file.Close()
		body, err = io.ReadAll(io.LimitReader(dataReader{ctx, file}, ref.Bytes+1))
	}
	if err != nil || int64(len(body)) != ref.Bytes || digestBytes(body) != ref.SHA256 || q.Offset > ref.Bytes {
		return api.BlobChunk{}, failure(api.CodeIntegrity, "archive frozen bytes changed")
	}
	data := append([]byte{}, body[q.Offset:min(ref.Bytes, q.Offset+int64(q.Limit))]...)
	return api.BlobChunk{ObjectID: ref.ID, Offset: q.Offset, Data: data, SHA256: digestBytes(data)}, nil
}

func (m *leaseManager) dispatchArchiveStorage(ctx context.Context, method string, raw json.RawMessage) (any, error) {
	var q archiveQuery
	if err := decodeStrict(raw, &q); err != nil {
		return nil, err
	}
	switch method {
	case "archive_freeze":
		return m.freezeArchive(ctx, q)
	case "archive_check":
		return m.checkArchive(ctx, q)
	case "archive_bytes":
		return m.archiveBytes(ctx, q)
	}
	return nil, failure(api.CodeForbidden, "unknown archive storage operation")
}

// Retain storage across process release. Only failed-launch abort retains its
// separate authorized recursive collection path. Root ownership prevents a
// recycled UID from regaining the ended lane's current bytes.
func (m *leaseManager) retainPrivateStorage(ctx context.Context, r *leaseRecord) error {
	if r.Storage == nil {
		return nil
	}
	if err := m.ensureCredentialsWithdrawn(*r); err != nil {
		return err
	}
	if err := m.resources.Quiescent(ctx, *r); err != nil {
		return err
	}
	for _, job := range r.DataJobs {
		if job.State != "collected" {
			return failure(api.CodeContainmentUnknown, "archive requires collected materialization descriptors")
		}
	}
	if err := m.retainArchiveCaptures(ctx, r); err != nil {
		return err
	}
	if r.Storage.Withdrawn {
		if len(r.Storage.OriginalModes) == 0 && r.Archive == nil {
			return failure(api.CodePrerequisite, "original storage modes are unavailable; retain existing bytes")
		}
		return withdrawLaneStageTraversal(storageBase(m.binding, *r), r.Lease.GID)
	}
	if !r.Storage.Withdrawing {
		modes, err := m.captureStorageModes(ctx, *r)
		if err != nil {
			return err
		}
		r.Storage.OriginalModes = modes
		r.Storage.Withdrawing = true
		if err := m.save(*r); err != nil {
			return err
		}
	}
	if len(r.Storage.OriginalModes) == 0 {
		return failure(api.CodePrerequisite, "interrupted withdrawal has no retained original modes")
	}
	if err := withdrawLaneStageTraversal(storageBase(m.binding, *r), r.Lease.GID); err != nil {
		return err
	}
	root, err := openStorageRoot(storageBase(m.binding, *r))
	if err != nil {
		return err
	}
	defer root.Close()
	directories, err := privateStorageDirectories(*r)
	if err != nil {
		return err
	}
	primary := map[api.ID]bool{}
	for _, item := range r.Storage.Directories {
		primary[item.ID] = true
	}
	for _, item := range directories {
		file, err := root.OpenFile(string(item.ID), os.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
		if err != nil {
			return err
		}
		identity, _, err := dataIdentity(file)
		if err == nil && identity != item.Device+":"+item.Inode {
			err = failure(api.CodeIntegrity, "retained storage root was replaced")
		}
		if err == nil && item.ID == r.Storage.Binding.WorkspaceID {
			err = m.checkWorkspacePointer(*r, file)
		}
		if err == nil {
			if primary[item.ID] {
				err = retainModeTree(ctx, file, item.ID, r.Storage.OriginalModes)
			} else {
				err = retainTree(ctx, file)
			}
		}
		closeErr := file.Close()
		if err != nil {
			return err
		}
		if closeErr != nil {
			return closeErr
		}
	}
	r.Storage.Withdrawing = false
	r.Storage.Withdrawn = true
	return m.save(*r)
}

func retainTree(ctx context.Context, root *os.File) error {
	var walk func(string, int) error
	count := 0
	walk = func(name string, depth int) error {
		count++
		if count > 4096 || depth > 64 {
			return failure(api.CodeBudget, "retained storage exceeds its complete bound")
		}
		if err := contextError(ctx); err != nil {
			return err
		}
		parent, err := archFile(root, path.Dir(name), true)
		if err != nil {
			return err
		}
		var named unix.Stat_t
		statErr := unix.Fstatat(int(parent.Fd()), path.Base(name), &named, unix.AT_SYMLINK_NOFOLLOW)
		if statErr != nil {
			parent.Close()
			return failure(api.CodeContainmentUnknown, "retained entry is unreadable")
		}
		if named.Mode&unix.S_IFMT == unix.S_IFLNK {
			if named.Nlink != 1 {
				parent.Close()
				return failure(api.CodeIntegrity, "retained symlink is aliased")
			}
			if err := dataLinkAttributes(parent, path.Base(name), named); err != nil {
				parent.Close()
				return err
			}
			err := unix.Fchownat(int(parent.Fd()), path.Base(name), 0, 0, unix.AT_SYMLINK_NOFOLLOW)
			return errors.Join(err, parent.Close())
		}
		if err := parent.Close(); err != nil {
			return err
		}
		file, err := archFile(root, name, false)
		if err != nil {
			return err
		}
		defer file.Close()
		var st unix.Stat_t
		if unix.Fstat(int(file.Fd()), &st) != nil || st.Dev != named.Dev || st.Ino != named.Ino || st.Ctim != named.Ctim {
			return failure(api.CodeIntegrity, "retained inode changed after reopening by name")
		}
		if st.Mode&unix.S_IFMT != unix.S_IFDIR && (st.Mode&unix.S_IFMT != unix.S_IFREG || st.Nlink != 1) {
			return failure(api.CodeIntegrity, "retained inode is special or aliased")
		}
		if err := dataNoAttributes(file); err != nil {
			return err
		}
		if st.Mode&unix.S_IFMT == unix.S_IFDIR {
			items, err := file.ReadDir(4097)
			if err != nil && !errors.Is(err, io.EOF) || len(items) > 4096 {
				return failure(api.CodeContainmentUnknown, "retained directory unreadable")
			}
			for _, item := range items {
				child := item.Name()
				if name != "." {
					child = name + "/" + child
				}
				if err := walk(child, depth+1); err != nil {
					return err
				}
			}
		}
		mode := st.Mode & 0700
		if st.Mode&unix.S_IFMT == unix.S_IFDIR {
			mode |= 0700
		} else {
			mode |= 0400
		}
		if unix.Fchown(int(file.Fd()), 0, 0) != nil || unix.Fchmod(int(file.Fd()), mode) != nil {
			return failure(api.CodeIntegrity, "cannot retain native storage ownership")
		}
		return file.Sync()
	}
	return walk(".", 0)
}

// Used only for descriptor identity diagnostics, never as deletion permission.
func nativeIdentity(st unix.Stat_t) string {
	return strconv.FormatUint(uint64(st.Dev), 10) + ":" + strconv.FormatUint(st.Ino, 10)
}
