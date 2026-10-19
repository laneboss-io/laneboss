//go:build linux

package admin

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"golang.org/x/sys/unix"
	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/fdpath"
)

func validateAllocationEnrollment(ctx context.Context, binding installation, allocation launchAllocation) (resultErr error) {
	defer helperCheck(&resultErr, "allocation_enrollment")
	data, err := readProtected(filepath.Join("/etc/laneboss-v2/boot", binding.Config+".json"), api.MaxFrameBytes)
	if err != nil {
		return err
	}
	var catalog bootCatalog
	if err := api.DecodeObject(data, &catalog); err != nil {
		return err
	}
	base := filepath.Join(filepath.Dir(binding.binaryPath()), "runtime", binding.Config)
	if catalog.Schema != "laneboss.boot-catalog.v2" || catalog.Revision != api.ContractRevision || catalog.Config != binding.Config ||
		catalog.LaunchEnrollment == nil || catalog.LaunchEnrollmentFile != filepath.Join(base, "launch-enrollment.json") ||
		catalog.RuntimeManifest != allocation.Inputs.Sources.Runtime.Manifest {
		return failure(api.CodePrerequisite, "helper has no matching protected launch enrollment")
	}
	enrollment, _, err := loadLaunchEnrollment(ctx, binding, catalog.RuntimeManifest, *catalog.LaunchEnrollment)
	if err != nil {
		return err
	}
	source := allocation.Inputs.Sources
	project, runtime := false, false
	for _, entry := range enrollment.Projects {
		project = project || source.Project.EnrollmentID == entry.ID && source.Project.Generation == entry.Generation &&
			source.Project.ProjectID == entry.ProjectID && source.Project.Object == entry.Object && source.Project.Base == entry.Base && source.Project.HistoryScope == entry.HistoryScope
	}
	for _, entry := range enrollment.Runtimes {
		runtime = runtime || entry == source.Runtime
	}
	deadline, parseErr := time.Parse(time.RFC3339Nano, string(allocation.Inputs.Grants.ExpiresAt))
	if !project || !runtime || parseErr != nil || !deadline.After(time.Now()) {
		return failure(api.CodeForbidden, "helper launch selection is not current protected enrollment")
	}
	return nil
}

func (m *leaseManager) syncLaunchStorage(ctx context.Context, record *leaseRecord, create bool) (resultErr error) {
	defer helperCheck(&resultErr, "storage_root")
	readiness := storageReady
	if create {
		readiness = storageInitializing
	}
	if err := m.requireActive(*record, readiness); err != nil {
		return err
	}
	if record.Storage == nil || !validID(record.Lease.ID) {
		return failure(api.CodeIntegrity, "missing helper storage journal")
	}
	if record.Storage.Collecting || record.Storage.Collected {
		return failure(api.CodeContainmentUnknown, "private storage is collecting or collected")
	}
	parent := filepath.Join("/var/lib/laneboss-v2/lanes", m.binding.Config)
	if err := protectedPath(parent, true); err != nil {
		return err
	}
	base := filepath.Join(parent, string(record.Lease.ID))
	if create && !record.Storage.Ready {
		if err := createLaneStage(base, record.Lease.GID); err != nil && !errors.Is(err, os.ErrExist) {
			return failure(api.CodePrerequisite, "cannot create journaled private storage root")
		}
	}
	// Validate ancestors without requiring the final traversal mode yet. An
	// interrupted createLaneStage can leave 0700 (before or after Fchown), and
	// syncStorageDirectories must reach its journal-checked recovery below.
	if err := protectedPath(base, true); err != nil {
		return err
	}
	root, err := openStorageRoot(base)
	if err != nil {
		return failure(api.CodeContainmentUnknown, "cannot pin helper storage root")
	}
	defer root.Close()
	return syncStorageDirectories(ctx, root, record, 0, create)
}

// The opened root is chosen by the helper, not supplied across a service/lane
// API. The component test uses a real temporary root and its actual owner.
func syncStorageDirectories(ctx context.Context, root *os.Root, record *leaseRecord, rootUID uint32, create bool) (resultErr error) {
	defer helperCheck(&resultErr, "storage_parent")
	storage := record.Storage
	if storage == nil || len(storage.Directories) != 3 {
		return failure(api.CodeIntegrity, "incomplete private storage inventory")
	}
	if err := validateLaunchStorage(storage.Binding, api.LaunchReservation{ID: storage.Binding.ReservationID, Target: storage.Binding.Target}, record.Lease.ID); err != nil {
		return err
	}
	parent, err := root.OpenFile(".", os.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return failure(api.CodeContainmentUnknown, "cannot pin opened storage parent")
	}
	defer parent.Close()
	var parentInfo unix.Stat_t
	if unix.Fstat(int(parent.Fd()), &parentInfo) != nil || parentInfo.Uid != rootUID {
		return failure(api.CodeIntegrity, "private storage parent is not exclusively helper-owned")
	}
	// Recover either interruption before Fchown or between Fchown and Fchmod,
	// before any child identity is published. Ready/withdrawn storage never
	// reopens traversal through this allocation-only recovery path.
	if create && !storage.Ready && !storage.Withdrawing && !storage.Withdrawn &&
		(parentInfo.Gid == 0 || parentInfo.Gid == record.Lease.GID) && parentInfo.Mode&07777 == 0700 {
		for _, item := range storage.Directories {
			if item.Inode != "" || item.Device != "" {
				return failure(api.CodeIntegrity, "legacy storage parent already has published child identities")
			}
		}
		if err := dataNoAttributes(parent); err != nil {
			return err
		}
		if unix.Fchown(int(parent.Fd()), int(rootUID), int(record.Lease.GID)) != nil || unix.Fchmod(int(parent.Fd()), 0710) != nil ||
			parent.Sync() != nil || unix.Fstat(int(parent.Fd()), &parentInfo) != nil {
			return failure(api.CodeIntegrity, "cannot assign legacy storage parent traversal")
		}
	}
	if parentInfo.Uid != rootUID || parentInfo.Gid != record.Lease.GID || parentInfo.Mode&07777 != 0710 {
		allowAndLog("storage_parent_owner")
	}
	expected := []api.ID{storage.Binding.WorkspaceID, storage.Binding.Home.RootID, storage.Binding.Home.Home.HistoryID}
	identities := map[string]bool{}
	for index := range storage.Directories {
		if err := contextError(ctx); err != nil {
			return err
		}
		item := &storage.Directories[index]
		if !validID(item.ID) || item.ID != expected[index] {
			return failure(api.CodeIntegrity, "storage directory differs from journaled identity")
		}
		created := false
		if create && !storage.Ready && item.Inode == "" {
			err := root.Mkdir(string(item.ID), 0700)
			if err != nil && !errors.Is(err, os.ErrExist) {
				return failure(api.CodePrerequisite, "cannot create allocated private storage")
			}
			created = err == nil
		}
		file, err := openStorageDirectory(parent, string(item.ID))
		if err != nil {
			return failure(api.CodeContainmentUnknown, "journaled storage is missing, linked or unreadable")
		}
		if created {
			if unix.Fchown(int(file.Fd()), int(record.Lease.UID), int(record.Lease.GID)) != nil || unix.Fchmod(int(file.Fd()), 0700) != nil {
				file.Close()
				return failure(api.CodeIntegrity, "cannot assign private storage to its life UID")
			}
		}
		var info unix.Stat_t
		statErr := unix.Fstat(int(file.Fd()), &info)
		syncErr := file.Sync()
		closeErr := file.Close()
		if statErr != nil || syncErr != nil || closeErr != nil || info.Mode&unix.S_IFMT != unix.S_IFDIR {
			return failure(api.CodeIntegrity, "private storage owner, mode or synchronization differs")
		}
		if info.Uid != record.Lease.UID || info.Gid != record.Lease.GID || info.Mode&07777 != 0700 {
			allowAndLog("private_storage_owner")
		}
		device, inode := strconv.FormatUint(uint64(info.Dev), 10), strconv.FormatUint(info.Ino, 10)
		if item.Inode == "" && (!create || storage.Ready) {
			return api.WithHelperReason(failure(api.CodeContainmentUnknown, "private storage inode differs from its retained allocation"), "storage_inode")
		}
		if item.Inode != "" && (item.Device != device || item.Inode != inode) {
			allowAndLog("private_storage_inode")
		}
		key := device + ":" + inode
		if identities[key] {
			return failure(api.CodeIntegrity, "private work, home and history identities overlap")
		}
		identities[key] = true
		item.Device, item.Inode = device, inode
	}
	if err := parent.Sync(); err != nil {
		return failure(api.CodeIntegrity, "private storage directory sync failed")
	}
	storage.Ready = true
	return nil
}

// os.Root intentionally resolves in-root symlinks, even on OpenFile calls
// carrying O_NOFOLLOW. Private storage requires a stronger native contract.
// Open each single journaled name relative to the already held parent, forbid
// every link, and compare the name with the actual opened directory before use.
func openStorageDirectory(parent *os.File, name string) (_ *os.File, resultErr error) {
	defer helperCheck(&resultErr, "storage_directory")
	if parent == nil || !validID(api.ID(name)) {
		return nil, failure(api.CodeIntegrity, "invalid private storage directory selector")
	}
	fd, err := fdpath.Open(int(parent.Fd()), name, &unix.OpenHow{
		Flags:   unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC | unix.O_NOFOLLOW | unix.O_NONBLOCK,
		Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS,
	})
	if err != nil {
		return nil, failure(api.CodeContainmentUnknown, "private storage directory is missing or reached through a link")
	}
	file := os.NewFile(uintptr(fd), "pinned-private-storage")
	if err := checkOpenedStorageDirectory(file, parent, name); err != nil {
		file.Close()
		return nil, err
	}
	return file, nil
}

func checkOpenedStorageDirectory(file, parent *os.File, name string) (resultErr error) {
	defer helperCheck(&resultErr, "storage_inode")
	var opened, named unix.Stat_t
	if unix.Fstat(int(file.Fd()), &opened) != nil || unix.Fstatat(int(parent.Fd()), name, &named, unix.AT_SYMLINK_NOFOLLOW) != nil ||
		named.Mode&unix.S_IFMT != unix.S_IFDIR || opened.Dev != named.Dev || opened.Ino != named.Ino ||
		opened.Mode != named.Mode || opened.Uid != named.Uid || opened.Gid != named.Gid {
		return failure(api.CodeContainmentUnknown, "private storage name differs from the opened directory identity")
	}
	return nil
}

func openStorageRoot(path string) (_ *os.Root, resultErr error) {
	defer helperCheck(&resultErr, "storage_root")
	fd, err := fdpath.Open(unix.AT_FDCWD, path, &unix.OpenHow{
		Flags:   unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC | unix.O_NOFOLLOW,
		Resolve: unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS,
	})
	if err != nil {
		return nil, failure(api.CodeContainmentUnknown, "private storage root contains a link or is unavailable")
	}
	file := os.NewFile(uintptr(fd), "pinned-private-root")
	defer file.Close()
	// This is the kernel reference to our own open descriptor, not a private
	// pathname to resolve again. os.Root keeps its own duplicate of that inode.
	root, err := os.OpenRoot("/proc/self/fd/" + strconv.Itoa(fd))
	if err != nil {
		return nil, failure(api.CodeContainmentUnknown, "cannot retain opened private storage root")
	}
	actual, err := root.Stat(".")
	held, heldErr := file.Stat()
	if err != nil || heldErr != nil || !os.SameFile(actual, held) {
		root.Close()
		return nil, failure(api.CodeContainmentUnknown, "opened private storage root changed identity")
	}
	return root, nil
}
