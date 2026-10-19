//go:build linux

package admin

import (
	"bufio"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
	"laneboss.io/laneboss/internal/v2/api"
)

func storageBase(binding installation, record leaseRecord) string {
	return filepath.Join("/var/lib/laneboss-v2/lanes", binding.Config, string(record.Lease.ID))
}

func inventoryStorage(ctx context.Context, root *os.Root, record leaseRecord) ([]storageInode, error) {
	var inventory []storageInode
	seen := map[storageInode]bool{}
	var walk func(*os.Root, string, uint64, int) error
	walk = func(parent *os.Root, name string, device uint64, depth int) error {
		if err := contextError(ctx); err != nil {
			return err
		}
		if depth > 64 || len(inventory) >= 4096 {
			return failure(api.CodeContainmentUnknown, "private collection inventory exceeds its retained bound")
		}
		info, err := parent.Lstat(name)
		if err != nil {
			return failure(api.CodeContainmentUnknown, "private collection entry is unreadable")
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || uint64(stat.Dev) != device || !info.IsDir() && stat.Nlink != 1 {
			return failure(api.CodeContainmentUnknown, "private collection crosses a mount or has an unresolved hard link")
		}
		identity := storageInode{Device: uint64(stat.Dev), Inode: stat.Ino}
		if !seen[identity] {
			seen[identity] = true
			inventory = append(inventory, identity)
		}
		if !info.IsDir() {
			return nil
		} // links are inventoried and later unlinked, never traversed
		directory, err := parent.OpenRoot(name)
		if err != nil {
			return failure(api.CodeContainmentUnknown, "cannot pin private collection directory")
		}
		defer directory.Close()
		file, err := directory.Open(".")
		if err != nil {
			return failure(api.CodeContainmentUnknown, "cannot enumerate private collection directory")
		}
		entries, readErr := file.ReadDir(4097)
		closeErr := file.Close()
		if readErr != nil && !errors.Is(readErr, io.EOF) || closeErr != nil || len(entries) > 4096 {
			return failure(api.CodeContainmentUnknown, "private collection directory exceeds its readable bound")
		}
		for _, entry := range entries {
			if err := walk(directory, entry.Name(), device, depth+1); err != nil {
				return err
			}
		}
		return nil
	}
	directories, err := privateStorageDirectories(record)
	if err != nil {
		return nil, err
	}
	for index, item := range directories {
		info, err := root.Lstat(string(item.ID))
		if errors.Is(err, os.ErrNotExist) && record.Storage.Collecting {
			continue
		}
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return nil, failure(api.CodeContainmentUnknown, "retained private collection root is missing or linked")
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		uid, gid, mode := record.Lease.UID, record.Lease.GID, uint32(0700)
		if record.Storage.Withdrawn {
			uid, gid = 0, 0
		}
		// Only the primary archive roots are frozen to 0500. Independent copy
		// roots retain their withdrawn 0700 mode until private collection.
		if record.Archive != nil && record.Archive.Phase == "frozen" && index < len(record.Storage.Directories) {
			mode = 0500
		}
		if !ok {
			return nil, failure(api.CodeIntegrity, "retained private collection root changed its inode or owner")
		}
		if item.Device != strconv.FormatUint(uint64(stat.Dev), 10) || item.Inode != strconv.FormatUint(stat.Ino, 10) ||
			stat.Uid != uid || stat.Gid != gid || stat.Mode&07777 != mode {
			allowAndLog("collection_root_owner")
		}
		if err := walk(root, string(item.ID), uint64(stat.Dev), 0); err != nil {
			return nil, err
		}
	}
	return inventory, nil
}

type mountObservation struct{ device, root, point string }

func readMountObservations(path string) ([]mountObservation, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	data, readErr := io.ReadAll(io.LimitReader(file, (4<<20)+1))
	closeErr := file.Close()
	if readErr != nil || closeErr != nil || len(data) > 4<<20 {
		return nil, failure(api.CodeContainmentUnknown, "mount observation exceeds its bound")
	}
	result := []mountObservation{}
	unescape := strings.NewReplacer(`\040`, " ", `\011`, "\t", `\012`, "\n", `\134`, `\`)
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 10 {
			return nil, failure(api.CodeContainmentUnknown, "mount observation has invalid shape")
		}
		result = append(result, mountObservation{device: fields[2], root: unescape.Replace(fields[3]), point: unescape.Replace(fields[4])})
	}
	return result, nil
}

func beneathPath(path, parent string) bool {
	return path == parent || strings.HasPrefix(path, strings.TrimSuffix(parent, "/")+"/")
}

func descriptorReferences(ctx context.Context, pid int, inventory []storageInode) (uint64, bool, error) {
	return scopedDescriptorReferences(ctx, pid, inventory, nil, nil)
}

// A nil namespace inventory preserves the standalone descriptor observation:
// it reports any peer mount namespace as held. The complete storage scan first
// inventories current namespaces, then reconciles descriptors against those
// pinned kernel identities. It never excludes a PID based on a lane label.
func scopedDescriptorReferences(ctx context.Context, pid int, inventory []storageInode, namespaces map[storageInode]*os.File, retired map[storageInode]bool) (uint64, bool, error) {
	identities := map[storageInode]bool{}
	for _, item := range inventory {
		identities[item] = true
	}
	pidfd, err := unix.PidfdOpen(pid, 0)
	if err != nil {
		return 0, false, err
	}
	defer unix.Close(pidfd)
	prefix := filepath.Join("/proc", strconv.Itoa(pid), "fd")
	fds, err := os.ReadDir(prefix)
	if err != nil {
		return 0, false, processInventoryError(pidfd, err)
	}
	var count uint64
	heldNamespace := false
	for _, fd := range fds {
		if err := contextError(ctx); err != nil {
			return 0, false, err
		}
		number, err := strconv.Atoi(fd.Name())
		if err != nil {
			return 0, false, failure(api.CodeContainmentUnknown, "a native descriptor number is invalid")
		}
		// pidfd_getfd duplicates the file description itself. In particular an
		// O_PATH symlink stays a symlink; it is never followed/opened as root.
		// A concurrent close is EBADF/ESRCH, and a swap gives one actual pinned
		// description instead of a Stat/Statfs/Open mixture of several targets.
		var duplicate int
		if pid == os.Getpid() {
			duplicate, err = unix.FcntlInt(uintptr(number), unix.F_DUPFD_CLOEXEC, 0)
		} else {
			duplicate, err = unix.PidfdGetfd(pidfd, number, 0)
		}
		if vanishedReference(err) || errors.Is(err, unix.EBADF) {
			continue
		}
		if err != nil {
			return 0, false, processInventoryError(pidfd, failure(api.CodeContainmentUnknown, "a native descriptor cannot be duplicated"))
		}
		file := os.NewFile(uintptr(duplicate), "pinned-reference")
		reference, mount, inspectErr := inspectStorageDescriptor(file, identities, namespaces, pid != os.Getpid() || namespaces != nil, retired)
		closeErr := file.Close()
		if inspectErr != nil || closeErr != nil {
			return 0, false, errors.Join(inspectErr, closeErr)
		}
		count += reference
		heldNamespace = heldNamespace || mount
	}
	tasks, err := os.ReadDir(filepath.Join("/proc", strconv.Itoa(pid), "task"))
	if err != nil {
		return 0, false, processInventoryError(pidfd, err)
	}
	for _, task := range tasks {
		for _, name := range []string{"cwd", "root"} {
			if err := contextError(ctx); err != nil {
				return 0, false, err
			}
			var stat unix.Stat_t
			err := unix.Stat(filepath.Join("/proc", strconv.Itoa(pid), "task", task.Name(), name), &stat)
			if vanishedReference(err) {
				continue
			}
			if err != nil {
				return 0, false, processInventoryError(pidfd, failure(api.CodeContainmentUnknown, "a native cwd or root reference is unreadable"))
			}
			if storageInodeReferenced(stat, identities, retired) {
				count++
			}
		}
	}
	mapped, err := mappedReferencesRetired(ctx, filepath.Join("/proc", strconv.Itoa(pid), "maps"), identities, retired)
	if err != nil {
		var native *os.PathError
		if errors.As(err, &native) {
			err = processInventoryError(pidfd, err)
		}
		return 0, false, err
	}
	count += mapped
	return count, heldNamespace, nil
}

// A task may exit after pidfd_open but before a procfs read or pidfd_getfd.
// Kernel exit readiness on that exact held lifetime is the only extra proof
// that discharges its failed observation. Live/unobservable peers still refuse.
func processInventoryError(pidfd int, original error) error {
	poll := []unix.PollFd{{Fd: int32(pidfd), Events: unix.POLLIN}}
	count, err := unix.Poll(poll, 100)
	if err == nil && count == 1 && poll[0].Revents&(unix.POLLIN|unix.POLLHUP) != 0 {
		return unix.ESRCH
	}
	return original
}

func vanishedReference(err error) bool {
	return errors.Is(err, os.ErrNotExist) || errors.Is(err, unix.ESRCH)
}

// A completed removal's old inode number is not a perpetual identity claim:
// the filesystem can assign it to an unrelated linked file or directory.
// An actual still-held removed inode has no links and remains a reference.
// Current and not-yet-collected inventories retain their original strict rule.
func storageInodeReferenced(stat unix.Stat_t, identities, retired map[storageInode]bool) bool {
	identity := storageInode{Device: uint64(stat.Dev), Inode: stat.Ino}
	return identities[identity] && (!retired[identity] || stat.Nlink == 0)
}

func inspectStorageDescriptor(file *os.File, identities map[storageInode]bool, namespaces map[storageInode]*os.File, inspectNamespace bool, retired map[storageInode]bool) (uint64, bool, error) {
	var stat unix.Stat_t
	var filesystem unix.Statfs_t
	if unix.Fstat(int(file.Fd()), &stat) != nil || unix.Fstatfs(int(file.Fd()), &filesystem) != nil {
		return 0, false, failure(api.CodeContainmentUnknown, "a pinned native descriptor is unreadable")
	}
	identity := storageInode{Device: uint64(stat.Dev), Inode: stat.Ino}
	var count uint64
	if storageInodeReferenced(stat, identities, retired) {
		count++
	}
	if !inspectNamespace || filesystem.Type != unix.NSFS_MAGIC || namespaces[identity] != nil {
		return count, false, nil
	}
	// Only our stable NSFS duplicate is supplied to the path-based classifier;
	// the peer's original descriptor number is never reopened for I/O.
	mount, err := retainedMountNamespace("/proc/self/fd/"+strconv.Itoa(int(file.Fd())), stat)
	return count, mount, err
}

// NSFS also holds network, PID, user and other namespace handles. Only a
// kernel-identified mount namespace can retain an unseen filesystem view.
// Pin without I/O before classifying. Only a verified, helper-owned NSFS pin
// may be reopened for the namespace ioctl, never a peer's mutable fd link.
func retainedMountNamespace(path string, expected unix.Stat_t) (bool, error) {
	fd, err := unix.Open(path, unix.O_PATH|unix.O_CLOEXEC, 0)
	if vanishedReference(err) || errors.Is(err, unix.ELOOP) {
		return false, nil
	}
	if err != nil {
		return false, failure(api.CodeContainmentUnknown, "a retained namespace descriptor cannot be pinned")
	}
	file := os.NewFile(uintptr(fd), path)
	mount, inspectErr := retainedMountNamespaceFile(file, expected)
	return mount, errors.Join(inspectErr, file.Close())
}

func retainedMountNamespaceFile(file *os.File, expected unix.Stat_t) (bool, error) {
	var actual unix.Stat_t
	var fs unix.Statfs_t
	if unix.Fstat(int(file.Fd()), &actual) != nil || unix.Fstatfs(int(file.Fd()), &fs) != nil ||
		actual.Dev != expected.Dev || actual.Ino != expected.Ino || fs.Type != unix.NSFS_MAGIC {
		return false, failure(api.CodeContainmentUnknown, "a retained namespace descriptor changed or has no native type")
	}
	// O_PATH descriptors cannot perform ioctls. This link selects our own
	// still-open, verified NSFS inode, so no peer can replace its target.
	ns, err := os.Open("/proc/self/fd/" + strconv.Itoa(int(file.Fd())))
	if err != nil {
		return false, failure(api.CodeContainmentUnknown, "a pinned namespace cannot be inspected")
	}
	kind, kindErr := unix.IoctlRetInt(int(ns.Fd()), unix.NS_GET_NSTYPE)
	statErr := unix.Fstat(int(ns.Fd()), &actual)
	closeErr := ns.Close()
	if kindErr != nil || statErr != nil || closeErr != nil || actual.Dev != expected.Dev || actual.Ino != expected.Ino {
		return false, failure(api.CodeContainmentUnknown, "a retained namespace descriptor changed or has no native type")
	}
	switch kind {
	case unix.CLONE_NEWNS:
		return true, nil
	case unix.CLONE_NEWNET, unix.CLONE_NEWPID, unix.CLONE_NEWUSER, unix.CLONE_NEWIPC, unix.CLONE_NEWUTS, unix.CLONE_NEWCGROUP, unix.CLONE_NEWTIME:
		return false, nil
	default:
		return false, failure(api.CodeContainmentUnknown, "a retained namespace descriptor has an unknown native type")
	}
}

func mappedReferences(ctx context.Context, name string, identities map[storageInode]bool) (uint64, error) {
	return mappedReferencesRetired(ctx, name, identities, nil)
}

func mappedReferencesRetired(ctx context.Context, name string, identities, retired map[storageInode]bool) (references uint64, resultErr error) {
	defer helperCheck(&resultErr, "storage_mappings")
	if err := contextError(ctx); err != nil {
		return 0, err
	}
	file, err := os.Open(name)
	if err != nil {
		return 0, err
	}
	defer func() {
		if err := file.Close(); err != nil {
			references = 0
			resultErr = errors.Join(resultErr, failure(api.CodeContainmentUnknown, "cannot close native memory map inventory"))
		}
	}()
	// Only the five fixed kernel fields determine identity. Drain pathname
	// chunks without retaining them, so neither long names nor a large mapping
	// inventory in an unrelated process can exhaust a whole-file/line bound.
	lines := bufio.NewReaderSize(file, 64<<10)
	var count uint64
	for {
		if err := contextError(ctx); err != nil {
			return 0, err
		}
		chunk, readErr := lines.ReadSlice('\n')
		if readErr != nil && !errors.Is(readErr, io.EOF) && !errors.Is(readErr, bufio.ErrBufferFull) {
			return 0, failure(api.CodeContainmentUnknown, "native memory map record is unreadable")
		}
		if len(chunk) == 0 && errors.Is(readErr, io.EOF) {
			break
		}
		fields := strings.Fields(string(chunk))
		if len(fields) == 0 {
			continue // a kernel thread has no user mappings
		}
		if len(fields) < 5 || len(fields) == 5 && errors.Is(readErr, bufio.ErrBufferFull) && chunk[len(chunk)-1] != ' ' && chunk[len(chunk)-1] != '\t' {
			return 0, failure(api.CodeContainmentUnknown, "native memory map has invalid shape")
		}
		major, minor, ok := strings.Cut(fields[3], ":")
		maj, majorErr := strconv.ParseUint(major, 16, 32)
		min, minorErr := strconv.ParseUint(minor, 16, 32)
		inode, inodeErr := strconv.ParseUint(fields[4], 10, 64)
		if !ok || majorErr != nil || minorErr != nil || inodeErr != nil {
			return 0, failure(api.CodeContainmentUnknown, "native memory map identity is invalid")
		}
		for errors.Is(readErr, bufio.ErrBufferFull) {
			if err := contextError(ctx); err != nil {
				return 0, err
			}
			_, readErr = lines.ReadSlice('\n')
		}
		if readErr != nil && !errors.Is(readErr, io.EOF) {
			return 0, failure(api.CodeContainmentUnknown, "native memory map pathname is unreadable")
		}
		identity := storageInode{Device: unix.Mkdev(uint32(maj), uint32(min)), Inode: inode}
		if identities[identity] {
			if retired[identity] {
				unlinked, err := retiredMappingReference(name, fields[0], identity)
				if err != nil {
					return 0, err
				}
				if !unlinked {
					continue
				}
			}
			count++
		}
	}
	return count, nil
}

func retiredMappingReference(maps, address string, expected storageInode) (bool, error) {
	start, end, ok := strings.Cut(address, "-")
	lo, loErr := strconv.ParseUint(start, 16, 64)
	hi, hiErr := strconv.ParseUint(end, 16, 64)
	if !ok || loErr != nil || hiErr != nil || lo >= hi {
		return false, failure(api.CodeContainmentUnknown, "a retired memory mapping has an invalid native range")
	}
	// Pin the kernel's mapping handle without opening its contents for I/O.
	// A pathname or the textual inode alone cannot distinguish inode reuse.
	fd, err := unix.Open(filepath.Join(filepath.Dir(maps), "map_files", address), unix.O_PATH|unix.O_CLOEXEC, 0)
	if vanishedReference(err) {
		return false, nil
	}
	if err != nil {
		return false, failure(api.CodeContainmentUnknown, "a retired memory mapping cannot be pinned")
	}
	var actual unix.Stat_t
	statErr, closeErr := unix.Fstat(fd, &actual), unix.Close(fd)
	if statErr != nil || closeErr != nil || uint64(actual.Dev) != expected.Device || actual.Ino != expected.Inode {
		return false, failure(api.CodeContainmentUnknown, "a retired memory mapping changed its native identity")
	}
	return actual.Nlink == 0, nil
}

// Scan every process fd and each actual mount namespace. Scope namespace
// handles by the kernel identities whose mount inventories were read first:
// another lane's current namespace is not an unknown retained export. A truly
// unscanned namespace still retains ownership, as does any actual inode/mount
// reference. Read references count too, including O_PATH symlink descriptors.
func scanStorageReferences(ctx context.Context, base string, inventory []storageInode) (uint64, error) {
	return scanStorageReferencesRetired(ctx, base, inventory, nil)
}

func scanStorageReferencesRetired(ctx context.Context, base string, inventory []storageInode, retired map[storageInode]bool) (uint64, error) {
	return scanStorageRoots(ctx, []string{base}, inventory, retired)
}

// All roots share the complete inode inventory. Inspect every task namespace
// against their union before the one descriptor/cwd/root/maps pass. Namespace
// pins stay live through that pass, exactly as for a single-root scan.
func scanStorageRoots(ctx context.Context, bases []string, inventory []storageInode, retired map[storageInode]bool) (uint64, error) {
	if len(bases) == 0 {
		return 0, failure(api.CodeContainmentUnknown, "private storage reference scan has no roots")
	}
	selfMounts, err := readMountObservations("/proc/self/mountinfo")
	if err != nil {
		return 0, failure(api.CodeContainmentUnknown, "cannot map the actual private storage filesystem")
	}
	targets := make([]mountObservation, 0, len(bases))
	for _, base := range bases {
		var containing mountObservation
		for _, mount := range selfMounts {
			if beneathPath(base, mount.point) && len(mount.point) > len(containing.point) {
				containing = mount
			}
		}
		if containing.point == "" {
			return 0, failure(api.CodeContainmentUnknown, "private storage has no observed containing mount")
		}
		physical := filepath.Join(containing.root, strings.TrimPrefix(strings.TrimPrefix(base, containing.point), "/"))
		targets = append(targets, mountObservation{device: containing.device, root: physical})
	}
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return 0, failure(api.CodeContainmentUnknown, "cannot enumerate native storage references")
	}
	namespaces := map[storageInode]*os.File{}
	defer func() {
		for _, file := range namespaces {
			file.Close()
		}
	}()
	var count uint64
	started := time.Now()
	// This pass precedes every fd inspection, independent of PID ordering. Pins
	// remain open until the complete scan ends, preventing namespace inode reuse
	// from making an unobserved namespace look like one already reconciled.
	for _, entry := range entries {
		if err := contextError(ctx); err != nil {
			return 0, err
		}
		if _, err := strconv.Atoi(entry.Name()); err != nil {
			continue
		}
		prefix := filepath.Join("/proc", entry.Name(), "task")
		tasks, err := os.ReadDir(prefix)
		if vanishedReference(err) {
			continue
		}
		if err != nil {
			return 0, failure(api.CodeContainmentUnknown, "a native namespace task inventory is unreadable")
		}
		for _, task := range tasks {
			references, err := scanCurrentMountNamespace(ctx, filepath.Join(prefix, task.Name()), targets[0].device, targets[0].root, namespaces, targets[1:]...)
			if err != nil {
				return 0, err
			}
			count += references
		}
	}
	archiveScanCost(ctx, "namespaces", time.Since(started))
	started = time.Now()
	// Namespace inventory is complete and its map is now read-only. PID
	// inspections are independent; join every bounded worker before returning
	// or closing any pin, including when an inspection or cancellation fails.
	type scanResult struct {
		count uint64
		err   error
	}
	workers := min(4, len(entries))
	results := make(chan scanResult, workers)
	for start := range workers {
		go func(start int) {
			var result scanResult
			defer func() { results <- result }()
			for index := start; index < len(entries); index += workers {
				if err := contextError(ctx); err != nil {
					result.err = err
					return
				}
				pid, err := strconv.Atoi(entries[index].Name())
				if err != nil {
					continue
				}
				references, heldNamespace, err := scopedDescriptorReferences(ctx, pid, inventory, namespaces, retired)
				if vanishedReference(err) {
					continue
				}
				if err != nil {
					result.err = errors.Join(failure(api.CodeContainmentUnknown, "a native descriptor inventory is unreadable"), err)
					return
				}
				result.count += references
				if heldNamespace {
					result.err = failure(api.CodeContainmentUnknown, "a foreign retained mount namespace has not been reconciled")
					return
				}
			}
		}(start)
	}
	var scanErr error
	for range workers {
		result := <-results
		count += result.count
		scanErr = errors.Join(scanErr, result.err)
	}
	archiveScanCost(ctx, "descriptors", time.Since(started))
	if scanErr != nil {
		return 0, scanErr
	}
	return count, nil
}

type mountNamespaceProbe struct {
	open  func(string) (*os.File, error)
	pin   func(int) (int, error)
	alive func(int) error
	tasks func(string) ([]os.DirEntry, error)
	stat  func(string) ([]byte, error)
}

func nativeMountNamespaceProbe() mountNamespaceProbe {
	return mountNamespaceProbe{open: os.Open,
		pin:   func(pid int) (int, error) { return unix.PidfdOpen(pid, 0) },
		alive: func(fd int) error { return unix.PidfdSendSignal(fd, 0, nil, 0) },
		tasks: os.ReadDir, stat: os.ReadFile}
}

// The private syscall seam is scoped to one internal call, never a request
// field or a process-wide hook. Production contexts use the native operations.
type mountNamespaceProbeKey struct{}

func currentMountNamespaceProbe(ctx context.Context) mountNamespaceProbe {
	if probe, ok := ctx.Value(mountNamespaceProbeKey{}).(mountNamespaceProbe); ok {
		return probe
	}
	return nativeMountNamespaceProbe()
}

func scanCurrentMountNamespace(ctx context.Context, prefix, device, physical string, namespaces map[storageInode]*os.File, extra ...mountObservation) (uint64, error) {
	return scanMountNamespace(ctx, prefix, device, physical, namespaces, currentMountNamespaceProbe(ctx), extra...)
}

func mountNamespaceFailure(message string, cause error) error {
	var native *os.PathError
	if errors.As(cause, &native) {
		cause = native.Err // Keep the errno, without publishing process selectors.
	}
	if cause != nil {
		message += ": " + cause.Error()
	}
	return errors.Join(failure(api.CodeContainmentUnknown, message), cause)
}

// Signal zero checks existence, so an exited but unreaped process may still
// answer it. Exit readiness on the same held pidfd is independent kernel proof;
// a live peer or a permission/error result never becomes an assumed exit.
func namespaceProcessExited(pidfd int, signalErr error) bool {
	if errors.Is(signalErr, unix.ESRCH) {
		return true
	}
	if signalErr != nil {
		return false
	}
	ready := []unix.PollFd{{Fd: int32(pidfd), Events: unix.POLLIN}}
	count, err := unix.Poll(ready, 0)
	return err == nil && count == 1 && ready[0].Revents&(unix.POLLERR|unix.POLLNVAL) == 0 && ready[0].Revents&unix.POLLIN != 0
}

var errNamespaceTaskExiting = errors.New("native namespace task has begun kernel exit")

func scanMountNamespace(ctx context.Context, prefix, device, physical string, namespaces map[storageInode]*os.File, probe mountNamespaceProbe, extra ...mountObservation) (references uint64, resultErr error) {
	if err := contextError(ctx); err != nil {
		return 0, err
	}
	parts := strings.Split(prefix, "/")
	if len(parts) != 5 || parts[0] != "" || parts[1] != "proc" || parts[3] != "task" {
		return 0, failure(api.CodeIntegrity, "native namespace selector is not a process task")
	}
	pid, pidErr := strconv.Atoi(parts[2])
	tid, tidErr := strconv.Atoi(parts[4])
	if pidErr != nil || tidErr != nil || pid <= 0 || tid <= 0 || strconv.Itoa(pid) != parts[2] || strconv.Itoa(tid) != parts[4] {
		return 0, failure(api.CodeIntegrity, "native namespace selector has an invalid process lifetime")
	}
	pidfd, err := probe.pin(pid)
	if errors.Is(err, unix.ESRCH) {
		return 0, nil // The kernel found no process to pin, before any namespace read.
	}
	if err != nil {
		return 0, mountNamespaceFailure("a native namespace process cannot be pinned", err)
	}
	defer func() {
		if err := unix.Close(pidfd); err != nil {
			references = 0
			resultErr = errors.Join(resultErr, mountNamespaceFailure("cannot close a native namespace process pin", err))
		}
	}()
	var missing error
	for pass := 0; pass < 3; pass++ {
		references, err := scanPinnedMountNamespace(ctx, prefix, device, physical, namespaces, probe, pidfd, pid, tid, extra...)
		if errors.Is(err, errNamespaceTaskExiting) {
			return recheckMountNamespaceGroup(ctx, filepath.Dir(prefix), device, physical, pidfd, pid, extra...)
		}
		if !vanishedReference(err) {
			return references, err
		}
		aliveErr := probe.alive(pidfd)
		if namespaceProcessExited(pidfd, aliveErr) {
			return 0, nil
		}
		if aliveErr != nil {
			return 0, err
		}
		// A group pidfd remains alive when just one of its tasks exits.
		// Re-enumerate that same group instead of treating signal zero as
		// proof that this particular task still owns a namespace.
		tasks, taskErr := probe.tasks(filepath.Dir(prefix))
		if taskErr != nil {
			if vanishedReference(taskErr) && namespaceProcessExited(pidfd, probe.alive(pidfd)) {
				return 0, nil
			}
			return 0, mountNamespaceFailure("a native namespace task recheck is unreadable", taskErr)
		}
		present := false
		for _, task := range tasks {
			present = present || task.Name() == parts[4]
		}
		if !present {
			return recheckMountNamespaceGroup(ctx, filepath.Dir(prefix), device, physical, pidfd, pid, extra...)
		}
		// A still-present task gets a fresh namespace observation, within a
		// fixed bound. Persistent ENOENT, like permission errors, refuses.
		missing = err
	}
	return 0, missing
}

// A vanished selector does not describe the live group's current tasks. Scan
// all of them, including the leader, and require a stable fresh enumeration.
// Recheck views are fresh and temporary: an earlier inventory cannot prove
// the current mounts of a namespace that stayed alive. Handles outside the
// caller's pinned inventory still fail closed in the later descriptor pass.
func recheckMountNamespaceGroup(ctx context.Context, prefix, device, physical string, pidfd, pid int, extra ...mountObservation) (uint64, error) {
	for pass := 0; pass < 3; pass++ {
		count, complete, err := func() (count uint64, complete bool, resultErr error) {
			if err := contextError(ctx); err != nil {
				return 0, false, err
			}
			// Passing nil requests actual pidfd readiness, independently of a
			// successful signal zero on a still-present zombie or live group.
			if namespaceProcessExited(pidfd, nil) {
				return 0, true, nil
			}
			probe := currentMountNamespaceProbe(ctx)
			before, err := probe.tasks(prefix)
			if err != nil {
				if vanishedReference(err) && namespaceProcessExited(pidfd, nil) {
					return 0, true, nil
				}
				return 0, false, mountNamespaceFailure("a fresh native namespace task inventory is unreadable", err)
			}
			views := map[storageInode]*os.File{}
			defer func() {
				for _, file := range views {
					if err := file.Close(); err != nil {
						count = 0
						resultErr = errors.Join(resultErr, mountNamespaceFailure("cannot close a fresh native namespace pin", err))
					}
				}
			}()
			leader, missing := false, false
			for _, task := range before {
				tid, err := strconv.Atoi(task.Name())
				if err != nil || tid <= 0 || strconv.Itoa(tid) != task.Name() {
					return 0, false, failure(api.CodeContainmentUnknown, "a fresh native task selector is invalid")
				}
				leader = leader || tid == pid
				references, err := scanPinnedMountNamespace(ctx, filepath.Join(prefix, task.Name()), device, physical, views, probe, pidfd, pid, tid, extra...)
				if errors.Is(err, errNamespaceTaskExiting) {
					continue // Kernel exit proved for this task; scan every other current task.
				}
				if err != nil {
					if !vanishedReference(err) {
						return 0, false, err
					}
					missing = true
				} else {
					count += references
				}
			}
			after, err := probe.tasks(prefix)
			if err != nil {
				if vanishedReference(err) && namespaceProcessExited(pidfd, nil) {
					return 0, true, nil
				}
				return 0, false, mountNamespaceFailure("a final native namespace task inventory is unreadable", err)
			}
			if namespaceProcessExited(pidfd, nil) {
				return 0, true, nil
			}
			if !leader {
				return 0, false, failure(api.CodeContainmentUnknown, "a live native task inventory has no observed leader")
			}
			if missing || len(before) != len(after) {
				return 0, false, nil
			}
			for index := range before {
				if before[index].Name() != after[index].Name() {
					return 0, false, nil
				}
			}
			return count, true, nil
		}()
		if err != nil {
			return 0, err
		}
		if complete {
			return count, nil
		}
	}
	return 0, failure(api.CodeContainmentUnknown, "a native namespace task inventory did not stabilize within three scans")
}

func namespaceTaskExiting(data []byte, tid string) (bool, error) {
	record := string(data)
	open, close := strings.IndexByte(record, '('), strings.LastIndexByte(record, ')')
	if len(data) > 4096 || open < 1 || close <= open || strings.TrimSpace(record[:open]) != tid {
		return false, failure(api.CodeContainmentUnknown, "a native namespace task state has invalid shape")
	}
	// The comm field may itself contain spaces and ')' characters. Field 3
	// starts only after its final delimiter, never the first ')' in comm.
	fields := strings.Fields(record[close+1:])
	if len(fields) < 20 || len(fields[0]) != 1 {
		return false, failure(api.CodeContainmentUnknown, "a native namespace task state is incomplete")
	}
	flags, err := strconv.ParseUint(fields[6], 10, 64) // proc stat field 9, task_struct.flags.
	if err != nil {
		return false, failure(api.CodeContainmentUnknown, "a native namespace task exit flags are invalid")
	}
	// Linux PF_EXITING is set by exit_signals before exit_task_namespaces.
	// The namespace links can therefore vanish while field 3 is still R or D;
	// neither those letters nor Z/X alone establish that kernel transition.
	const pfExiting = 0x00000004
	return flags&pfExiting != 0, nil
}

func scanPinnedMountNamespace(ctx context.Context, prefix, device, physical string, namespaces map[storageInode]*os.File, probe mountNamespaceProbe, pidfd, pid, tid int, extra ...mountObservation) (references uint64, resultErr error) {
	if err := contextError(ctx); err != nil {
		return 0, err
	}
	name := filepath.Join(prefix, "ns/mnt")
	file, err := probe.open(name)
	// Probe the held lifetime after the syscall, including failed opens. An
	// unreadable live namespace and EACCES/EPERM never become absence evidence.
	aliveErr := probe.alive(pidfd)
	if err != nil {
		exited := namespaceProcessExited(pidfd, aliveErr)
		if vanishedReference(err) && exited {
			return 0, nil
		}
		if vanishedReference(err) && aliveErr == nil {
			data, stateErr := probe.stat(filepath.Join(prefix, "stat"))
			if stateErr == nil {
				exiting, parseErr := namespaceTaskExiting(data, strconv.Itoa(tid))
				if parseErr != nil {
					return 0, parseErr
				}
				if exiting {
					// Do not use earlier namespace views to discharge the whole
					// group. Its live companions may have acquired new mounts.
					return 0, errNamespaceTaskExiting
				}
			} else if !vanishedReference(stateErr) {
				return 0, mountNamespaceFailure("a native namespace task state is unreadable", stateErr)
			}
		}
		lifetime := "present"
		if exited {
			lifetime = "exited"
		} else if aliveErr != nil {
			lifetime = "unobservable"
		}
		task := "unobservable"
		taskErr := unix.Tgkill(pid, tid, 0)
		if errors.Is(taskErr, unix.ESRCH) {
			task = "absent"
		} else if taskErr == nil {
			task = "present"
		}
		return 0, mountNamespaceFailure("a native mount namespace is unreadable for a "+lifetime+" pinned process and "+task+" task", err)
	}
	retained := false
	defer func() {
		if !retained {
			if err := file.Close(); err != nil {
				references = 0
				resultErr = errors.Join(resultErr, mountNamespaceFailure("cannot close a native mount namespace pin", err))
			}
		}
	}()
	if aliveErr != nil {
		return 0, mountNamespaceFailure("native namespace process changed during its open", aliveErr)
	}
	var pinned, current unix.Stat_t
	if unix.Fstat(int(file.Fd()), &pinned) != nil {
		return 0, failure(api.CodeContainmentUnknown, "a native mount namespace cannot be identified")
	}
	identity := storageInode{Device: uint64(pinned.Dev), Inode: pinned.Ino}
	if namespaces[identity] != nil {
		return 0, nil
	}
	mounts, err := readMountObservations(filepath.Join(prefix, "mountinfo"))
	if err != nil {
		if vanishedReference(err) && namespaceProcessExited(pidfd, probe.alive(pidfd)) {
			return 0, nil
		}
		return 0, mountNamespaceFailure("a native mount inventory is unreadable", err)
	}
	err = unix.Stat(name, &current)
	if vanishedReference(err) && namespaceProcessExited(pidfd, probe.alive(pidfd)) {
		return 0, nil
	}
	if err != nil {
		return 0, mountNamespaceFailure("a native mount namespace cannot be reidentified", err)
	}
	if current.Dev != pinned.Dev || current.Ino != pinned.Ino {
		return 0, failure(api.CodeContainmentUnknown, "a native mount namespace changed during its inventory")
	}
	var count uint64
	for _, mount := range mounts {
		matched := mount.device == device && beneathPath(mount.root, physical)
		for _, target := range extra {
			matched = matched || mount.device == target.device && beneathPath(mount.root, target.root)
		}
		if matched {
			count++
		}
	}
	namespaces[identity], retained = file, true
	return count, nil
}

func (m *leaseManager) storageReferences(ctx context.Context, record leaseRecord) (uint64, []storageInode, error) {
	if record.Storage == nil {
		return 0, nil, nil
	}
	base := storageBase(m.binding, record)
	if err := inventoryStorageParent(base, record); err != nil {
		return 0, nil, err
	}
	root, err := openStorageRoot(base)
	if err != nil {
		return 0, nil, failure(api.CodeContainmentUnknown, "cannot pin storage for independent collection inventory")
	}
	inventory, err := inventoryStorage(ctx, root, record)
	closeErr := root.Close()
	if err != nil {
		return 0, nil, err
	}
	if closeErr != nil {
		return 0, nil, failure(api.CodeContainmentUnknown, "cannot close private inventory root")
	}
	var retired map[storageInode]bool
	if record.Storage.Collected {
		retired = map[storageInode]bool{}
		for _, item := range record.Storage.Inventory {
			retired[item] = true
		}
		// A currently present entry is never discharged by a historical flag.
		for _, item := range inventory {
			delete(retired, item)
		}
	}
	if record.Storage.Collecting {
		inventory = append(inventory, record.Storage.Inventory...)
	}
	count, err := scanStorageReferencesRetired(ctx, base, inventory, retired)
	return count, inventory, err
}

func (m *leaseManager) captureJobs(ctx context.Context, record leaseRecord) (uint64, error) {
	var count uint64
	for _, judge := range record.Judges {
		if !judge.Collected {
			count++
		}
	}
	for _, job := range record.DataJobs {
		if job.State != "collected" {
			count++
		}
	}
	for id, live := range m.captures {
		native, ok := live.(*nativeCapture)
		if !ok {
			return count, failure(api.CodeContainmentUnknown, "outside job registry has an unknown native owner")
		}
		if native.binding.HelperLeaseID != record.Lease.ID {
			continue
		}
		found := false
		for _, capture := range record.Captures {
			found = found || capture.Binding.ID == id && capture.Native != nil
		}
		if !found {
			return count, failure(api.CodeContainmentUnknown, "outside capture job lost its retained binding")
		}
	}
	for _, capture := range record.Captures {
		if capture.Native == nil {
			continue
		}
		if capture.Native.Drain != nil && capture.Native.Drain.Discharged {
			if err := m.measureDischargedCapture(ctx, record, capture); err != nil {
				return count, err
			}
			continue
		}
		count++
		live := m.captures[capture.Binding.ID]
		if live == nil {
			return count, failure(api.CodeContainmentUnknown, "capture job ownership was lost; retained spool cannot be discarded")
		}
		if err := live.Observe(ctx); err != nil {
			return count, err
		}
		// Authentication and AppendCapture acknowledgements belong to the
		// fixed outside-job ingress. A live/empty spool does not discharge it.
		return count, failure(api.CodeContainmentUnknown, "capture spool and EOF have no authenticated service drain acknowledgement")
	}
	return count, nil
}

func (m *leaseManager) collectPrivateStorage(ctx context.Context, record *leaseRecord) error {
	if err := m.ensureCredentialsWithdrawn(*record); err != nil {
		return err
	}
	if record.Storage == nil {
		return nil
	}
	if _, ok := m.resources.(*linuxResources); !ok {
		return failure(api.CodeContainmentUnknown, "private storage requires its independent native collection owner")
	}
	if err := m.resources.Quiescent(ctx, *record); err != nil {
		return err
	}
	if jobs, err := m.captureJobs(ctx, *record); err != nil || jobs != 0 {
		if err != nil {
			return err
		}
		return failure(api.CodeContainmentUnknown, "private storage still has queued outside jobs")
	}
	count, inventory, err := m.storageReferences(ctx, *record)
	if err != nil {
		return err
	}
	if count != 0 {
		return failure(api.CodeContainmentUnknown, "private storage still has native descriptor or mount references")
	}
	if record.Storage.Collected {
		return nil
	}
	if !record.Storage.Collecting {
		record.Storage.Collecting, record.Storage.Inventory = true, inventory
		if err := m.save(*record); err != nil {
			return err
		}
	}
	root, err := openStorageRoot(storageBase(m.binding, *record))
	if err != nil {
		return failure(api.CodeContainmentUnknown, "cannot pin journaled collection parent")
	}
	defer root.Close()
	directories, err := privateStorageDirectories(*record)
	if err != nil {
		return err
	}
	for _, item := range directories {
		// Recheck the fixed journaled inode immediately before the rooted
		// removal. No live lane can rename entries under this helper-owned root.
		info, err := root.Lstat(string(item.ID))
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return failure(api.CodeContainmentUnknown, "private collection root became unreadable")
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Mode&unix.S_IFMT != unix.S_IFDIR || item.Device != strconv.FormatUint(uint64(stat.Dev), 10) || item.Inode != strconv.FormatUint(stat.Ino, 10) {
			return failure(api.CodeIntegrity, "private collection root was replaced")
		}
		if err := root.RemoveAll(string(item.ID)); err != nil {
			return failure(api.CodeContainmentUnknown, "rooted private storage collection failed; retain its UID")
		}
	}
	parent, err := root.Open(".")
	if err != nil {
		return failure(api.CodeIntegrity, "cannot sync collected private storage parent")
	}
	// Emptying child roots alone does not discharge the lane's old GID. Revoke
	// parent traversal before publishing Collected or returning its UID/GID.
	syncErr, closeErr := withdrawStageTraversal(parent, record.Lease.GID), parent.Close()
	if syncErr != nil || closeErr != nil {
		return failure(api.CodeIntegrity, "private storage collection sync failed")
	}
	record.Storage.Collected = true
	return m.save(*record)
}

func (m *leaseManager) abortPrepared(ctx context.Context, record *leaseRecord, request api.HelperAbortRequest) error {
	if record.Gate == nil {
		if request.PreparedID != "" {
			return failure(api.CodeIntegrity, "abort selects a gate that was never registered")
		}
		return m.stopCaptureJobs(ctx, *record)
	}
	gate := record.Gate
	if request.PreparedID != gate.Prepared.ID || gate.Permit != nil || gate.Open != nil ||
		gate.State != "preparing" && gate.State != "prepared" && gate.State != "aborted" {
		return failure(api.CodeConflict, "abort cannot replace an opened or uncertain release")
	}
	if gate.State == "aborted" && record.Phase == "aborted" {
		return nil
	}
	if err := m.killAndWait(ctx, *record); err != nil {
		return err
	}
	if err := m.stopCaptureJobs(ctx, *record); err != nil {
		return err
	}
	gate.State = "aborted"
	return nil
}

func (m *leaseManager) stopCaptureJobs(ctx context.Context, record leaseRecord) error {
	for _, capture := range record.Captures {
		if capture.Native == nil {
			continue
		}
		if capture.Native.Drain == nil || !capture.Native.Drain.Discharged {
			return failure(api.CodeContainmentUnknown, "capture abort requires its authenticated service drain before collection")
		}
		if err := m.measureDischargedCapture(ctx, record, capture); err != nil {
			return err
		}
	}
	return nil
}

func (m *leaseManager) waitContainmentEmpty(ctx context.Context, record leaseRecord) error {
	resources, ok := m.resources.(containmentController)
	if !ok {
		return failure(api.CodeContainmentUnknown, "containment has no native event owner")
	}
	return resources.WaitContainmentEmpty(ctx, record)
}

func (resources *linuxResources) WaitContainmentEmpty(ctx context.Context, record leaseRecord) error {
	root, err := resources.open(record)
	if err != nil {
		return err
	}
	defer root.Close()
	if err := waitCgroupEvent(ctx, root, "populated", "0"); err != nil {
		return err
	}
	return resources.Quiescent(ctx, record)
}

func waitCgroupEvent(ctx context.Context, root *os.Root, field, expected string) error {
	events, err := root.OpenFile("cgroup.events", os.O_RDONLY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return failure(api.CodeContainmentUnknown, "cannot pin containment population events")
	}
	defer events.Close()
	deadline := time.Now().Add(5 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	for {
		if _, err := events.Seek(0, io.SeekStart); err != nil {
			return failure(api.CodeContainmentUnknown, "cannot read containment event generation")
		}
		data, err := io.ReadAll(io.LimitReader(events, 4097))
		if err != nil || len(data) > 4096 {
			return failure(api.CodeContainmentUnknown, "containment event observation failed")
		}
		for _, line := range strings.Split(string(data), "\n") {
			if line == field+" "+expected {
				return nil
			}
		}
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return failure(api.CodeContainmentUnknown, "containment event did not reach its required state before the deadline")
		}
		fds := []unix.PollFd{{Fd: int32(events.Fd()), Events: unix.POLLPRI | unix.POLLERR}}
		if _, err := unix.Poll(fds, int(min(remaining.Milliseconds()+1, 1000))); err != nil && !errors.Is(err, unix.EINTR) {
			return failure(api.CodeContainmentUnknown, "containment event wait failed")
		}
		if err := contextError(ctx); err != nil {
			return err
		}
	}
}
