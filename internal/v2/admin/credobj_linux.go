//go:build linux

package admin

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"reflect"
	"runtime"
	"strconv"
	"time"

	"golang.org/x/sys/unix"
	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/fdpath"
)

func credentialObject(file *os.File) (string, unix.Stat_t, error) {
	var st unix.Stat_t
	if file == nil || unix.Fstat(int(file.Fd()), &st) != nil {
		return "", st, failure(api.CodeContainmentUnknown, "held credential descriptor is unavailable")
	}
	return fmt.Sprintf("%d:%d", st.Dev, st.Ino), st, nil
}

func credentialDescriptor(file *os.File, sealed bool) (api.CredentialDescriptorFact, error) {
	id, st, err := credentialObject(file)
	if err != nil {
		return api.CredentialDescriptorFact{}, err
	}
	access, err := unix.FcntlInt(file.Fd(), unix.F_GETFL, 0)
	if err != nil {
		return api.CredentialDescriptorFact{}, failure(api.CodeIntegrity, "credential access flags are unavailable")
	}
	flags, err := unix.FcntlInt(file.Fd(), unix.F_GETFD, 0)
	if err != nil {
		return api.CredentialDescriptorFact{}, failure(api.CodeIntegrity, "credential inheritance flags are unavailable")
	}
	var writers *uint64
	if sealed {
		seals, err := unix.FcntlInt(file.Fd(), unix.F_GET_SEALS, 0)
		if err != nil || seals&bootstrapSeals != bootstrapSeals {
			return api.CredentialDescriptorFact{}, failure(api.CodeIntegrity, "credential source is not sealed against all writes")
		}
		zero := uint64(0)
		writers = &zero // F_SEAL_WRITE forbids writes through every alias and mapping.
	}
	return api.CredentialDescriptorFact{ObjectID: id, OwnerUID: st.Uid, Mode: st.Mode & 07777, Size: st.Size, Links: uint64(st.Nlink), Regular: st.Mode&unix.S_IFMT == unix.S_IFREG, ReadOnly: access&unix.O_ACCMODE == unix.O_RDONLY, CloseOnExec: flags&unix.FD_CLOEXEC != 0, WritableHandles: writers}, nil
}

func (r *credentialRuntime) inspect(ctx context.Context, t api.CredentialTransfer) (_ []api.CredentialDescriptorFact, resultErr error) {
	defer func() {
		if resultErr != nil {
			resultErr = errors.Join(resultErr, closeCredentialFiles(t.Files))
		}
	}()
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	if r.manager == nil || os.Geteuid() != 0 || r.peer == nil {
		return nil, failure(api.CodeForbidden, "credential receive is restricted to the native root owner")
	}
	peer, err := r.peer.Facts(ctx)
	if err != nil {
		return nil, err
	}
	generation, err := processGeneration(os.Getpid(), r.manager.bootID)
	if err != nil {
		return nil, err
	}
	a := t.Authority
	if a.BrokerPeer != peer || a.HelperPeer.HostPID != os.Getpid() || a.HelperPeer.HostUID != 0 || a.HelperPeer.HostGID != 0 || a.HelperPeer.ProcessGeneration != generation ||
		a.BootID != r.manager.bootID || a.ServiceUID != r.manager.binding.Service.UID || a.InstallationGeneration != r.manager.binding.Generation || a.Helper.SHA256 != r.manager.binding.Artifact.SHA256 {
		return nil, failure(api.CodeUnauthenticated, "credential authority differs from observed helper and broker lifetimes")
	}
	if channel, ok := r.peer.(*credentialChannel); !ok || a.Broker != channel.pin.Executable {
		return nil, failure(api.CodeUnauthenticated, "credential authority changed the installed broker executable")
	}
	facts := make([]api.CredentialDescriptorFact, len(t.Files))
	for i, file := range t.Files {
		fact, err := credentialDescriptor(file, true)
		if err != nil {
			return nil, err
		}
		facts[i] = fact
	}
	if err := api.ValidateCredentialTransfer(t, facts, time.Now()); err != nil {
		return nil, err
	}
	return facts, nil
}

func copyCredential(ctx context.Context, input, output *os.File, size int64) error {
	if input == nil || output == nil || size <= 0 || size > api.MaxFrameBytes {
		return failure(api.CodeInvalid, "credential private copy exceeds its bound")
	}
	buffer := make([]byte, 32<<10)
	defer clear(buffer)
	if _, err := input.Seek(0, io.SeekStart); err != nil {
		return failure(api.CodeIntegrity, "credential source offset is unavailable")
	}
	remaining := size
	for remaining > 0 {
		if err := contextError(ctx); err != nil {
			return err
		}
		n, err := input.Read(buffer[:min(int64(len(buffer)), remaining)])
		if err != nil || n <= 0 {
			return failure(api.CodeIntegrity, "credential source bytes are incomplete")
		}
		if written, err := output.Write(buffer[:n]); err != nil || written != n {
			return failure(api.CodeIntegrity, "credential private copy failed")
		}
		remaining -= int64(n)
	}
	var extra [1]byte
	defer clear(extra[:])
	if n, err := input.Read(extra[:]); n != 0 || !errors.Is(err, io.EOF) {
		return failure(api.CodeIntegrity, "credential source length changed")
	}
	return output.Sync()
}

// Reopen only this newly created destination, never a broker/source pathname.
func anonymousCredential(ctx context.Context, input *os.File, size int64) (_ *os.File, resultErr error) {
	fd, err := unix.MemfdCreate("held-credential", unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING)
	if err != nil {
		return nil, failure(api.CodePrerequisite, "cannot create anonymous credential holding")
	}
	writer := os.NewFile(uintptr(fd), "new-private-credential")
	defer func() {
		if writer != nil {
			resultErr = errors.Join(resultErr, writer.Close())
		}
	}()
	if err := unix.Fchmod(fd, 0600); err != nil {
		return nil, err
	}
	if err := copyCredential(ctx, input, writer, size); err != nil {
		return nil, err
	}
	if _, err := unix.FcntlInt(writer.Fd(), unix.F_ADD_SEALS, bootstrapSeals); err != nil {
		return nil, failure(api.CodePrerequisite, "cannot seal private credential destination")
	}
	readFD, err := unix.Open("/proc/self/fd/"+strconv.Itoa(fd), unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, failure(api.CodeIntegrity, "cannot retain read-only private destination")
	}
	reader := os.NewFile(uintptr(readFD), "held-private-credential")
	a, _, err := credentialObject(writer)
	b, _, other := credentialObject(reader)
	if err != nil || other != nil || a != b {
		reader.Close()
		return nil, failure(api.CodeIntegrity, "private destination changed on read-only handoff")
	}
	closeErr := writer.Close()
	writer = nil
	if closeErr != nil {
		return nil, errors.Join(failure(api.CodeContainmentUnknown, "credential writer close is uncertain"), reader.Close())
	}
	return reader, nil
}

func credentialParent(home *os.File, name string, uid, gid, mode uint32) (*os.File, string, error) {
	parent := path.Dir(name)
	current, err := dataFile(home, ".", true)
	if err != nil {
		return nil, "", err
	}
	if parent != "." {
		for _, component := range splitCredentialPath(parent) {
			if err := unix.Mkdirat(int(current.Fd()), component, mode); err != nil && !errors.Is(err, unix.EEXIST) {
				current.Close()
				return nil, "", failure(api.CodeIntegrity, "cannot create fixed credential parent")
			}
			next, err := dataFile(current, component, true)
			current.Close()
			if err != nil {
				return nil, "", err
			}
			current = next
			var st unix.Stat_t
			if unix.Fstat(int(current.Fd()), &st) != nil || st.Mode&0022 != 0 || st.Uid != 0 && st.Uid != uid {
				current.Close()
				return nil, "", failure(api.CodeIntegrity, "credential parent has foreign ownership or writable aliases")
			}
			if unix.Fchown(int(current.Fd()), int(uid), int(gid)) != nil || unix.Fchmod(int(current.Fd()), mode) != nil {
				current.Close()
				return nil, "", failure(api.CodeIntegrity, "cannot assign fixed credential parent")
			}
		}
	}
	return current, path.Base(name), nil
}
func splitCredentialPath(name string) []string {
	var result []string
	for name != "." {
		result = append([]string{path.Base(name)}, result...)
		name = path.Dir(name)
	}
	return result
}

func (r *credentialRuntime) home(record leaseRecord, q api.CredentialProjectionRequest) (*os.File, error) {
	if record.Storage == nil || record.Storage.Binding.Home != q.Home {
		return nil, failure(api.CodeIntegrity, "credential home differs from retained private storage")
	}
	parent, err := dataParentMode(storageBase(r.manager.binding, record), record.Lease.GID, 0710)
	if err != nil {
		return nil, err
	}
	defer parent.Close()
	home, err := openStorageDirectory(parent, string(q.Home.RootID))
	if err != nil {
		return nil, err
	}
	if err := checkOpenedStorageDirectory(home, parent, string(q.Home.RootID)); err != nil {
		home.Close()
		return nil, err
	}
	_, st, err := credentialObject(home)
	if err != nil || st.Uid != record.Lease.UID || st.Gid != record.Lease.GID || st.Mode&07777 != 0700 {
		home.Close()
		return nil, failure(api.CodeIntegrity, "credential home owner or mode changed")
	}
	for _, entry := range record.Storage.Directories {
		if entry.ID == q.Home.RootID && entry.Device == strconv.FormatUint(uint64(st.Dev), 10) && entry.Inode == strconv.FormatUint(st.Ino, 10) {
			return home, nil
		}
	}
	home.Close()
	return nil, failure(api.CodeIntegrity, "credential home is not the retained inode")
}

func (r *credentialRuntime) project(ctx context.Context, t api.CredentialTransfer) (receipt api.CredentialProjectionReceipt, resultErr error) {
	facts, err := r.inspect(ctx, t)
	if err != nil {
		return receipt, err
	}
	defer func() { resultErr = errors.Join(resultErr, closeCredentialFiles(t.Files)) }()
	a := t.Authority
	if r.held[a.ID] != nil {
		return receipt, failure(api.CodeConflict, "credential projection objects are one-use")
	}
	record, err := r.manager.findActive(a.Request.Lease.ID, storageReady)
	if err != nil {
		return receipt, err
	}
	if record.Gate == nil || record.Gate.Prepared != a.Request.Prepared || record.Gate.State != "prepared" || record.Gate.Permit != nil {
		return receipt, failure(api.CodeConflict, "credential projection requires its original closed gate")
	}
	home, err := r.home(record, a.Request)
	if err != nil {
		return receipt, err
	}
	held := &heldCredentials{home: home, record: api.CredentialProjectionRecord{Authority: a, Generation: a.Generation, State: "reserved"}, sources: make([]string, len(facts)), sourceHandles: append([]*os.File{}, t.Files...)}
	r.held[a.ID] = held // partial attempts remain owned and can only withdraw
	for i, target := range a.Targets {
		if err := contextError(ctx); err != nil {
			return receipt, err
		}
		held.sources[i] = facts[i].ObjectID
		var output *os.File
		if target.Delivery == "env" {
			output, err = anonymousCredential(ctx, t.Files[i], facts[i].Size)
		} else {
			mode := uint32(0700)
			if target.FileMode == 0400 {
				mode = 0500
			}
			parent, base, e := credentialParent(home, target.RelativePath, a.Request.Lease.UID, a.Request.Lease.GID, mode)
			if e != nil {
				return receipt, e
			}
			fd, e := reserveCredentialFile(parent, base, target.FileMode)
			if e != nil {
				parent.Close()
				return receipt, failure(api.CodeIntegrity, "credential destination exists or cannot be reserved")
			}
			writer := os.NewFile(uintptr(fd), "projected-private-credential")
			if keyStoreTarget(a, target) {
				err = copyKeyStore(ctx, t.Files[i], writer, facts[i].Size)
			} else {
				err = copyCredential(ctx, t.Files[i], writer, facts[i].Size)
			}
			if err == nil {
				err = unix.Fchown(fd, int(a.Request.Lease.UID), int(a.Request.Lease.GID))
			}
			if err == nil {
				err = unix.Fchmod(fd, target.FileMode)
			}
			if err == nil {
				output, err = dataFile(parent, base, false)
			}
			err = errors.Join(err, writer.Close(), parent.Close())
		}
		if output != nil {
			held.files = append(held.files, output)
			_, st, e := credentialObject(output)
			if e != nil {
				return receipt, e
			}
			held.destinations = append(held.destinations, storageInode{Device: uint64(st.Dev), Inode: st.Ino})
		}
		if err != nil {
			return receipt, failure(api.CodeIntegrity, "credential destination holding failed")
		}
		if target.Delivery == "file" && (target.FileMode == 0400 || target.EnvironmentName != "") {
			if err := r.readOnlyView(ctx, record, target, output); err != nil {
				return receipt, err
			}
		}
	}
	// Close all escrow duplicates before measuring/acknowledging holding.
	sourceSnapshot := t
	closeErr := closeCredentialFiles(t.Files)
	t.Files = nil
	if closeErr != nil {
		return receipt, closeErr
	}
	receipt, err = r.measure(ctx, held)
	if err != nil {
		return receipt, err
	}
	if err := api.ValidateCredentialProjectionReceipt(sourceSnapshot, facts, receipt, time.Now()); err != nil {
		return receipt, err
	}
	held.record.Receipt = &receipt
	return receipt, nil
}

func (r *credentialRuntime) childRoot(record leaseRecord) (*os.File, error) {
	native, ok := r.manager.gates[record.Lease.ID].(*nativeGate)
	if !ok || native.innerLifetime(r.manager.bootID) != nil {
		return nil, failure(api.CodeContainmentUnknown, "credential view lost its actual bootstrap owner")
	}
	return os.Open("/proc/" + strconv.Itoa(native.innerPID) + "/root")
}

func (r *credentialRuntime) readOnlyView(ctx context.Context, record leaseRecord, target api.CredentialTarget, file *os.File) error {
	native, ok := r.manager.gates[record.Lease.ID].(*nativeGate)
	if !ok {
		return failure(api.CodeContainmentUnknown, "credential mount has no native gate")
	}
	root, err := r.childRoot(record)
	if err != nil {
		return err
	}
	defer root.Close()
	parent, base, err := credentialParentInView(root, target.RelativePath)
	if err != nil {
		return err
	}
	defer parent.Close()
	ns, err := os.Open("/proc/" + strconv.Itoa(native.innerPID) + "/ns/mnt")
	if err != nil {
		return failure(api.CodeContainmentUnknown, "credential mount namespace is unavailable")
	}
	defer ns.Close()
	if err := credentialViewThread(func() (resultErr error) {
		// Clone and seal in the helper namespace. A bind clone can retain
		// the source's shared peer group: make it private before attachment
		// so a later overmount in the child cannot propagate to the source.
		mount, err := unix.OpenTree(int(file.Fd()), "", unix.OPEN_TREE_CLONE|unix.OPEN_TREE_CLOEXEC|unix.AT_EMPTY_PATH)
		if err != nil {
			return failure(api.CodePrerequisite, "cannot clone the helper credential view")
		}
		defer func() { resultErr = errors.Join(resultErr, unix.Close(mount)) }()
		if err := unix.MountSetattr(mount, "", unix.AT_EMPTY_PATH, &unix.MountAttr{Attr_set: unix.MOUNT_ATTR_RDONLY | unix.MOUNT_ATTR_NOSUID | unix.MOUNT_ATTR_NODEV | unix.MOUNT_ATTR_NOEXEC, Propagation: unix.MS_PRIVATE}); err != nil {
			return failure(api.CodePrerequisite, "cannot seal the detached credential view")
		}
		if err := unix.Unshare(unix.CLONE_FS); err != nil {
			return failure(api.CodePrerequisite, "cannot enter the retained credential mount namespace (unshare "+errnoName(err)+")")
		}
		if err := unix.Setns(int(ns.Fd()), unix.CLONE_NEWNS); err != nil {
			return failure(api.CodePrerequisite, "cannot enter the retained credential mount namespace (setns "+errnoName(err)+")")
		}
		if err := unix.MoveMount(mount, "", int(parent.Fd()), base, unix.MOVE_MOUNT_F_EMPTY_PATH); err != nil {
			return failure(api.CodePrerequisite, "kernel refused the read-only credential view")
		}
		return nil
	}); err != nil {
		return err
	}
	return contextError(ctx)
}

// A namespace operation leaves a private fs_struct even if setns is reversed.
// Returning while locked retires this OS thread instead of pooling that state.
func credentialViewThread(action func() error) error {
	finished := make(chan error)
	go func() {
		finished <- runCredentialView(action)
	}()
	return <-finished
}

func runCredentialView(action func() error) error {
	runtime.LockOSThread()
	// Unlike other locked threads, the runtime parks a retiring process
	// leader. Refuse before changing its namespace or private fs_struct.
	if unix.Gettid() == unix.Getpid() {
		return failure(api.CodePrerequisite, "credential view cannot use the process leader")
	}
	return action()
}

func credentialParentInView(root *os.File, name string) (*os.File, string, error) {
	fd, err := fdpath.Open(int(root.Fd()), path.Join("home/lane", path.Dir(name)), &unix.OpenHow{Flags: unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC | unix.O_NOFOLLOW, Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS})
	if err != nil {
		return nil, "", failure(api.CodeContainmentUnknown, "credential view parent changed")
	}
	return os.NewFile(uintptr(fd), "credential-view-parent"), path.Base(name), nil
}

func reserveCredentialFile(parent *os.File, base string, mode uint32) (int, error) {
	return fdpath.Open(int(parent.Fd()), base, &unix.OpenHow{Flags: unix.O_CREAT | unix.O_EXCL | unix.O_RDWR | unix.O_CLOEXEC | unix.O_NOFOLLOW,
		Mode: uint64(mode), Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS | unix.RESOLVE_NO_XDEV})
}

func (r *credentialRuntime) measure(ctx context.Context, held *heldCredentials) (api.CredentialProjectionReceipt, error) {
	a := held.record.Authority
	q := a.Request
	record, err := r.manager.find(q.Lease.ID)
	if err != nil {
		return api.CredentialProjectionReceipt{}, err
	}
	if record.Gate == nil || record.Gate.Prepared != q.Prepared || record.Gate.State != "prepared" || record.Gate.Permit != nil {
		return api.CredentialProjectionReceipt{}, failure(api.CodeConflict, "credential holding is no longer behind the closed gate")
	}
	home, err := r.home(record, q)
	if err != nil {
		return api.CredentialProjectionReceipt{}, err
	}
	defer home.Close()
	aID, _, err := credentialObject(home)
	bID, _, other := credentialObject(held.home)
	if err != nil || other != nil || aID != bID {
		return api.CredentialProjectionReceipt{}, failure(api.CodeIntegrity, "credential holding root was replaced")
	}
	if len(held.files) != len(a.Targets) {
		return api.CredentialProjectionReceipt{}, failure(api.CodeContainmentUnknown, "credential projection has incomplete held descriptors")
	}
	receipt := api.CredentialProjectionReceipt{ProjectionID: a.ID, Generation: a.Generation + 1, Prepared: q.Prepared, HelperLeaseID: q.Lease.ID, SpecSHA256: q.Handoff.SpecSHA256, Home: q.Home, CancellationEpoch: q.Cause.CancellationEpoch, GateClosed: true, ObservedAt: gateTimestamp()}
	var count uint64
	state, err := dataParent(r.manager.binding.statePath())
	if err != nil {
		return receipt, err
	}
	var private unix.Stat_t
	err = unix.Fstat(int(state.Fd()), &private)
	closeErr := state.Close()
	if err != nil || closeErr != nil || private.Uid != 0 || private.Mode&07777 != 0700 {
		return receipt, failure(api.CodeIntegrity, "anonymous credential holding owner or mode changed")
	}
	for i, target := range a.Targets {
		id, st, err := credentialObject(held.files[i])
		if err != nil {
			return receipt, err
		}
		count++
		item := api.CredentialHeldTarget{Target: target, SourceObjectID: held.sources[i], ObjectID: id, RootID: q.Home.RootID, HomeGeneration: q.Home.Generation, OwnerUID: st.Uid, Mode: st.Mode & 07777, Links: uint64(st.Nlink), ParentMode: private.Mode & 07777, WritableByOthers: st.Mode&0077 != 0}
		if target.Delivery == "file" {
			parent, base, err := dataEntryParent(home, target.RelativePath)
			if err != nil {
				return receipt, err
			}
			var actual, dir unix.Stat_t
			err = unix.Fstatat(int(parent.Fd()), base, &actual, unix.AT_SYMLINK_NOFOLLOW)
			dirErr := unix.Fstat(int(parent.Fd()), &dir)
			parent.Close()
			if err != nil || dirErr != nil || actual.Dev != st.Dev || actual.Ino != st.Ino {
				return receipt, failure(api.CodeIntegrity, "projected credential name or inode was replaced")
			}
			item.ParentMode = dir.Mode & 07777
			if target.FileMode == 0400 || target.EnvironmentName != "" {
				root, err := r.childRoot(record)
				if err != nil {
					return receipt, err
				}
				parent, base, err := credentialParentInView(root, target.RelativePath)
				root.Close()
				if err != nil {
					return receipt, err
				}
				fd, err := unix.Openat(int(parent.Fd()), base, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
				parent.Close()
				if err != nil {
					return receipt, failure(api.CodeContainmentUnknown, "credential read-only view is unavailable")
				}
				var fs unix.Statfs_t
				var view unix.Stat_t
				err = unix.Fstatfs(fd, &fs)
				statErr := unix.Fstat(fd, &view)
				unix.Close(fd)
				if err != nil || statErr != nil || view.Dev != st.Dev || view.Ino != st.Ino || fs.Flags&unix.ST_RDONLY == 0 {
					return receipt, failure(api.CodeIntegrity, "credential view is not the held read-only inode")
				}
				item.ReadOnlyView = true
			}
		}
		receipt.Targets = append(receipt.Targets, item)
	}
	inherited, err := inheritedCredentialSources(held.sourceHandles)
	if err != nil {
		return receipt, err
	}
	receipt.HeldDescriptors = &count
	receipt.InheritedSources = &inherited
	return receipt, contextError(ctx)
}

func inheritedCredentialSources(files []*os.File) (uint64, error) {
	var count uint64
	for _, file := range files {
		if file == nil {
			return count, failure(api.CodeContainmentUnknown, "credential source disposition is unknown")
		}
		_, err := file.Stat()
		if err == nil {
			count++
		} else if !errors.Is(err, os.ErrClosed) {
			return count, failure(api.CodeContainmentUnknown, "credential source close cannot be measured")
		}
	}
	return count, nil
}

func (r *credentialRuntime) observe(ctx context.Context, id api.ID) (api.CredentialProjectionReceipt, error) {
	held := r.held[id]
	if held == nil {
		return api.CredentialProjectionReceipt{}, failure(api.CodeContainmentUnknown, "original credential objects were lost; no reopen is allowed")
	}
	receipt, err := r.measure(ctx, held)
	if err != nil {
		return receipt, err
	}
	if held.record.Receipt == nil || !reflect.DeepEqual(receipt.Targets, held.record.Receipt.Targets) {
		return receipt, failure(api.CodeIntegrity, "credential holding changed after acknowledgement")
	}
	return receipt, nil
}

// errnoName names a system call error by its errno, never by text.
func errnoName(err error) string {
	var errno unix.Errno
	if errors.As(err, &errno) {
		return unix.ErrnoName(errno)
	}
	return "other"
}
