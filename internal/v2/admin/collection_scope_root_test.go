//go:build linux && laneboss_root_canary

package admin

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"laneboss.io/laneboss/internal/v2/api"
)

func init() {
	if len(os.Args) == 5 && os.Args[1] == "admin-collection-peer" {
		os.Exit(collectionPeer(os.Args[2], os.Args[3], os.Args[4] == "reference"))
	}
}

// The peer has a distinct real mount namespace and lane UID. Even a peer
// without any mount of lane A may retain A's file description inherited at
// exec; namespace/UID scoping must never hide that reference.
func collectionPeer(mode, directory string, reference bool) int {
	if unix.Mount("", "/", "", unix.MS_REC|unix.MS_PRIVATE, "") != nil {
		return 80
	}
	if mode == "mount" {
		point := filepath.Join(directory, "storage")
		if !reference {
			return 89
		}
		if os.Mkdir(point, 0700) != nil {
			return 90
		}
		var source unix.Stat_t
		if unix.Fstat(5, &source) != nil || source.Mode&unix.S_IFMT != unix.S_IFDIR {
			return 93
		}
		if err := unix.MoveMount(5, "", unix.AT_FDCWD, point, unix.MOVE_MOUNT_F_EMPTY_PATH); err != nil {
			var errno unix.Errno
			if errors.As(err, &errno) && errno > 0 && errno < 156 {
				return 100 + int(errno)
			}
			return 91
		}
		if unix.Close(5) != nil {
			return 92
		}
		reference = false // The bind mount alone retains storage after fd 5 closes.
	}
	if syscall.Setgroups([]int{}) != nil || syscall.Setgid(61002) != nil || syscall.Setuid(61002) != nil {
		return 80
	}
	stop, ready := os.NewFile(3, "peer-lifetime"), os.NewFile(4, "peer-ready")
	defer stop.Close()
	var held []*os.File
	defer func() {
		for _, file := range held {
			file.Close()
		}
	}()
	if reference {
		held = append(held, os.NewFile(5, "other-lane-reference"))
	}
	var racing chan struct{}
	var finished chan error
	switch mode {
	case "mount":
	case "own":
		file, err := os.Open("/proc/self/ns/mnt")
		if err != nil {
			return 81
		}
		held = append(held, file)
	case "loop":
		name := filepath.Join(directory, "loop")
		if os.Symlink("loop", name) != nil {
			return 82
		}
		fd, err := unix.Open(name, unix.O_PATH|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err != nil {
			return 83
		}
		held = append(held, os.NewFile(uintptr(fd), "self-referential-symlink"))
	case "race":
		file, err := os.Open("/proc/self/ns/net")
		if err != nil {
			return 84
		}
		held = append(held, file)
		racing, finished = make(chan struct{}), make(chan error, 1)
		go func() {
			for {
				select {
				case <-racing:
					finished <- nil
					return
				default:
				}
				if err := unix.Dup3(int(file.Fd()), 100, unix.O_CLOEXEC); err != nil {
					finished <- err
					return
				}
				runtime.Gosched()
				if err := unix.Close(100); err != nil {
					finished <- err
					return
				}
				runtime.Gosched()
			}
		}()
	default:
		return 85
	}
	if n, err := ready.Write([]byte{1}); err != nil || n != 1 || ready.Close() != nil {
		return 86
	}
	if _, err := io.Copy(io.Discard, stop); err != nil {
		return 87
	}
	if racing != nil {
		close(racing)
		if err := <-finished; err != nil {
			return 88
		}
	}
	return 0
}

func collectionCanaryContext(t *testing.T) context.Context {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Fatal("collection isolation canary requires disposable Linux root, never a skipped check")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	t.Cleanup(cancel)
	return ctx
}

func collectionPeerStart(t *testing.T, mode string, reference *os.File) (int, func()) {
	t.Helper()
	pid, _, stop := collectionPeerLifetime(t, mode, reference)
	return pid, stop
}

func collectionPeerLifetime(t *testing.T, mode string, reference *os.File) (int, func(), func()) {
	t.Helper()
	ctx := collectionCanaryContext(t)
	id, err := randomID("lb-collection-peer-")
	if err != nil {
		t.Fatal(err)
	}
	directory := filepath.Join("/run", string(id))
	if err := os.Mkdir(directory, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(directory, 61002, 61002); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(directory); err != nil {
			t.Error(err)
		}
	})
	stopRead, stopWrite, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer stopRead.Close()
	readyRead, readyWrite, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer readyRead.Close()
	defer readyWrite.Close()
	argument := "no-reference"
	files := []*os.File{stopRead, readyWrite}
	if reference != nil {
		argument = "reference"
		input := reference
		if mode == "mount" {
			// An inherited source pins the parent's mount and cannot be cloned
			// after CLONE_NEWNS. Prepare its exact detached clone here, then let
			// the child attach it. Both descriptor copies close before inventory.
			fd, err := unix.OpenTree(int(reference.Fd()), "", unix.OPEN_TREE_CLONE|unix.OPEN_TREE_CLOEXEC|unix.AT_EMPTY_PATH)
			if err != nil {
				t.Fatal("collection peer could not clone its pinned source", err)
			}
			input = os.NewFile(uintptr(fd), "collection-peer-detached-mount")
			defer func() {
				if err := input.Close(); err != nil {
					t.Error(err)
				}
			}()
			var source, clone unix.Stat_t
			if unix.Fstat(int(reference.Fd()), &source) != nil || unix.Fstat(fd, &clone) != nil ||
				source.Dev != clone.Dev || source.Ino != clone.Ino || clone.Mode&unix.S_IFMT != unix.S_IFDIR {
				t.Fatal("collection peer clone differs from its actual storage source")
			}
			if err := unix.MountSetattr(fd, "", unix.AT_EMPTY_PATH, &unix.MountAttr{Propagation: unix.MS_PRIVATE}); err != nil {
				t.Fatal("collection peer could not make its detached mount private", err)
			}
		}
		files = append(files, input)
	}
	command := exec.CommandContext(ctx, "/proc/self/exe", "admin-collection-peer", mode, directory, argument)
	command.Env, command.ExtraFiles = []string{}, files
	command.SysProcAttr = &syscall.SysProcAttr{Cloneflags: unix.CLONE_NEWNS}
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	if err := readyWrite.Close(); err != nil {
		t.Fatal(err)
	}
	signalled, stopped := false, false
	exit := func() {
		if !signalled {
			signalled = true
			if err := stopWrite.Close(); err != nil {
				t.Error(err)
			}
		}
	}
	stop := func() {
		if stopped {
			return
		}
		stopped = true
		exit()
		if err := command.Wait(); err != nil {
			var exited *exec.ExitError
			if errors.As(err, &exited) && exited.ExitCode() > 100 && exited.ExitCode() < 256 {
				t.Error("collection peer mount setup failed", unix.Errno(exited.ExitCode()-100))
				return
			}
			t.Error("collection peer setup, race or collection failed", err)
		}
	}
	t.Cleanup(stop)
	if err := readyRead.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	var signal [1]byte
	if n, err := readyRead.Read(signal[:]); err != nil || n != 1 || signal[0] != 1 {
		t.Fatal("collection peer did not establish its real kernel inputs", err)
	}
	return command.Process.Pid, exit, stop
}

// Use the same real protected parent, durable journal and native containment
// observations as production collection. The uniquely named cgroup is absent;
// Quiescent must still independently scan every actual UID thread.
func collectionLeaseFixture(t *testing.T, initialize bool) (*leaseManager, leaseRecord, string) {
	t.Helper()
	collectionCanaryContext(t)
	_, record, _ := storageFixture(t)
	binding := testBinding()
	id, err := randomID("lb-collection-stage-")
	if err != nil {
		t.Fatal(err)
	}
	group, err := randomID("lb-collection-cg-")
	if err != nil {
		t.Fatal(err)
	}
	record.Lease = api.HelperLease{ID: id, UID: binding.Lanes[0].UID, GID: binding.Lanes[0].GID,
		ContainmentID: group, EndpointGeneration: binding.Generation}
	record.Storage.Binding.LeaseID, record.IssuedAt = id, gateTimestamp()
	base := storageBase(binding, record)
	if err := os.MkdirAll(filepath.Dir(base), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(base, 0700); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(base); err != nil {
			t.Error(err)
		}
	})
	journal, err := os.OpenRoot(privateTestDir(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := journal.Close(); err != nil {
			t.Error(err)
		}
	})
	m := newLeaseManager(binding, record.BootID, &fileLeaseStore{root: journal}, nil)
	m.resources = &linuxResources{binding: binding, manager: m}
	if initialize {
		if err := createLaneStageTraversalForCanary(base, record.Lease.GID); err != nil {
			t.Fatal(err)
		}
		root, err := openStorageRoot(base)
		if err != nil {
			t.Fatal(err)
		}
		syncErr := syncStorageDirectories(context.Background(), root, &record, 0, true)
		closeErr := root.Close()
		if syncErr != nil || closeErr != nil {
			t.Fatal(syncErr, closeErr)
		}
		if err := m.save(record); err != nil {
			t.Fatal(err)
		}
	}
	return m, record, base
}

// Initialize without invoking the interrupted-create recovery under test.
func createLaneStageTraversalForCanary(base string, gid uint32) error {
	if err := os.Chown(base, 0, int(gid)); err != nil {
		return err
	}
	return os.Chmod(base, 0710)
}

func TestCollectionPeerIsolation(t *testing.T) {
	for _, mode := range []string{"own", "loop", "race"} {
		for _, reference := range []string{"none", "file", "symlink"} {
			t.Run(mode+"/"+reference, func(t *testing.T) {
				ctx := collectionCanaryContext(t)
				m, record, base := collectionLeaseFixture(t, true)
				name := filepath.Join(base, string(record.Storage.Binding.WorkspaceID), "retained")
				var file *os.File
				if reference != "none" {
					if reference == "symlink" {
						if err := os.Symlink("retained", name); err != nil {
							t.Fatal(err)
						}
						fd, err := unix.Open(name, unix.O_PATH|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
						if err != nil {
							t.Fatal(err)
						}
						file = os.NewFile(uintptr(fd), "real-retained-symlink")
					} else {
						var err error
						file, err = os.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
						if err != nil {
							t.Fatal(err)
						}
						if _, err := file.Write([]byte("real retained private bytes\n")); err != nil {
							t.Fatal(err)
						}
					}
				}
				_, stop := collectionPeerStart(t, mode, file)
				if file != nil {
					if err := file.Close(); err != nil {
						t.Fatal(err)
					}
				}
				for attempt := 0; attempt < 4; attempt++ {
					count, _, err := m.storageReferences(ctx, record)
					if err != nil || (count != 0) != (reference != "none") {
						t.Fatalf("acceptance: unrelated peer blocked collection or a real peer reference disappeared: count=%d error=%v", count, err)
					}
				}
				if reference != "none" {
					err := m.collectPrivateStorage(ctx, &record)
					var typed *api.Error
					if !errors.As(err, &typed) || typed.Code != api.CodeContainmentUnknown || typed.Message != "private storage still has native descriptor or mount references" || record.Storage.Collecting {
						t.Fatal("acceptance: real peer reference did not stop the actual collection gate", err)
					}
					if _, err := os.Lstat(name); err != nil {
						t.Fatal("refused collection removed retained bytes", err)
					}
				}
				if reference == "none" {
					// The unrelated lane stays live through the actual deletion
					// gate, not merely through an isolated scanner call.
					if err := m.collectPrivateStorage(ctx, &record); err != nil {
						t.Fatal("unrelated live peer blocked actual collection", err)
					}
					stop()
				} else {
					stop()
					if err := m.collectPrivateStorage(ctx, &record); err != nil {
						t.Fatal("collection did not accept the released-reference control", err)
					}
				}
				if !record.Storage.Collected {
					t.Fatal("collection did not publish the measured result")
				}
				var parent unix.Stat_t
				if unix.Stat(base, &parent) != nil || parent.Uid != 0 || parent.Gid != 0 || parent.Mode&07777 != 0700 {
					t.Fatal("acceptance: collected stage parent retained lane GID traversal")
				}
				if err := m.collectPrivateStorage(ctx, &record); err != nil {
					t.Fatal("root-only collected parent was not retryable", err)
				}
			})
		}
	}
}

func TestCollectionRetiredInodeReferences(t *testing.T) {
	ctx := collectionCanaryContext(t)
	m, record, _ := collectionLeaseFixture(t, true)
	if err := m.collectPrivateStorage(ctx, &record); err != nil {
		t.Fatal(err)
	}
	file, err := os.CreateTemp(privateTestDir(t), "linked-reference-")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if err := file.Truncate(int64(os.Getpagesize())); err != nil {
		t.Fatal(err)
	}
	mapping, err := unix.Mmap(int(file.Fd()), 0, os.Getpagesize(), unix.PROT_READ, unix.MAP_SHARED)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if mapping != nil {
			if err := unix.Munmap(mapping); err != nil {
				t.Error(err)
			}
		}
	})
	var observed unix.Stat_t
	if err := unix.Fstat(int(file.Fd()), &observed); err != nil || observed.Nlink != 1 {
		t.Fatal("linked inode control was not measured", err)
	}
	// Model numerical inode reuse in the retired journal using an actual
	// unrelated linked inode, rather than depending on allocator timing.
	record.Storage.Inventory = append(record.Storage.Inventory, storageInode{Device: uint64(observed.Dev), Inode: observed.Ino})
	count, _, err := m.storageReferences(ctx, record)
	if err != nil || count != 0 {
		t.Fatal("completed collection mistook a linked reused inode for retained storage", count, err)
	}
	live := record
	storage := *record.Storage
	live.Storage = &storage
	live.Storage.Collected = false
	if count, _, err := m.storageReferences(ctx, live); err != nil || count == 0 {
		t.Fatal("uncompleted collection ignored its real linked reference", count, err)
	}
	if err := os.Remove(file.Name()); err != nil {
		t.Fatal(err)
	}
	if err := unix.Fstat(int(file.Fd()), &observed); err != nil || observed.Nlink != 0 {
		t.Fatal("unlinked held inode control was not measured", err)
	}
	if count, _, err := m.storageReferences(ctx, record); err != nil || count == 0 {
		t.Fatal("completed collection ignored an actual held unlinked inode", count, err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if count, _, err := m.storageReferences(ctx, record); err != nil || count == 0 {
		t.Fatal("completed collection ignored an actual unlinked memory mapping", count, err)
	}
	if err := unix.Munmap(mapping); err != nil {
		t.Fatal(err)
	}
	mapping = nil
	if count, _, err := m.storageReferences(ctx, record); err != nil || count != 0 {
		t.Fatal("closed and unmapped inode control still blocked completed collection", count, err)
	}
}

func TestCollectionRetainedMountNamespace(t *testing.T) {
	ctx := collectionCanaryContext(t)
	m, record, base := collectionLeaseFixture(t, true)
	source, err := os.Open(filepath.Join(base, string(record.Storage.Binding.WorkspaceID)))
	if err != nil {
		t.Fatal(err)
	}
	pid, stop := collectionPeerStart(t, "mount", source)
	if err := source.Close(); err != nil {
		t.Fatal(err)
	}
	count, _, err := m.storageReferences(ctx, record)
	if err != nil || count == 0 {
		t.Fatal("acceptance: a peer bind mount of private storage was measured as zero", err)
	}
	retained, err := os.Open("/proc/" + strconv.Itoa(pid) + "/ns/mnt")
	if err != nil {
		t.Fatal(err)
	}
	stop()
	// The process is gone, but this actual namespace still retains the mount.
	// Its contents cannot be reconciled from a live task's mountinfo anymore.
	_, _, err = m.storageReferences(ctx, record)
	var typed *api.Error
	if !errors.As(err, &typed) || typed.Code != api.CodeContainmentUnknown || typed.Message != "a foreign retained mount namespace has not been reconciled" {
		t.Fatal("acceptance: an unscanned retained storage namespace was ignored", err)
	}
	if err := retained.Close(); err != nil {
		t.Fatal(err)
	}
	if err := m.collectPrivateStorage(ctx, &record); err != nil {
		t.Fatal("released namespace control did not allow collection", err)
	}
}

func TestCollectionVanishedNamespace(t *testing.T) {
	collectionCanaryContext(t)
	file, err := os.Open("/proc/self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	var expected unix.Stat_t
	if err := unix.Fstat(int(file.Fd()), &expected); err != nil {
		t.Fatal(err)
	}
	name := "/proc/self/fd/" + strconv.Itoa(int(file.Fd()))
	if mount, err := retainedMountNamespace(name, expected); err != nil || mount {
		t.Fatal("live non-mount namespace control was not classified", err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if mount, err := retainedMountNamespace(name, expected); err != nil || mount {
		t.Fatal("acceptance: a closed namespace descriptor became containment_unknown", err)
	}
}

func TestCollectionNamespaceSwapNoIO(t *testing.T) {
	collectionCanaryContext(t)
	file, err := os.Open("/proc/self/ns/mnt")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	var expected unix.Stat_t
	if err := unix.Fstat(int(file.Fd()), &expected); err != nil {
		t.Fatal(err)
	}
	if mount, err := retainedMountNamespace(file.Name(), expected); err != nil || !mount {
		t.Fatal("real mount namespace control was not classified", err)
	}
	base := privateTestDir(t)
	fifo, swapped := filepath.Join(base, "fifo"), filepath.Join(base, "swapped")
	if err := unix.Mkfifo(fifo, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(fifo, swapped); err != nil {
		t.Fatal(err)
	}
	watch, err := unix.InotifyInit1(unix.IN_NONBLOCK | unix.IN_CLOEXEC)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(watch)
	if _, err := unix.InotifyAddWatch(watch, fifo, unix.IN_OPEN); err != nil {
		t.Fatal(err)
	}
	if _, err := retainedMountNamespace(swapped, expected); err == nil {
		t.Fatal("acceptance: a swapped FIFO was accepted as a namespace")
	}
	var events [4096]byte
	if n, err := unix.Read(watch, events[:]); n > 0 || !errors.Is(err, unix.EAGAIN) {
		t.Fatal("acceptance: namespace inspection opened an attacker-selected FIFO for I/O", err)
	}
}
