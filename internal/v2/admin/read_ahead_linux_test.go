//go:build linux

package admin

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/fdpath"
)

func TestSharedWalk(t *testing.T) {
	base := privateTestDir(t)
	if err := os.MkdirAll(filepath.Join(base, "nested", "directory"), 0700); err != nil {
		t.Fatal(err)
	}
	content, err := randomID("walk-input-")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(base, "nested", "directory", "record"), []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("nested", filepath.Join(base, "alias")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("record", filepath.Join(base, "nested", "directory", "alias")); err != nil {
		t.Fatal(err)
	}
	root, err := os.Open(base)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	how := unix.OpenHow{Flags: unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NOFOLLOW, Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS | unix.RESOLVE_NO_XDEV}
	for _, cause := range []error{unix.EPERM, unix.ENOSYS} {
		trigger := func(int, string, *unix.OpenHow) (int, error) { return -1, cause }
		for _, name := range []string{"nested/directory/record", "alias/directory/record", "nested/directory/alias", "nested/../nested/directory/record", "nested//directory/record"} {
			t.Run(cause.Error()+"/"+strings.ReplaceAll(name, "/", "_"), func(t *testing.T) {
				fd, err := fdpath.OpenWith(int(root.Fd()), name, &how, trigger)
				if name != "nested/directory/record" {
					if fd >= 0 {
						unix.Close(fd)
					}
					if err == nil || fd >= 0 {
						t.Fatal("acceptance: shared walk admitted an unproved component")
					}
					return
				}
				if err != nil {
					t.Fatal("acceptance: shared fallback did not open the actual input", err)
				}
				file := os.NewFile(uintptr(fd), "walk-result")
				data, readErr := io.ReadAll(file)
				closeErr := file.Close()
				if readErr != nil || closeErr != nil || string(data) != string(content) {
					t.Fatal("shared walk did not retain the input bytes")
				}
			})
		}
		created, err := fdpath.OpenWith(int(root.Fd()), "nested/new", &unix.OpenHow{Flags: unix.O_WRONLY | unix.O_CREAT | unix.O_EXCL | unix.O_NOFOLLOW | unix.O_CLOEXEC, Mode: 0600, Resolve: how.Resolve}, trigger)
		if err != nil {
			t.Fatal("shared walk could not create beneath the held parent", err)
		}
		if err := unix.Close(created); err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(filepath.Join(base, "nested", "new")); err != nil {
			t.Fatal(err)
		}
	}
	original := &os.SyscallError{Syscall: "openat2", Err: unix.EACCES}
	fd, err := fdpath.OpenWith(int(root.Fd()), "nested/directory/record", &how, func(int, string, *unix.OpenHow) (int, error) { return -1, original })
	if fd >= 0 || err != original {
		t.Fatal("acceptance: shared walk bypassed an unrelated refusal")
	}
}

func denyOpenat2() error {
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return err
	}
	filter := []unix.SockFilter{
		{Code: unix.BPF_LD | unix.BPF_W | unix.BPF_ABS, K: 0},
		{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jf: 1, K: unix.SYS_OPENAT2},
		{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_ERRNO | uint32(unix.EPERM)},
		{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_ALLOW},
	}
	program := unix.SockFprog{Len: uint16(len(filter)), Filter: &filter[0]}
	result, _, errno := unix.Syscall(unix.SYS_SECCOMP, unix.SECCOMP_SET_MODE_FILTER, unix.SECCOMP_FILTER_FLAG_TSYNC, uintptr(unsafe.Pointer(&program)))
	runtime.KeepAlive(filter)
	if errno != 0 {
		return errno
	}
	if result != 0 {
		return unix.EIO
	}
	return nil
}

func init() {
	if len(os.Args) == 3 && os.Args[1] == "admin-mount-crossing-canary" {
		if err := mountCrossingCanary(os.Args[2]); err != nil {
			os.Exit(62)
		}
		os.Exit(0)
	}
	if len(os.Args) == 3 && os.Args[1] == "admin-walk-restriction-canary" {
		if err := walkRestrictionCanary(os.Args[2]); err != nil {
			os.Exit(61)
		}
		os.Exit(0)
	}
}

func mountCrossingCanary(base string) error {
	if err := unix.Mount("", "/", "", unix.MS_REC|unix.MS_PRIVATE, ""); err != nil {
		return err
	}
	alias := filepath.Join(base, "alias")
	if err := unix.Mount(filepath.Join(base, "source"), alias, "", unix.MS_BIND, ""); err != nil {
		return err
	}
	defer unix.Unmount(alias, 0)
	root, err := os.Open(base)
	if err != nil {
		return err
	}
	defer root.Close()
	how := unix.OpenHow{Flags: unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NOFOLLOW, Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS | unix.RESOLVE_NO_XDEV}
	trigger := func(int, string, *unix.OpenHow) (int, error) { return -1, unix.EPERM }
	fd, err := fdpath.OpenWith(int(root.Fd()), "source/record", &how, trigger)
	if err != nil {
		return err
	}
	if err := unix.Close(fd); err != nil {
		return err
	}
	fd, err = fdpath.OpenWith(int(root.Fd()), "alias/record", &how, trigger)
	if fd >= 0 {
		unix.Close(fd)
	}
	if !errors.Is(err, unix.EXDEV) || fd >= 0 {
		return unix.EIO
	}
	fd, err = fdpath.Inspect(int(root.Fd()), "alias")
	if fd >= 0 {
		unix.Close(fd)
	}
	if !errors.Is(err, unix.EXDEV) || fd >= 0 {
		return unix.EIO
	}
	fd, err = fdpath.ResolveBeneath(int(root.Fd()), "alias/record")
	if fd >= 0 {
		unix.Close(fd)
	}
	if !errors.Is(err, unix.EXDEV) || fd >= 0 {
		return unix.EIO
	}
	return nil
}

func walkRestrictionCanary(base string) error {
	if os.Geteuid() != 0 {
		return unix.EPERM
	}
	endpoint, err := os.MkdirTemp("/run", "laneboss-restricted-socket-")
	if err != nil {
		return err
	}
	workers := filepath.Join(endpoint, "workers")
	if err := os.Mkdir(workers, 0700); err != nil {
		return err
	}
	socketPath := filepath.Join(workers, "walk-worker.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: socketPath, Net: "unix"})
	if err != nil {
		return err
	}
	if err := os.Chmod(socketPath, 0666); err != nil {
		return err
	}
	if err := denyOpenat2(); err != nil {
		return err
	}
	fd, err := unix.Openat2(unix.AT_FDCWD, base, &unix.OpenHow{Flags: unix.O_PATH | unix.O_CLOEXEC})
	if fd >= 0 {
		unix.Close(fd)
	}
	if !errors.Is(err, unix.EPERM) {
		return unix.EINVAL
	}
	manager := &leaseManager{binding: installation{Config: "walk-route"}}
	socket, err := manager.dataSocketAtBinding(dataJob{Reg: dataReg{Worker: api.WorkerLease{ID: "walk-worker"}}}, api.InstalledBinding{Socket: filepath.Join(endpoint, "control.sock")})
	if err != nil {
		return err
	}
	if err := socket.file.Close(); err != nil {
		return err
	}
	if err := listener.Close(); err != nil {
		return err
	}
	if err := os.Remove(workers); err != nil {
		return err
	}
	if err := os.Remove(endpoint); err != nil {
		return err
	}
	root, err := openStorageRoot(base)
	if err != nil {
		return err
	}
	if err := root.Close(); err != nil {
		return err
	}
	parent, err := dataParent(base)
	if err != nil {
		return err
	}
	defer parent.Close()
	directory, err := openStorageDirectory(parent, "nested")
	if err != nil {
		return err
	}
	defer directory.Close()
	file, err := dataFile(parent, "nested/record", false)
	if err != nil {
		return err
	}
	data, readErr := io.ReadAll(file)
	if err := errors.Join(readErr, file.Close()); err != nil || string(data) != "restricted-walk-bytes" {
		return unix.EIO
	}
	destination, err := openStorageDirectory(parent, "staged")
	if err != nil {
		return err
	}
	defer destination.Close()
	ref := api.BlobRef{ID: "restricted-input", SHA256: digestBytes(data), Bytes: int64(len(data)), Class: "data"}
	manifest := api.ObjectManifest{Schema: "laneboss.objects.v2", Entries: []api.ObjectEntry{{Path: ".", Kind: "directory", Mode: 0700}, {Path: "record", Kind: "file", Mode: 0600, Content: &ref}}}
	if err := dataStage(context.Background(), directory, destination, manifest, uint32(os.Geteuid()), uint32(os.Getegid())); err != nil {
		return err
	}
	if err := dataVerify(context.Background(), destination, manifest, uint32(os.Geteuid()), uint32(os.Getegid())); err != nil {
		return err
	}
	runtime.LockOSThread()
	if err := bootstrapLandlock([]bootstrapPath{{Path: filepath.Join(base, "nested"), Directory: true}}); err != nil {
		return err
	}
	if _, err := os.ReadFile(filepath.Join(base, "nested", "record")); err != nil {
		return err
	}
	if _, err := os.ReadFile(filepath.Join(base, "outside")); !errors.Is(err, unix.EACCES) {
		return unix.EIO
	}
	return nil
}

type fileTaskResources struct {
	observedResources
	root *os.Root
}

func (r *fileTaskResources) Survivors(context.Context, leaseRecord) (uint64, error) {
	return readSurvivors(r.root)
}

func TestRunningSurvivors(t *testing.T) {
	path := privateTestDir(t)
	root, err := os.OpenRoot(path)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	m := &leaseManager{resources: &fileTaskResources{root: root}}
	for _, count := range []uint64{3, 17, 2} {
		if err := os.WriteFile(filepath.Join(path, "pids.current"), []byte(strconv.FormatUint(count, 10)+"\n"), 0600); err != nil {
			t.Fatal(err)
		}
		observation := api.ProcessObservation{State: "running"}
		if err := m.measureRunningSurvivors(context.Background(), leaseRecord{}, &observation); err != nil || observation.Survivors == nil || *observation.Survivors != count {
			t.Fatal("acceptance: running observation lost its measured native task count")
		}
	}
	for _, value := range []string{"", "max", "-1", "1 2", "18446744073709551616", "0"} {
		if err := os.WriteFile(filepath.Join(path, "pids.current"), []byte(value), 0600); err != nil {
			t.Fatal(err)
		}
		observation := api.ProcessObservation{State: "running"}
		if err := m.measureRunningSurvivors(context.Background(), leaseRecord{}, &observation); err == nil || observation.Survivors != nil {
			t.Fatal("acceptance: running observation invented survivors for an unavailable count")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := (&linuxResources{}).Survivors(ctx, leaseRecord{}); err == nil {
		t.Fatal("cancelled survivor observation ignored its context")
	}
}

func TestLiveObservationSurvivors(t *testing.T) {
	m, _, gate, reader, store := retainedGateFixture(t)
	records, err := store.Records()
	if err != nil || len(records) != 1 {
		t.Fatal("live observation fixture lost its actual retained gate")
	}
	path := privateTestDir(t)
	root, err := os.OpenRoot(path)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	m.resources = &fileTaskResources{root: root}
	for _, count := range []string{"7", "13"} {
		if err := os.WriteFile(filepath.Join(path, "pids.current"), []byte(count), 0600); err != nil {
			t.Fatal(err)
		}
		handle := gateHandle(records[0])
		observation, err := m.observeGate(context.Background(), api.HelperObserveRequest{LeaseID: records[0].Lease.ID, Handle: handle})
		if err != nil || observation.State != "running" || observation.Handle != handle || observation.Survivors == nil || strconv.FormatUint(*observation.Survivors, 10) != count {
			t.Fatal("acceptance: live helper observation omitted the measured containment tasks")
		}
	}
	if gate.released {
		t.Fatal("survivor observation released the closed gate")
	}
	assertGateClosed(t, reader, "survivor observation executed the vendor")
}

func TestDescriptorOnlyArgs(t *testing.T) {
	controls := make([]*os.File, 8) // Capture's existing descriptors 3 through 10.
	mounts := []*nativeMount{{target: isolationDescriptorPath, sealed: true}, {target: workerInputPath, sealed: true}, {target: "/runtime/laneboss-worker.sock", socket: true}, {target: "/work/main", directory: true, writable: true}}
	args, files := nativeGateArgs("descriptor-fixture", "prepared-gate", controls, mounts, true)
	if len(files) != 12 {
		t.Fatal("descriptor-only projection changed capture descriptor positions")
	}
	for index, mount := range mounts[:3] {
		want := "--symlink /proc/self/fd/" + strconv.Itoa(11+index) + " " + mount.target
		if !strings.Contains(strings.Join(args, " "), want) {
			t.Fatal("acceptance: immutable input or socket became a bind source")
		}
	}
	if !strings.Contains(strings.Join(args, " "), "--bind-fd 14 /work/main") {
		t.Fatal("descriptor-only projection displaced the following storage descriptor")
	}
}

func readAheadContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	return ctx
}
