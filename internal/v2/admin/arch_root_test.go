//go:build linux && laneboss_root_canary

package admin

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"laneboss.io/laneboss/internal/v2/api"
)

func init() {
	if len(os.Args) == 2 && os.Args[1] == "archive-cg-hold" {
		ready := os.NewFile(4, "cgroup-ready")
		hold := os.NewFile(3, "cgroup-lifetime")
		if n, err := ready.Write([]byte{1}); err != nil || n != 1 {
			os.Exit(64)
		}
		if ready.Close() != nil {
			os.Exit(65)
		}
		if _, err := io.Copy(io.Discard, hold); err != nil {
			os.Exit(66)
		}
		if hold.Close() != nil {
			os.Exit(67)
		}
		os.Exit(0)
	}
	if len(os.Args) != 2 || os.Args[1] != "archive-write-canary" {
		return
	}
	file, err := os.OpenFile("/proc/self/fd/3", os.O_WRONLY, 0)
	if err == nil {
		if file.Close() != nil {
			os.Exit(61)
		}
		if _, err := os.Stdout.WriteString("allowed\n"); err != nil {
			os.Exit(63)
		}
		os.Exit(0)
	}
	if !errors.Is(err, os.ErrPermission) {
		os.Exit(62)
	}
	if _, err := os.Stdout.WriteString("denied\n"); err != nil {
		os.Exit(63)
	}
	os.Exit(0)
}

func archiveRootFixture(t *testing.T) (*os.File, string) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Fatal("native archive canary requires the disposable root Linux host")
	}
	base := privateTestDir(t)
	root, err := os.Open(base)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := root.Close(); err != nil {
			t.Error(err)
		}
	})
	return root, base
}

func TestArchiveCurrent(t *testing.T) {
	root, base := archiveRootFixture(t)
	file := filepath.Join(base, "current.txt")
	if err := os.WriteFile(file, []byte("initial launch snapshot\n"), 0600); err != nil {
		t.Fatal(err)
	}
	current := []byte("current completed workspace\n")
	if err := os.WriteFile(file, current, 0600); err != nil {
		t.Fatal(err)
	}
	ceiling := uint64(1 << 20)
	entries, objects, _, err := walkArchive(context.Background(), root, "workspace", "archive-op", nil, false, false, &ceiling)
	if err != nil {
		t.Fatal(err)
	}
	if len(objects) != 1 || objects[0].Ref.SHA256 != digestBytes(current) || objects[0].Ref.Bytes != int64(len(current)) {
		t.Fatal("acceptance: archive did not measure current workspace bytes")
	}
	prior := map[string]api.ObjectEntry{}
	for _, e := range entries {
		prior[e.Path] = e
	}
	ceiling = 1 << 20
	if _, _, _, err := walkArchive(context.Background(), root, "workspace", "archive-op", prior, true, false, &ceiling); err != nil {
		t.Fatal(err)
	}
	ceiling = 1 << 20
	if _, _, _, err := walkArchive(context.Background(), root, "workspace", "archive-op", prior, false, true, &ceiling); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, []byte("changed after native freeze\n"), 0600); err != nil {
		t.Fatal(err)
	}
	ceiling = 1 << 20
	if _, _, _, err := walkArchive(context.Background(), root, "workspace", "archive-op", prior, false, true, &ceiling); err == nil {
		t.Fatal("acceptance: archive accepted changed frozen content")
	}
}

func archiveWriteAttempt(t *testing.T, file *os.File, identities ...uint32) string {
	t.Helper()
	uid := uint32(62001)
	if len(identities) == 1 {
		uid = identities[0]
	}
	command := exec.Command("/proc/self/exe", "archive-write-canary")
	command.Env = []string{}
	command.ExtraFiles = []*os.File{file}
	command.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uid, Gid: uid, Groups: []uint32{}}}
	output, err := command.Output()
	if err != nil {
		t.Fatal("archive write canary setup failed")
	}
	return strings.TrimSpace(string(output))
}

func TestArchiveFreeze(t *testing.T) {
	t.Run("original-modes", testArchiveOriginalModes)
	root, base := archiveRootFixture(t)
	name := filepath.Join(base, "owned.txt")
	if err := os.WriteFile(name, []byte("owned current bytes\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(name, 62001, 62001); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(name)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if archiveWriteAttempt(t, file) != "allowed" {
		t.Fatal("archive positive writer control was not writable")
	}
	ceiling := uint64(1 << 20)
	if _, _, _, err := walkArchive(context.Background(), root, "workspace", "archive-op", nil, true, false, &ceiling); err != nil {
		t.Fatal(err)
	}
	var st unix.Stat_t
	if unix.Fstat(int(file.Fd()), &st) != nil || st.Uid != 0 || st.Gid != 0 || st.Mode&0222 != 0 || archiveWriteAttempt(t, file) != "denied" {
		t.Fatal("acceptance: archive freeze retained writable ownership or mode")
	}
}

func TestArchiveWriter(t *testing.T) {
	_, base := archiveRootFixture(t)
	file, err := os.OpenFile(filepath.Join(base, "writer"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	var st unix.Stat_t
	if unix.Fstat(int(file.Fd()), &st) != nil {
		t.Fatal("writer stat failed")
	}
	inventory := []storageInode{{Device: uint64(st.Dev), Inode: st.Ino}}
	count, _, err := descriptorReferences(context.Background(), os.Getpid(), inventory)
	if err != nil {
		file.Close()
		t.Fatal(err)
	}
	if count == 0 {
		file.Close()
		t.Fatal("native writer positive control was not observed")
	}
	refusal := archiveNoReferences(count)
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if refusal == nil {
		t.Fatal("acceptance: archive reported zero with an actual held writer")
	}
	var typed *api.Error
	if !errors.As(refusal, &typed) || typed.Code != api.ErrorCode("archive_live_writer") || typed.Retryable || typed.Owner != owner {
		t.Fatal("acceptance: measured writer lost its distinct non-retryable code")
	}
	count, _, err = descriptorReferences(context.Background(), os.Getpid(), inventory)
	if err != nil || archiveNoReferences(count) != nil {
		t.Fatal("closed writer was not independently measured as zero")
	}
}

func TestArchiveInputs(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Fatal("archive input canary requires the disposable root Linux host")
	}
	base, err := os.MkdirTemp("/run", "lb-v2-admin-inputs-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(base); err != nil {
			t.Error(err)
		}
	})
	roots := map[string]string{}
	expected := map[string][]byte{}
	r := leaseRecord{Request: testAllocation(), Storage: &launchStorageRecord{Ready: true, Directories: make([]storageIdentity, 3)}}
	for index, prefix := range []string{"workspace", "home", "history", "captures/capture-a"} {
		name := filepath.Join(base, strconv.Itoa(index))
		if err := os.Mkdir(name, 0700); err != nil {
			t.Fatal(err)
		}
		roots[prefix] = name
		file, err := os.Open(name)
		if err != nil {
			t.Fatal(err)
		}
		_, st, readErr := dataIdentity(file)
		closeErr := file.Close()
		if readErr != nil || closeErr != nil {
			t.Fatal("archive root setup failed")
		}
		if index < 3 {
			r.Storage.Directories[index] = storageIdentity{ID: api.ID("root-" + strconv.Itoa(index)), Device: strconv.FormatUint(uint64(st.Dev), 10), Inode: strconv.FormatUint(st.Ino, 10)}
		}
		files := []string{"record"}
		if index == 3 {
			files = []string{"marker", "stdout", "stderr"}
		}
		for _, member := range files {
			body := []byte(prefix + " current " + member + "\n")
			expected[prefix+"/"+member] = body
			if err := os.WriteFile(filepath.Join(name, member), body, 0600); err != nil {
				t.Fatal(err)
			}
		}
	}
	m := &leaseManager{}
	_, objects, _, err := m.measureArchiveRoots(context.Background(), r, roots, false, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(objects) != len(expected) {
		t.Fatal("acceptance: archive omitted current history or capture bytes")
	}
	for _, source := range objects {
		body, found := expected[source.Root+"/"+source.Name]
		if !found || source.Ref.SHA256 != digestBytes(body) || source.Ref.Bytes != int64(len(body)) {
			t.Fatal("acceptance: archive omitted current history or capture bytes")
		}
	}
	t.Run("replaced-root", func(t *testing.T) {
		changed := r
		storage := *r.Storage
		changed.Storage = &storage
		storage.Directories = append([]storageIdentity{}, r.Storage.Directories...)
		storage.Directories[2].Inode += "-replaced"
		if _, _, _, err := m.measureArchiveRoots(context.Background(), changed, roots, false, false); err == nil {
			t.Fatal("acceptance: archive accepted a replaced input root identity")
		}
	})
	t.Run("missing-capture", func(t *testing.T) {
		name := roots["captures/capture-a"]
		held := name + "-held"
		if err := os.Rename(name, held); err != nil {
			t.Fatal(err)
		}
		if _, _, _, err := m.measureArchiveRoots(context.Background(), r, roots, false, false); err == nil {
			t.Fatal("acceptance: archive accepted a missing capture root")
		}
		if err := os.Rename(held, name); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("reopen", testRetainedReopen)
}

func testArchiveOriginalModes(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Fatal("original mode canary requires the disposable root Linux host")
	}
	_, r, _ := storageFixture(t)
	b := testBinding()
	id, err := randomID("lb-v2-admin-modes-")
	if err != nil {
		t.Fatal(err)
	}
	group, err := randomID("lb-v2-admin-cg-")
	if err != nil {
		t.Fatal(err)
	}
	r.Lease = api.HelperLease{ID: id, UID: b.Lanes[0].UID, GID: b.Lanes[0].GID, ContainmentID: group, EndpointGeneration: b.Generation}
	r.IssuedAt = gateTimestamp()
	r.Storage.Binding.LeaseID = id
	base := storageBase(b, r)
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
	root, err := openStorageRoot(base)
	if err != nil {
		t.Fatal(err)
	}
	if err := syncStorageDirectories(context.Background(), root, &r, 0, true); err != nil {
		root.Close()
		t.Fatal(err)
	}
	if err := root.Close(); err != nil {
		t.Fatal(err)
	}
	want := map[string]uint32{"plain": 0644, "executable": 0755, "group-write": 0664}
	workspace := filepath.Join(base, string(r.Storage.Binding.WorkspaceID))
	for name, mode := range want {
		full := filepath.Join(workspace, name)
		if err := os.WriteFile(full, []byte("original mode bytes\n"), 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(full, os.FileMode(mode)); err != nil {
			t.Fatal(err)
		}
		if err := os.Chown(full, int(r.Lease.UID), int(r.Lease.GID)); err != nil {
			t.Fatal(err)
		}
	}
	journal, err := os.OpenRoot(privateTestDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer journal.Close()
	m := newLeaseManager(b, r.BootID, &fileLeaseStore{root: journal}, nil)
	m.resources = &linuxResources{binding: b, manager: m}
	if err := m.save(r); err != nil {
		t.Fatal(err)
	}
	if err := m.retainPrivateStorage(context.Background(), &r); err != nil {
		t.Fatal(err)
	}
	roots, err := m.archiveRoots(r)
	if err != nil {
		t.Fatal(err)
	}
	tree, _, _, err := m.measureArchiveRoots(context.Background(), r, roots, false, false)
	if err != nil {
		t.Fatal(err)
	}
	seen := 0
	for _, entry := range tree.Entries {
		if mode, ok := want[strings.TrimPrefix(entry.Path, "workspace/")]; ok {
			seen++
			if entry.Mode != mode {
				t.Fatal("acceptance: archive manifest replaced an original lane mode")
			}
		}
	}
	if seen != len(want) {
		t.Fatal("acceptance: archive manifest omitted original mode entries")
	}
	file := filepath.Join(workspace, "plain")
	if err := os.WriteFile(file, []byte("extra bytes\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(file, 0644); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := m.measureArchiveRoots(context.Background(), r, roots, false, false); err == nil {
		t.Fatal("acceptance: archive accepted restored permissions after withdrawal")
	}
}

func testRetainedReopen(t *testing.T) {
	root, base := archiveRootFixture(t)
	name := filepath.Join(base, "original")
	if err := os.WriteFile(name, []byte("original inode\n"), 0600); err != nil {
		t.Fatal(err)
	}
	var named unix.Stat_t
	if unix.Fstatat(int(root.Fd()), "original", &named, unix.AT_SYMLINK_NOFOLLOW) != nil {
		t.Fatal("native inode setup failed")
	}
	file, err := reopenRetained(root, "original", named, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(name, filepath.Join(base, "kept")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(name, []byte("replacement inode\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(name, 62001, 62001); err != nil {
		t.Fatal(err)
	}
	file, err = reopenRetained(root, "original", named, false)
	if file != nil {
		file.Close()
	}
	if err == nil {
		t.Fatal("acceptance: retained reopen accepted a substituted inode")
	}
	var after unix.Stat_t
	if unix.Fstatat(int(root.Fd()), "original", &after, unix.AT_SYMLINK_NOFOLLOW) != nil || after.Uid != 62001 {
		t.Fatal("acceptance: refused retained reopen changed replacement ownership")
	}
}

// Native wait/UID component evidence; the installed cgroup barrier remains a
// separate Linux acceptance requirement of the full helper path.
func TestArchiveWait(t *testing.T) {
	archiveRootFixture(t)
	for _, binary := range []string{"/bin/true", "/bin/false"} {
		t.Run(filepath.Base(binary), func(t *testing.T) {
			command := exec.Command(binary)
			command.Env = []string{}
			command.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 62001, Gid: 62001, Groups: []uint32{}}}
			if err := command.Start(); err != nil {
				t.Fatal(err)
			}
			waitErr := command.Wait()
			var exit *exec.ExitError
			if waitErr != nil && !errors.As(waitErr, &exit) {
				t.Fatal(waitErr)
			}
			live := &nativeGate{command: command, state: command.ProcessState, waitErr: waitErr, done: make(chan struct{}), released: true}
			close(live.done)
			handle := api.ProcessHandle{ID: "archive-process", Target: api.LifeRef{LifeID: "archive-life", Run: 1}, ContainmentID: "archive-containment", Generation: "native-component"}
			read, err := measureArchiveNative(context.Background(), live, handle, func() error { return uidQuiescent(context.Background(), 62001) })
			if binary == "/bin/false" {
				if err == nil {
					t.Fatal("acceptance: archive accepted a measured nonzero exit")
				}
			} else if err != nil || read.ExitCode == nil || *read.ExitCode != 0 || read.Survivors == nil || *read.Survivors != 0 {
				t.Fatal("acceptance: archive lost the actual successful wait")
			}
		})
	}
	t.Run("cgroup", testArchiveCgroup)
}

// Exercise linuxResources through the actual native cgroup path, first with
// a real surviving process and then after that same process has been reaped.
func testArchiveCgroup(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Fatal("archive cgroup canary requires the disposable root Linux host")
	}
	b := testBinding()
	nonce, err := randomID("cg-")
	if err != nil {
		t.Fatal(err)
	}
	b.Config = "lb-v2-admin-" + string(nonce)[3:13]
	unit := filepath.Dir(b.cgroupPath())
	lanes := b.cgroupPath()
	group := api.ID("archive-group")
	for _, name := range []string{unit, lanes, filepath.Join(lanes, string(group))} {
		if err := os.Mkdir(name, 0755); err != nil {
			t.Fatal("native cgroup fixture could not create its own hierarchy")
		}
	}
	t.Cleanup(func() {
		for _, name := range []string{filepath.Join(lanes, string(group)), lanes, unit} {
			if err := unix.Rmdir(name); err != nil {
				t.Error("native cgroup fixture retained an uncollected group")
			}
		}
	})
	cgroup, err := os.Open(filepath.Join(lanes, string(group)))
	if err != nil {
		t.Fatal(err)
	}
	defer cgroup.Close()
	if _, err := cgroupIdentity(cgroup); err != nil {
		t.Fatal(err)
	}
	holdRead, holdWrite, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer holdRead.Close()
	readyRead, readyWrite, err := os.Pipe()
	if err != nil {
		holdWrite.Close()
		t.Fatal(err)
	}
	defer readyRead.Close()
	blocker := exec.Command("/proc/self/exe", "archive-cg-hold")
	blocker.Env = []string{}
	blocker.ExtraFiles = []*os.File{holdRead, readyWrite}
	blocker.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 62001, Gid: 62001, Groups: []uint32{}}, UseCgroupFD: true, CgroupFD: int(cgroup.Fd())}
	if err := blocker.Start(); err != nil {
		holdWrite.Close()
		readyWrite.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if blocker.ProcessState == nil {
			if err := blocker.Process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
				t.Error(err)
			}
			if err := blocker.Wait(); err != nil {
				var exit *exec.ExitError
				if !errors.As(err, &exit) {
					t.Error(err)
				}
			}
		}
	})
	if err := readyWrite.Close(); err != nil {
		t.Fatal(err)
	}
	if err := readyRead.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	var byteReady [1]byte
	if _, err := io.ReadFull(readyRead, byteReady[:]); err != nil {
		t.Fatal("native cgroup survivor did not become ready")
	}
	actualRoot, err := os.OpenRoot(filepath.Join(lanes, string(group)))
	if err != nil {
		t.Fatal(err)
	}
	population, readErr := readControl(actualRoot, "cgroup.events")
	closeErr := actualRoot.Close()
	if readErr != nil || closeErr != nil || !strings.Contains(population, "populated 1") {
		t.Fatal("native cgroup positive control was not populated")
	}
	command := exec.Command("/bin/true")
	command.Env = []string{}
	command.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 62001, Gid: 62001, Groups: []uint32{}}, UseCgroupFD: true, CgroupFD: int(cgroup.Fd())}
	if err := command.Run(); err != nil {
		t.Fatal(err)
	}
	live := &nativeGate{command: command, state: command.ProcessState, done: make(chan struct{}), released: true}
	close(live.done)
	handle := api.ProcessHandle{ID: "archive-process", Target: api.LifeRef{LifeID: "archive-life", Run: 1}, ContainmentID: group, Generation: "cgroup-component"}
	r := leaseRecord{Lease: api.HelperLease{UID: 62001, GID: 62001, ContainmentID: group}, Phase: "active"}
	resources := &linuxResources{binding: b}
	_, observedErr := measureArchiveNative(context.Background(), live, handle, func() error { return resources.Quiescent(context.Background(), r) })
	if err := holdWrite.Close(); err != nil {
		t.Fatal(err)
	}
	if err := blocker.Wait(); err != nil {
		t.Fatal(err)
	}
	var typed *api.Error
	if !errors.As(observedErr, &typed) || typed.Code != api.CodeContainmentUnknown {
		t.Fatal("acceptance: archive wait ignored a populated native cgroup")
	}
	observation, err := measureArchiveNative(context.Background(), live, handle, func() error { return resources.Quiescent(context.Background(), r) })
	if err != nil || observation.Survivors == nil || *observation.Survivors != 0 {
		t.Fatal("acceptance: empty native cgroup did not supply known zero survivors")
	}
}
