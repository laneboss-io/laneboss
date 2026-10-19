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
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"laneboss.io/laneboss/internal/v2/api"
)

func init() {
	if len(os.Args) != 3 || os.Args[1] != "admin-credential-view-child" {
		return
	}
	runtime.LockOSThread()
	if unix.Mount("", "/", "", unix.MS_REC|unix.MS_PRIVATE, "") != nil || unix.Chroot(os.Args[2]) != nil || unix.Chdir("/") != nil {
		os.Exit(61)
	}
	ready := os.NewFile(3, "view-canary-readiness")
	hold := os.NewFile(4, "view-canary-lifetime")
	if n, err := ready.Write([]byte{1}); err != nil || n != 1 {
		os.Exit(62)
	}
	if err := ready.Close(); err != nil {
		os.Exit(63)
	}
	if _, err := io.Copy(io.Discard, hold); err != nil {
		os.Exit(64)
	}
	if err := hold.Close(); err != nil {
		os.Exit(65)
	}
	os.Exit(0)
}

// This requires a root Linux host with mount namespace privileges. It executes
// the production setns, open_tree, mount_setattr and move_mount path without mocks.
func TestCredROView(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Fatal("read-only credential view canary requires the disposable root Linux host")
	}
	leaderNS, err := os.Readlink("/proc/self/ns/mnt")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		after, err := os.Readlink("/proc/self/ns/mnt")
		if err != nil || after != leaderNS {
			t.Fatal("acceptance: credential view changed the process leader namespace")
		}
	})
	for _, mode := range []string{"task", "headless"} {
		t.Run(mode, func(t *testing.T) {
			// Give the source its own shared peer group, independently of
			// the host's propagation defaults. Child exit precedes its cleanup.
			source, data := sharedViewSource(t)
			target := api.CredentialTarget{Delivery: "file", RelativePath: ".secrets/task", FileMode: 0400}
			if mode == "headless" {
				target.RelativePath, target.FileMode, target.EnvironmentName = ".runnerhome-runtime/token", 0600, "CLAUDE_CODE_OAUTH_TOKEN"
			}
			root := t.TempDir()
			name := filepath.Join(root, "home/lane", target.RelativePath)
			if err := os.MkdirAll(filepath.Dir(name), 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(name, []byte("unprojected destination"), os.FileMode(target.FileMode)); err != nil {
				t.Fatal(err)
			}
			readyRead, readyWrite, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer readyRead.Close()
			holdRead, holdWrite, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			executable, err := os.Open("/proc/self/exe")
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			command := exec.CommandContext(ctx, "/proc/self/fd/5", "admin-credential-view-child", root)
			command.Env = []string{}
			command.ExtraFiles = []*os.File{readyWrite, holdRead, executable}
			// Pdeathsig follows the creating OS thread, not the process. The
			// hold pipe and bounded command context own this child's lifetime.
			command.SysProcAttr = &syscall.SysProcAttr{Cloneflags: unix.CLONE_NEWNS}
			creator := 0
			if err := credentialViewThread(func() error {
				creator = unix.Gettid()
				return command.Start()
			}); err != nil {
				cancel()
				t.Fatal("cannot start actual child mount namespace")
			}
			t.Cleanup(func() {
				if err := holdWrite.Close(); err != nil {
					t.Error(err)
				}
				if err := command.Wait(); err != nil {
					t.Error("credential view child did not exit successfully")
				}
				cancel()
			})
			for _, file := range []*os.File{readyWrite, holdRead, executable} {
				if err := file.Close(); err != nil {
					t.Fatal(err)
				}
			}
			// Deliberately retire the exact thread that created the child.
			// This makes accidental Pdeathsig coupling observable every run.
			waitViewThread(t, creator)
			if err := readyRead.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
				t.Fatal(err)
			}
			var ready [1]byte
			if _, err := io.ReadFull(readyRead, ready[:]); err != nil || ready[0] != 1 {
				t.Fatal("acceptance: credential view child depended on its creating thread")
			}
			boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
			if err != nil {
				t.Fatal(err)
			}
			bootID := strings.TrimSpace(string(boot))
			pid := command.Process.Pid
			generation, err := processGeneration(pid, bootID)
			if err != nil {
				t.Fatalf("acceptance: credential view child depended on its creating thread: %v", err)
			}
			pidfd, err := unix.PidfdOpen(pid, 0)
			if err != nil {
				t.Fatalf("acceptance: credential view child depended on its creating thread: %v", err)
			}
			defer unix.Close(pidfd)
			native := &nativeGate{innerPID: pid, innerFD: pidfd, innerGeneration: generation}
			if err := native.innerLifetime(bootID); err != nil {
				t.Fatal("acceptance: credential view child depended on its creating thread")
			}
			record := leaseRecord{Lease: api.HelperLease{ID: "view-canary"}}
			manager := newLeaseManager(testBinding(), bootID, nil, nil)
			manager.gates = map[api.ID]ownedGate{record.Lease.ID: native}
			receiver := &credentialRuntime{manager: manager}
			if err := source.Chmod(os.FileMode(target.FileMode)); err != nil {
				t.Fatal(err)
			}
			want, _, err := credentialObject(source)
			if err != nil {
				t.Fatal(err)
			}
			mounts := helperViewMounts(t)
			if err := receiver.readOnlyView(ctx, record, target, source); err != nil {
				t.Fatal("acceptance: read-only credential view did not install in child namespace")
			}
			checkViewMounts(t, mounts, "accepted")
			refused := target
			refused.RelativePath = filepath.ToSlash(filepath.Join(filepath.Dir(target.RelativePath), "missing-view"))
			if _, err := os.Lstat(filepath.Join(root, "home/lane", refused.RelativePath)); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("refused view destination must actually be absent")
			}
			err = receiver.readOnlyView(ctx, record, refused, source)
			var refusal *api.Error
			if !errors.As(err, &refusal) || refusal.Code != api.CodePrerequisite || refusal.Message != "kernel refused the read-only credential view" {
				t.Fatal("acceptance: refused view did not reach the native mount worker")
			}
			checkViewMounts(t, mounts, "refused")
			if err := native.innerLifetime(bootID); err != nil {
				t.Fatal("acceptance: refused view stopped its retained child")
			}
			if err := receiver.readOnlyView(ctx, record, target, source); err != nil {
				t.Fatal("acceptance: refused view prevented the next projection")
			}
			checkViewMounts(t, mounts, "accepted")
			childName := "/proc/" + strconv.Itoa(pid) + "/root/home/lane/" + target.RelativePath
			view, err := os.Open(childName)
			if err != nil {
				t.Fatal("acceptance: child credential view is unavailable")
			}
			defer view.Close()
			got, _, err := credentialObject(view)
			var fs unix.Statfs_t
			flags := int64(unix.ST_RDONLY | unix.ST_NOSUID | unix.ST_NODEV | unix.ST_NOEXEC)
			if err != nil || got != want || unix.Fstatfs(int(view.Fd()), &fs) != nil || fs.Flags&flags != flags {
				t.Fatal("acceptance: child credential view lost its inode or read-only mount flags")
			}
			actual, err := io.ReadAll(view)
			if err != nil || string(actual) != string(data) {
				t.Fatal("acceptance: child credential view changed the canary bytes")
			}
			if fd, err := unix.Open(childName, unix.O_WRONLY|unix.O_CLOEXEC, 0); !errors.Is(err, unix.EROFS) {
				if err == nil {
					unix.Close(fd)
				}
				t.Fatal("acceptance: child credential view remained writable")
			}
			if unix.Fstatfs(int(source.Fd()), &fs) != nil || fs.Flags&unix.ST_RDONLY != 0 {
				t.Fatal("acceptance: credential view changed the helper source mount")
			}
		})
	}
}

func sharedViewSource(t *testing.T) (*os.File, []byte) {
	t.Helper()
	input, data := credentialCanary(t)
	base := filepath.Dir(input.Name())
	if err := unix.Mount(base, base, "", unix.MS_BIND, ""); err != nil {
		t.Fatal("cannot create the source propagation fixture")
	}
	t.Cleanup(func() {
		// This is the fixture's own bind, never a lazy disposal of leaked
		// production mounts. A nested leaked mount makes normal unmount fail.
		if err := unix.Unmount(base, 0); err != nil {
			t.Errorf("cannot unmount the source propagation fixture: %v", err)
		}
	})
	if unix.Mount("", base, "", unix.MS_PRIVATE, "") != nil || unix.Mount("", base, "", unix.MS_SHARED, "") != nil {
		t.Fatal("cannot give the source its own shared peer group")
	}
	// Reopen through the bind so open_tree uses this mount, rather than
	// the containing mount retained by the original descriptor.
	source, err := os.OpenFile(input.Name(), os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := source.Close(); err != nil {
			t.Error(err)
		}
	})
	if err := input.Close(); err != nil {
		t.Fatal(err)
	}
	return source, data
}

func helperViewMounts(t *testing.T) []mountObservation {
	t.Helper()
	mounts, err := readMountObservations("/proc/self/mountinfo")
	if err != nil || len(mounts) == 0 {
		t.Fatal("cannot inventory the helper mount namespace")
	}
	return mounts
}

func checkViewMounts(t *testing.T, before []mountObservation, phase string) {
	t.Helper()
	after := helperViewMounts(t)
	t.Logf("%s projection helper mounts: before=%d after=%d", phase, len(before), len(after))
	counts := make(map[mountObservation]int, len(before))
	for _, mount := range before {
		counts[mount]++
	}
	for _, mount := range after {
		counts[mount]--
	}
	changed := len(before) != len(after)
	for _, count := range counts {
		changed = changed || count != 0
	}
	if changed {
		if phase == "refused" {
			t.Fatal("acceptance: refused credential view changed helper mounts")
		}
		t.Fatal("acceptance: accepted credential view changed helper mounts")
	}
}

func waitViewThread(t *testing.T, tid int) {
	t.Helper()
	if tid <= 0 || tid == unix.Getpid() {
		t.Fatal("acceptance: credential view creator used the process leader")
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		_, err := os.Stat("/proc/self/task/" + strconv.Itoa(tid))
		if errors.Is(err, os.ErrNotExist) {
			return
		}
		if err != nil || !time.Now().Before(deadline) {
			t.Fatal("acceptance: credential view creator thread did not retire")
		}
		time.Sleep(time.Millisecond)
	}
}

func TestCredViewThread(t *testing.T) {
	leaderNS, err := os.Readlink("/proc/self/ns/mnt")
	if err != nil {
		t.Fatal(err)
	}
	tid := 0
	if err := credentialViewThread(func() error {
		tid = unix.Gettid()
		return unix.Unshare(unix.CLONE_FS)
	}); err != nil {
		t.Fatal(err)
	}
	if tid <= 0 || tid == unix.Getpid() {
		t.Fatal("acceptance: credential view worker used the process leader")
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		_, err := os.Stat("/proc/self/task/" + strconv.Itoa(tid))
		if errors.Is(err, os.ErrNotExist) {
			after, err := os.Readlink("/proc/self/ns/mnt")
			if err != nil || after != leaderNS {
				t.Fatal("acceptance: credential view changed the process leader namespace")
			}
			return
		}
		if err != nil || !time.Now().Before(deadline) {
			t.Fatal("acceptance: credential view thread returned to the pool")
		}
		time.Sleep(time.Millisecond)
	}
}
