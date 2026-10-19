//go:build linux && laneboss_root_canary

package admin

import (
	"context"
	"encoding/binary"
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
	if len(os.Args) == 4 && os.Args[1] == "admin-collection-recheck-peer" {
		os.Exit(collectionRecheckPeer(os.Args[2], os.Args[3]))
	}
	if len(os.Args) == 3 && os.Args[1] == "admin-collection-native-denial" {
		os.Exit(collectionNativeDenial(os.Args[2]))
	}
}

func collectionRecheckPeer(mode, directory string) int {
	runtime.LockOSThread()
	if unix.Gettid() != os.Getpid() {
		return 81
	}
	if unix.Mount("", "/", "", unix.MS_REC|unix.MS_PRIVATE, "") != nil {
		return 93
	}
	group, retire := os.NewFile(3, "group-lifetime"), os.NewFile(4, "task-lifetime")
	ready, create := os.NewFile(5, "task-ready"), os.NewFile(6, "replacement-trigger")
	announce := func(tid int) {
		if binary.Write(ready, binary.LittleEndian, uint64(tid)) != nil {
			os.Exit(82)
		}
	}
	finish := func() {
		if _, err := io.Copy(io.Discard, group); err != nil {
			os.Exit(83)
		}
		os.Exit(0)
	}
	if mode == "zombie" {
		// A comm with several ')' characters exercises the stat delimiter.
		if os.WriteFile("/proc/self/comm", []byte("lb ) ) zombie"), 0600) != nil {
			return 84
		}
		started := make(chan struct{})
		go func() {
			runtime.LockOSThread()
			close(started)
			finish()
		}()
		<-started
		announce(os.Getpid())
		if _, err := io.Copy(io.Discard, retire); err != nil {
			return 85
		}
		// Exit only the leader, leaving a companion thread and the group
		// alive. The parent cannot reap this leader while that thread lives.
		unix.Syscall(unix.SYS_EXIT, 0, 0, 0)
		return 86
	}
	if mode != "replacement" && mode != "shared" {
		return 87
	}
	go func() {
		runtime.LockOSThread()
		announce(unix.Gettid())
		if _, err := io.Copy(io.Discard, retire); err != nil {
			os.Exit(88)
		}
		// No UnlockOSThread: returning terminates the actual old task.
	}()
	if _, err := io.Copy(io.Discard, create); err != nil {
		return 89
	}
	go func() {
		runtime.LockOSThread()
		if mode == "replacement" && unix.Unshare(unix.CLONE_NEWNS) != nil {
			os.Exit(90)
		}
		if unix.Mount("", "/", "", unix.MS_REC|unix.MS_PRIVATE, "") != nil {
			os.Exit(90)
		}
		if unix.Mount(filepath.Join(directory, "source"), filepath.Join(directory, "target"), "", unix.MS_BIND, "") != nil {
			os.Exit(91)
		}
		announce(unix.Gettid())
		select {} // This real task alone retains the new mount namespace.
	}()
	finish()
	return 92
}

type collectionRecheckControl struct {
	pid, tid  int
	directory string
	retire    func()
	replace   func() int
}

func collectionRecheckStart(t *testing.T, mode string) collectionRecheckControl {
	t.Helper()
	ctx := collectionCanaryContext(t)
	directory := t.TempDir()
	for _, name := range []string{"source", "target"} {
		if err := os.Mkdir(filepath.Join(directory, name), 0700); err != nil {
			t.Fatal(err)
		}
	}
	pipes := make([]*os.File, 0, 8)
	for pair := 0; pair < 4; pair++ {
		read, write, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		pipes = append(pipes, read, write)
	}
	groupRead, groupWrite, retireRead, retireWrite := pipes[0], pipes[1], pipes[2], pipes[3]
	readyRead, readyWrite, createRead, createWrite := pipes[4], pipes[5], pipes[6], pipes[7]
	command := exec.CommandContext(ctx, "/proc/self/exe", "admin-collection-recheck-peer", mode, directory)
	command.Env = []string{}
	command.ExtraFiles = []*os.File{groupRead, retireRead, readyWrite, createRead}
	command.SysProcAttr = &syscall.SysProcAttr{Cloneflags: unix.CLONE_NEWNS}
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	for _, file := range []*os.File{groupRead, retireRead, readyWrite, createRead} {
		if err := file.Close(); err != nil {
			t.Fatal(err)
		}
	}
	retired, created := false, false
	retire := func() {
		if !retired {
			retired = true
			if err := retireWrite.Close(); err != nil {
				t.Error(err)
			}
		}
	}
	create := func() {
		if !created {
			created = true
			if err := createWrite.Close(); err != nil {
				t.Error(err)
			}
		}
	}
	t.Cleanup(func() {
		retire()
		create()
		if err := groupWrite.Close(); err != nil {
			t.Error(err)
		}
		if err := command.Wait(); err != nil {
			t.Error("native collection peer failed", err)
		}
		if err := readyRead.Close(); err != nil {
			t.Error(err)
		}
	})
	readTID := func() int {
		if err := readyRead.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
			t.Fatal(err)
		}
		var tid uint64
		if err := binary.Read(readyRead, binary.LittleEndian, &tid); err != nil || tid == 0 || uint64(int(tid)) != tid {
			t.Fatal("native task did not announce readiness", err)
		}
		return int(tid)
	}
	pid, tid := command.Process.Pid, readTID()
	if (mode == "zombie") != (tid == pid) {
		t.Fatal("native control did not select the intended task lifetime")
	}
	prefix := filepath.Join("/proc", strconv.Itoa(pid), "task", strconv.Itoa(tid))
	return collectionRecheckControl{pid: pid, tid: tid, directory: directory, retire: func() {
		retire()
		for {
			if mode == "zombie" {
				data, err := os.ReadFile(filepath.Join(prefix, "status"))
				if err != nil {
					t.Fatal("unreaped control lost its task record", err)
				}
				if strings.Contains(string(data), "\nState:\tZ ") {
					return
				}
			} else {
				_, err := os.Stat(prefix)
				if errors.Is(err, os.ErrNotExist) {
					return
				}
				if err != nil {
					t.Fatal(err)
				}
			}
			if ctx.Err() != nil {
				t.Fatal("native task did not complete its controlled exit", ctx.Err())
			}
			runtime.Gosched() // Await a kernel predicate, never an elapsed delay.
		}
	}, replace: func() int {
		create()
		return readTID()
	}}
}

func collectionAssertGroupAlive(t *testing.T, fd int) {
	t.Helper()
	ready := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
	count, err := unix.Poll(ready, 0)
	if err != nil || count != 0 || unix.PidfdSendSignal(fd, 0, nil, 0) != nil {
		t.Fatal("control did not retain its live thread group", err)
	}
}

func TestCollectionNamespaceZombieTask(t *testing.T) {
	for _, denied := range []bool{false, true} {
		t.Run(strconv.FormatBool(denied), func(t *testing.T) {
			ctx := collectionCanaryContext(t)
			peer := collectionRecheckStart(t, "zombie")
			prefix := filepath.Join("/proc", strconv.Itoa(peer.pid), "task", strconv.Itoa(peer.tid))
			if _, err := os.Stat(filepath.Join(prefix, "ns/mnt")); err != nil {
				t.Fatal("leader namespace was not initially live", err)
			}
			fd, err := unix.PidfdOpen(peer.pid, 0)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := unix.Close(fd); err != nil {
					t.Error(err)
				}
			})
			probe := nativeMountNamespaceProbe()
			readStat := probe.stat
			statReads, opens := 0, 0
			var openErr error
			probe.stat = func(name string) ([]byte, error) {
				statReads++
				return readStat(name)
			}
			probe.open = func(name string) (*os.File, error) {
				opens++
				if opens == 1 {
					peer.retire()
				}
				if _, err := os.Stat(prefix); err != nil {
					t.Fatal("zombie task directory disappeared before collection", err)
				}
				collectionAssertGroupAlive(t, fd)
				if denied {
					openErr = &os.PathError{Op: "open", Path: name, Err: unix.EACCES}
					return nil, openErr
				}
				file, err := os.Open(name)
				openErr = err
				return file, err
			}
			namespaces := map[storageInode]*os.File{}
			count, err := scanMountNamespace(ctx, prefix, "unrelated-device", "/unrelated-storage", namespaces, probe)
			if count != 0 || len(namespaces) != 0 || opens == 0 {
				t.Fatal("zombie control retained a namespace instead of observing exit", err)
			}
			collectionAssertGroupAlive(t, fd)
			if denied {
				var typed *api.Error
				if !errors.As(err, &typed) || typed.Code != api.CodeContainmentUnknown || statReads != 0 {
					t.Fatal("zombie state discharged a namespace permission denial", err)
				}
			} else if !errors.Is(openErr, unix.ENOENT) || err != nil || statReads == 0 {
				t.Fatal("unreaped task blocked collection despite actual zombie exit", openErr, err)
			}
		})
	}
}

func TestCollectionNamespaceReplacement(t *testing.T) {
	collectionNamespaceReplacement(t, "replacement", false)
}

func TestCollectionNsReplaceSharedView(t *testing.T) {
	collectionNamespaceReplacement(t, "shared", true)
}

func collectionNamespaceReplacement(t *testing.T, mode string, primed bool) {
	t.Helper()
	ctx := collectionCanaryContext(t)
	peer := collectionRecheckStart(t, mode)
	tasksPath := filepath.Join("/proc", strconv.Itoa(peer.pid), "task")
	prefix := filepath.Join(tasksPath, strconv.Itoa(peer.tid))
	tasks, err := os.ReadDir(tasksPath)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, task := range tasks {
		found = found || task.Name() == strconv.Itoa(peer.tid)
	}
	if !found {
		t.Fatal("old task was missing before the replacement hook")
	}
	source := filepath.Join(peer.directory, "source")
	mounts, err := readMountObservations("/proc/self/mountinfo")
	if err != nil {
		t.Fatal(err)
	}
	var containing mountObservation
	for _, mount := range mounts {
		if beneathPath(source, mount.point) && len(mount.point) > len(containing.point) {
			containing = mount
		}
	}
	if containing.point == "" {
		t.Fatal("replacement source has no observed filesystem")
	}
	physical := filepath.Join(containing.root, strings.TrimPrefix(strings.TrimPrefix(source, containing.point), "/"))
	namespaces := map[storageInode]*os.File{}
	t.Cleanup(func() {
		for _, file := range namespaces {
			if err := file.Close(); err != nil {
				t.Error(err)
			}
		}
	})
	if primed {
		leader := filepath.Join(tasksPath, strconv.Itoa(peer.pid))
		count, err := scanCurrentMountNamespace(ctx, leader, containing.device, physical, namespaces)
		if err != nil || count != 0 || len(namespaces) != 1 {
			t.Fatal("shared view was not actually inventoried before the replacement", count, err)
		}
	}
	probe := nativeMountNamespaceProbe()
	opens, replacement := 0, 0
	probe.open = func(name string) (*os.File, error) {
		opens++
		if opens == 1 {
			peer.retire()
			replacement = peer.replace()
			if replacement == peer.tid || replacement == peer.pid {
				t.Fatal("replacement did not create a distinct native task")
			}
		}
		return os.Open(name)
	}
	count, err := scanMountNamespace(ctx, prefix, containing.device, physical, namespaces, probe)
	if err != nil || count == 0 || replacement == 0 {
		t.Fatal("new task's real mount reference disappeared after the old task exited", count, err)
	}
}

func collectionNativeDenial(selector string) int {
	pid, err := strconv.Atoi(selector)
	if err != nil || pid <= 0 || os.Geteuid() == 0 {
		return 81
	}
	prefix := filepath.Join("/proc", selector, "task", selector)
	file, openErr := os.Open(filepath.Join(prefix, "ns/mnt"))
	if file != nil {
		file.Close()
		return 82
	}
	if !errors.Is(openErr, unix.EACCES) && !errors.Is(openErr, unix.EPERM) {
		return 83
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	namespaces := map[storageInode]*os.File{}
	count, scanErr := scanCurrentMountNamespace(ctx, prefix, "unrelated-device", "/unrelated-storage", namespaces)
	var typed *api.Error
	if count != 0 || len(namespaces) != 0 || !errors.As(scanErr, &typed) || typed.Code != api.CodeContainmentUnknown {
		return 84
	}
	return 0
}

func TestCollectionNamespaceNativeDenial(t *testing.T) {
	ctx := collectionCanaryContext(t)
	command := exec.CommandContext(ctx, "/proc/self/exe", "admin-collection-native-denial", strconv.Itoa(os.Getpid()))
	command.Env = []string{}
	command.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 61003, Gid: 61003}}
	if err := command.Run(); err != nil {
		t.Fatal("live namespace kernel permission denial was not preserved", err)
	}
}
