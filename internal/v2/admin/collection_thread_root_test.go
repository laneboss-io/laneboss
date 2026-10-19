//go:build linux && laneboss_root_canary

package admin

import (
	"encoding/binary"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"laneboss.io/laneboss/internal/v2/api"
)

func init() {
	if len(os.Args) == 2 && os.Args[1] == "admin-collection-thread-peer" {
		os.Exit(collectionThreadPeer())
	}
}

func collectionThreadPeer() int {
	// Reserve the initial thread so the controlled worker is a non-leader.
	runtime.LockOSThread()
	group := os.NewFile(3, "group-lifetime")
	thread := os.NewFile(4, "thread-lifetime")
	ready := os.NewFile(5, "thread-ready")
	go func() {
		runtime.LockOSThread()
		tid := unix.Gettid()
		if tid == os.Getpid() {
			os.Exit(81)
		}
		if err := binary.Write(ready, binary.LittleEndian, uint64(tid)); err != nil || ready.Close() != nil {
			os.Exit(82)
		}
		if _, err := io.Copy(io.Discard, thread); err != nil || thread.Close() != nil {
			os.Exit(83)
		}
		// Returning while locked terminates this native thread. The group
		// remains blocked on its independent lifetime pipe.
	}()
	if _, err := io.Copy(io.Discard, group); err != nil || group.Close() != nil {
		return 84
	}
	return 0
}

func collectionThreadStart(t *testing.T) (int, int, func()) {
	t.Helper()
	ctx := collectionCanaryContext(t)
	groupRead, groupWrite, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer groupRead.Close()
	threadRead, threadWrite, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer threadRead.Close()
	readyRead, readyWrite, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer readyRead.Close()
	defer readyWrite.Close()
	command := exec.CommandContext(ctx, "/proc/self/exe", "admin-collection-thread-peer")
	command.Env = []string{}
	command.ExtraFiles = []*os.File{groupRead, threadRead, readyWrite}
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	closed := false
	exit := func() {
		if !closed {
			closed = true
			if err := threadWrite.Close(); err != nil {
				t.Error(err)
			}
		}
	}
	t.Cleanup(func() {
		exit()
		if err := groupWrite.Close(); err != nil {
			t.Error(err)
		}
		if err := command.Wait(); err != nil {
			t.Error("native thread control failed", err)
		}
	})
	if err := readyWrite.Close(); err != nil {
		t.Fatal(err)
	}
	if err := readyRead.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	var nativeTID uint64
	if err := binary.Read(readyRead, binary.LittleEndian, &nativeTID); err != nil {
		t.Fatal("native thread control did not become ready", err)
	}
	pid, tid := command.Process.Pid, int(nativeTID)
	if tid <= 0 || tid == pid || uint64(tid) != nativeTID {
		t.Fatal("native thread control did not create a non-leader")
	}
	prefix := filepath.Join("/proc", strconv.Itoa(pid), "task", strconv.Itoa(tid))
	return pid, tid, func() {
		exit()
		// Wait for an observed kernel state, never an elapsed delay. A
		// locked goroutine's return precedes the kernel's task removal.
		for {
			_, err := os.Stat(prefix)
			if errors.Is(err, os.ErrNotExist) {
				return
			}
			if err != nil || ctx.Err() != nil {
				t.Fatal("controlled thread did not leave its native task directory", err, ctx.Err())
			}
			runtime.Gosched()
		}
	}
}

func TestCollectionNamespaceThreadExit(t *testing.T) {
	for _, scenario := range []string{"live", "exited", "live-missing", "recovers-on-recheck", "denied-exited", "forbidden-exited"} {
		t.Run(scenario, func(t *testing.T) {
			ctx := collectionCanaryContext(t)
			pid, tid, exit := collectionThreadStart(t)
			tasksPath := filepath.Join("/proc", strconv.Itoa(pid), "task")
			prefix := filepath.Join(tasksPath, strconv.Itoa(tid))
			initial, err := os.ReadDir(tasksPath)
			if err != nil {
				t.Fatal(err)
			}
			found := false
			for _, task := range initial {
				found = found || task.Name() == strconv.Itoa(tid)
			}
			if !found {
				t.Fatal("controlled thread was absent from actual initial enumeration")
			}
			groupFD, err := unix.PidfdOpen(pid, 0)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := unix.Close(groupFD); err != nil {
					t.Error(err)
				}
			})
			probe := nativeMountNamespaceProbe()
			pin, alive, tasks := probe.pin, probe.alive, probe.tasks
			pinned, checked := false, false
			opens, rechecks := 0, 0
			var openErr error
			probe.pin = func(selected int) (int, error) {
				if selected != pid || opens != 0 {
					t.Fatal("namespace control pinned another group or pinned after open")
				}
				fd, err := pin(selected)
				pinned = err == nil
				return fd, err
			}
			probe.alive = func(fd int) error {
				if !pinned || opens == 0 {
					t.Fatal("namespace control probed before its pinned open")
				}
				checked = true
				return alive(fd)
			}
			probe.tasks = func(name string) ([]os.DirEntry, error) {
				if !pinned || opens == 0 || name != tasksPath {
					t.Fatal("task recheck did not enumerate the same pinned group")
				}
				rechecks++
				return tasks(name)
			}
			probe.open = func(name string) (*os.File, error) {
				opens++
				if !pinned || name != filepath.Join(prefix, "ns/mnt") || opens > 3 {
					t.Fatal("namespace open lost its pinned selector or exceeded its bound")
				}
				if opens == 1 && (scenario == "exited" || scenario == "denied-exited" || scenario == "forbidden-exited") {
					exit() // Actual non-leader exit occurs inside the open hook.
				}
				if scenario == "denied-exited" || scenario == "forbidden-exited" {
					errno := unix.EACCES
					if scenario == "forbidden-exited" {
						errno = unix.EPERM
					}
					openErr = &os.PathError{Op: "open", Path: name, Err: errno}
					return nil, openErr
				}
				if scenario == "live-missing" || scenario == "recovers-on-recheck" && opens == 1 {
					name = filepath.Join(filepath.Dir(name), "absent-thread-namespace-control")
				}
				file, err := os.Open(name)
				openErr = err
				return file, err
			}
			namespaces := map[storageInode]*os.File{}
			t.Cleanup(func() {
				for _, file := range namespaces {
					if err := file.Close(); err != nil {
						t.Error(err)
					}
				}
			})
			count, err := scanMountNamespace(ctx, prefix, "unrelated-device", "/unrelated-storage", namespaces, probe)
			if !pinned || !checked || opens == 0 || count != 0 {
				t.Fatal("thread observation lacked its actual pinned namespace proof", err)
			}
			ready := []unix.PollFd{{Fd: int32(groupFD), Events: unix.POLLIN}}
			pollCount, pollErr := unix.Poll(ready, 0)
			if unix.PidfdSendSignal(groupFD, 0, nil, 0) != nil || pollErr != nil || pollCount != 0 {
				t.Fatal("thread control accidentally exited its process group", pollErr)
			}
			switch scenario {
			case "exited":
				if !vanishedReference(openErr) || err != nil || len(namespaces) != 0 || rechecks == 0 {
					t.Fatal("exited non-leader namespace blocked its live group", openErr, err)
				}
			case "live", "recovers-on-recheck":
				if err != nil || openErr != nil || len(namespaces) != 1 || scenario == "recovers-on-recheck" && rechecks == 0 {
					t.Fatal("live namespace was not inventoried after its task recheck", openErr, err)
				}
			default:
				var typed *api.Error
				if !errors.As(err, &typed) || typed.Code != api.CodeContainmentUnknown || len(namespaces) != 0 {
					t.Fatal("present unreadable task or permission error was discharged", openErr, err)
				}
				if scenario == "live-missing" && (rechecks == 0 || opens != 3) {
					t.Fatal("present missing namespace did not exhaust its bounded recheck", opens, rechecks)
				}
				if scenario != "live-missing" && opens != 1 {
					t.Fatal("permission failure was retried instead of refused", opens)
				}
			}
		})
	}
}
