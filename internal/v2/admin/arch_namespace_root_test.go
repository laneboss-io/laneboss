//go:build linux && laneboss_root_canary

package admin

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
	"laneboss.io/laneboss/internal/v2/api"
)

// Count actual namespace opens for one pinned task. The probe delegates every
// syscall to the native implementation; it changes no observation or verdict.
func TestArchiveFenceOnce(t *testing.T) {
	ctx := collectionCanaryContext(t)
	m, record, _ := collectionLeaseFixture(t, true)
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	name := filepath.Join("/proc", strconv.Itoa(os.Getpid()), "task", strconv.Itoa(unix.Gettid()), "ns/mnt")
	probe := nativeMountNamespaceProbe()
	open := probe.open
	opens := 0
	probe.open = func(path string) (*os.File, error) {
		if path == name {
			opens++
		}
		return open(path)
	}
	ctx = context.WithValue(ctx, mountNamespaceProbeKey{}, probe)
	if err := m.archiveReferenceFence(ctx, record, nil); err != nil {
		t.Fatal("native archive reference control failed", err)
	}
	if opens != 1 {
		t.Fatalf("one archive fence opened the same live task namespace %d times; want 1", opens)
	}
	// Each root must participate even when no descriptor/inode inventory can
	// reveal the export. The foreign peer closes its source FD after attaching
	// a real detached mount; its mount namespace alone retains the root.
	roots, err := m.archiveRoots(record)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"workspace", "home", "history"} {
		root, err := archiveRoot(roots[name])
		if err != nil {
			t.Fatal(err)
		}
		_, stop := collectionPeerStart(t, "mount", root)
		if err := root.Close(); err != nil {
			t.Fatal(err)
		}
		err = m.archiveReferenceFence(ctx, record, nil)
		var typed *api.Error
		if !errors.As(err, &typed) || typed.Code != CodeArchiveLiveWriter {
			t.Fatal("batched archive fence omitted a retained root's native mount", name, err)
		}
		stop()
		if err := m.archiveReferenceFence(ctx, record, nil); err != nil {
			t.Fatal("archive fence did not clear after native export collection", name, err)
		}
	}
}

// Exercise the actual reference fence shared by freeze, freeze read-back and
// archive worker-parent validation. Only the selected syscall observations are
// faulted; roots, procfs, process pinning and the live companion are native.
func TestArchiveNamespaceExitWindow(t *testing.T) {
	for _, scenario := range []string{"exiting-R", "exiting-D", "live-R", "live-Z", "denied-exiting", "forbidden-exiting"} {
		t.Run(scenario, func(t *testing.T) {
			ctx := collectionCanaryContext(t)
			m, record, _ := collectionLeaseFixture(t, true)
			peer := collectionRecheckStart(t, "zombie")
			prefix := filepath.Join("/proc", strconv.Itoa(peer.pid), "task", strconv.Itoa(peer.tid))
			group, err := unix.PidfdOpen(peer.pid, 0)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := unix.Close(group); err != nil {
					t.Error(err)
				}
			})
			if err := m.archiveReferenceFence(ctx, record, nil); err != nil {
				t.Fatal("live archive control did not establish its native fence", err)
			}
			probe := nativeMountNamespaceProbe()
			open, stat, tasks := probe.open, probe.stat, probe.tasks
			opens, states, fresh := 0, 0, 0
			exiting := !strings.HasPrefix(scenario, "live-")
			errno := unix.ENOENT
			if scenario == "denied-exiting" {
				errno = unix.EACCES
			} else if scenario == "forbidden-exiting" {
				errno = unix.EPERM
			}
			probe.open = func(name string) (*os.File, error) {
				if name != filepath.Join(prefix, "ns/mnt") {
					return open(name)
				}
				opens++
				if opens == 1 && exiting {
					peer.retire()
				}
				collectionAssertGroupAlive(t, group)
				if errno != unix.ENOENT {
					return nil, &os.PathError{Op: "open", Path: name, Err: errno}
				}
				if !exiting {
					name = filepath.Join(prefix, "ns/absent-archive-control")
				}
				file, err := open(name)
				if !errors.Is(err, unix.ENOENT) {
					t.Fatal("exit-window control did not observe native namespace absence", err)
				}
				return file, err
			}
			probe.stat = func(name string) ([]byte, error) {
				data, err := stat(name)
				if name != filepath.Join(prefix, "stat") || err != nil {
					return data, err
				}
				states++
				close := strings.LastIndexByte(string(data), ')')
				if close < 0 {
					t.Fatal("native task stat has no comm delimiter")
				}
				fields := strings.Fields(string(data[close+1:]))
				if len(fields) < 20 {
					t.Fatal("native task stat is incomplete")
				}
				flags, err := strconv.ParseUint(fields[6], 10, 64)
				if err != nil || (flags&0x00000004 != 0) != exiting {
					t.Fatal("control lacks the actual kernel PF_EXITING evidence", err)
				}
				// Preserve the kernel's flags and every identity field. Fault only
				// the state letter to expose do_exit's earlier R/D window, and
				// separately prove that a Z letter without exit evidence refuses.
				fields[0] = strings.TrimPrefix(scenario, "exiting-")
				if scenario == "live-R" {
					fields[0] = "R"
				} else if scenario == "live-Z" {
					fields[0] = "Z"
				}
				return []byte(string(data[:close+1]) + " " + strings.Join(fields, " ") + "\n"), nil
			}
			probe.tasks = func(name string) ([]os.DirEntry, error) {
				if name == filepath.Dir(prefix) && states > 0 {
					fresh++
				}
				return tasks(name)
			}
			ctx = context.WithValue(ctx, mountNamespaceProbeKey{}, probe)
			err = m.archiveReferenceFence(ctx, record, nil)
			if opens == 0 {
				t.Fatal("archive path bypassed the controlled shared namespace scanner", err)
			}
			collectionAssertGroupAlive(t, group)
			if scenario == "exiting-R" || scenario == "exiting-D" {
				if err != nil || states == 0 || fresh < 2 {
					t.Fatal("archive rejected a proven exiting task or omitted the fresh full group scan", err, states, fresh)
				}
				return
			}
			var typed *api.Error
			if !errors.As(err, &typed) || typed.Code != api.CodeContainmentUnknown || !errors.Is(err, errno) {
				t.Fatal("archive accepted an unreadable live task or permission denial", err)
			}
			if errno != unix.ENOENT && states != 0 {
				t.Fatal("archive used task exit metadata to discharge a permission denial")
			}
		})
	}
}
