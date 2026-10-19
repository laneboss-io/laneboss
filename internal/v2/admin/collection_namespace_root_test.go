//go:build linux && laneboss_root_canary

package admin

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"golang.org/x/sys/unix"
	"laneboss.io/laneboss/internal/v2/api"
)

func TestCollectionNamespaceLifetime(t *testing.T) {
	for _, scenario := range []string{"live", "exit-before-open", "zombie-before-open", "missing-while-live", "denied-live", "denied-exited", "forbidden-live", "forbidden-exited"} {
		t.Run(scenario, func(t *testing.T) {
			ctx := collectionCanaryContext(t)
			pid, exit, stop := collectionPeerLifetime(t, "own", nil)
			prefix := filepath.Join("/proc", strconv.Itoa(pid), "task", strconv.Itoa(pid))
			// Enumerate the actual native selector before the controlled exit.
			if _, err := os.Stat(filepath.Join(prefix, "ns/mnt")); err != nil {
				t.Fatal("namespace control was not initially observable", err)
			}
			probe := nativeMountNamespaceProbe()
			pin, alive := probe.pin, probe.alive
			pinned, opened, checked := false, false, false
			pidfd := -1
			exitObserved := false
			var openErr, signalErr error
			probe.pin = func(selected int) (int, error) {
				if selected != pid || opened {
					t.Fatal("namespace process was pinned after opening or used another selector")
				}
				fd, err := pin(selected)
				pinned = err == nil
				pidfd = fd
				return fd, err
			}
			probe.open = func(name string) (*os.File, error) {
				opened = true
				if scenario == "zombie-before-open" {
					if !pinned {
						t.Fatal("exit hook has no held native process lifetime")
					}
					exit()
					ready := []unix.PollFd{{Fd: int32(pidfd), Events: unix.POLLIN}}
					count, err := unix.Poll(ready, 10000)
					if err != nil || count != 1 || ready[0].Revents&unix.POLLIN == 0 {
						t.Fatal("exit hook did not observe actual kernel exit readiness", err)
					}
					exitObserved = true // Wait/reap remains deferred until after observation.
				}
				if scenario == "exit-before-open" || scenario == "denied-exited" || scenario == "forbidden-exited" {
					stop() // The real child exits and is reaped here, without a delay.
				}
				if scenario == "missing-while-live" {
					file, err := os.Open(filepath.Join(filepath.Dir(name), "absent-namespace-control"))
					openErr = err
					return file, err
				}
				if scenario == "denied-live" || scenario == "denied-exited" || scenario == "forbidden-live" || scenario == "forbidden-exited" {
					// Fault the syscall port, not its classification or kernel
					// liveness proof. These are explicit errno controls.
					errno := unix.EACCES
					if scenario == "forbidden-live" || scenario == "forbidden-exited" {
						errno = unix.EPERM
					}
					openErr = &os.PathError{Op: "open", Path: name, Err: errno}
					return nil, openErr
				}
				file, err := os.Open(name)
				openErr = err
				return file, err
			}
			probe.alive = func(fd int) error {
				if !pinned || !opened {
					t.Fatal("namespace liveness was checked without a held process and completed open")
				}
				checked = true
				signalErr = alive(fd)
				return signalErr
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
			if !opened || !pinned || !checked {
				t.Fatal("namespace observation lacked its pinned kernel process proof", err)
			}
			switch scenario {
			case "live":
				if openErr != nil || signalErr != nil || err != nil || count != 0 || len(namespaces) != 1 {
					t.Fatal("live namespace control was not actually inventoried", openErr, signalErr, err)
				}
			case "exit-before-open":
				if !vanishedReference(openErr) || !errors.Is(signalErr, unix.ESRCH) || err != nil || count != 0 || len(namespaces) != 0 {
					t.Fatal("exited namespace was not discharged by exact kernel absence", openErr, signalErr, err)
				}
			case "zombie-before-open":
				if !exitObserved || !vanishedReference(openErr) || signalErr != nil && !errors.Is(signalErr, unix.ESRCH) || err != nil || count != 0 || len(namespaces) != 0 {
					t.Fatal("kernel-exited unreaped namespace was not discharged", openErr, signalErr, err)
				}
			default:
				exited := scenario == "denied-exited" || scenario == "forbidden-exited"
				if exited && !errors.Is(signalErr, unix.ESRCH) || !exited && signalErr != nil {
					t.Fatal("unreadable namespace control did not measure its actual peer lifetime", signalErr)
				}
				var typed *api.Error
				if !errors.As(err, &typed) || typed.Code != api.CodeContainmentUnknown || len(namespaces) != 0 {
					t.Fatal("unreadable namespace or live missing selector was accepted", openErr, signalErr, err)
				}
			}
		})
	}
}
