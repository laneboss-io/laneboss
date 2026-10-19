//go:build linux

package admin

import (
	"context"
	"errors"
	"os"
	"runtime"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"laneboss.io/laneboss/internal/v2/api"
)

func TestNativeReleaseSignals(t *testing.T) {
	gate, _, _, _, _, _ := descriptorGate(t)
	connection, _ := nativePair(t)
	peer := nativePeer(t, connection)
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	pid, tid := os.Getpid(), unix.Gettid()
	bursts, finished := make(chan chan error), make(chan struct{})
	go func() {
		defer close(finished)
		for result := range bursts {
			var err error
			for range 8 {
				if err = unix.Tgkill(pid, tid, unix.SIGURG); err != nil {
					break
				}
				runtime.Gosched()
			}
			result <- err
		}
	}()
	defer func() {
		close(bursts)
		<-finished
	}()
	// Keep every native observation assertion under finite signal bursts.
	// An unbounded producer can legitimately exhaust the fail-closed retry
	// budget under package load; TestNativeReleasePoll checks that refusal.
	var burst chan error
	for attempt := range 1000000 {
		if attempt%1000 == 0 {
			burst = make(chan error, 1)
			bursts <- burst
		}
		gate.mu.Lock()
		err := gate.releaseLifetimeLocked()
		gate.mu.Unlock()
		if err != nil {
			t.Fatalf("live gate refused under actual signal delivery after %d checks: %v", attempt, err)
		}
		if err := peer.alive(); err != nil {
			t.Fatalf("live helper peer refused under actual signal delivery after %d checks: %v", attempt, err)
		}
		observation, err := gate.Observe(context.Background(), api.ProcessHandle{})
		if err != nil || observation.State != "running" {
			t.Fatalf("live helper gate observation refused under actual signal delivery after %d checks: %v", attempt, err)
		}
		if attempt%1000 == 999 {
			if err := <-burst; err != nil {
				t.Fatal("targeted signal delivery failed", err)
			}
		}
	}
}

func TestNativeReleasePoll(t *testing.T) {
	for _, mode := range []string{"interrupted", "exited", "exhausted", "invalid"} {
		t.Run(mode, func(t *testing.T) {
			gate, _, _, _, _, _ := descriptorGate(t)
			gate.mu.Lock()
			defer gate.mu.Unlock()
			release, calls := gate.release, 0
			err := gate.releaseLifetimeWithPollLocked(func(fds []unix.PollFd, timeout int) (int, error) {
				calls++
				if len(fds) != 1 || int(fds[0].Fd) != gate.pidfd || fds[0].Events != unix.POLLIN || timeout != 0 {
					t.Fatal("release did not recheck the original native lifetime")
				}
				if mode == "exhausted" {
					return 0, unix.EINTR
				}
				if mode == "invalid" {
					return 0, unix.EBADF
				}
				if calls == 1 {
					if mode == "exited" {
						if err := unix.PidfdSendSignal(gate.pidfd, unix.SIGKILL, nil, 0); err != nil {
							t.Fatal("cannot end the original native process", err)
						}
						deadline := time.Now().Add(3 * time.Second)
						for {
							observed := []unix.PollFd{{Fd: int32(gate.pidfd), Events: unix.POLLIN}}
							n, err := unix.Poll(observed, 10)
							if err == nil && n == 1 && observed[0].Revents&unix.POLLIN != 0 {
								break
							}
							if err != nil && !errors.Is(err, unix.EINTR) || time.Now().After(deadline) {
								t.Fatal("native exit was not observed before retry", err)
							}
						}
					}
					return 0, unix.EINTR
				}
				return unix.Poll(fds, timeout)
			})
			if mode == "interrupted" {
				if err != nil || calls != 2 {
					t.Fatal("acceptance: interrupted release did not complete a fresh live pidfd poll", err)
				}
			} else {
				var typed *api.Error
				if !errors.As(err, &typed) || typed.Code != api.CodeContainmentUnknown {
					t.Fatal("acceptance: incomplete or ended lifetime admitted release", err)
				}
				if mode == "exited" && calls != 2 || mode == "exhausted" && calls != 32 || mode == "invalid" && calls != 1 {
					t.Fatal("acceptance: release retry ignored its errno or finite bound")
				}
			}
			if gate.release != release || gate.released {
				t.Fatal("acceptance: lifetime observation consumed the release pipe")
			}
		})
	}
}
