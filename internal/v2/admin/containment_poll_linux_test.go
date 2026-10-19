//go:build linux

package admin

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"laneboss.io/laneboss/internal/v2/api"
)

func init() {
	if len(os.Args) != 2 || os.Args[1] != "containment-poll-peer" {
		return
	}
	ready := os.NewFile(3, "containment-ready")
	if n, err := ready.Write([]byte{1}); err != nil || n != 1 {
		os.Exit(81)
	}
	if err := ready.Close(); err != nil {
		os.Exit(82)
	}
	var value [1]byte
	if n, err := os.Stdin.Read(value[:]); n != 0 || !errors.Is(err, io.EOF) {
		os.Exit(83)
	}
	os.Exit(0)
}

// Only signal interruption is injected. Credentials, cgroup, generation and
// final live/exit observations come from a real child and the actual pidfd.
func TestContainmentPollLifetime(t *testing.T) {
	for _, mode := range []string{"interrupted-live", "interrupted-exit", "bounded-interruption"} {
		t.Run(mode, func(t *testing.T) {
			readyRead, readyWrite, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer readyRead.Close()
			defer readyWrite.Close()
			releaseRead, releaseWrite, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer releaseRead.Close()
			defer releaseWrite.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			command := exec.CommandContext(ctx, "/proc/self/exe", "containment-poll-peer")
			command.Env, command.Stdin, command.ExtraFiles = []string{}, releaseRead, []*os.File{readyWrite}
			if err := command.Start(); err != nil {
				t.Fatal(err)
			}
			waited := false
			t.Cleanup(func() {
				if !waited {
					cancel()
					if err := command.Wait(); err != nil && !t.Failed() {
						t.Error(err)
					}
				}
			})
			if err := readyWrite.Close(); err != nil {
				t.Fatal(err)
			}
			if err := readyRead.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
				t.Fatal(err)
			}
			var ready [1]byte
			if _, err := io.ReadFull(readyRead, ready[:]); err != nil || ready[0] != 1 {
				t.Fatal("containment peer did not reach its held lifetime", err)
			}
			boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
			if err != nil {
				t.Fatal(err)
			}
			bootID := strings.TrimSpace(string(boot))
			generation, err := processGeneration(command.Process.Pid, bootID)
			if err != nil {
				t.Fatal(err)
			}
			membership, err := cgroupMembership(command.Process.Pid)
			if err != nil {
				t.Fatal(err)
			}
			facts := api.PeerFacts{HostUID: uint32(os.Getuid()), HostGID: uint32(os.Getgid()), HostPID: command.Process.Pid, ProcessGeneration: generation}
			calls, released := 0, false
			poll := func(fds []unix.PollFd, timeout int) (int, error) {
				calls++
				if len(fds) != 1 || fds[0].Events != unix.POLLIN || timeout != 0 {
					t.Fatal("containment poll lost its original lifetime selector")
				}
				if calls == 1 || mode == "bounded-interruption" {
					return -1, unix.EINTR
				}
				if mode == "interrupted-exit" {
					if err := releaseWrite.Close(); err != nil {
						t.Fatal(err)
					}
					released = true
					count, err := unix.Poll(fds, 2000)
					if err != nil || count != 1 || fds[0].Revents&unix.POLLIN == 0 {
						t.Fatal("the original pidfd did not measure the peer's actual exit", err)
					}
					return count, err
				}
				return unix.Poll(fds, timeout)
			}
			err = verifyContainedProcessWithPoll(ctx, facts, bootID, membership, poll)
			if mode == "interrupted-live" {
				if err != nil || calls != 2 {
					t.Fatal("a signal interruption falsely ended the actual live containment peer", calls, err)
				}
			} else {
				requireCode(t, err, api.CodeUnauthenticated)
				want := 2
				if mode == "bounded-interruption" {
					want = 32
				}
				if calls != want {
					t.Fatal("containment liveness did not enforce its bounded native observation", calls)
				}
			}
			if !released {
				if err := releaseWrite.Close(); err != nil {
					t.Fatal(err)
				}
			}
			waitErr := command.Wait()
			waited = true
			if waitErr != nil {
				t.Fatal("containment peer did not finish its measured lifetime", waitErr)
			}
		})
	}
}
