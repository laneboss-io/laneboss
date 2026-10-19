package linux

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
	"laneboss.io/laneboss/internal/v2/api"
)

func TestLiveInterrupted(t *testing.T) {
	fd, err := unix.PidfdOpen(os.Getpid(), 0)
	if err != nil {
		t.Fatal("native live pidfd fixture unavailable")
	}
	defer unix.Close(fd)
	for _, operation := range []string{"signal", "poll"} {
		t.Run(operation, func(t *testing.T) {
			signals, polls := 0, 0
			err := liveFDWithCalls(fd, func(actual int, signal unix.Signal, info *unix.Siginfo, flags int) error {
				signals++
				if actual != fd || signal != 0 || info != nil || flags != 0 {
					t.Fatal("liveness signal arguments changed")
				}
				if operation == "signal" && signals == 1 {
					return unix.EINTR
				}
				return unix.PidfdSendSignal(actual, signal, info, flags)
			}, func(fds []unix.PollFd, timeout int) (int, error) {
				polls++
				if len(fds) != 1 || int(fds[0].Fd) != fd || fds[0].Events != unix.POLLIN || timeout != 0 {
					t.Fatal("liveness poll arguments changed")
				}
				if operation == "poll" && polls == 1 {
					return 0, unix.EINTR
				}
				return unix.Poll(fds, timeout)
			})
			if err != nil || operation == "signal" && signals != 2 || operation == "poll" && polls != 2 || polls == 0 {
				t.Fatal("acceptance: interrupted liveness failed to complete the real kernel checks")
			}
		})
	}
}

func TestLiveInterruptedRefusals(t *testing.T) {
	fd, err := unix.PidfdOpen(os.Getpid(), 0)
	if err != nil {
		t.Fatal("native live pidfd fixture unavailable")
	}
	defer unix.Close(fd)
	for _, cause := range []error{unix.EINTR, unix.EINVAL} {
		polls := 0
		err := liveFDWithCalls(fd, unix.PidfdSendSignal, func([]unix.PollFd, int) (int, error) {
			polls++
			return 0, cause
		})
		var typed *api.Error
		if !errors.As(err, &typed) || typed.Code != api.CodeUnauthenticated || cause == unix.EINTR && polls != 4 || cause != unix.EINTR && polls != 1 {
			t.Fatal("acceptance: incomplete liveness observation was admitted or retried without a bound")
		}
		if !strings.Contains(typed.Message, "poll=") {
			t.Fatal("acceptance: liveness refusal lost its deciding syscall")
		}
	}
}

func TestLiveExitDuringRetry(t *testing.T) {
	f := startNativeFixture(t, "ordinary")
	calls := 0
	err := liveFDWithCalls(f.peer.fd, unix.PidfdSendSignal, func(fds []unix.PollFd, timeout int) (int, error) {
		calls++
		if calls == 1 {
			f.end(t)
			return 0, unix.EINTR
		}
		return unix.Poll(fds, timeout)
	})
	var typed *api.Error
	if !errors.As(err, &typed) || typed.Code != api.CodeUnauthenticated || calls != 2 {
		t.Fatal("acceptance: interrupted retry admitted the actually ended child")
	}
	if f.peer.Alive(context.Background()) == nil {
		t.Fatal("acceptance: native peer accepted an actually ended process")
	}
}
