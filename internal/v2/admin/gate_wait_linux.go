//go:build linux

package admin

import (
	"errors"
	"time"

	"golang.org/x/sys/unix"
	"laneboss.io/laneboss/internal/v2/api"
)

const nativeStderrDrainWindow = time.Second

func (g *nativeGate) startWaitOwner() error {
	if err := g.watchPrimaryExit(); err != nil {
		return err
	}
	go func() {
		err := g.command.Wait()
		g.spawnLifetime.observedWait(g.command.ProcessState)
		if closeErr := g.stderr.close(); closeErr != nil {
			// Keep the actual ProcessState without allowing an ExitError to
			// disguise a descriptor-collection failure as a completed wait.
			err = failure(api.CodeContainmentUnknown, "cannot close drained stderr capture owner")
		}
		if g.workerJournal != nil {
			if journalErr := writeWorkerExit(g.workerJournal, g.command.ProcessState, g.stderr); journalErr != nil {
				err = failure(api.CodeContainmentUnknown, "cannot journal native worker exit")
			}
		}
		g.mu.Lock()
		g.waitErr, g.state, g.waitFinishedAt = err, g.command.ProcessState, time.Now()
		if g.wall != nil {
			g.wall.Stop()
		}
		if closeErr := unix.Close(g.pidfd); closeErr != nil {
			g.waitErr = failure(api.CodeContainmentUnknown, "cannot close ended process lifetime descriptor")
		}
		g.pidfd = -1
		if g.innerFD >= 0 {
			if closeErr := unix.Close(g.innerFD); closeErr != nil {
				g.waitErr = failure(api.CodeContainmentUnknown, "cannot close ended bootstrap lifetime descriptor")
			}
			g.innerFD = -1
		}
		close(g.done)
		g.mu.Unlock()
	}()
	return nil
}

// Observe the actual primary pidfd independently of exec.Cmd.Wait's stderr
// copier. The private duplicate cannot be reused when the wait owner closes
// its descriptor. Neither this watcher nor its deadline closes a capture pipe.
func (g *nativeGate) watchPrimaryExit() error {
	fd, err := unix.FcntlInt(uintptr(g.pidfd), unix.F_DUPFD_CLOEXEC, 3)
	if err != nil {
		return failure(api.CodeContainmentUnknown, "cannot retain primary exit observation")
	}
	g.primaryDone, g.drainBound = make(chan struct{}), make(chan struct{})
	go func() {
		fds := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
		var observed bool
		var observationErr error
		for {
			count, err := unix.Poll(fds, -1)
			if errors.Is(err, unix.EINTR) {
				continue
			}
			if err != nil || count != 1 || fds[0].Revents&unix.POLLIN == 0 || fds[0].Revents&^(unix.POLLIN|unix.POLLHUP) != 0 {
				observationErr = failure(api.CodeContainmentUnknown, "native primary pidfd observation failed")
			} else {
				observed = true
			}
			break
		}
		if err := unix.Close(fd); err != nil {
			observationErr = failure(api.CodeContainmentUnknown, "cannot close primary exit observation")
		}
		if observed {
			g.spawnLifetime.observedExit()
		}
		g.mu.Lock()
		g.primaryExited, g.primaryExitAt, g.primaryErr = observed, time.Now(), observationErr
		close(g.primaryDone)
		g.mu.Unlock()
		if observationErr == nil {
			timer := time.NewTimer(nativeStderrDrainWindow)
			defer timer.Stop()
			select {
			case <-g.done:
			case <-timer.C:
			}
		}
		g.mu.Lock()
		if err := g.drainErrorLocked(); err != nil {
			g.primaryErr = err
		}
		close(g.drainBound)
		g.mu.Unlock()
	}()
	return nil
}

// The deadline bounds acceptance/Stop, not byte retention. If a descendant
// retains stderr, report uncertainty and keep the lease, copier and capture.
// The copier can still forward every successful write through eventual EOF.
// A late EOF cannot erase a previously expired collection window.
func (g *nativeGate) drainErrorLocked() error {
	if g.primaryErr != nil {
		return g.primaryErr
	}
	if g.primaryExited {
		deadline := g.primaryExitAt.Add(nativeStderrDrainWindow)
		if !time.Now().Before(deadline) && (g.waitFinishedAt.IsZero() || g.waitFinishedAt.After(deadline)) {
			g.drainExpired = true
		}
	}
	if g.drainExpired {
		return failure(api.CodeContainmentUnknown, "native primary exited but stderr drain exceeded its bound; retain capture and lease")
	}
	return nil
}
