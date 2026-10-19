//go:build linux

package admin

import (
	"io"
	"os"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

func (g *nativeGate) primaryFactLocked() string {
	if g.state != nil {
		if status, ok := g.state.Sys().(syscall.WaitStatus); ok && (status.Exited() || status.Signaled()) {
			return "waited"
		}
	}
	if g.command == nil || g.command.Process == nil || g.pidfd < 0 {
		return "unavailable"
	}
	fds := []unix.PollFd{{Fd: int32(g.pidfd), Events: unix.POLLIN}}
	count, err := unix.Poll(fds, 0)
	if err != nil {
		return "unavailable"
	}
	if count == 0 && fds[0].Revents == 0 {
		return "live"
	}
	if count == 1 && fds[0].Revents&unix.POLLIN != 0 && fds[0].Revents&^(unix.POLLIN|unix.POLLHUP) == 0 {
		return "exited"
	}
	return "unavailable"
}

func (g *nativeGate) failureFacts() string {
	g.mu.Lock()
	defer g.mu.Unlock()
	primary := g.primaryFactLocked()
	seccomp, nnp := "unavailable", "unavailable"
	spawnSignal, parentDeath := "unavailable", "unavailable"
	if g.command != nil {
		parentDeath = "not_requested"
		for _, argument := range g.command.Args {
			if argument == "--" {
				break
			}
			if argument == "--die-with-parent" {
				parentDeath = "requested"
			}
		}
		if g.command.SysProcAttr != nil {
			switch g.command.SysProcAttr.Pdeathsig {
			case 0:
				spawnSignal = "none"
			case syscall.SIGKILL:
				spawnSignal = "SIGKILL"
			default:
				spawnSignal = "other"
			}
		}
		if primary == "live" && g.command.Process != nil {
			file, err := os.Open("/proc/" + strconv.Itoa(g.command.Process.Pid) + "/status")
			if err == nil {
				data, readErr := io.ReadAll(io.LimitReader(file, 8193))
				closeErr := file.Close()
				if readErr == nil && closeErr == nil && len(data) <= 8192 && g.primaryFactLocked() == "live" {
					seccomp, nnp = nativeProcessSecurity(data)
				}
			}
		}
	}
	return "primary=" + primary + "; spawn_thread=" + g.spawnLifetime.fact() + "; spawn_pdeathsig=" + spawnSignal +
		"; bwrap_die_with_parent=" + parentDeath + "; primary_seccomp=" + seccomp + "; primary_nnp=" + nnp
}

func nativeProcessSecurity(data []byte) (string, string) {
	seccomp, nnp := "unavailable", "unavailable"
	seen := map[string]bool{}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 || fields[0] != "Seccomp:" && fields[0] != "NoNewPrivs:" {
			continue
		}
		if len(fields) != 2 || seen[fields[0]] {
			return "unavailable", "unavailable"
		}
		seen[fields[0]] = true
		if fields[0] == "Seccomp:" {
			switch fields[1] {
			case "0":
				seccomp = "none"
			case "1":
				seccomp = "strict"
			case "2":
				seccomp = "filter"
			}
		} else {
			switch fields[1] {
			case "0":
				nnp = "unset"
			case "1":
				nnp = "set"
			}
		}
	}
	return seccomp, nnp
}

func (g *nativeGate) helperKillFact() string {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.helperKill == "" {
		return "not_requested"
	}
	return g.helperKill
}
