// Package cosprocess stops an interactive request and its descendant groups.
package cosprocess

import (
	"context"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

var DefaultWaits = []time.Duration{6 * time.Second, 4 * time.Second, 2 * time.Second}
var DefaultPS = []string{"/bin/ps", "/usr/bin/ps"}

func Gone(pid int) bool { return syscall.Kill(-pid, 0) == syscall.ESRCH }
func positive(s string) (int, bool) {
	if s == "" || len(s) > 10 {
		return 0, false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return 0, false
		}
	}
	n, e := strconv.ParseInt(s, 10, 32)
	return int(n), e == nil && n > 0
}
func family(pid int, paths []string) []int {
	program := ""
	for _, path := range paths {
		if info, e := os.Stat(path); e == nil && info.Mode().IsRegular() && info.Mode().Perm()&0111 != 0 {
			program = path
			break
		}
	}
	if program == "" {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, program, "-axo", "pid=,ppid=,pgid=")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	out, e := cmd.Output()
	if e != nil {
		return nil
	}
	type row struct{ pid, parent, group int }
	rows := []row{}
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 3 {
			continue
		}
		p, a := positive(fields[0])
		parent, b := positive(fields[1])
		group, c := positive(fields[2])
		if a && b && c {
			rows = append(rows, row{p, parent, group})
		}
	}
	if len(rows) == 0 {
		return nil
	}
	children := map[int][]row{}
	todo := []int{pid}
	seen := map[int]bool{pid: true}
	for _, r := range rows {
		children[r.parent] = append(children[r.parent], r)
		if r.group == pid && !seen[r.pid] {
			todo = append(todo, r.pid)
			seen[r.pid] = true
		}
	}
	leaders := map[int]bool{}
	for len(todo) > 0 {
		p := todo[len(todo)-1]
		todo = todo[:len(todo)-1]
		for _, r := range children[p] {
			if seen[r.pid] {
				continue
			}
			seen[r.pid] = true
			todo = append(todo, r.pid)
			if r.group == r.pid && r.group > 1 && r.group != pid && r.group != syscall.Getpgrp() {
				leaders[r.group] = true
			}
		}
	}
	groups := []int{}
	for group := range leaders {
		groups = append(groups, group)
	}
	sort.Ints(groups)
	return groups
}
func alive(pid int, groups []int) []int {
	left := []int{}
	if !Gone(pid) {
		left = append(left, pid)
	}
	for _, group := range groups {
		if !Gone(group) {
			left = append(left, group)
		}
	}
	return left
}

// Stop escalates SIGINT, SIGTERM and SIGKILL. The caller reaps its child while
// this function waits; notify receives a failed ancestry-listing message.
// A terminal signal is returned after cleanup; Ctrl-C advances to the next step.
func Stop(pid int, waits []time.Duration, paths []string, notify func(string), signals <-chan os.Signal) ([]int, int) {
	if pid <= 1 || pid == syscall.Getpgrp() {
		return []int{pid}, 0
	}
	if len(waits) != 3 {
		waits = DefaultWaits
	}
	groups := []int{}
	exit := 0
	wait := func(duration time.Duration, interrupt bool) {
		timer := time.NewTimer(duration)
		defer timer.Stop()
		tick := time.NewTicker(50 * time.Millisecond)
		defer tick.Stop()
		for len(alive(pid, groups)) > 0 {
			select {
			case <-timer.C:
				return
			case <-tick.C:
			case sig := <-signals:
				if sig == syscall.SIGINT && interrupt {
					return
				}
				if sig == syscall.SIGHUP || sig == syscall.SIGTERM {
					exit = 128 + int(sig.(syscall.Signal))
				}
			}
		}
	}
	for index, sig := range []syscall.Signal{syscall.SIGINT, syscall.SIGTERM, syscall.SIGKILL} {
		if sig == syscall.SIGKILL {
			groups = family(pid, paths)
			if groups == nil {
				groups = []int{}
				if notify != nil {
					notify("[could not list the request's processes: some of its tools may still run]")
				}
			}
		}
		targets := []int{pid}
		if sig == syscall.SIGKILL {
			targets = append(targets, groups...)
		}
		for _, group := range targets {
			syscall.Kill(-group, sig)
		}
		wait(waits[index], true)
		if len(alive(pid, groups)) == 0 {
			break
		}
	}
	wait(500*time.Millisecond, false)
	return alive(pid, groups), exit
}
