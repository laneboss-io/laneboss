package caller

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
	"laneboss.io/laneboss/internal/faults"
)

type process struct {
	PID    int    `json:"pid"`
	Start  string `json:"start"`
	PGID   int    `json:"pgid"`
	SID    int    `json:"sid"`
	Parent int    `json:"-"`
	State  string `json:"-"`
}

func processTable() (map[int]process, error) {
	if runtime.GOOS == "linux" && os.Getenv("LANEBOSS_PROCESSES") != "portable" {
		entries, err := os.ReadDir("/proc")
		if err != nil {
			return nil, fmt.Errorf("the caller's process table cannot be read")
		}
		table := map[int]process{}
		for _, entry := range entries {
			pid, err := strconv.Atoi(entry.Name())
			if err != nil {
				continue
			}
			data, err := faults.ProcStat(fmt.Sprintf("/proc/%d/stat", pid))
			if errors.Is(err, fs.ErrNotExist) || errors.Is(err, syscall.ESRCH) {
				continue
			}
			if err != nil {
				return nil, fmt.Errorf("the caller's process table cannot be read")
			}
			p, err := parseProc(pid, data)
			if err != nil {
				return nil, err
			}
			table[pid] = p
		}
		return table, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "ps", "-A", "-o", "pid=", "-o", "ppid=", "-o", "pgid=", "-o", "stat=", "-o", "lstart=")
	cmd.Env = localeEnvironment()
	data, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("the caller's process table cannot be read")
	}
	table := map[int]process{}
	for _, line := range strings.Split(string(data), "\n") {
		parts := strings.Fields(line)
		if len(parts) < 9 {
			continue
		}
		pid, a := strconv.Atoi(parts[0])
		parent, b := strconv.Atoi(parts[1])
		group, c := strconv.Atoi(parts[2])
		if a != nil || b != nil || c != nil {
			return nil, fmt.Errorf("the caller's process table is malformed")
		}
		sid, err := unix.Getsid(pid)
		if err != nil {
			continue
		} // A process can exit after ps took its snapshot.
		table[pid] = process{PID: pid, Parent: parent, PGID: group, SID: sid, State: parts[3], Start: strings.Join(parts[4:], " ")}
	}
	return table, nil
}

func parseProc(pid int, data []byte) (process, error) {
	end := bytes.LastIndexByte(data, ')')
	if end < 0 {
		return process{}, fmt.Errorf("the caller's process stat is malformed")
	}
	parts := strings.Fields(string(data[end+1:]))
	if len(parts) < 20 {
		return process{}, fmt.Errorf("the caller's process stat is incomplete")
	}
	parent, a := strconv.Atoi(parts[1])
	group, b := strconv.Atoi(parts[2])
	sid, c := strconv.Atoi(parts[3])
	if a != nil || b != nil || c != nil {
		return process{}, fmt.Errorf("the caller's process stat is malformed")
	}
	return process{PID: pid, Parent: parent, PGID: group, SID: sid, State: parts[0], Start: parts[19]}, nil
}

func localeEnvironment() []string {
	env := []string{}
	for _, entry := range os.Environ() {
		key, _, _ := strings.Cut(entry, "=")
		if key != "LC_ALL" && key != "LANG" && key != "TZ" {
			env = append(env, entry)
		}
	}
	return append(env, "LC_ALL=C", "LANG=C", "TZ=UTC0")
}

func sameProcess(id process, table map[int]process) bool {
	p, ok := table[id.PID]
	return ok && id.PID > 0 && id.Start != "" && p.Start == id.Start && !strings.HasPrefix(p.State, "Z")
}

func numericStart(start string) bool {
	if start == "" {
		return false
	}
	for _, r := range start {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func ancestor(id process, mine process, table map[int]process) bool {
	if !sameProcess(id, table) {
		return false
	}
	seen := map[int]bool{}
	for p := mine; p.PID > 0 && !seen[p.PID]; p = table[p.Parent] {
		if p.PID == id.PID {
			return true
		}
		seen[p.PID] = true
	}
	return false
}

func laneProcess(id process, mine process, table map[int]process) bool {
	if !sameProcess(id, table) {
		return false
	}
	p := table[id.PID]
	return ancestor(id, mine, table) || p.SID > 0 && mine.SID == p.SID
}

// ProcessAlive checks a recorded PID and start time without accepting PID alone.
func ProcessAlive(identity map[string]any) (bool, error) {
	data, err := json.Marshal(identity)
	if err != nil {
		return false, fmt.Errorf("the process identity is invalid")
	}
	var id process
	if json.Unmarshal(data, &id) != nil || id.PID < 1 || id.Start == "" {
		return false, fmt.Errorf("the process identity is invalid")
	}
	table, err := processTable()
	if err != nil {
		return false, err
	}
	return sameProcess(id, table), nil
}

// ttyName checks the controlling terminal, independently of stdin and of TMUX.
func ttyName() (string, error) {
	f, err := os.OpenFile("/dev/tty", os.O_RDONLY|syscall.O_NOCTTY, 0)
	if errors.Is(err, syscall.ENXIO) || errors.Is(err, syscall.ENODEV) || errors.Is(err, os.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("the caller's controlling terminal cannot be checked")
	}
	f.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "ps", "-p", strconv.Itoa(os.Getpid()), "-o", "tty=")
	cmd.Env = localeEnvironment()
	data, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("the caller's controlling terminal cannot be checked")
	}
	tty := strings.TrimSpace(string(data))
	if tty == "" || tty == "?" || tty == "??" || tty == "-" {
		return "", nil
	}
	return "/dev/" + strings.TrimPrefix(tty, "/dev/"), nil
}
