package laneturns

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type processEntry struct {
	pid, ppid, pgid, sid int
	start, state         string
}

func nativeProcesses() bool {
	return runtime.GOOS == "linux" && os.Getenv("LANEBOSS_PROCESSES") != "portable"
}
func procEntry(pid int) (*processEntry, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if os.IsNotExist(err) || err == syscall.ESRCH {
		return nil, nil
	}
	if err != nil {
		return nil, refused("the process table cannot be read: a process stat file is unreadable")
	}
	end := bytes.LastIndexByte(data, ')')
	if end < 0 {
		return nil, refused("the process table cannot be read: a process stat file is malformed")
	}
	parts := strings.Fields(string(data[end+1:]))
	if len(parts) < 20 {
		return nil, refused("the process table cannot be read: a process stat file is incomplete")
	}
	ppid, err := strconv.Atoi(parts[1])
	if err != nil {
		return nil, err
	}
	pgid, err := strconv.Atoi(parts[2])
	if err != nil {
		return nil, err
	}
	sid, err := strconv.Atoi(parts[3])
	if err != nil {
		return nil, err
	}
	return &processEntry{pid, ppid, pgid, sid, parts[19], parts[0]}, nil
}
func portableTable(pid int) (map[int]processEntry, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	args := []string{"-A", "-o", "pid=", "-o", "ppid=", "-o", "pgid=", "-o", "stat=", "-o", "lstart="}
	if pid > 0 {
		args = append(args[1:], "-p", strconv.Itoa(pid))
	}
	cmd := exec.CommandContext(ctx, "ps", args...)
	env := []string{}
	for _, entry := range os.Environ() {
		key, _, _ := strings.Cut(entry, "=")
		if key != "LC_ALL" && key != "LANG" && key != "TZ" {
			env = append(env, entry)
		}
	}
	cmd.Env = append(env, "LC_ALL=C", "LANG=C", "TZ=UTC0")
	var out, errOut bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errOut
	err := cmd.Run()
	found := map[int]processEntry{}
	if err != nil {
		var exit *exec.ExitError
		if pid > 0 && out.Len() == 0 && errOut.Len() == 0 && errorsAsExit(err, &exit) && exit.ExitCode() == 1 {
			return found, nil
		}
		return nil, refused("the process table cannot be read: ps could not be run or did not answer")
	}
	for _, line := range strings.Split(out.String(), "\n") {
		parts := strings.Fields(line)
		if len(parts) < 9 {
			continue
		}
		id, e := strconv.Atoi(parts[0])
		ppid, f := strconv.Atoi(parts[1])
		pgid, g := strconv.Atoi(parts[2])
		if e != nil || f != nil || g != nil {
			continue
		}
		found[id] = processEntry{id, ppid, pgid, 0, strings.Join(parts[4:], " "), parts[3]}
	}
	if len(found) == 0 {
		return nil, refused("the process table cannot be read: ps printed no process")
	}
	return found, nil
}
func errorsAsExit(err error, out **exec.ExitError) bool {
	v, ok := err.(*exec.ExitError)
	if ok {
		*out = v
	}
	return ok
}
func processTable() (map[int]processEntry, error) {
	if !nativeProcesses() {
		return portableTable(0)
	}
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, refused("the process table cannot be read: /proc is unreadable")
	}
	found := map[int]processEntry{}
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}
		info, err := procEntry(pid)
		if err != nil {
			return nil, err
		}
		if info != nil {
			found[pid] = *info
		}
	}
	if len(found) == 0 {
		return nil, refused("the process table cannot be read: /proc shows no process")
	}
	return found, nil
}
func processInfo(pid int) (*processEntry, error) {
	if nativeProcesses() {
		return procEntry(pid)
	}
	table, err := portableTable(pid)
	if err != nil {
		return nil, err
	}
	entry, ok := table[pid]
	if !ok {
		return nil, nil
	}
	return &entry, nil
}
func identityOf(entry processEntry) object {
	sid := any(nil)
	if entry.sid > 0 {
		sid = entry.sid
	}
	return object{"pid": entry.pid, "start": entry.start, "pgid": entry.pgid, "sid": sid}
}
func processIdentity(pid int) (object, error) {
	entry, err := processInfo(pid)
	if err != nil || entry == nil {
		return nil, err
	}
	if strings.HasPrefix(entry.state, "Z") {
		return nil, nil
	}
	return identityOf(*entry), nil
}
func validIdentity(v object) bool {
	return v != nil && boundedInteger(v["pid"], 1, 2147483647) && str(v["start"]) != ""
}
func sameProcess(entry *processEntry, identity object) (bool, error) {
	if entry == nil || !validIdentity(identity) || entry.pid != integer(identity["pid"]) {
		return false, nil
	}
	digits := func(s string) bool {
		if s == "" {
			return false
		}
		for _, r := range s {
			if r < '0' || r > '9' {
				return false
			}
		}
		return true
	}
	if digits(entry.start) != digits(str(identity["start"])) {
		return false, refused("a process identity was recorded with another LANEBOSS_PROCESSES setting; use the same setting for every command of a configuration")
	}
	return entry.start == str(identity["start"]), nil
}
func entryMatches(entry *processEntry, identity object) (bool, error) {
	if entry != nil && strings.HasPrefix(entry.state, "Z") {
		return false, nil
	}
	return sameProcess(entry, identity)
}

// An uncollected child may be a zombie. Its PID and start time must still
// match before its state or process group can be used by the supervisor.
func checkRunnerEntry(entry *processEntry, identity object) error {
	yes, err := sameProcess(entry, identity)
	if err != nil {
		return err
	}
	if !yes {
		return refused("the runner's PID and start time no longer match its recorded identity; the mismatched process is refused")
	}
	return nil
}
func observeRunner(identity object) (*processEntry, error) {
	if !validIdentity(identity) {
		return nil, refused("the runner has no recorded PID and start time")
	}
	entry, err := processInfo(integer(identity["pid"]))
	if err != nil {
		return nil, err
	}
	if err = checkRunnerEntry(entry, identity); err != nil {
		return nil, err
	}
	return entry, nil
}
func processAlive(identity object) (bool, error) {
	if !validIdentity(identity) {
		return false, nil
	}
	entry, err := processInfo(integer(identity["pid"]))
	if err != nil {
		return false, err
	}
	return entryMatches(entry, identity)
}
func living(identities []object, table map[int]processEntry) ([]object, error) {
	var err error
	if table == nil {
		table, err = processTable()
		if err != nil {
			return nil, err
		}
	}
	found := []object{}
	for _, id := range identities {
		entry, ok := table[integer(id["pid"])]
		var ptr *processEntry
		if ok {
			ptr = &entry
		}
		yes, err := entryMatches(ptr, id)
		if err != nil {
			return nil, err
		}
		if yes {
			found = append(found, id)
		}
	}
	return found, nil
}
func signalChecked(identity object, signal syscall.Signal) (bool, error) {
	if !validIdentity(identity) {
		return false, nil
	}
	if nativeProcesses() {
		handled, sent, err := nativeSignal(identity, signal)
		if handled {
			return sent, err
		}
	}
	alive, err := processAlive(identity)
	if err != nil || !alive {
		return false, err
	}
	err = syscall.Kill(integer(identity["pid"]), signal)
	if err == syscall.ESRCH {
		return false, nil
	}
	if err != nil {
		return false, refused("the recorded process could not be signalled")
	}
	return true, nil
}
func recordMembers(record object) []object {
	found := []object{}
	root := obj(record["runner"])
	if validIdentity(root) {
		found = append(found, root)
	}
	for _, entry := range array(record["processes"]) {
		v := obj(entry)
		if validIdentity(v) {
			mergeIdentities(&found, []object{v})
		}
	}
	return found
}
func mergeIdentities(known *[]object, found []object) bool {
	changed := false
	for _, id := range found {
		exists := false
		for _, old := range *known {
			if integer(old["pid"]) == integer(id["pid"]) && old["start"] == id["start"] {
				exists = true
				break
			}
		}
		if !exists {
			*known = append(*known, id)
			changed = true
		}
	}
	return changed
}
func discoverProcesses(roots []object, group int, adopted bool, excluded ...int) ([]object, error) {
	table, err := processTable()
	if err != nil {
		return nil, err
	}
	active, err := living(roots, table)
	if err != nil {
		return nil, err
	}
	ids := map[int]bool{}
	for _, root := range active {
		ids[integer(root["pid"])] = true
	}
	// An uncollected zombie still owns its PID. Use it as an ancestor while
	// walking the same snapshot, while excluding it from signals and survivors.
	for _, root := range roots {
		entry, ok := table[integer(root["pid"])]
		if ok && entry.start == str(root["start"]) {
			ids[entry.pid] = true
		}
	}
	if adopted {
		ids[os.Getpid()] = true
	}
	groupKnown := false
	for _, root := range roots {
		entry, ok := table[integer(root["pid"])]
		if ok && entry.start == str(root["start"]) && entry.pgid == group {
			groupKnown = true
		}
	}
	found := map[int]processEntry{}
	changed := true
	for changed {
		changed = false
		for pid, entry := range table {
			if pid == os.Getpid() {
				continue
			}
			blocked := false
			for _, skip := range excluded {
				if pid == skip {
					blocked = true
				}
			}
			if blocked {
				continue
			}
			if ids[entry.ppid] || ids[pid] || groupKnown && (entry.pgid == group || entry.sid == group) {
				if !ids[pid] {
					ids[pid] = true
					changed = true
				}
				if !strings.HasPrefix(entry.state, "Z") {
					found[pid] = entry
				}
			}
		}
	}
	pids := []int{}
	for pid := range found {
		pids = append(pids, pid)
	}
	sort.Ints(pids)
	result := []object{}
	for _, pid := range pids {
		result = append(result, identityOf(found[pid]))
	}
	if adopted {
		reapOrphans(table, group, excluded...)
	}
	return result, nil
}
func stopIdentities(known *[]object, grace float64, discover func() ([]object, error)) (int, []object, error) {
	sent := map[string]bool{}
	removed := 0
	deadline := time.Now().Add(time.Duration(grace * float64(time.Second)))
	killDeadline := deadline.Add(5 * time.Second)
	for {
		if discover != nil {
			found, err := discover()
			if err != nil {
				return removed, nil, err
			}
			mergeIdentities(known, found)
		}
		alive, err := living(*known, nil)
		if err != nil {
			return removed, nil, err
		}
		if len(alive) == 0 {
			for _, id := range *known {
				if sent[fmt.Sprintf("%d/%s", integer(id["pid"]), str(id["start"]))] {
					removed++
				}
			}
			return removed, alive, nil
		}
		if time.Now().After(killDeadline) {
			return removed, alive, nil
		}
		signal := syscall.SIGTERM
		if !time.Now().Before(deadline) {
			signal = syscall.SIGKILL
		}
		for i := len(alive) - 1; i >= 0; i-- {
			id := alive[i]
			key := fmt.Sprintf("%d/%s", integer(id["pid"]), str(id["start"]))
			if signal == syscall.SIGTERM && sent[key] {
				continue
			}
			yes, err := signalChecked(id, signal)
			if err != nil {
				return removed, nil, err
			}
			if yes {
				sent[key] = true
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
}
func refuseLive(s *laneSession, lane string) error {
	previous, err := s.latest(lane)
	if err != nil {
		return err
	}
	if previous != nil && previous["run"] != nil {
		record, err := s.record(lane, str(previous["launch"]))
		if err != nil {
			return err
		}
		if record == nil {
			ended, err := s.store.last(lane, "lane.ended")
			if err != nil {
				return err
			}
			gone, err := s.store.last(lane, "lane.gone")
			if err != nil {
				return err
			}
			safe := ended != nil && integer(obj(ended["payload"])["run"]) == integer(previous["run"]) && integer(obj(ended["payload"])["survivors"]) == 0 || gone != nil && integer(obj(gone["payload"])["run"]) == integer(previous["run"])
			if !safe {
				return refused("lane %s's run %d has no run record and no end event that shows its processes are gone; restore the record or declare the launch gone with lane mark --gone", lane, integer(previous["run"]))
			}
		}
	}
	dir, err := s.state.dir("lanes/"+lane+"/runs", false)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	defer dir.Close()
	f, err := dir.Open(".")
	if err != nil {
		return err
	}
	names, err := f.Readdirnames(-1)
	f.Close()
	if err != nil {
		return err
	}
	table, err := processTable()
	if err != nil {
		return err
	}
	for _, name := range names {
		if !strings.HasSuffix(name, ".json") {
			continue
		}
		record, err := s.record(lane, strings.TrimSuffix(name, ".json"))
		if err != nil {
			return err
		}
		if record == nil {
			continue
		}
		live, err := living([]object{obj(record["supervisor"])}, table)
		if err != nil {
			return err
		}
		if len(live) > 0 {
			return refused("lane %s's run %d is still supervised (its supervising process lives)", lane, integer(record["run"]))
		}
		survivors, err := living(recordMembers(record), table)
		if err != nil {
			return err
		}
		if len(survivors) > 0 {
			return refused("%d process(es) of lane %s's run %d survive their supervising process; lane stop removes them", len(survivors), lane, integer(record["run"]))
		}
	}
	return nil
}
