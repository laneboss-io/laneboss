package lane

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

type processInfo struct {
	ppid, pgid, sid int
	state, start    string
}
type processTable map[int]processInfo

func nativeProcesses() bool {
	return runtime.GOOS == "linux" && os.Getenv("LANEBOSS_PROCESSES") != "portable"
}
func linuxInfo(pid int) (*processInfo, error) {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if os.IsNotExist(err) || err == syscall.ESRCH {
		return nil, nil
	}
	if err != nil {
		return nil, refuse("the process table cannot be read: /proc/%d/stat", pid)
	}
	end := bytes.LastIndexByte(b, ')')
	if end < 0 {
		return nil, refuse("the process table has an unreadable entry")
	}
	f := strings.Fields(string(b[end+1:]))
	if len(f) < 20 {
		return nil, refuse("the process table has an incomplete entry")
	}
	ppid, e1 := strconv.Atoi(f[1])
	pgid, e2 := strconv.Atoi(f[2])
	sid, e3 := strconv.Atoi(f[3])
	if e1 != nil || e2 != nil || e3 != nil {
		return nil, refuse("the process table has an invalid entry")
	}
	return &processInfo{ppid, pgid, sid, f[0], f[19]}, nil
}
func psTable(pid int) (processTable, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	args := []string{"-A", "-o", "pid=", "-o", "ppid=", "-o", "pgid=", "-o", "stat=", "-o", "lstart="}
	if pid > 0 {
		args = append(args[1:], "-p", strconv.Itoa(pid))
	}
	cmd := exec.CommandContext(ctx, "ps", args...)
	cmd.Env = changedEnv(os.Environ(), map[string]string{"LC_ALL": "C", "LANG": "C", "TZ": "UTC0"}, nil)
	var errors bytes.Buffer
	cmd.Stderr = &errors
	b, err := cmd.Output()
	if err != nil {
		if e, ok := err.(*exec.ExitError); ok && pid > 0 && e.ExitCode() == 1 && len(bytes.TrimSpace(b)) == 0 && len(bytes.TrimSpace(errors.Bytes())) == 0 {
			return processTable{}, nil
		}
		return nil, refuse("the process table cannot be read: ps failed or did not answer within 10 seconds")
	}
	found := processTable{}
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if len(f) < 9 {
			continue
		}
		id, e1 := strconv.Atoi(f[0])
		ppid, e2 := strconv.Atoi(f[1])
		pgid, e3 := strconv.Atoi(f[2])
		if e1 == nil && e2 == nil && e3 == nil {
			found[id] = processInfo{ppid, pgid, 0, f[3], strings.Join(f[4:], " ")}
		}
	}
	if len(found) == 0 {
		return nil, refuse("the process table cannot be read: ps printed no process")
	}
	return found, nil
}
func processSnapshot() (processTable, error) {
	if !nativeProcesses() {
		return psTable(0)
	}
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, refuse("the process table cannot be read: /proc")
	}
	found := processTable{}
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		p, err := linuxInfo(pid)
		if err != nil {
			return nil, err
		}
		if p != nil {
			found[pid] = *p
		}
	}
	if len(found) == 0 {
		return nil, refuse("the process table cannot be read: /proc shows no process")
	}
	return found, nil
}
func processEntry(pid int) (*processInfo, error) {
	if nativeProcesses() {
		return linuxInfo(pid)
	}
	table, err := psTable(pid)
	if err != nil {
		return nil, err
	}
	if p, ok := table[pid]; ok {
		return &p, nil
	}
	return nil, nil
}
func processIdentity(pid int) (object, error) {
	p, err := processEntry(pid)
	if err != nil || p == nil || strings.HasPrefix(p.state, "Z") {
		return nil, err
	}
	var sid any
	if p.sid > 0 {
		sid = p.sid
	}
	return object{"pid": pid, "start": p.start, "pgid": p.pgid, "sid": sid}, nil
}
func validIdentity(v any) bool {
	m := obj(v)
	return m != nil && whole(m["pid"], 1, 1<<31) && str(m["start"]) != ""
}
func processMatches(p *processInfo, id object) (bool, error) {
	if p == nil || strings.HasPrefix(p.state, "Z") {
		return false, nil
	}
	if match(`[0-9]+`, p.start) != match(`[0-9]+`, str(id["start"])) {
		return false, refuse("a process identity was recorded with another LANEBOSS_PROCESSES setting than this command uses; use the same setting")
	}
	return p.start == str(id["start"]), nil
}
func identityAlive(id object, table processTable) (bool, error) {
	if !validIdentity(id) {
		return false, nil
	}
	if table != nil {
		p, ok := table[integer(id["pid"])]
		if !ok {
			return false, nil
		}
		return processMatches(&p, id)
	}
	p, err := processEntry(integer(id["pid"]))
	if err != nil {
		return false, err
	}
	return processMatches(p, id)
}
func living(ids []object, table processTable) ([]object, error) {
	if table == nil {
		var err error
		table, err = processSnapshot()
		if err != nil {
			return nil, err
		}
	}
	result := []object{}
	for _, id := range ids {
		yes, err := identityAlive(id, table)
		if err != nil {
			return nil, err
		}
		if yes {
			result = append(result, id)
		}
	}
	return result, nil
}
func signalChecked(id object, sig syscall.Signal) (bool, error) {
	if !validIdentity(id) {
		return false, refuse("cannot signal an invalid process identity")
	}
	if nativeProcesses() {
		sent, handled, err := nativeSignal(id, sig)
		if handled {
			return sent, err
		}
	}
	yes, err := identityAlive(id, nil)
	if err != nil || !yes {
		return false, err
	}
	return syscall.Kill(integer(id["pid"]), sig) == nil, nil
}
func mergeIdentities(known []object, found []object) ([]object, bool) {
	keys := map[string]bool{}
	for _, id := range known {
		keys[fmt.Sprintf("%d/%s", integer(id["pid"]), str(id["start"]))] = true
	}
	added := false
	for _, id := range found {
		key := fmt.Sprintf("%d/%s", integer(id["pid"]), str(id["start"]))
		if !keys[key] {
			keys[key] = true
			known = append(known, id)
			added = true
		}
	}
	return known, added
}
func discoverProcesses(table processTable, roots []int, group int) []object {
	selected := map[int]bool{}
	for _, p := range roots {
		selected[p] = true
	}
	if group > 0 {
		for pid, p := range table {
			if p.pgid == group || p.sid == group {
				selected[pid] = true
			}
		}
	}
	changed := true
	for changed {
		changed = false
		for pid, p := range table {
			if selected[p.ppid] && !selected[pid] {
				selected[pid] = true
				changed = true
			}
		}
	}
	pids := []int{}
	for pid := range selected {
		if pid != os.Getpid() {
			if p, ok := table[pid]; ok && !strings.HasPrefix(p.state, "Z") {
				pids = append(pids, pid)
			}
		}
	}
	sort.Ints(pids)
	result := []object{}
	for _, pid := range pids {
		p := table[pid]
		var sid any
		if p.sid > 0 {
			sid = p.sid
		}
		result = append(result, object{"pid": pid, "start": p.start, "pgid": p.pgid, "sid": sid})
	}
	return result
}
func stopIdentities(ids []object, grace float64, discover func() ([]object, error)) ([]object, []object, error) {
	known := append([]object{}, ids...)
	if discover != nil {
		found, err := discover()
		if err != nil {
			return nil, nil, err
		}
		known, _ = mergeIdentities(known, found)
	}
	targets, err := living(known, nil)
	if err != nil {
		return nil, nil, err
	}
	for _, id := range targets {
		if _, err = signalChecked(id, syscall.SIGTERM); err != nil {
			return nil, nil, err
		}
	}
	deadline := time.Now().Add(time.Duration(grace * float64(time.Second)))
	for {
		if discover != nil {
			found, err := discover()
			if err != nil {
				return nil, nil, err
			}
			for _, id := range found {
				var added bool
				known, added = mergeIdentities(known, []object{id})
				if added {
					targets = append(targets, id)
					if _, err = signalChecked(id, syscall.SIGTERM); err != nil {
						return nil, nil, err
					}
				}
			}
		}
		left, err := living(known, nil)
		if err != nil {
			return nil, nil, err
		}
		if len(left) == 0 || !time.Now().Before(deadline) {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	left, err := living(known, nil)
	if err != nil {
		return nil, nil, err
	}
	if len(left) > 0 {
		if discover != nil {
			found, err := discover()
			if err != nil {
				return nil, nil, err
			}
			known, _ = mergeIdentities(known, found)
		}
		left, err = living(known, nil)
		if err != nil {
			return nil, nil, err
		}
		for _, id := range left {
			if _, err = signalChecked(id, syscall.SIGKILL); err != nil {
				return nil, nil, err
			}
		}
		deadline = time.Now().Add(2 * time.Second)
		for {
			left, err = living(known, nil)
			if err != nil {
				return nil, nil, err
			}
			if len(left) == 0 || !time.Now().Before(deadline) {
				break
			}
			time.Sleep(50 * time.Millisecond)
		}
	}
	removed := []object{}
	for _, id := range targets {
		present := false
		for _, v := range left {
			if integer(v["pid"]) == integer(id["pid"]) && v["start"] == id["start"] {
				present = true
			}
		}
		if !present {
			removed = append(removed, id)
		}
	}
	return removed, left, nil
}
func (s *session) readRecord(lane, launch string) (object, error) {
	if !match(`[0-9a-f]{32}`, launch) {
		return nil, integrity("a launch has an invalid identifier")
	}
	r, err := s.laneRoot(lane, false)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer r.Close()
	b, err := rootRead(r, "runs/"+launch+".json", 4*1024*1024)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, integrity("the run record of lane %s launch %s is not readable", lane, launch)
	}
	v, err := parseJSON(b)
	m := obj(v)
	if err != nil || m == nil || str(m["launch"]) != launch || list(m["processes"]) == nil {
		return nil, integrity("the run record of lane %s launch %s is not a run record", lane, launch)
	}
	return m, nil
}
func (s *session) writeRecord(lane string, record object) error {
	r, err := s.laneRoot(lane, true)
	if err != nil {
		return err
	}
	defer r.Close()
	return rootWrite(r, "runs/"+str(record["launch"])+".json", append(canonical(record), '\n'), true, 0600)
}
func (s *session) everyRecord(lane string) ([]object, error) {
	r, err := s.laneRoot(lane, false)
	if os.IsNotExist(err) {
		return []object{}, nil
	}
	if err != nil {
		return nil, err
	}
	defer r.Close()
	runs, err := rootChild(r, "runs", false)
	if os.IsNotExist(err) {
		return []object{}, nil
	}
	if err != nil {
		return nil, err
	}
	defer runs.Close()
	f, err := runs.Open(".")
	if err != nil {
		return nil, err
	}
	names, err := f.Readdirnames(-1)
	f.Close()
	if err != nil {
		return nil, err
	}
	sort.Strings(names)
	result := []object{}
	for _, name := range names {
		if !strings.HasSuffix(name, ".json") {
			continue
		}
		record, err := s.readRecord(lane, strings.TrimSuffix(name, ".json"))
		if err != nil {
			return nil, err
		}
		if record != nil {
			result = append(result, record)
		}
	}
	return result, nil
}
func recordMembers(r object) []object {
	result := []object{}
	for _, v := range list(r["processes"]) {
		if validIdentity(v) {
			result = append(result, obj(v))
		}
	}
	if validIdentity(r["runner"]) {
		result, _ = mergeIdentities(result, []object{obj(r["runner"])})
	}
	return result
}
func recordAlive(r object, table processTable) (bool, error) {
	return identityAlive(obj(r["supervisor"]), table)
}
func recordSurvivors(r object, table processTable) ([]object, error) {
	return living(recordMembers(r), table)
}
func (s *session) latest(lane string) (object, object, error) {
	e, err := s.last(lane, "lane.started")
	if err != nil {
		return nil, nil, err
	}
	if e != nil {
		p := obj(e["payload"])
		record, err := s.readRecord(lane, str(p["launch"]))
		return p, record, err
	}
	e, err = s.last(lane, "lane.adopted")
	return obj(e["payload"]), nil, err
}
func (s *session) refuseLive(lane string) error {
	p, record, err := s.latest(lane)
	if err != nil {
		return err
	}
	if p != nil && p["run"] != nil && record == nil {
		ended, e := s.last(lane, "lane.ended")
		if e != nil {
			return e
		}
		gone, e := s.last(lane, "lane.gone")
		if e != nil {
			return e
		}
		if !(ended != nil && integer(obj(ended["payload"])["run"]) == integer(p["run"]) && integer(obj(ended["payload"])["survivors"]) == 0 || gone != nil && integer(obj(gone["payload"])["run"]) == integer(p["run"])) {
			return refuse("lane %s's run has no run record and no end event that shows its processes are gone; restore the record, or declare the launch gone with lane mark --gone", lane)
		}
	}
	records, err := s.everyRecord(lane)
	if err != nil {
		return err
	}
	table, err := processSnapshot()
	if err != nil {
		return err
	}
	for _, r := range records {
		alive, err := recordAlive(r, table)
		if err != nil {
			return err
		}
		if alive {
			return refuse("lane %s's run %d is still supervised (its supervising process lives)", lane, integer(r["run"]))
		}
		left, err := recordSurvivors(r, table)
		if err != nil {
			return err
		}
		if len(left) > 0 {
			return refuse("%d processes of lane %s's run %d survive; lane stop removes them", len(left), lane, integer(r["run"]))
		}
	}
	return nil
}
func changedEnv(base []string, values map[string]string, drop func(string) bool) []string {
	m := map[string]string{}
	for _, entry := range base {
		k, v, ok := strings.Cut(entry, "=")
		if ok && (drop == nil || !drop(k)) {
			m[k] = v
		}
	}
	for k, v := range values {
		m[k] = v
	}
	r := []string{}
	for k, v := range m {
		r = append(r, k+"="+v)
	}
	return r
}
