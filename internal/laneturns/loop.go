package laneturns

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

const loopSession = "laneboss+loop"

func checkLoopEvent(e object) error {
	kind := str(e["kind"])
	p := obj(e["payload"])
	keys := ""
	switch kind {
	case "loop.started":
		keys = "loop pid start detached unrecorded_end"
	case "loop.stopped":
		keys = "loop reason turns skips"
	case "loop.turn":
		keys = "loop kind sequences run"
	case "loop.skipped":
		keys = "loop reason until after detail"
	default:
		return refused("kind: is not a documented loop event")
	}
	if !exactKeys(p, keys) || !launchPattern.MatchString(str(p["loop"])) {
		return refused("the loop event is not in the documented form")
	}
	about := kind == "loop.turn" || kind == "loop.skipped"
	if about && !lanePattern.MatchString(str(e["lane"])) || !about && e["lane"] != nil {
		return refused("the loop event's lane is not in the documented form")
	}
	switch kind {
	case "loop.started":
		if !isWhole(p["pid"]) || integer(p["pid"]) < 1 || str(p["start"]) == "" || shown(str(p["start"])) != str(p["start"]) {
			return refused("loop.started: process identity is invalid")
		}
		if _, ok := p["detached"].(bool); !ok {
			return refused("loop.started: detached must be true or false")
		}
		if p["unrecorded_end"] != nil && !launchPattern.MatchString(str(p["unrecorded_end"])) {
			return refused("loop.started: unrecorded_end is invalid")
		}
	case "loop.stopped":
		if !contains([]string{"stop", "error"}, str(p["reason"])) || !isWhole(p["turns"]) || !isWhole(p["skips"]) || number(p["turns"]) < 0 || number(p["skips"]) < 0 {
			return refused("loop.stopped: counters or reason are invalid")
		}
	case "loop.turn":
		if !contains([]string{"mail", "idle"}, str(p["kind"])) || integer(p["run"]) < 2 || integer(p["run"]) > 1000000 || !isWhole(p["run"]) || len(array(p["sequences"])) > 64 {
			return refused("loop.turn: its turn is invalid")
		}
		if err := checkSequences(p["sequences"]); err != nil {
			return err
		}
	case "loop.skipped":
		if !contains([]string{"backoff", "refused", "no-room"}, str(p["reason"])) {
			return refused("loop.skipped: its reason is invalid")
		}
		if p["until"] != nil {
			if _, err := moment(p["until"]); err != nil {
				return refused("loop.skipped: until is invalid")
			}
		}
		if p["after"] != nil {
			after := obj(p["after"])
			if !exactKeys(after, "run reason") || !isWhole(after["run"]) || integer(after["run"]) < 1 || !contains([]string{"exit", "timeout", "stopped", "limit", "dropped", "lost", "gone", "cut"}, str(after["reason"])) {
				return refused("loop.skipped: after is invalid")
			}
		}
		if p["detail"] != nil {
			detail, ok := p["detail"].(string)
			if !ok || detail == "" || len([]rune(detail)) > 200 || shown(detail) != detail {
				return refused("loop.skipped: detail is invalid")
			}
		}
	}
	return nil
}
func loopForm(e object) bool { return checkLoopEvent(e) == nil }
func declared(row object) bool {
	return flag(obj(row["mail"])["turn_based"]) && row["state"] != "abandoned" && !flag(row["cleaned"])
}
func due(row object, now time.Time) (string, error) {
	m := obj(row["mail"])
	if queued(m) > 0 {
		return "mail", nil
	}
	if m["idle_seconds"] != nil && row["state_at"] != nil {
		at, err := moment(row["state_at"])
		if err != nil {
			return "", err
		}
		if !now.Before(at.Add(time.Duration(integer(m["idle_seconds"])) * time.Second)) {
			return "idle", nil
		}
	}
	return "", nil
}
func latestClosing(s *laneSession, lane string) (object, error) {
	var latest object
	for _, kind := range []string{"lane.ended", "lane.lost", "lane.gone"} {
		e, err := s.store.last(lane, kind)
		if err != nil {
			return nil, err
		}
		if e != nil && (latest == nil || integer(e["seq"]) > integer(latest["seq"])) {
			latest = e
		}
	}
	return latest, nil
}
func loopWait(s *laneSession, lane string, backoff, limitBackoff float64) (time.Time, object, error) {
	e, err := latestClosing(s, lane)
	if err != nil || e == nil {
		return time.Time{}, nil, err
	}
	p := obj(e["payload"])
	outcome, reason := settlement(str(e["kind"]), p)
	if outcome == "delivered" {
		return time.Time{}, nil, nil
	}
	at, err := moment(eventTime(e))
	if err != nil {
		return time.Time{}, nil, err
	}
	seconds := backoff
	if reason == "limit" {
		seconds = limitBackoff
	}
	return at.Add(time.Duration(seconds * float64(time.Second))), object{"run": p["run"], "reason": reason}, nil
}
func badEnds(s *laneSession, lane string) (int, error) {
	events, err := s.store.events(lane, "")
	if err != nil {
		return 0, err
	}
	outcomes := map[int]string{}
	last := 0
	for _, e := range events {
		kind := str(e["kind"])
		if !contains([]string{"lane.ended", "lane.lost", "lane.gone"}, kind) {
			continue
		}
		p := obj(e["payload"])
		run := integer(p["run"])
		if _, ok := outcomes[run]; !ok {
			outcomes[run], _ = settlement(kind, p)
		}
		if run > last {
			last = run
		}
	}
	count := 0
	for n := last; n > 0; n-- {
		if outcome, ok := outcomes[n]; ok {
			if outcome == "delivered" {
				break
			}
			count++
		}
	}
	return count, nil
}
func latestSkip(s *laneSession, lane string) (object, error) {
	events, err := s.store.events(lane, "loop.skipped")
	if err != nil {
		return nil, err
	}
	for i := len(events) - 1; i >= 0; i-- {
		if loopForm(events[i]) {
			p := obj(events[i]["payload"])
			return object{"reason": p["reason"], "until": p["until"]}, nil
		}
	}
	return nil, nil
}
func unrecordedLoop(s *laneSession, own string) (any, error) {
	stopped, err := s.store.events("", "loop.stopped")
	if err != nil {
		return nil, err
	}
	set := map[string]bool{}
	for _, e := range stopped {
		if loopForm(e) {
			set[str(obj(e["payload"])["loop"])] = true
		}
	}
	started, err := s.store.events("", "loop.started")
	if err != nil {
		return nil, err
	}
	for i := len(started) - 1; i >= 0; i-- {
		e := started[i]
		if !loopForm(e) {
			continue
		}
		id := str(obj(e["payload"])["loop"])
		if id != own && !set[id] {
			return id, nil
		}
	}
	return nil, nil
}
func loopStarted(s *laneSession, id string) (object, error) {
	events, err := s.store.events("", "loop.started")
	if err != nil {
		return nil, err
	}
	for i := len(events) - 1; i >= 0; i-- {
		if loopForm(events[i]) && obj(events[i]["payload"])["loop"] == id {
			return events[i], nil
		}
	}
	return nil, nil
}
func readLoopRecord(s *stateDir) object {
	if s == nil {
		return nil
	}
	data, err := readAt(s.root, "loop.json", "loop.json", 65536)
	if err != nil {
		return nil
	}
	v, err := decodeJSON(data)
	if err != nil || !exactKeys(v, "loop pid start since detached last_error") || !launchPattern.MatchString(str(v["loop"])) || !isWhole(v["pid"]) || integer(v["pid"]) < 1 || str(v["start"]) == "" {
		return nil
	}
	if _, ok := v["detached"].(bool); !ok {
		return nil
	}
	if _, err = moment(v["since"]); err != nil {
		return nil
	}
	if v["last_error"] != nil {
		f := obj(v["last_error"])
		if !exactKeys(f, "at message") {
			return nil
		}
		if _, ok := f["message"].(string); !ok {
			return nil
		}
		if _, err = moment(f["at"]); err != nil {
			return nil
		}
	}
	return v
}
func believedLoop(s *stateDir) (object, error) {
	r := readLoopRecord(s)
	if r == nil {
		return nil, nil
	}
	alive, err := processAlive(object{"pid": r["pid"], "start": r["start"]})
	if err != nil {
		return nil, err
	}
	if !alive {
		return nil, nil
	}
	return r, nil
}
func loopLockHeld(s *stateDir) (bool, error) {
	if s == nil {
		return false, nil
	}
	f, err := regularAt(s.root, "loop.lock", "loop.lock", os.O_RDWR, 0)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	defer f.Close()
	err = syscall.Flock(int(f.Fd()), syscall.LOCK_SH|syscall.LOCK_NB)
	if err == syscall.EAGAIN || err == syscall.EWOULDBLOCK {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
	return false, nil
}
func secondLoop(s *stateDir) error {
	r, err := believedLoop(s)
	if err != nil {
		return err
	}
	if r == nil {
		return refused("another loop holds the loop lock, and its record loop.json names no live process")
	}
	return refused("another loop runs for configuration %s (process %d); lane loop --stop ends it", s.c.name, integer(r["pid"]))
}
func runLoop(c *configuration, a arguments, stdout, stderr io.Writer) int {
	var result object
	var err error
	switch {
	case a.flags["status"]:
		result, err = loopStatus(c)
	case a.flags["stop"]:
		result, err = stopLoop(c)
	case a.flags["detach"]:
		result, err = detachLoop(c)
	default:
		return serveLoop(c, "", false, true, stdout, stderr)
	}
	if err != nil {
		return reportError(stderr, err)
	}
	return reportError(stderr, printJSON(stdout, result))
}
func loopStatus(c *configuration) (object, error) {
	result := object{"running": false, "loop": nil, "pid": nil, "since": nil, "detached": nil, "session": nil, "last_error": nil, "unrecorded_end": nil, "lanes": []any{}}
	s, err := openSession(c, false)
	if err != nil {
		return nil, err
	}
	defer s.close()
	if s.state == nil {
		return result, nil
	}
	running, err := loopLockHeld(s.state)
	if err != nil {
		return nil, err
	}
	result["running"] = running
	if running {
		record, err := believedLoop(s.state)
		if err != nil {
			return nil, err
		}
		if record != nil {
			for _, key := range []string{"loop", "pid", "since", "detached"} {
				result[key] = record[key]
			}
			if flag(record["detached"]) {
				result["session"] = loopSession
			}
			if f := obj(record["last_error"]); f != nil {
				result["last_error"] = object{"at": f["at"], "message": screened(str(f["message"]))}
			}
			started, err := loopStarted(s, str(record["loop"]))
			if err != nil {
				return nil, err
			}
			if started != nil {
				result["unrecorded_end"] = obj(started["payload"])["unrecorded_end"]
			}
		}
	}
	rows, err := s.store.rows()
	if err != nil {
		return nil, err
	}
	listed := []any{}
	for _, row := range rows {
		if !declared(row) {
			continue
		}
		var next any
		var until any
		if !flag(row["running"]) {
			d, err := due(row, time.Now())
			if err != nil {
				return nil, err
			}
			next = nilIfEmpty(d)
			wait, _, err := loopWait(s, str(row["lane"]), c.setting("turns", "backoff_seconds", 300), c.setting("turns", "limit_backoff_seconds", 1800))
			if err != nil {
				return nil, err
			}
			if !wait.IsZero() && time.Now().Before(wait) {
				until = stamp(wait)
				if next != nil {
					next = "backoff"
				}
			}
		}
		bad, err := badEnds(s, str(row["lane"]))
		if err != nil {
			return nil, err
		}
		listed = append(listed, object{"lane": row["lane"], "state": row["state"], "waiting": queued(obj(row["mail"])), "backoff_until": until, "next": next, "bad_ends": bad})
	}
	result["lanes"] = listed
	return result, nil
}
func stopLoop(c *configuration) (object, error) {
	s, err := openSession(c, false)
	if err != nil {
		return nil, err
	}
	defer s.close()
	held, err := loopLockHeld(s.state)
	if err != nil {
		return nil, err
	}
	if !held {
		return nil, refused("no loop runs for configuration %s", c.name)
	}
	r, err := believedLoop(s.state)
	if err != nil {
		return nil, err
	}
	if r == nil {
		return nil, refused("a loop holds the lock, but its record loop.json names no live process, so nothing was signalled")
	}
	sent, err := signalChecked(object{"pid": r["pid"], "start": r["start"]}, syscall.SIGTERM)
	if err != nil {
		return nil, err
	}
	if !sent {
		return nil, refused("the loop's process could not be signalled; nothing was stopped")
	}
	deadline := time.Now().Add(30 * time.Second)
	for {
		held, err = loopLockHeld(s.state)
		if err != nil {
			return nil, err
		}
		if !held {
			break
		}
		if time.Now().After(deadline) {
			return nil, refused("the loop (process %d) is still running 30 seconds after SIGTERM; it is never killed, and no turn was stopped", integer(r["pid"]))
		}
		time.Sleep(100 * time.Millisecond)
	}
	if err = s.refresh(); err != nil {
		return nil, err
	}
	stopped, err := s.store.events("", "loop.stopped")
	if err != nil {
		return nil, err
	}
	var event any
	for i := len(stopped) - 1; i >= 0; i-- {
		if loopForm(stopped[i]) && obj(stopped[i]["payload"])["loop"] == r["loop"] {
			event = eventRef(stopped[i])
			break
		}
	}
	return object{"stopped": true, "pid": r["pid"], "event": event}, nil
}
func detachLoop(c *configuration) (object, error) {
	s, err := openSession(c, true)
	if err != nil {
		return nil, err
	}
	defer s.close()
	held, err := loopLockHeld(s.state)
	if err != nil {
		return nil, err
	}
	if held {
		return nil, secondLoop(s.state)
	}
	socket := socketPath(c.name, s.state.path)
	alive, err := tmuxAlive(socket, loopSession)
	if err != nil {
		return nil, err
	}
	if alive {
		return nil, refused("a tmux session %s is still open at %s", loopSession, socket)
	}
	id, err := randomID()
	if err != nil {
		return nil, err
	}
	name := ".loop-" + id + ".fifo"
	if err = makeFIFO(s.state.root, name); err != nil {
		return nil, err
	}
	defer s.state.root.Remove(name)
	binary, err := os.Executable()
	if err != nil {
		return nil, err
	}
	process, err := tmuxNew(socket, loopSession, s.state.path, []string{binary, "loop", "__turn_loop", s.state.path + "/" + name})
	if err != nil {
		return nil, err
	}
	data, err := canonical(object{"environment": captureEnvironment(), "spec": object{"config": c.name, "loop": id}})
	if err != nil {
		return nil, err
	}
	deadline := time.Now().Add(30 * time.Second)
	if err = handOver(s.state.root, name, data, process, deadline); err != nil {
		signalChecked(process, syscall.SIGHUP)
		return nil, err
	}
	for {
		if err = s.refresh(); err != nil {
			return nil, err
		}
		event, err := loopStarted(s, id)
		if err != nil {
			return nil, err
		}
		if event != nil {
			return object{"loop": id, "pid": obj(event["payload"])["pid"], "session": loopSession}, nil
		}
		alive, err := processAlive(process)
		if err != nil {
			return nil, err
		}
		if !alive {
			return nil, refused("the loop ended before it recorded loop.started; its messages are in loop.log")
		}
		if time.Now().After(deadline) {
			signalChecked(process, syscall.SIGHUP)
			return nil, refused("the loop did not record loop.started within 30 seconds; it was asked to stop")
		}
		time.Sleep(100 * time.Millisecond)
	}
}

type laneLoop struct {
	c              *configuration
	s              *laneSession
	id             string
	identity       object
	detached, echo bool
	stdout, stderr io.Writer
	log            *os.File
	record         object
	turns, skips   int
	waits          map[string]object
	environment    object
	stop           <-chan struct{}
}

func (l *laneLoop) stopped() bool {
	select {
	case <-l.stop:
		return true
	default:
		return false
	}
}
func (l *laneLoop) wait(seconds float64) bool {
	select {
	case <-l.stop:
		return false
	case <-time.After(time.Duration(seconds * float64(time.Second))):
		return true
	}
}
func (l *laneLoop) append(kind, lane string, p object, at ...time.Time) (object, error) {
	e, err := envelope(kind, lane, "laneboss", p)
	if err != nil {
		return nil, err
	}
	if len(at) > 0 {
		e["occurred_at"] = stamp(at[0])
	}
	st, err := openStore(l.s.state, true)
	if err != nil {
		return nil, err
	}
	defer st.close()
	e, err = st.append(e)
	if err == nil && l.echo {
		if err = printJSON(l.stdout, e); err != nil {
			l.echo = false
			err = nil
		}
	}
	return e, err
}
func (l *laneLoop) note(message string) object {
	text := screened(strings.Join(strings.Fields(message), " "))
	if len([]rune(text)) > 1000 {
		text = string([]rune(text)[:1000])
	}
	at := nowStamp()
	if _, err := fmt.Fprintf(l.log, "%s %s\n", at, text); err != nil {
		fmt.Fprintf(l.stderr, "%s loop.log could not be written: %s\n", at, text)
	}
	return object{"at": at, "message": text}
}
func (l *laneLoop) save() error {
	data, err := canonical(l.record)
	if err != nil {
		return err
	}
	return writeAtomic(l.s.state.root, "loop.json", append(data, '\n'), 0600, true)
}
func (l *laneLoop) fail(err error) {
	l.record["last_error"] = l.note("the pass could not be made: " + err.Error())
	if err = l.save(); err != nil {
		l.note("loop.json could not be written")
	}
}
func (l *laneLoop) skip(lane, reason string, until time.Time, after object, detail any, at ...time.Time) error {
	memo := object{"reason": reason, "until": stamp(until)}
	if equalJSON(l.waits[lane], memo) {
		return nil
	}
	_, err := l.append("loop.skipped", lane, object{"loop": l.id, "reason": reason, "until": stamp(until), "after": after, "detail": detail}, at...)
	if err != nil {
		return err
	}
	l.skips++
	l.waits[lane] = memo
	return nil
}
func (l *laneLoop) pass() error {
	c, err := loadConfig(l.c.name)
	if err != nil {
		return err
	}
	l.c = c
	s, err := openSession(c, false)
	if err != nil {
		return err
	}
	defer s.close()
	rows, err := s.store.rows()
	if err != nil {
		return err
	}
	passStarted := map[string]int{}
	for _, row := range rows {
		if l.stopped() {
			return nil
		}
		if !declared(row) {
			continue
		}
		lane := str(row["lane"])
		if flag(row["running"]) {
			if err = checkLost(s, lane); err != nil {
				if isExpectedError(err) {
					l.fail(err)
				} else {
					return err
				}
			}
			continue
		}
		kind, err := due(row, time.Now())
		if err != nil {
			return err
		}
		if kind == "" {
			continue
		}
		backoff := c.setting("turns", "backoff_seconds", 300)
		memo, exists := l.waits[lane]
		if !exists {
			memo, err = latestSkip(s, lane)
			if err != nil {
				return err
			}
			l.waits[lane] = memo
		}
		if memo != nil && (memo["reason"] == "refused" || memo["reason"] == "no-room") && memo["until"] != nil {
			until, err := moment(memo["until"])
			if err != nil {
				return err
			}
			now := time.Now()
			if now.Before(until) && !until.After(now.Add(time.Duration(backoff*float64(time.Second)))) {
				continue
			}
		}
		until, after, err := loopWait(s, lane, backoff, c.setting("turns", "limit_backoff_seconds", 1800))
		if err != nil {
			return err
		}
		if !until.IsZero() && time.Now().Before(until) {
			if err = l.skip(lane, "backoff", until, after, nil); err != nil {
				return err
			}
			continue
		}
		a := arguments{action: "turn", values: map[string]string{"lane": lane}, flags: map[string]bool{"idle": kind == "idle"}}
		result, err := turn(c, a, l.environment, passStarted)
		if err != nil {
			var busy *busyStoreError
			if errors.As(err, &busy) {
				return err
			}
			reason := "refused"
			detail := safeDetail(err)
			prefix := "lane " + lane + ": no turn starts, because "
			if strings.HasPrefix(err.Error(), prefix) {
				reason = "no-room"
				detail = safeDetail(refused("%s", strings.TrimPrefix(err.Error(), prefix)))
			}
			at := time.Now().UTC().Truncate(time.Microsecond)
			if err = l.skip(lane, reason, at.Add(time.Duration(backoff*float64(time.Second))), nil, detail, at); err != nil {
				return err
			}
			continue
		}
		if !flag(result["started"]) {
			continue
		}
		if account := str(result["account"]); account != "" {
			passStarted[account]++
		}
		l.waits[lane] = nil
		_, err = l.append("loop.turn", lane, object{"loop": l.id, "kind": obj(result["turn"])["kind"], "sequences": obj(result["turn"])["mail"], "run": result["run"]})
		if err != nil {
			l.fail(refused("lane %s: run %d started, and loop.turn could not be recorded: %s", lane, integer(result["run"]), err.Error()))
		} else {
			l.turns++
		}
	}
	return nil
}
func serveLoop(c *configuration, id string, detached, echo bool, stdout, stderr io.Writer) int {
	s, err := openSession(c, true)
	if err != nil {
		return reportError(stderr, err)
	}
	defer s.close()
	// Open the log before asking for the lock. Shared status probes may hold
	// the lock briefly while observing that the loop is beginning.
	log, err := regularAt(s.state.root, "loop.log", "loop.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return reportError(stderr, err)
	}
	defer log.Close()
	f, err := regularAt(s.state.root, "loop.lock", "loop.lock", os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return reportError(stderr, err)
	}
	defer f.Close()
	locked := false
	for i := 0; i < 10; i++ {
		err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			locked = true
			break
		}
		if err != syscall.EWOULDBLOCK && err != syscall.EAGAIN {
			return reportError(stderr, err)
		}
		if i < 9 {
			time.Sleep(50 * time.Millisecond)
		}
	}
	if !locked {
		return reportError(stderr, secondLoop(s.state))
	}
	defer syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
	identity, err := processIdentity(os.Getpid())
	if err != nil || identity == nil {
		if err == nil {
			err = refused("the loop's own process is not in the process table")
		}
		return reportError(stderr, err)
	}
	if id == "" {
		id, err = randomID()
		if err != nil {
			return reportError(stderr, err)
		}
	}
	if detached {
		stderr = log
	}
	signals := make(chan os.Signal, 8)
	signal.Notify(signals, syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP)
	defer signal.Stop(signals)
	stop := make(chan struct{})
	finished := make(chan struct{})
	defer close(finished)
	go func() {
		select {
		case <-signals:
			close(stop)
		case <-finished:
		}
	}()
	l := &laneLoop{c: c, s: s, id: id, identity: identity, detached: detached, echo: echo, stdout: stdout, stderr: stderr, log: log, waits: map[string]object{}, environment: captureEnvironment(), stop: stop}
	l.record = object{"loop": id, "pid": os.Getpid(), "start": identity["start"], "since": nowStamp(), "detached": detached, "last_error": nil}
	if err = l.save(); err != nil {
		return reportError(stderr, err)
	}
	started := false
	for !l.stopped() {
		if err = s.refresh(); err == nil {
			var earlier any
			earlier, err = unrecordedLoop(s, id)
			if err == nil {
				_, err = l.append("loop.started", "", object{"loop": id, "pid": os.Getpid(), "start": identity["start"], "detached": detached, "unrecorded_end": earlier})
			}
		}
		if err == nil {
			started = true
			break
		}
		l.fail(refused("loop.started could not be recorded yet: %s", err.Error()))
		l.wait(l.c.setting("turns", "poll_seconds", 10))
	}
	stopReason := "stop"
	var fatalError error
	for started && !l.stopped() {
		if err = l.pass(); err != nil {
			if isExpectedError(err) {
				l.fail(err)
			} else {
				stopReason = "error"
				fatalError = err
				if os.IsPermission(err) {
					l.note("internal error: PermissionError: a required directory could not be read")
				} else {
					l.note("internal error: the loop could not complete its pass")
				}
				break
			}
		}
		l.wait(l.c.setting("turns", "poll_seconds", 10))
	}
	if started {
		if _, err = l.append("loop.stopped", "", object{"loop": id, "reason": stopReason, "turns": l.turns, "skips": l.skips}); err != nil {
			l.note("loop.stopped could not be recorded: " + err.Error())
		}
	}
	return reportError(stderr, fatalError)
}
func checkLost(s *laneSession, lane string) error {
	if err := s.drain(lane); err != nil {
		return err
	}
	row, err := s.known(lane)
	if err != nil || !flag(row["running"]) {
		return err
	}
	p, err := s.latest(lane)
	if err != nil || p == nil {
		return err
	}
	record, err := s.record(lane, str(p["launch"]))
	if err != nil || record == nil || !validIdentity(obj(record["supervisor"])) {
		return err
	}
	alive, err := processAlive(obj(record["supervisor"]))
	if err != nil || alive {
		return err
	}
	record, err = s.record(lane, str(p["launch"]))
	if err != nil {
		return err
	}
	survivors, err := living(recordMembers(record), nil)
	if err != nil {
		return err
	}
	if _, err = s.append("lane.lost", lane, "laneboss", object{"run": row["run"], "survivors": len(survivors)}); err != nil {
		return err
	}
	if err = s.refresh(); err != nil {
		return err
	}
	row, err = s.known(lane)
	if err != nil {
		return err
	}
	settled := obj(obj(row["mail"])["settled"])
	if settled != nil && !flag(settled["announced"]) && integer(settled["run"]) == integer(row["run"]) {
		payload := object{"run": settled["run"], "sequences": settled["sequences"], "reason": settled["reason"]}
		_, err = s.append("lane.returned", lane, "laneboss", payload)
	}
	return err
}
