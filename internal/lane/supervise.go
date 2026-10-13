package lane

import (
	"encoding/base64"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

func receiveFIFO(path string) (object, error) {
	if !match(`\.launch-[0-9a-f]{32}\.fifo`, filepath.Base(path)) {
		return nil, refuse("invalid launch FIFO")
	}
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	defer syscall.Close(fd)
	var info syscall.Stat_t
	if err = syscall.Fstat(fd, &info); err != nil {
		return nil, err
	}
	if info.Mode&syscall.S_IFMT != syscall.S_IFIFO || info.Mode&0077 != 0 {
		return nil, refuse("the launch input is not a private FIFO")
	}
	deadline := time.Now().Add(30 * time.Second)
	data := []byte{}
	buffer := make([]byte, 65536)
	for {
		n, e := syscall.Read(fd, buffer)
		if n > 0 {
			data = append(data, buffer[:n]...)
			if len(data) > 32*1024*1024 {
				return nil, refuse("the launch description exceeds its byte limit")
			}
		}
		if e != nil && e != syscall.EAGAIN && e != syscall.EINTR {
			return nil, e
		}
		if n == 0 && e == nil && len(data) > 0 {
			break
		}
		if !time.Now().Before(deadline) {
			return nil, refuse("no launch input arrived within 30 seconds")
		}
		if n <= 0 {
			time.Sleep(10 * time.Millisecond)
		}
	}
	v, err := parseJSON(data)
	if err != nil || !exactKeys(obj(v), []string{"environment", "spec"}) {
		return nil, refuse("the launch description is not readable")
	}
	return obj(v), nil
}

type recorder struct {
	s            *session
	lane, launch string
	run          int
	watch        io.Writer
	mu           sync.Mutex
	queue        []object
	notify       chan struct{}
	finishing    bool
	closed       bool
	done         chan int
}

func newRecorder(s *session, lane, launch string, run int, watch io.Writer) *recorder {
	r := &recorder{s: s, lane: lane, launch: launch, run: run, watch: watch, queue: []object{}, notify: make(chan struct{}, 1), done: make(chan int, 1)}
	go r.work()
	return r
}
func (r *recorder) enqueue(e object) {
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		root, unlock, err := r.s.laneLock(r.lane, false)
		if err == nil {
			err = rootWrite(root, "pending-"+r.launch+"-"+newID()[:8]+".jsonl", append(canonical(e), '\n'), false, 0600)
			unlock()
		}
		if err != nil {
			debugRun(r.run, r.watch, "late event could be kept nowhere: %s", safeMessage(err.Error()))
		}
		return
	}
	r.queue = append(r.queue, e)
	r.mu.Unlock()
	select {
	case r.notify <- struct{}{}:
	default:
	}
}
func (r *recorder) work() {
	status := 0
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for {
		r.mu.Lock()
		var e object
		if len(r.queue) > 0 {
			e = r.queue[0]
			r.queue[0] = nil
			r.queue = r.queue[1:]
		}
		finish := e == nil && r.finishing
		if finish {
			r.closed = true
		}
		r.mu.Unlock()
		if finish {
			r.retryPending(10)
			r.done <- status
			return
		}
		if e == nil {
			select {
			case <-r.notify:
			case <-ticker.C:
				_, _, _, err := r.s.flush(r.lane, 2)
				if err != nil {
					debugRun(r.run, r.watch, "pending events still wait: %s", safeMessage(err.Error()))
				}
			}
			continue
		}
		stored, err := r.s.record(e, 2)
		if err != nil {
			debugRun(r.run, r.watch, "event %s could not be recorded: %s", str(e["kind"]), safeMessage(err.Error()))
			if _, kept := err.(*storeRefusalError); !kept {
				root, unlock, e2 := r.s.laneLock(r.lane, false)
				if e2 == nil {
					name := "pending-" + r.launch + "-" + newID()[:8] + ".jsonl"
					e2 = rootWrite(root, name, append(canonical(e), '\n'), false, 0600)
					unlock()
				}
				if e2 != nil {
					status = 1
					debugRun(r.run, r.watch, "event %s could not be recorded anywhere", str(e["kind"]))
				}
			}
		} else if !stored {
			debugRun(r.run, r.watch, "event %s is pending", str(e["kind"]))
		}
	}
}
func (r *recorder) put(kind string, p object, at string) {
	e := envelope(r.lane, kind, p, "laneboss")
	if at != "" {
		e["occurred_at"] = at
	}
	r.enqueue(e)
}
func (r *recorder) finish() int {
	r.mu.Lock()
	r.finishing = true
	r.mu.Unlock()
	select {
	case r.notify <- struct{}{}:
	default:
	}
	return <-r.done
}
func (r *recorder) retryPending(seconds float64) {
	deadline := time.Now().Add(time.Duration(seconds * float64(time.Second)))
	for {
		count, err := r.s.pendingCount(r.lane)
		if err == nil && count == 0 {
			return
		}
		if err == nil {
			_, _, _, err = r.s.flush(r.lane, 2)
		}
		if err != nil {
			debugRun(r.run, r.watch, "pending events could not be retried: %s", safeMessage(err.Error()))
		}
		if !time.Now().Before(deadline) {
			debugRun(r.run, r.watch, "events still pending; lane check will append them")
			return
		}
		time.Sleep(time.Second)
	}
}

type supervisedRun struct {
	scanner       *scanFollower
	helpers       map[int]bool
	s             *session
	spec, record  object
	lane          string
	run           int
	watch         io.Writer
	command       *exec.Cmd
	known         []object
	reaper        bool
	recorder      *recorder
	prompt        []byte
	promptSet     bool
	promptWritten atomic.Int64
	promptDone    chan struct{}
	promptWriter  *os.File
	runnerWaited  bool
}

func supervise(fifo string, stderr io.Writer) int {
	signals := make(chan os.Signal, 16)
	signal.Notify(signals, syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP)
	defer signal.Stop(signals)
	message, err := receiveFIFO(fifo)
	if err != nil {
		return 2
	}
	environment := obj(message["environment"])
	spec := obj(message["spec"])
	if environment == nil || spec == nil {
		return 2
	}
	os.Clearenv()
	for k, v := range environment {
		if _, ok := v.(string); ok {
			if err = os.Setenv(k, str(v)); err != nil {
				return 2
			}
		} else {
			return 2
		}
	}
	c, err := loadConfiguration(str(spec["config"]))
	if err != nil {
		return 2
	}
	s, err := openSession(c, false)
	if err != nil {
		return 2
	}
	defer s.close()
	lane := str(spec["lane"])
	if !match(`[a-z0-9][a-z0-9._-]{0,63}`, lane) || s.root == nil {
		return 2
	}
	root, err := s.laneRoot(lane, false)
	if err != nil {
		return 2
	}
	defer root.Close()
	watch, err := childOpen(root, "watch.log", os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0600)
	if err != nil {
		return 2
	}
	defer watch.Close()
	info, err := watch.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return 2
	}
	record, err := s.readRecord(lane, str(spec["launch"]))
	if err != nil || record == nil || !validIdentity(record["supervisor"]) || integer(obj(record["supervisor"])["pid"]) != os.Getpid() {
		debugRun(integer(spec["run"]), watch, "the run record does not name this process as the supervising process")
		return 2
	}
	mine, err := processIdentity(os.Getpid())
	if err != nil || mine == nil || str(mine["start"]) != str(obj(record["supervisor"])["start"]) {
		return 2
	}
	run := &supervisedRun{s: s, spec: spec, record: record, lane: lane, run: integer(spec["run"]), watch: watch, known: []object{}, helpers: map[int]bool{}}
	status := run.execute(root, environment, signals)
	debugRun(run.run, watch, "the supervising process exits with status %d", status)
	return status
}
func (r *supervisedRun) saveRecord() {
	r.record["processes"] = r.known
	if err := r.s.writeRecord(r.lane, r.record); err != nil {
		debugRun(r.run, r.watch, "the run record could not be written (it is tried again): %s", safeMessage(err.Error()))
	}
}
func (r *supervisedRun) sample() ([]object, error) {
	table, err := processSnapshot()
	if err != nil {
		return nil, err
	}
	if r.command == nil || r.command.Process == nil {
		return []object{}, nil
	}
	runnerPID := r.command.Process.Pid
	roots := []int{}
	if !r.runnerWaited {
		roots = append(roots, runnerPID)
	}
	if r.reaper {
		roots = append(roots, os.Getpid())
	}
	groupKnown := false
	if p, ok := table[runnerPID]; ok && !r.runnerWaited && p.pgid == runnerPID {
		groupKnown = true
	}
	for _, id := range r.known {
		alive, e := identityAlive(id, table)
		if e != nil {
			return nil, e
		}
		if alive {
			pid := integer(id["pid"])
			roots = append(roots, pid)
			if table[pid].pgid == runnerPID {
				groupKnown = true
			}
		}
	}
	group := 0
	if groupKnown {
		group = runnerPID
	}
	foundAll := discoverProcesses(table, roots, group)
	found := []object{}
	for _, id := range foundAll {
		if !r.helpers[integer(id["pid"])] {
			found = append(found, id)
		}
	}
	r.known, _ = mergeIdentities(r.known, found)
	if r.record["runner"] == nil {
		for _, id := range found {
			if integer(id["pid"]) == runnerPID {
				r.record["runner"] = id
				break
			}
		}
	}
	for pid, p := range table {
		if r.reaper && p.ppid == os.Getpid() && pid != runnerPID && !r.helpers[pid] && strings.HasPrefix(p.state, "Z") {
			var status syscall.WaitStatus
			syscall.Wait4(pid, &status, syscall.WNOHANG, nil)
		}
	}
	r.saveRecord()
	return found, nil
}
func (r *supervisedRun) runnerEnded() (bool, error) {
	p, err := processEntry(r.command.Process.Pid)
	if err != nil {
		return false, err
	}
	return p == nil || strings.HasPrefix(p.state, "Z"), nil
}
func (r *supervisedRun) stopAll(grace float64) int {
	since := ""
	for {
		_, left, err := stopIdentities(r.known, grace, r.sample)
		ended, e := r.runnerEnded()
		if err == nil && e == nil && ended {
			r.command.Wait()
			r.runnerWaited = true
			break
		}
		if since == "" {
			since = utcNow()
		}
		r.record["stopping"] = object{"since": since, "survivors": len(left)}
		r.saveRecord()
		debugRun(r.run, r.watch, "the runner could not be removed yet; trying again")
		time.Sleep(2 * time.Second)
		grace = 0
	}
	for {
		_, left, err := stopIdentities(r.known, 1, r.sample)
		if err != nil {
			debugRun(r.run, r.watch, "the run's remaining processes cannot be observed; trying again")
			time.Sleep(2 * time.Second)
			continue
		}
		r.record["finished"] = true
		r.record["stopping"] = nil
		r.saveRecord()
		return len(left)
	}
}
func (r *supervisedRun) promptFate() object {
	if r.promptDone != nil {
		select {
		case <-r.promptDone:
		case <-time.After(2 * time.Second):
			if r.promptWriter != nil {
				r.promptWriter.Close()
			}
		}
	}
	written := r.promptWritten.Load()
	state := "cut"
	if written == int64(len(r.prompt)) {
		state = "written"
	}
	return object{"state": state, "bytes": written, "length": len(r.prompt)}
}
func (r *supervisedRun) execute(root *os.Root, environment object, signals chan os.Signal) int {
	log, err := childOpen(root, "output.log", os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0600)
	if err != nil {
		return 2
	}
	defer log.Close()
	info, err := log.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return 2
	}
	offset := info.Size()
	r.record["log"] = object{"start": offset, "end": nil}
	r.saveRecord()
	if resumed := obj(r.spec["resumed"]); resumed != nil {
		if _, err = r.s.append(envelope(r.lane, "lane.resumed", resumed, "laneboss"), 10); err != nil {
			debugRun(r.run, r.watch, "resume was refused: %s", safeMessage(err.Error()))
			return 2
		}
	}
	if _, err = r.s.append(envelope(r.lane, "lane.started", obj(r.spec["started"]), "laneboss"), 10); err != nil {
		debugRun(r.run, r.watch, "start was refused: %s", safeMessage(err.Error()))
		return 2
	}
	recorderSession, err := openSession(r.s.c, false)
	if err != nil {
		return 3
	}
	defer recorderSession.close()
	r.recorder = newRecorder(recorderSession, r.lane, str(r.spec["launch"]), r.run, r.watch)
	r.startScanner()
	defer r.stopScanner(false, "")
	if r.spec["prompt"] != nil {
		r.prompt, err = base64.StdEncoding.Strict().DecodeString(str(r.spec["prompt"]))
		if err != nil {
			debugRun(r.run, r.watch, "prompt description is invalid")
			return r.finishRecording()
		}
		r.promptSet = true
	}
	r.reaper = becomeSubreaper()
	argv := stringsOf(r.spec["argv"])
	if len(argv) == 0 {
		debugRun(r.run, r.watch, "runner description has no argument vector")
		return r.finishRecording()
	}
	debugRun(r.run, r.watch, "started (adopting orphans: %t)", r.reaper)
	began := time.Now()
	r.command = exec.Command(argv[0], argv[1:]...)
	r.command.Dir = str(r.spec["cwd"])
	base := []string{}
	for k, v := range environment {
		if k != "TMUX" && k != "TMUX_PANE" {
			base = append(base, k+"="+str(v))
		}
	}
	r.command.Env = changedEnv(base, map[string]string{"LANEBOSS_CONFIG": r.s.c.name, "LANEBOSS_LANE": r.lane, "LANEBOSS_RUN": strconv.Itoa(r.run)}, nil)
	r.command.Stdout = log
	r.command.Stderr = log
	r.command.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	var promptReader *os.File
	if r.promptSet {
		promptReader, r.promptWriter, err = os.Pipe()
		if err != nil {
			debugRun(r.run, r.watch, "prompt pipe cannot be created")
			r.end("exit", 0, nil, nil, utcNow(), time.Since(began).Seconds(), false)
			return r.finishRecording()
		}
		r.command.Stdin = promptReader
	}
	if err = r.command.Start(); err != nil {
		if promptReader != nil {
			promptReader.Close()
			r.promptWriter.Close()
		}
		r.record["finished"] = true
		obj(r.record["log"])["end"] = offset
		r.saveRecord()
		debugRun(r.run, r.watch, "the runner could not be started: %s", safeMessage(err.Error()))
		r.end("exit", 0, nil, nil, utcNow(), time.Since(began).Seconds(), false)
		return r.finishRecording()
	}
	if promptReader != nil {
		promptReader.Close()
		r.promptDone = make(chan struct{})
		go func() {
			defer close(r.promptDone)
			defer r.promptWriter.Close()
			for r.promptWritten.Load() < int64(len(r.prompt)) {
				start := int(r.promptWritten.Load())
				end := start + 16384
				if end > len(r.prompt) {
					end = len(r.prompt)
				}
				n, e := r.promptWriter.Write(r.prompt[start:end])
				r.promptWritten.Add(int64(n))
				if e != nil {
					debugRun(r.run, r.watch, "the prompt was not written to the runner's standard input in full (%d of %d bytes)", r.promptWritten.Load(), len(r.prompt))
					return
				}
			}
		}()
	}
	id, e := processIdentity(r.command.Process.Pid)
	if e == nil && id != nil {
		r.record["runner"] = id
		r.known = append(r.known, id)
	}
	r.saveRecord()
	defer func() {
		if !r.runnerWaited {
			r.stopAll(number(r.spec["grace_seconds"]))
		}
	}()
	lastSize, lastGrowth := offset, began
	lastSample := time.Time{}
	reported := false
	hung, stopped := false, false
	for {
		for {
			select {
			case sig := <-signals:
				if sig == syscall.SIGHUP {
					hung = true
				} else {
					stopped = true
				}
			default:
				goto drained
			}
		}
	drained:
		ended, e := r.runnerEnded()
		if e != nil {
			debugRun(r.run, r.watch, "the runner's end cannot be observed; keeping supervision")
		} else if ended {
			if _, e = r.sample(); e != nil {
				debugRun(r.run, r.watch, "the run's processes cannot be sampled: %s", safeMessage(e.Error()))
			}
			endedAt := utcNow()
			duration := time.Since(began).Seconds()
			survivors := r.stopAll(1)
			r.finishLog(log)
			reason, pattern, classification := classifyOutput(root, offset, r.spec)
			if classification == "read-error" {
				debugRun(r.run, r.watch, "classification failed because the output could not be read")
				r.stopScanner(false, "")
				r.finishRecording()
				return 3
			}
			r.end(reason, survivors, pattern, classification, endedAt, duration, true)
			break
		}
		now := time.Now()
		if now.Sub(lastSample) >= 500*time.Millisecond {
			lastSample = now
			if _, e = r.sample(); e != nil {
				debugRun(r.run, r.watch, "the run's processes cannot be sampled: %s", safeMessage(e.Error()))
			}
		}
		if hung {
			debugRun(r.run, r.watch, "the session went away; stopping the run without an event")
			r.stopAll(number(r.spec["grace_seconds"]))
			r.finishLog(log)
			break
		}
		if stopped {
			debugRun(r.run, r.watch, "stop requested")
			survivors := r.stopAll(number(r.spec["grace_seconds"]))
			r.finishLog(log)
			r.end("stopped", survivors, nil, nil, utcNow(), time.Since(began).Seconds(), true)
			break
		}
		if time.Since(began).Seconds() >= number(r.spec["budget_seconds"]) {
			observed := utcNow()
			elapsed := rounded(time.Since(began).Seconds())
			debugRun(r.run, r.watch, "the budget passed; stopping the run")
			survivors := r.stopAll(number(r.spec["grace_seconds"]))
			r.finishLog(log)
			r.recorder.put("lane.timeout", object{"run": r.run, "budget_minutes": obj(r.spec["started"])["budget_minutes"], "elapsed_seconds": elapsed}, observed)
			r.end("timeout", survivors, nil, nil, utcNow(), time.Since(began).Seconds(), true)
			break
		}
		info, e = log.Stat()
		if e != nil {
			debugRun(r.run, r.watch, "the log cannot be observed")
		} else if info.Size() != lastSize {
			lastSize, lastGrowth, reported = info.Size(), now, false
		} else if !reported && now.Sub(lastGrowth).Seconds() >= number(r.spec["quiet_seconds"]) {
			bytes := lastSize - offset
			if bytes < 0 {
				bytes = 0
			}
			r.recorder.put("lane.stuck", object{"run": r.run, "quiet_seconds": r.spec["quiet_seconds"], "output_bytes": bytes}, "")
			reported = true
		}
		time.Sleep(200 * time.Millisecond)
	}
	return r.finishRecording()
}
func (r *supervisedRun) finishLog(log *os.File) {
	if info, err := log.Stat(); err == nil {
		obj(r.record["log"])["end"] = info.Size()
		r.saveRecord()
	}
}
func (r *supervisedRun) end(reason string, survivors int, pattern, classification any, at string, duration float64, ran bool) {
	r.stopScanner(true, at)
	var exitCode, sig any
	if ran && r.command.ProcessState != nil {
		status, ok := r.command.ProcessState.Sys().(syscall.WaitStatus)
		if ok && status.Signaled() {
			sig = int(status.Signal())
		} else if r.command.ProcessState.ExitCode() >= 0 {
			exitCode = r.command.ProcessState.ExitCode()
		}
	}
	p := object{"run": r.run, "reason": reason, "exit_code": exitCode, "signal": sig, "duration_seconds": rounded(duration), "pattern": pattern, "classification": classification, "survivors": survivors}
	if r.promptSet {
		p["prompt"] = r.promptFate()
	}
	r.recorder.put("lane.ended", p, at)
	carried := list(obj(r.spec["started"])["mail"])
	if len(carried) > 0 {
		outcome, why := settlement("ended", p)
		payload := object{"run": r.run, "sequences": carried}
		if outcome == "returned" {
			payload["reason"] = why
		}
		r.recorder.put("lane."+outcome, payload, "")
	}
	debugRun(r.run, r.watch, "ended, reason %s, exit code %v, signal %v, %d other processes survive", reason, exitCode, sig, survivors)
}

func (r *supervisedRun) finishRecording() int {
	r.stopScanner(false, "")
	status := r.recorder.finish()
	if status == 0 && os.Getenv("LANEBOSS_INSTANCE") != "" {
		debugRun(r.run, r.watch, "history ingest %s", string(canonical(r.historyReceipt())))
	}
	return status
}
