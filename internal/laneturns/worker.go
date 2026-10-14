package laneturns

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"os/exec"
	"os/signal"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"laneboss.io/laneboss/internal/hookconfig"
	"laneboss.io/laneboss/internal/selfexec"
)

func hangupSignal() syscall.Signal { return syscall.SIGHUP }
func captureEnvironment() object {
	v := object{}
	for _, entry := range os.Environ() {
		key, value, _ := strings.Cut(entry, "=")
		v[key] = value
	}
	return v
}
func environmentList(env object) []string {
	r := []string{}
	for k, v := range env {
		if k != "TMUX" && k != "TMUX_PANE" {
			r = append(r, k+"="+str(v))
		}
	}
	return r
}
func writeRecord(s *laneSession, lane string, record object) error {
	data, err := canonical(record)
	if err != nil {
		return err
	}
	return s.state.write("lanes/"+lane+"/runs/"+str(record["launch"])+".json", append(data, '\n'), 0600, true)
}
func handOver(root *os.Root, name string, data []byte, process object, deadline time.Time) error {
	var f *os.File
	for {
		var err error
		f, err = root.OpenFile(name, os.O_WRONLY|syscall.O_NONBLOCK|syscall.O_NOFOLLOW, 0)
		if err == nil {
			break
		}
		if !os.IsNotExist(err) && !errors.Is(err, syscall.ENXIO) {
			return refused("the supervising process's FIFO could not be opened")
		}
		if os.IsNotExist(err) {
			return refused("the supervising process's FIFO disappeared before it read its input")
		}
		if time.Now().After(deadline) {
			return refused("the supervising process did not read its input within 30 seconds")
		}
		alive, e := processAlive(process)
		if e != nil {
			return e
		}
		if !alive {
			return refused("the supervising process ended before it read its input")
		}
		time.Sleep(20 * time.Millisecond)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeNamedPipe == 0 {
		return refused("the supervising process's input is not a FIFO")
	}
	for len(data) > 0 {
		if time.Now().After(deadline) {
			return refused("the supervising process did not read its input within 30 seconds")
		}
		n, err := syscall.Write(int(f.Fd()), data)
		if n > 0 {
			data = data[n:]
		}
		if err == syscall.EAGAIN || err == syscall.EWOULDBLOCK || err == syscall.EINTR {
			time.Sleep(10 * time.Millisecond)
			continue
		}
		if err != nil {
			return refused("the supervising process stopped reading its input")
		}
	}
	return nil
}
func receiveFIFO(path string) (object, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, refused("the worker's input FIFO cannot be opened")
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeNamedPipe == 0 {
		return nil, refused("the worker's input is not a FIFO")
	}
	deadline := time.Now().Add(30 * time.Second)
	var data bytes.Buffer
	chunk := make([]byte, 65536)
	for {
		if time.Now().After(deadline) {
			return nil, refused("no input arrived for the worker within 30 seconds")
		}
		n, err := syscall.Read(int(f.Fd()), chunk)
		if n > 0 {
			data.Write(chunk[:n])
			if data.Len() > 16*1024*1024 {
				return nil, refused("the worker's input exceeds its size limit")
			}
		}
		if n == 0 && err == nil && data.Len() > 0 {
			break
		}
		if err != nil && err != syscall.EAGAIN && err != syscall.EWOULDBLOCK && err != syscall.EINTR {
			return nil, refused("the worker's input could not be read")
		}
		if n <= 0 {
			time.Sleep(10 * time.Millisecond)
		}
	}
	return decodeJSON(data.Bytes())
}
func beginWorker(s *laneSession, lane string, spec, environment object) (object, error) {
	dir, err := s.state.dir("lanes/"+lane, true)
	if err != nil {
		return nil, err
	}
	defer dir.Close()
	name := ".launch-" + str(spec["launch"]) + ".fifo"
	if err = makeFIFO(dir, name); err != nil {
		return nil, err
	}
	defer dir.Remove(name)
	binary, err := os.Executable()
	if err != nil {
		return nil, err
	}
	process, err := tmuxNew(str(obj(obj(spec["started"])["session"])["socket"]), sessionName(lane), str(spec["cwd"]), append([]string{binary}, selfexec.Args("lane", "turn", "__turn_supervise", s.state.lanePath(lane, name))...))
	if err != nil {
		return nil, err
	}
	record := object{"config": s.c.name, "lane": lane, "run": spec["run"], "launch": spec["launch"], "supervisor": process, "runner": nil, "processes": []any{}, "finished": false}
	if err = writeRecord(s, lane, record); err != nil {
		signalChecked(process, syscall.SIGHUP)
		return nil, err
	}
	if environment == nil {
		environment = captureEnvironment()
	}
	message, err := canonical(object{"environment": environment, "spec": spec})
	if err != nil {
		return nil, err
	}
	if err = handOver(dir, name, message, process, time.Now().Add(30*time.Second)); err != nil {
		signalChecked(process, syscall.SIGHUP)
		return nil, err
	}
	return process, nil
}
func worker(kind, path string, stdout, stderr io.Writer) int {
	var runSignals chan os.Signal
	if kind == "__turn_supervise" {
		runSignals = make(chan os.Signal, 8)
		signal.Notify(runSignals, syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP)
		defer signal.Stop(runSignals)
	}
	message, err := receiveFIFO(path)
	if err != nil {
		return reportError(stderr, err)
	}
	environment := obj(message["environment"])
	spec := obj(message["spec"])
	if environment == nil || spec == nil {
		return reportError(stderr, refused("the worker's handoff is malformed"))
	}
	for key, value := range environment {
		if key == "" || strings.ContainsAny(key, "=\x00") {
			return 2
		}
		s, ok := value.(string)
		if !ok || strings.ContainsRune(s, 0) {
			return 2
		}
	}
	os.Clearenv()
	for key, value := range environment {
		if err = os.Setenv(key, str(value)); err != nil {
			return 2
		}
	}
	c, err := loadConfig(str(spec["config"]))
	if err != nil {
		return reportError(stderr, err)
	}
	if kind == "__turn_loop" {
		return serveLoop(c, str(spec["loop"]), true, false, stdout, stderr)
	}
	s, err := openSession(c, false)
	if err != nil {
		return reportError(stderr, err)
	}
	defer s.close()
	lane := str(spec["lane"])
	if s.state == nil || !lanePattern.MatchString(lane) || !launchPattern.MatchString(str(spec["launch"])) {
		return 2
	}
	dir, err := s.state.dir("lanes/"+lane, false)
	if err != nil {
		return reportError(stderr, err)
	}
	defer dir.Close()
	watch, err := regularAt(dir, "watch.log", "watch.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return reportError(stderr, err)
	}
	defer watch.Close()
	record, err := s.record(lane, str(spec["launch"]))
	if err != nil {
		return reportError(watch, err)
	}
	identity, err := processIdentity(os.Getpid())
	if err != nil {
		return reportError(watch, err)
	}
	if record == nil || !validIdentity(obj(record["supervisor"])) || integer(obj(record["supervisor"])["pid"]) != os.Getpid() || obj(record["supervisor"])["start"] != identity["start"] {
		return reportError(watch, refused("the run record does not name this process as the supervising process"))
	}
	return reportError(watch, superviseTurn(s, spec, record, environment, watch, runSignals))
}

type promptProgress struct {
	written atomic.Int64
	length  int64
	done    chan struct{}
}

func (p *promptProgress) fate() object {
	state := "cut"
	n := p.written.Load()
	if n == p.length {
		state = "written"
	}
	return object{"state": state, "bytes": n, "length": p.length}
}

func superviseTurn(s *laneSession, spec, record, environment object, watch io.Writer, signals <-chan os.Signal) (resultErr error) {
	lane := str(spec["lane"])
	started := obj(spec["started"])
	run := integer(spec["run"])
	prompt, err := base64.StdEncoding.Strict().DecodeString(str(spec["prompt"]))
	if err != nil || len(prompt) == 0 {
		return refused("the turn's prompt is malformed")
	}
	if err = checkPayload("lane.started", started); err != nil {
		return err
	}
	if err = checkBinding(s.state, lane, "lane.started", started); err != nil {
		return err
	}
	dir, err := s.state.dir("lanes/"+lane, false)
	if err != nil {
		return err
	}
	defer dir.Close()
	log, err := regularAt(dir, "output.log", "output.log", os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer log.Close()
	logInfo, err := log.Stat()
	if err != nil {
		return err
	}
	offset := logInfo.Size()
	hookMonitor := &hookconfig.Monitor{}
	record["log"] = object{"start": offset, "end": nil}
	if err = writeRecord(s, lane, record); err != nil {
		return err
	}
	if _, err = s.append("lane.resumed", lane, "laneboss", obj(spec["resumed"])); err != nil {
		return err
	}
	if _, err = s.append("lane.started", lane, "laneboss", started); err != nil {
		return err
	}
	recorder := newRecorder(s, lane, str(spec["launch"]), watch)
	defer func() { resultErr = errors.Join(resultErr, recorder.finish()) }()
	var scanner *scanProcess
	runner := obj(obj(s.c.data["runners"])[str(started["runner"])])
	if len(array(s.c.data["guards"])) > 0 && len(array(runner["records"])) > 0 {
		scanner, err = startScanProcess(s, lane, run, offset, recorder, watch)
		if err != nil {
			fmt.Fprintf(watch, "%s run %d: the refusal scanner could not start; no runner started\n", nowStamp(), run)
			record["finished"] = true
			obj(record["log"])["end"] = offset
			if err = writeRecord(s, lane, record); err != nil {
				return err
			}
			return recorder.ending(endedPayload(run, "exit", nil, nil, 0, nil, nil, 0, nil), started)
		}
		defer scanner.stop()
	}
	adopted := becomeSubreaper()
	argv := texts(spec["argv"])
	if len(argv) == 0 {
		return refused("the turn has no runner command")
	}
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Dir = str(spec["cwd"])
	env := copyObject(environment)
	env["LANEBOSS_CONFIG"] = s.c.name
	env["LANEBOSS_LANE"] = lane
	env["LANEBOSS_RUN"] = strconv.Itoa(run)
	cmd.Env = environmentList(env)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	cmd.Stdout = hookMonitor.Writer(log, false)
	cmd.Stderr = hookMonitor.Writer(log, true)
	cmd.WaitDelay = 2 * time.Second
	readPipe, writePipe, err := os.Pipe()
	if err != nil {
		return err
	}
	cmd.Stdin = readPipe
	began := time.Now()
	progress := &promptProgress{length: int64(len(prompt)), done: make(chan struct{})}
	if err = hookconfig.Revet(argv, cmd.Dir, cmd.Env); err != nil {
		readPipe.Close()
		writePipe.Close()
		marker, markerErr := hookconfig.Marker(hookconfig.DefaultPath(argv, cmd.Dir), run, false)
		if markerErr == nil {
			markerErr = writeAtomic(dir, "hook-config.json", marker, 0600, true)
		}
		record["finished"] = true
		obj(record["log"])["end"] = offset
		if err := writeRecord(s, lane, record); err != nil {
			return err
		}
		fmt.Fprintf(watch, "%s run %d: hook-config re-vetting refused before runner exec\n", nowStamp(), run)
		return recorder.ending(endedPayload(run, "hook-config", hookconfig.ExitCode, nil, time.Since(began).Seconds(), nil, nil, 0, nil), started)
	}
	if err = cmd.Start(); err != nil {
		readPipe.Close()
		writePipe.Close()
		record["finished"] = true
		obj(record["log"])["end"] = offset
		if err = writeRecord(s, lane, record); err != nil {
			return err
		}
		fmt.Fprintf(watch, "%s run %d: the runner could not be started; its arguments were not printed\n", nowStamp(), run)
		end := endedPayload(run, "exit", nil, nil, time.Since(began).Seconds(), nil, nil, 0, nil)
		return recorder.ending(end, started)
	}
	readPipe.Close()
	entry, err := processInfo(cmd.Process.Pid)
	if err != nil || entry == nil || entry.start == "" {
		cmd.Process.Kill()
		cmd.Wait()
		writePipe.Close()
		if err == nil {
			err = refused("the new runner's PID and start time could not be recorded")
		}
		return err
	}
	identity := identityOf(*entry)
	known := []object{identity}
	record["runner"] = identity
	record["processes"] = known
	if err = writeRecord(s, lane, record); err != nil {
		signalChecked(identity, syscall.SIGKILL)
		cmd.Wait()
		writePipe.Close()
		return err
	}
	go func() {
		defer close(progress.done)
		defer writePipe.Close()
		remaining := prompt
		for len(remaining) > 0 {
			n, e := writePipe.Write(remaining)
			if n > 0 {
				progress.written.Add(int64(n))
				remaining = remaining[n:]
			}
			if e != nil {
				return
			}
		}
	}()
	group := integer(identity["pid"])
	discover := func() ([]object, error) { return discoverProcesses(known, group, adopted, scanner.pid()) }
	var lastRecordFailure time.Time
	sample := func() error {
		found, e := discover()
		if e != nil {
			return e
		}
		mergeIdentities(&known, found)
		record["processes"] = known
		if e = writeRecord(s, lane, record); e != nil {
			// Keep tracking identities and enforcing the budget while a record
			// write is unavailable. The next sample retries the same record.
			if lastRecordFailure.IsZero() || time.Since(lastRecordFailure) >= 10*time.Second {
				fmt.Fprintf(watch, "%s run %d: the run record could not be written (it is tried again): %s\n", nowStamp(), run, safeDetail(e))
				lastRecordFailure = time.Now()
			}
		} else {
			lastRecordFailure = time.Time{}
		}
		return nil
	}
	lastSize := offset
	lastGrowth := began
	stuck := false
	reason := "exit"
	hangup := false
	done := false
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	var observationErr error
	var lastSampleFailure time.Time
	for !done {
		select {
		case sig := <-signals:
			if sig == syscall.SIGHUP {
				hangup = true
				fmt.Fprintf(watch, "%s run %d: the session went away; stopping the run without an event\n", nowStamp(), run)
			} else {
				fmt.Fprintf(watch, "%s run %d: stop requested\n", nowStamp(), run)
			}
			reason = "stopped"
			done = true
		case <-ticker.C:
			failed, path, inspectionErr := hookMonitor.Poll()
			if failed || inspectionErr != nil {
				if path == "" {
					path = hookconfig.DefaultPath(argv, str(spec["cwd"]))
				}
				sent, signalErr := signalChecked(identity, syscall.SIGTERM)
				marker, markerErr := hookconfig.Marker(path, run, sent && signalErr == nil)
				if markerErr == nil {
					markerErr = writeAtomic(dir, "hook-config.json", marker, 0600, true)
				}
				if markerErr != nil {
					fmt.Fprintf(watch, "%s run %d: hook-config marker could not be kept; resuming remains refused\n", nowStamp(), run)
				}
				reason, done = "hook-config", true
				break
			}
			entry, e := observeRunner(identity)
			if e != nil {
				observationErr = e
				done = true
				break
			}
			if e := sample(); e != nil {
				// A global process-table failure does not invalidate the runner
				// identity just checked above. Keep known identities, retry the
				// sample, and continue enforcing its budget and stop requests.
				if lastSampleFailure.IsZero() || time.Since(lastSampleFailure) >= 10*time.Second {
					fmt.Fprintf(watch, "%s run %d: the run's processes could not be sampled (it is tried again): %s\n", nowStamp(), run, safeDetail(e))
					lastSampleFailure = time.Now()
				}
			} else {
				lastSampleFailure = time.Time{}
			}
			if strings.HasPrefix(entry.state, "Z") {
				done = true
				break
			}
			if time.Since(began).Seconds() >= number(spec["budget_seconds"]) {
				fmt.Fprintf(watch, "%s run %d: the budget passed; stopping the run\n", nowStamp(), run)
				reason = "timeout"
				done = true
				break
			}
			info, e := log.Stat()
			if e != nil {
				observationErr = e
				done = true
				break
			}
			if info.Size() != lastSize {
				lastSize = info.Size()
				lastGrowth = time.Now()
				stuck = false
			} else if !stuck && time.Since(lastGrowth).Seconds() >= number(spec["quiet_seconds"]) {
				event, e := envelope("lane.stuck", lane, "laneboss", object{"run": run, "quiet_seconds": spec["quiet_seconds"], "output_bytes": max(int64(0), lastSize-offset)})
				if e != nil {
					observationErr = e
					done = true
					break
				}
				recorder.put(event)
				stuck = true
			}
		}
	}
	if observationErr != nil {
		signalChecked(identity, syscall.SIGKILL)
		writePipe.Close()
		fmt.Fprintf(watch, "%s run %d: observation failed: %s\n", nowStamp(), run, screened(shown(observationErr.Error())))
	}
	grace := number(spec["grace_seconds"])
	if reason == "hook-config" {
		grace = 0
	}
	if hangup {
		grace = math.Min(grace, 5)
	}
	_, survivors, stopErr := stopIdentities(&known, grace, discover)
	writePipe.Close()
	if stopErr != nil {
		signalChecked(identity, syscall.SIGKILL)
		cmd.Wait()
		return stopErr
	}
	// Keep the runner's zombie until the last tree observation. Its PID and
	// process group cannot be reassigned during discovery and cleanup.
	if err = sample(); err != nil {
		signalChecked(identity, syscall.SIGKILL)
		cmd.Wait()
		return err
	}
	cmd.Wait()
	if failed, path, inspectionErr := hookMonitor.Poll(); !hangup && (failed || inspectionErr != nil) && reason != "hook-config" {
		if path == "" {
			path = hookconfig.DefaultPath(argv, str(spec["cwd"]))
		}
		marker, markerErr := hookconfig.Marker(path, run, false)
		if markerErr == nil {
			markerErr = writeAtomic(dir, "hook-config.json", marker, 0600, true)
		}
		if markerErr != nil {
			fmt.Fprintf(watch, "%s run %d: hook-config marker could not be kept; resuming remains refused\n", nowStamp(), run)
		}
		reason = "hook-config"
	}
	select {
	case <-progress.done:
	case <-time.After(time.Second):
		return refused("the prompt writer did not finish")
	}
	if err = sample(); err != nil {
		return err
	}
	info, err := log.Stat()
	if err != nil {
		return err
	}
	obj(record["log"])["end"] = info.Size()
	record["finished"] = len(survivors) == 0
	if err = writeRecord(s, lane, record); err != nil {
		return err
	}
	if hangup {
		if scanner != nil {
			scanner.stop()
		}
		return nil
	}
	if scanner != nil && !scanner.finish(nowStamp(), info.Size()) {
		fmt.Fprintf(watch, "%s run %d: the refusal scan did not finish its last pass; lane scan must cover the run\n", nowStamp(), run)
	}
	if observationErr != nil {
		return observationErr
	}
	var code, signalNumber any
	if cmd.ProcessState != nil {
		status, ok := cmd.ProcessState.Sys().(syscall.WaitStatus)
		if ok && status.Signaled() {
			signalNumber = int(status.Signal())
		} else if cmd.ProcessState.ExitCode() >= 0 {
			code = cmd.ProcessState.ExitCode()
		}
	}
	var pattern, classification any
	if reason == "hook-config" {
		code, signalNumber = hookconfig.ExitCode, nil
	}
	if reason == "exit" {
		reason, pattern, classification, err = classifyOutput(s, lane, offset, spec)
		if err != nil {
			return err
		}
	}
	if reason == "timeout" {
		e, err := envelope("lane.timeout", lane, "laneboss", object{"run": run, "budget_minutes": started["budget_minutes"], "elapsed_seconds": math.Round(time.Since(began).Seconds()*1000) / 1000})
		if err != nil {
			return err
		}
		recorder.put(e)
	}
	end := endedPayload(run, reason, code, signalNumber, time.Since(began).Seconds(), pattern, classification, len(survivors), progress.fate())
	if os.Getenv("LANEBOSS_INSTANCE") != "" {
		fmt.Fprintf(watch, "%s run %d: automatic organisation history ingest is not yet ported; lane ingest is required\n", nowStamp(), run)
	}
	return recorder.ending(end, started)
}
func endedPayload(run int, reason string, code, signal any, duration float64, pattern, classification any, survivors int, prompt object) object {
	p := object{"run": run, "reason": reason, "exit_code": code, "signal": signal, "duration_seconds": math.Round(math.Max(duration, 0)*1000) / 1000, "pattern": pattern, "classification": classification, "survivors": survivors}
	if prompt != nil {
		p["prompt"] = prompt
	}
	return p
}
func classifyOutput(s *laneSession, lane string, offset int64, spec object) (string, any, any, error) {
	if len(array(spec["limit_patterns"])) == 0 && len(array(spec["dropped_patterns"])) == 0 {
		return "exit", nil, nil, nil
	}
	file, err := openLog(s, lane)
	if err != nil {
		return "", nil, nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return "", nil, nil, err
	}
	if offset > info.Size() {
		return "", nil, nil, integrity("the lane's output log was truncated")
	}
	begin := max(offset, info.Size()-65536)
	data, err := io.ReadAll(io.NewSectionReader(file, begin, info.Size()-begin))
	if err != nil {
		return "", nil, nil, err
	}
	lines := strings.Split(strings.ToValidUTF8(string(data), "\ufffd"), "\n")
	if begin > offset && len(lines) > 0 {
		lines = lines[1:]
	}
	type outputPattern struct {
		group string
		index int
		rx    *regexp.Regexp
	}
	patterns := []outputPattern{}
	for _, group := range []string{"limit", "dropped"} {
		for i, pattern := range texts(spec[group+"_patterns"]) {
			rx, err := regexp.Compile(pattern)
			if err != nil {
				return "", nil, nil, invalid("the runner's output pattern cannot be compiled")
			}
			patterns = append(patterns, outputPattern{group, i, rx})
		}
	}
	for i := len(lines) - 1; i >= 0; i-- {
		line := cutText(strings.TrimSuffix(lines[i], "\r"), 4096)
		for _, pattern := range patterns {
			if pattern.rx.MatchString(line) {
				return pattern.group, fmt.Sprintf("%s_patterns[%d]", pattern.group, pattern.index), "matched", nil
			}
		}
	}
	return "exit", nil, "unmatched", nil
}
func recordOrQueue(s *laneSession, lane string, e object, watch io.Writer) error {
	_, err := s.appendEnvelopeWait(e, false, 200)
	if err == nil {
		return nil
	}
	var p *problem
	if value, ok := err.(*problem); ok {
		p = value
	}
	if p != nil && p.code == 2 && !strings.Contains(p.message, "busy") && !strings.Contains(p.message, "waiting") {
		dir, openErr := s.state.dir("lanes/"+lane, true)
		if openErr != nil {
			return openErr
		}
		defer dir.Close()
		lock, openErr := lockRoot(dir, ".", 60, "lane directory lock", false, false)
		if openErr != nil {
			return openErr
		}
		defer lock.close()
		data, readErr := readAt(dir, "refused.jsonl", "refused.jsonl", 16*1024*1024)
		if readErr != nil && !os.IsNotExist(readErr) {
			return readErr
		}
		line, encodeErr := canonical(object{"envelope": e, "reason": p.message})
		if encodeErr != nil {
			return encodeErr
		}
		return writeAtomic(dir, "refused.jsonl", append(append(data, line...), '\n'), 0600, true)
	}
	dir, openErr := s.state.dir("lanes/"+lane, true)
	if openErr != nil {
		return openErr
	}
	defer dir.Close()
	lock, openErr := lockRoot(dir, ".", 60, "lane directory lock", false, false)
	if openErr != nil {
		return openErr
	}
	defer lock.close()
	data, readErr := readAt(dir, "pending.jsonl", "pending.jsonl", 16*1024*1024)
	if readErr != nil && !os.IsNotExist(readErr) {
		name := "pending-" + str(obj(e["payload"])["launch"])
		id, idErr := randomID()
		if idErr != nil {
			return idErr
		}
		line, encodeErr := canonical(e)
		if encodeErr != nil {
			return encodeErr
		}
		return writeAtomic(dir, name+"-"+id[:8]+".jsonl", append(line, '\n'), 0600, false)
	}
	line, encodeErr := canonical(e)
	if encodeErr != nil {
		return encodeErr
	}
	fmt.Fprintf(watch, "%s an event is pending: %s\n", nowStamp(), safeDetail(err))
	return writeAtomic(dir, "pending.jsonl", append(append(data, line...), '\n'), 0600, true)
}
