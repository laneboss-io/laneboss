package lane

import (
	"bufio"
	"io"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"
)

type scanFollower struct {
	command          *exec.Cmd
	identity         object
	control, output  *os.File
	done, readerDone chan struct{}
}

func (r *supervisedRun) startScanner() {
	if !configured(r.s.c, str(obj(r.spec["started"])["runner"])) {
		return
	}
	binary, err := os.Executable()
	if err != nil {
		debugRun(r.run, r.watch, "the refusal scan could not be started")
		return
	}
	inRead, inWrite, err := os.Pipe()
	if err != nil {
		return
	}
	outRead, outWrite, err := os.Pipe()
	if err != nil {
		inRead.Close()
		inWrite.Close()
		return
	}
	command := exec.Command(binary, "__follow")
	command.Args[0] = scannerProcessLabel
	command.Stdin = inRead
	command.Stdout = outWrite
	command.Stderr = r.watch
	command.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err = command.Start(); err != nil {
		inRead.Close()
		inWrite.Close()
		outRead.Close()
		outWrite.Close()
		debugRun(r.run, r.watch, "the refusal scan could not be started")
		return
	}
	inRead.Close()
	outWrite.Close()
	r.helpers[command.Process.Pid] = true
	identity, err := processIdentity(command.Process.Pid)
	if err != nil || identity == nil {
		inWrite.Close()
		outRead.Close()
		if killError := command.Process.Kill(); killError != nil && killError != os.ErrProcessDone {
			debugRun(r.run, r.watch, "the refusal scan's own child could not be signalled")
		}
		waited := make(chan struct{})
		go func() { command.Wait(); close(waited) }()
		select {
		case <-waited:
		case <-time.After(5 * time.Second):
			debugRun(r.run, r.watch, "the refusal scan (pid %d) could not be collected", command.Process.Pid)
		}
		return
	}
	f := &scanFollower{command: command, identity: identity, control: inWrite, output: outRead, done: make(chan struct{}), readerDone: make(chan struct{})}
	r.scanner = f
	go func() { command.Wait(); close(f.done) }()
	go func() {
		defer close(f.readerDone)
		reader := bufio.NewReaderSize(outRead, 65536)
		for {
			line, _, _, large, err := boundedLine(reader)
			if err != nil && len(line) == 0 {
				return
			}
			if !large {
				v, e := parseJSON(line)
				event := obj(v)
				if e == nil && contains([]string{"lane.refusal", "lane.workaround_suspected"}, str(event["kind"])) && str(event["lane"]) == r.lane {
					r.recorder.enqueue(event)
				}
			}
			if err != nil {
				return
			}
		}
	}()
	job := object{"config": r.s.c.name, "lane": r.lane, "run": r.run}
	if _, err = inWrite.Write(append(canonical(job), '\n')); err != nil {
		r.stopScanner(false, "")
	}
}
func (r *supervisedRun) stopScanner(final bool, endedAt string) {
	f := r.scanner
	if f == nil {
		return
	}
	r.scanner = nil
	deadline := time.Now().Add(7 * time.Second)
	if final {
		job := object{"finish": endedAt, "log_end": obj(r.record["log"])["end"]}
		f.control.Write(append(canonical(job), '\n'))
	} else {
		f.control.Close()
	}
	wait := time.NewTimer(5 * time.Second)
	select {
	case <-f.done:
		wait.Stop()
	case <-wait.C:
		// The Go process handle names this exact child and is marked done by Wait.
		// A slow or unavailable external process-table reader must not extend the bound.
		if err := f.command.Process.Signal(syscall.SIGTERM); err != nil && err != os.ErrProcessDone {
			debugRun(r.run, r.watch, "the refusal scan (pid %d) could not receive SIGTERM", f.command.Process.Pid)
		}
		select {
		case <-f.done:
		case <-time.After(time.Second):
			if err := f.command.Process.Kill(); err != nil && err != os.ErrProcessDone {
				debugRun(r.run, r.watch, "the refusal scan (pid %d) could not receive SIGKILL", f.command.Process.Pid)
			}
		}
	}
	remaining := time.Until(deadline)
	if remaining < 0 {
		remaining = 0
	}
	select {
	case <-f.done:
	case <-time.After(remaining):
		debugRun(r.run, r.watch, "the refusal scan did not end in time; lane scan covers the run")
	}
	f.control.Close()
	select {
	case <-f.readerDone:
	case <-time.After(max(time.Duration(0), time.Until(deadline))):
		f.output.Close()
		debugRun(r.run, r.watch, "the refusal scan's output did not close in time")
	}
	f.output.Close()
}
func followRecords(stdin io.Reader, stdout, stderr io.Writer) int {
	reader := bufio.NewReaderSize(stdin, 65536)
	first, _, _, large, err := boundedLine(reader)
	if err != nil || large {
		return 2
	}
	v, err := parseJSON(first)
	job := obj(v)
	if err != nil || !exactKeys(job, strings.Fields("config lane run")) {
		return 2
	}
	c, err := loadConfiguration(str(job["config"]))
	if err != nil {
		return 2
	}
	s, err := openSession(c, false)
	if err != nil {
		return 2
	}
	defer s.close()
	lane, run := str(job["lane"]), integer(job["run"])
	if !match(`[a-z0-9][a-z0-9._-]{0,63}`, lane) {
		return 2
	}
	controls := make(chan object, 1)
	go func() {
		for {
			line, _, _, large, err := boundedLine(reader)
			if err != nil || large {
				controls <- nil
				return
			}
			v, e := parseJSON(line)
			if e == nil {
				controls <- obj(v)
			}
		}
	}()
	known := map[string]bool{}
	emit := func(e object) error {
		p := obj(e["payload"])
		id := str(p["refusal"])
		if str(e["kind"]) == "lane.workaround_suspected" {
			id = str(p["suspicion"])
		}
		if known[id] {
			return nil
		}
		if _, err := stdout.Write(append(canonical(e), '\n')); err != nil {
			return err
		}
		known[id] = true
		return nil
	}
	scan, err := newScan(s, lane, "supervising process", false, emit)
	if err != nil {
		debugRun(run, stderr, "the refusal scan could not start")
		return 3
	}
	scan.live = true
	var current *scanRun
	for _, item := range scan.runs {
		if item.number == run {
			current = item
		}
	}
	if current == nil || scan.runs[len(scan.runs)-1] != current {
		return 2
	}
	current.ended, current.end, current.logEnd = false, 0, -1
	saved := map[int]map[string]bool{}
	for _, item := range scan.runs {
		saved[item.number] = map[string]bool{}
		for _, entry := range scan.inventoryByRun[item.number] {
			if str(entry["state"]) != "covered" {
				saved[item.number][str(entry["path"])+"\x00"+str(entry["state"])] = true
			}
		}
	}
	written := time.Now()
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	for {
		final := false
		endedAt := ""
		logEnd := int64(-1)
		select {
		case control := <-controls:
			if control == nil {
				return 0
			}
			endedAt = str(control["finish"])
			if endedAt == "" {
				continue
			}
			final = true
			if whole(control["log_end"], 0, 1<<62) {
				logEnd = int64(number(control["log_end"]))
			}
		case <-ticker.C:
		}
		if err = s.refresh(); err != nil {
			debugRun(run, stderr, "the refusal scan could not read the store")
			if final {
				return 3
			}
			continue
		}
		scan.final = final
		if final {
			current.ended = true
			current.end, _ = moment(endedAt)
			current.logEnd = logEnd
			for _, record := range scan.records {
				if record.format == "text" && record.run == run {
					record.end = logEnd
				}
			}
		}
		if err = scan.read(); err != nil {
			debugRun(run, stderr, "the refusal scan failed: %s", safeMessage(err.Error()))
			if final {
				return 3
			}
			continue
		}
		due := time.Since(written) >= 5*time.Second
		for _, r := range scan.runs {
			coverage := scan.coverage(r)
			seen := map[string]bool{}
			changed := false
			for _, value := range list(coverage["inventory"]) {
				entry := obj(value)
				if str(entry["state"]) != "covered" {
					key := str(entry["path"]) + "\x00" + str(entry["state"])
					seen[key] = true
					changed = changed || !saved[r.number][key]
				}
			}
			if !final && !(due && r == current) && !changed {
				continue
			}
			kept, saveError := s.writeCoverage(lane, coverage)
			if saveError != nil {
				err = saveError
				debugRun(run, stderr, "the refusal scan's coverage could not be saved: %s", safeMessage(err.Error()))
				continue
			}
			for key := range seen {
				saved[r.number][key] = true
			}
			for _, value := range list(kept["inventory"]) {
				entry := obj(value)
				if str(entry["state"]) != "covered" {
					saved[r.number][str(entry["path"])+"\x00"+str(entry["state"])] = true
				}
			}
		}
		if due {
			written = time.Now()
		}
		if final {
			return 0
		}
	}
}
