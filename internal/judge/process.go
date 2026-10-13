package judge

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

type result struct {
	Judge       string   `json:"judge"`
	Question    string   `json:"question"`
	Outcome     string   `json:"outcome"`
	Probability *float64 `json:"probability"`
	Model       *string  `json:"model"`
	Request     *string  `json:"request"`
	Withheld    []string `json:"withheld"`
	Cut         []string `json:"cut"`
	Duration    int64    `json:"duration_ms"`
}

func askJudge(c *configuration, o options, j judgeDefinition, r request) (result, string, bool, error) {
	res := result{Judge: o.judge, Question: o.question, Withheld: r.withheld, Cut: r.cut}
	state, err := c.openState(true)
	if err != nil {
		return res, "", false, err
	}
	defer state.close()
	if err = state.recordOwner(c); err != nil {
		return res, "", false, err
	}
	directory, err := state.childDirectory("judges", true)
	if err != nil {
		return res, "", false, egressProblem(nothingAsked + ": the egress log's directory cannot be made or opened (" + safeFailure(err) + ")")
	}
	defer directory.close()
	interrupts := make(chan os.Signal, 1)
	signal.Notify(interrupts, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	defer signal.Stop(interrupts)
	if err = state.file.Sync(); err != nil {
		return res, "", false, egressProblem(nothingAsked + ": the state directory cannot be synced (" + safeOSMessage(err) + ")")
	}
	ask, err := newID()
	if err != nil {
		return res, "", false, err
	}
	var lane any
	if o.laneSet {
		lane = o.lane
	}
	sent := map[string]any{"at": utcNow(), "ask": ask, "event": "sent", "judge": o.judge, "question": o.question, "lane": lane, "request_sha256": r.hash, "request_bytes": len(r.data), "withheld": r.withheld, "cut": r.cut}
	if err = directory.writeLog(logBytes(sent), true, nothingAsked); err != nil {
		return res, "", false, err
	}
	started := time.Now()
	reason, status, out, stderr, interrupted := runCommand(j.command, r.data, j.seconds, interrupts)
	var a answer
	if reason == "" {
		if status != 0 {
			reason = "exit"
		} else if found, ok := readAnswer(out); ok {
			reason = "answered"
			a = found
		} else {
			reason = "output"
		}
	}
	res.Outcome, res.Probability, res.Model, res.Request = reason, a.p, a.model, a.request
	res.Duration = int64(time.Since(started).Round(time.Millisecond) / time.Millisecond)
	outcome := map[string]any{"at": utcNow(), "ask": ask, "event": "outcome", "outcome": reason, "probability": a.p, "model": a.model, "request": a.request, "duration_ms": res.Duration}
	if err = directory.writeLog(logBytes(outcome), false, outcomeUnlogged); err != nil {
		return res, "", interrupted, err
	}
	detail := ""
	if reason != "answered" {
		switch reason {
		case "timeout":
			detail = fmt.Sprintf("no answer within %d second(s)", j.seconds)
		case "not-found":
			detail = "the program was not found or could not be started"
		case "output":
			detail = "standard output is not one answer object"
		default:
			if status > 0 {
				detail = fmt.Sprintf("exit status %d", status)
			} else {
				detail = "ended by a signal"
			}
		}
		if line := explanation(stderr); line != "" {
			detail += ": " + line
		}
	}
	return res, detail, interrupted, nil
}

type pipeData struct {
	bytes  []byte
	failed bool
}

func collectPipe(f *os.File, limit int, rejectOverflow bool, overflow chan<- struct{}, done chan<- pipeData) {
	defer f.Close()
	data := make([]byte, 0, limit)
	buf := make([]byte, 32768)
	for {
		n, err := f.Read(buf)
		if n > 0 {
			room := limit - len(data)
			if n > room && rejectOverflow {
				data = append(data, buf[:room]...)
				select {
				case overflow <- struct{}{}:
				default:
				}
				done <- pipeData{data, true}
				return
			}
			if n > room {
				n = room
			}
			data = append(data, buf[:n]...)
		}
		if err != nil {
			done <- pipeData{data, err != io.EOF && !os.IsTimeout(err) && !strings.Contains(err.Error(), "closed")}
			return
		}
	}
}

// All three pipes are pumped independently. Waiting for the leader never waits
// for a child that inherited a pipe, and every read has the total ask deadline.
func runCommand(argv []string, input []byte, seconds int, interrupts <-chan os.Signal) (string, int, []byte, []byte, bool) {
	var opened []*os.File
	closeOpened := func() {
		for _, f := range opened {
			f.Close()
		}
	}
	inRead, inWrite, err := os.Pipe()
	if err != nil {
		return "not-found", -1, nil, nil, false
	}
	opened = append(opened, inRead, inWrite)
	outRead, outWrite, err := os.Pipe()
	if err != nil {
		closeOpened()
		return "not-found", -1, nil, nil, false
	}
	opened = append(opened, outRead, outWrite)
	errRead, errWrite, err := os.Pipe()
	if err != nil {
		closeOpened()
		return "not-found", -1, nil, nil, false
	}
	opened = append(opened, errRead, errWrite)
	defer closeOpened()
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = inRead, outWrite, errWrite
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	cmd.Env = make([]string, 0)
	for _, variable := range os.Environ() {
		if !strings.HasPrefix(variable, "LANEBOSS_") {
			cmd.Env = append(cmd.Env, variable)
		}
	}
	select {
	case <-interrupts:
		return "exit", -1, nil, nil, true
	default:
	}
	if err = cmd.Start(); err != nil {
		return "not-found", -1, nil, nil, false
	}
	inRead.Close()
	outWrite.Close()
	errWrite.Close()
	deadline := time.Now().Add(time.Duration(seconds) * time.Second)
	outputDeadline := outRead.SetReadDeadline(deadline)
	errorDeadline := errRead.SetReadDeadline(deadline)
	inputDeadline := inWrite.SetWriteDeadline(deadline)
	writeDone := make(chan struct{}, 1)
	go func() { _, _ = inWrite.Write(input); inWrite.Close(); writeDone <- struct{}{} }()
	overflow := make(chan struct{}, 1)
	outDone := make(chan pipeData, 1)
	errDone := make(chan pipeData, 1)
	go collectPipe(outRead, 65536, true, overflow, outDone)
	go collectPipe(errRead, 4096, false, overflow, errDone)
	waitDone := make(chan error, 1)
	go func() { waitDone <- cmd.Wait() }()
	timer := time.NewTimer(time.Until(deadline))
	defer timer.Stop()
	reason := ""
	interrupted := false
	ended := false
	if outputDeadline != nil || errorDeadline != nil || inputDeadline != nil {
		reason = "exit"
		outRead.Close()
		errRead.Close()
		inWrite.Close()
	} else {
		select {
		case <-overflow:
			reason = "output"
		case <-timer.C:
			reason = "timeout"
		case <-interrupts:
			reason = "exit"
			interrupted = true
		case <-waitDone:
			ended = true
		}
	}
	if reason == "" && !time.Now().Before(deadline) {
		reason = "timeout"
	}
	if ended {
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	} else {
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM)
		grace := time.NewTimer(time.Second)
		select {
		case <-waitDone:
			ended = true
		case <-grace.C:
		}
		grace.Stop()
		// A leader may have ended while a child ignores TERM; always kill the group.
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		if !ended {
			killGrace := time.NewTimer(time.Second)
			select {
			case <-waitDone:
				ended = true
			case <-killGrace.C:
			}
			killGrace.Stop()
		}
	}
	inWrite.Close()
	// Drain bytes already in the pipes, bounded even for a writer in a detached
	// session. Closing the read ends gives that writer SIGPIPE.
	drainDeadline := time.Now().Add(50 * time.Millisecond)
	if drainDeadline.After(deadline) {
		drainDeadline = deadline
	}
	if err := outRead.SetReadDeadline(drainDeadline); err != nil {
		outRead.Close()
	}
	if err := errRead.SetReadDeadline(drainDeadline); err != nil {
		errRead.Close()
	}
	out, errout := <-outDone, <-errDone
	<-writeDone
	if reason == "" && out.failed {
		reason = "output"
	}
	select {
	case <-overflow:
		if reason == "" {
			reason = "output"
		}
	default:
	}
	status := -1
	if ended && cmd.ProcessState != nil {
		status = cmd.ProcessState.ExitCode()
	}
	return reason, status, out.bytes, errout.bytes, interrupted
}
