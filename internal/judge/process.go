package judge

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"laneboss.io/laneboss/internal/faults"
	"laneboss.io/laneboss/internal/guardtime"
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

	command      string
	confidence   float64
	nouls        map[string]float64
	distribution map[string]float64
}

func askJudge(c *configuration, o options, j judgeDefinition, r request) (result, string, bool, error) {
	return askJudgeContext(context.Background(), c, o, j, r)
}

func askJudgeWithin(c *configuration, o options, j judgeDefinition, r request, limit time.Duration) (result, string, bool, error) {
	ctx := context.Background()
	if limit > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, limit)
		defer cancel()
	}
	return askJudgeContext(ctx, c, o, j, r)
}

func askJudgeContext(ctx context.Context, c *configuration, o options, j judgeDefinition, r request) (result, string, bool, error) {
	res := result{Judge: o.judge, Question: o.question, Withheld: r.withheld, Cut: r.cut}
	if err := ctx.Err(); err != nil {
		return res, "", false, err
	}
	state, err := c.openState(true)
	if err != nil {
		return res, "", false, err
	}
	defer state.close()
	return askJudgeInStateContext(ctx, c, state, o, j, r)
}

func askJudgeInStateWithin(c *configuration, state *directory, o options, j judgeDefinition, r request, limit time.Duration) (result, string, bool, error) {
	ctx := context.Background()
	if limit > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, limit)
		defer cancel()
	}
	return askJudgeInStateContext(ctx, c, state, o, j, r)
}

func askJudgeInState(c *configuration, state *directory, o options, j judgeDefinition, r request) (result, string, bool, error) {
	return askJudgeInStateContext(context.Background(), c, state, o, j, r)
}

func askJudgeInStateContext(ctx context.Context, c *configuration, state *directory, o options, j judgeDefinition, r request) (result, string, bool, error) {
	res := result{Judge: o.judge, Question: o.question, Withheld: r.withheld, Cut: r.cut}
	expected, err := filepath.EvalSymlinks(c.statePath)
	if err != nil || expected != state.real {
		return res, "", false, refused("the state directory does not belong to this configuration")
	}
	if err = state.recordOwner(c, ctx); err != nil {
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
	if err = faults.Sync(state.file); err != nil {
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
	if r.batch {
		sent["outcome_reserve"] = batchOutcomeReserve
	}
	if err = directory.writeLog(logBytes(sent), true, nothingAsked, ctx); err != nil {
		return res, "", false, err
	}
	started := time.Now()
	processCtx := ctx
	cancel := func() {}
	if deadline, ok := ctx.Deadline(); ok {
		// Reserve time inside the same budget for process cleanup and recording
		// the timeout outcome; a log lock never gets a fresh deadline.
		reserve := guardtime.Cleanup
		if remaining := time.Until(deadline) / 4; remaining < reserve {
			reserve = remaining
		}
		if reserve > 0 {
			processCtx, cancel = context.WithDeadline(ctx, deadline.Add(-reserve))
		}
	}
	defer cancel()
	reason, status, out, stderr, interrupted := runCommandEnvironmentContext(processCtx, j.command, r.data, j.seconds, interrupts, nil)
	var a answer
	decode := readAnswer
	if r.decode != nil {
		decode = r.decode
	}
	if reason == "" {
		if status != 0 {
			reason = "exit"
		} else if found, ok := decode(out); ok {
			reason = "answered"
			a = found
		} else {
			reason = "output"
		}
	}
	res.Outcome, res.Probability, res.Model, res.Request = reason, a.p, a.model, a.request
	res.command, res.confidence = a.command, a.confidence
	res.nouls = a.nouls
	res.distribution = a.distribution
	res.Duration = int64(time.Since(started).Round(time.Millisecond) / time.Millisecond)
	outcome := map[string]any{"at": utcNow(), "ask": ask, "event": "outcome", "outcome": reason, "probability": a.p, "model": a.model, "request": a.request, "duration_ms": res.Duration}
	if a.nouls != nil {
		outcome["probabilities"] = a.nouls
	}
	if err = directory.writeLog(logBytes(outcome), false, outcomeUnlogged, ctx); err != nil {
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
	return runCommandEnvironment(argv, input, seconds, interrupts, nil)
}

func runCommandEnvironment(argv []string, input []byte, seconds int, interrupts <-chan os.Signal, environment []string) (string, int, []byte, []byte, bool) {
	return runCommandEnvironmentContext(context.Background(), argv, input, seconds, interrupts, environment)
}

func runCommandWithin(argv []string, input []byte, seconds int, limit time.Duration, interrupts <-chan os.Signal) (string, int, []byte, []byte, bool) {
	ctx := context.Background()
	if limit > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, limit)
		defer cancel()
	}
	return runCommandEnvironmentContext(ctx, argv, input, seconds, interrupts, nil)
}

func runCommandEnvironmentWithin(argv []string, input []byte, seconds int, limit time.Duration, interrupts <-chan os.Signal, environment []string) (string, int, []byte, []byte, bool) {
	ctx := context.Background()
	if limit > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, limit)
		defer cancel()
	}
	return runCommandEnvironmentContext(ctx, argv, input, seconds, interrupts, environment)
}

func runCommandEnvironmentContext(ctx context.Context, argv []string, input []byte, seconds int, interrupts <-chan os.Signal, environment []string) (string, int, []byte, []byte, bool) {
	if ctx.Err() != nil {
		return "timeout", -1, nil, nil, false
	}
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
	if environment != nil {
		cmd.Env = environment
	}
	select {
	case <-interrupts:
		return "exit", -1, nil, nil, true
	default:
	}
	faults.BeforeJudgeStart()
	if err = cmd.Start(); err != nil {
		return "not-found", -1, nil, nil, false
	}
	inRead.Close()
	outWrite.Close()
	errWrite.Close()
	deadline := time.Now().Add(time.Duration(seconds) * time.Second)
	if bound, ok := ctx.Deadline(); ok && bound.Before(deadline) {
		deadline = bound
	}
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
		case <-ctx.Done():
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
		grace := time.NewTimer(50 * time.Millisecond)
		select {
		case <-waitDone:
			ended = true
		case <-grace.C:
		}
		grace.Stop()
		// A leader may have ended while a child ignores TERM; always kill the group.
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		if !ended {
			killGrace := time.NewTimer(50 * time.Millisecond)
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
