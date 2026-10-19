package boxrun

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"laneboss.io/laneboss/internal/boxcore"
)

type runSession struct {
	s                *service
	ctx              context.Context
	opts             boxcore.RunOptions
	req              boxcore.Request
	p                boxcore.Provider
	tr               boxcore.Transport
	transportOpts    boxcore.TransportOptions
	result           boxcore.RunResult
	err              error
	sourceSHA        string
	launchAt         time.Time
	startedAt        time.Time
	started          bool
	complete         bool
	stopped          bool
	harvestAttempted bool
	verified         bool
}

// Run launches, executes, verifies results and confirms cleanup on every path.
func (s *service) Run(ctx context.Context, o boxcore.RunOptions) (result boxcore.RunResult, err error) {
	result = boxcore.RunResult{SuiteExit: -1, Verdict: "launch-failed", ExitCode: boxcore.ExitUsage}
	req, err := s.request(o.Request)
	if err != nil {
		return result, err
	}
	p, err := s.provider(req.Provider)
	if err != nil {
		return result, err
	}
	dir := o.OutDir
	if dir == "" {
		dir = filepath.Join(s.d.Config.Defaults.RunDir, req.RunID)
	}
	work := &runSession{s: s, ctx: ctx, opts: o, req: req, p: p,
		result: boxcore.RunResult{RunID: req.RunID, SuiteExit: -1, OutDir: dir}}
	// Install cleanup before launch: WaitRunning and the ledger may panic too.
	defer func() {
		if recovered := recover(); recovered != nil {
			work.fail(boxcore.ExitInternal, "internal", fmt.Errorf("boxrun: panic: %v", recovered))
		}
		work.finish()
		result, err = work.result, work.err
	}()
	launched, effective, launchErr := s.launch(ctx, boxcore.LaunchOptions{Request: req}, true,
		func(b boxcore.Box, attempt boxcore.Request) {
			work.result.Box, work.req = b, attempt
			if work.launchAt.IsZero() {
				work.launchAt = s.d.Now()
			}
		})
	work.req = effective
	if launched.ExitCode != boxcore.ExitOK {
		work.result.ExitCode, work.result.Verdict = launched.ExitCode, "launch-failed"
		work.err = launchErr
		return work.result, work.err
	}
	work.result.Box = launched.Box
	if launchUTC, ok := boxcore.NormalizeUTC(launched.Box.LaunchTimeUTC); ok {
		if parsed, parseErr := time.Parse(time.RFC3339, launchUTC); parseErr == nil {
			work.launchAt = parsed
		}
	}
	work.execute()
	return work.result, work.err
}

func (w *runSession) execute() {
	root, err := openOutput(w.result.OutDir)
	if err != nil {
		w.fail(boxcore.ExitAccess, "access", err)
		return
	}
	if err := root.Close(); err != nil {
		w.fail(boxcore.ExitAccess, "access", err)
		return
	}
	if w.opts.Archive != "" {
		w.sourceSHA, err = copySource(w.opts.Archive, w.result.OutDir)
		if err != nil {
			w.fail(boxcore.ExitAccess, "access", err)
			return
		}
	}
	if !boxcore.PlainName(w.result.Box.ID) {
		w.fail(boxcore.ExitAccess, "access", errors.New("boxrun: unsafe instance id for host key file"))
		return
	}
	w.transportOpts.KnownHostsFile = filepath.Join(w.result.OutDir, "known_hosts."+w.result.Box.ID)
	w.tr = w.p.Transport(w.result.Box, w.transportOpts)
	if err := w.ready(); err != nil {
		w.fail(boxcore.ExitAccess, "access", err)
		return
	}
	if err := w.upload(); err != nil {
		w.fail(boxcore.ExitAccess, "access", err)
		return
	}
	var output shortOutput
	// A transport failure can occur after the detached process has started.
	w.started, w.startedAt = true, w.s.d.Now()
	code, err := execBound(w.ctx, w.tr, startCommand(w.s.d.Config.Guest.OutDir), nil,
		&output, w.s.d.Err, 30*time.Second)
	if err != nil || code != 0 || strings.TrimSpace(output.String()) != "started" {
		w.fail(boxcore.ExitAccess, "access", errors.Join(err, fmt.Errorf("boxrun: wrapper start exit %d", code)))
		return
	}
	w.pollSuite()
	if w.result.ExitCode != boxcore.ExitPreempted && w.ctx.Err() == nil {
		if !w.complete {
			w.stop()
		}
		w.collect()
	}
}

func (w *runSession) ready() error {
	var last error
	for attempt := 0; attempt < 30; attempt++ {
		code, err := execBound(w.ctx, w.tr, readyCommand(), nil, nil, w.s.d.Err, 30*time.Second)
		if err == nil && code == 0 {
			return nil
		}
		last = errors.Join(err, fmt.Errorf("boxrun: ready exit %d", code))
		if w.ctx.Err() != nil {
			return errors.Join(last, w.ctx.Err())
		}
		if attempt < 29 {
			if err := w.s.d.Sleep(w.ctx, 6*time.Second); err != nil {
				return errors.Join(last, err)
			}
		}
	}
	return last
}

func (w *runSession) upload() error {
	if w.opts.Archive != "" {
		if err := w.uploadFile(filepath.Join(w.result.OutDir, "src.tar"), remoteSource); err != nil {
			return err
		}
	}
	for _, put := range w.opts.Puts {
		remote := put.Remote
		if remote == "" {
			remote = "/tmp/" + filepath.Base(put.Local)
		}
		if err := w.uploadFile(put.Local, remote); err != nil {
			return err
		}
	}
	if err := w.uploadReader(strings.NewReader(suiteScript(w.opts.Suite, w.opts.Archive != "")), remoteSuite); err != nil {
		return err
	}
	wrapper, err := wrapperScript(w.s.d.Config.Guest, w.req.RunID)
	if err != nil {
		return err
	}
	return w.uploadReader(strings.NewReader(wrapper), remoteWrapper)
}

func (w *runSession) uploadFile(local, remote string) error {
	if err := remotePath(remote); err != nil {
		return err
	}
	file, err := os.Open(local)
	if err != nil {
		return err
	}
	return errors.Join(w.uploadReader(file, remote), file.Close())
}

func (w *runSession) uploadReader(input io.Reader, remote string) error {
	command, err := uploadCommand(remote)
	if err != nil {
		return err
	}
	code, err := execBound(w.ctx, w.tr, command, input, nil, w.s.d.Err, 2*time.Minute)
	if err != nil || code != 0 {
		return errors.Join(err, fmt.Errorf("boxrun: upload exit %d", code))
	}
	return nil
}

func (w *runSession) pollSuite() {
	timeoutMin := w.req.HardMin - 5
	if w.opts.TimeoutMin > 0 {
		timeoutMin = min(timeoutMin, w.opts.TimeoutMin)
	}
	deadline := w.startedAt.Add(time.Duration(timeoutMin) * time.Minute)
	hourly := boxcore.HourlyUSD(w.result.Box.QuoteUSDHour, w.req.RootGB, w.s.d.Config.Defaults.DiskUSDGBMonth)
	failures := 0
	var unreachableAt time.Time
	for {
		if err := w.ctx.Err(); err != nil {
			w.fail(boxcore.ExitAccess, "access", err)
			return
		}
		now := w.s.d.Now()
		if !now.Before(deadline) {
			w.fail(boxcore.ExitTimeout, "timeout", nil)
			w.stop()
			return
		}
		if now.Sub(w.launchAt).Hours()*hourly > w.req.CostCapUSD {
			w.fail(boxcore.ExitCostCap, "cost-cap", nil)
			w.stop()
			return
		}
		var output shortOutput
		code, err := execBound(w.ctx, w.tr, pollCommand(w.s.d.Config.Guest.OutDir), nil,
			&output, w.s.d.Err, 30*time.Second)
		if err != nil || code != 0 {
			if failures == 0 {
				unreachableAt = w.s.d.Now()
			}
			failures++
			w.s.note("suite poll for %s failed: exit %d, %v", w.result.Box.ID, code, err)
			if failures%3 == 0 {
				state, describeErr := describeBound(w.ctx, w.p, w.result.Box)
				if describeErr != nil {
					w.s.note("describe during suite for %s: %v", w.result.Box.ID, describeErr)
				} else if taken(state.Name) {
					w.fail(boxcore.ExitPreempted, "preempted", nil)
					w.fetchPartial()
					w.harvestAttempted = true
					return
				}
			}
			if w.s.d.Now().Sub(unreachableAt) >= 10*time.Minute {
				w.fail(boxcore.ExitAccess, "access", errors.New("boxrun: unreachable for ten minutes"))
				return
			}
		} else {
			failures = 0
			word := strings.TrimSpace(output.String())
			if word != "running" {
				if _, err := strconv.Atoi(word); err != nil {
					w.fail(boxcore.ExitAccess, "access", errors.New("boxrun: invalid suite poll response"))
					return
				}
				// The actual suite result comes only from the verified harvest.
				w.complete = true
				return
			}
		}
		if err := w.s.d.Sleep(w.ctx, 15*time.Second); err != nil {
			w.fail(boxcore.ExitAccess, "access", err)
			return
		}
	}
}

func (w *runSession) fetchPartial() {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(w.ctx), 2*time.Minute)
	defer cancel()
	dir := filepath.Join(w.result.OutDir, "partial")
	root, err := openOutput(dir)
	if err == nil {
		err = root.Close()
	}
	if err != nil {
		w.s.note("partial harvest directory for %s: %v", w.result.Box.ID, err)
		return
	}
	if _, err := w.p.FetchHarvest(ctx, w.result.Box, w.req.RunID, dir); err != nil &&
		boxcore.KindOf(err) != boxcore.KindUnsupported {
		w.s.note("partial harvest for %s: %v", w.result.Box.ID, err)
	}
}

func (w *runSession) stop() {
	if w.stopped || w.complete || !w.started {
		return
	}
	w.stopped = true
	ctx, cancel := context.WithTimeout(context.WithoutCancel(w.ctx), 2*time.Minute)
	defer cancel()
	code, err := execBound(ctx, w.tr, killCommand(w.s.d.Config.Guest.OutDir), nil, nil, w.s.d.Err, 30*time.Second)
	if err != nil || code != 0 {
		w.s.note("stop wrapper for %s: exit %d, %v", w.result.Box.ID, code, err)
	}
	deadline := w.s.d.Now().Add(20 * time.Second)
	for {
		var output shortOutput
		code, err := execBound(ctx, w.tr, pollCommand(w.s.d.Config.Guest.OutDir), nil,
			&output, w.s.d.Err, 5*time.Second)
		if err == nil && code == 0 && strings.TrimSpace(output.String()) != "running" {
			if _, err := strconv.Atoi(strings.TrimSpace(output.String())); err == nil {
				w.complete = true
				return
			}
		}
		remaining := deadline.Sub(w.s.d.Now())
		if remaining <= 0 {
			w.s.note("wrapper for %s did not complete within twenty seconds", w.result.Box.ID)
			return
		}
		if err := w.s.d.Sleep(ctx, min(remaining, time.Second)); err != nil {
			w.s.note("wait for wrapper %s: %v", w.result.Box.ID, err)
			return
		}
	}
}

func (w *runSession) collect() {
	if w.harvestAttempted || w.tr == nil {
		return
	}
	w.harvestAttempted = true
	ctx, cancel := context.WithTimeout(context.WithoutCancel(w.ctx), 2*time.Minute)
	defer cancel()
	dir := filepath.Join(w.result.OutDir, "out")
	info, err := w.s.harvest(ctx, w.tr, w.s.d.Config.Guest.OutDir, dir, w.stopped)
	w.result.Files, w.result.Bytes = info.files, info.bytes
	if err != nil {
		w.fail(boxcore.ExitHarvest, "harvest-failed", err)
		return
	}
	suiteExit, err := readSuiteExit(dir, info)
	if err != nil {
		w.fail(boxcore.ExitHarvest, "harvest-failed", err)
		return
	}
	w.result.SuiteExit, w.result.ManifestSHA256, w.verified = suiteExit, info.manifest, true
	if suiteExit != 0 {
		w.fail(boxcore.ExitFailed, "failed", nil)
	} else if w.result.ExitCode == boxcore.ExitOK {
		w.result.Verdict = "passed"
	}
}

func (w *runSession) finish() {
	defer w.saveResult()
	if w.result.Box.ID == "" {
		return
	}
	// End is a separate defer so a cleanup harvest panic cannot bypass it.
	defer func() {
		if recovered := recover(); recovered != nil {
			w.fail(boxcore.ExitInternal, "internal", fmt.Errorf("boxrun: cleanup panic: %v", recovered))
		}
		w.endBox()
	}()
	if w.ctx.Err() != nil && w.result.Verdict != "launch-failed" {
		w.fail(boxcore.ExitAccess, "access", w.ctx.Err())
	}
	if w.started && !w.harvestAttempted {
		w.stop()
		w.collect()
	}
	if w.result.ExitCode == boxcore.ExitOK && !w.verified {
		w.fail(boxcore.ExitHarvest, "harvest-failed", errors.New("boxrun: harvest not verified"))
	}
}

func (w *runSession) endBox() {
	extra := map[string]any{
		"suite_exit": w.result.SuiteExit, "verdict": w.result.Verdict,
		"harvest_files": w.result.Files, "harvest_bytes": w.result.Bytes,
	}
	if w.sourceSHA != "" {
		extra["src_sha256"] = w.sourceSHA
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(w.ctx), 11*time.Minute)
	defer cancel()
	ended, err := w.s.end(ctx, boxcore.EndOptions{Provider: w.req.Provider,
		ID: w.result.Box.ID, Address: w.result.Box.Address}, extra, w.result.Box,
		w.req.RunID, w.transportOpts)
	w.err = errors.Join(w.err, err)
	w.result.Terminated = terminal(ended.State) && !ended.Pending
	w.result.BilledSeconds = ended.BilledSeconds
	hourly := boxcore.HourlyUSD(w.result.Box.QuoteUSDHour, w.req.RootGB, w.s.d.Config.Defaults.DiskUSDGBMonth)
	w.result.CostUSD = float64(ended.BilledSeconds) / 3600 * hourly
	if ended.Pending || !w.result.Terminated {
		w.result.ExitCode, w.result.Verdict = boxcore.ExitEndPending, "end-pending"
	} else if ended.ExitCode != boxcore.ExitOK && w.result.ExitCode == boxcore.ExitOK {
		w.result.ExitCode, w.result.Verdict = ended.ExitCode, "end-failed"
	}
}

func (w *runSession) saveResult() {
	if recovered := recover(); recovered != nil {
		w.fail(boxcore.ExitEndPending, "end-pending", fmt.Errorf("boxrun: end panic: %v", recovered))
	}
	if err := writeRunJSON(w.result); err != nil {
		w.err = errors.Join(w.err, err)
		w.s.note("write run result: %v", err)
		if w.result.ExitCode == boxcore.ExitOK {
			w.result.ExitCode, w.result.Verdict = boxcore.ExitInternal, "internal"
		}
	}
}

func (w *runSession) fail(code int, verdict string, err error) {
	w.err = errors.Join(w.err, err)
	if exitPriority(code) > exitPriority(w.result.ExitCode) {
		w.result.ExitCode, w.result.Verdict = code, verdict
	}
}

func exitPriority(code int) int {
	switch code {
	case boxcore.ExitOK:
		return 0
	case boxcore.ExitFailed:
		return 1
	case boxcore.ExitCostCap:
		return 2
	case boxcore.ExitTimeout:
		return 3
	case boxcore.ExitHarvest:
		return 4
	case boxcore.ExitAccess:
		return 5
	case boxcore.ExitPreempted:
		return 6
	case boxcore.ExitEndPending:
		return 8
	default:
		return 7
	}
}

type shortOutput struct {
	buf bytes.Buffer
}

func (b *shortOutput) Write(data []byte) (int, error) {
	if len(data) > 4096-b.buf.Len() {
		return 0, errors.New("boxrun: command response too large")
	}
	return b.buf.Write(data)
}

func (b *shortOutput) String() string {
	return b.buf.String()
}

func copySource(source, dir string) (digest string, err error) {
	input, err := os.Open(source)
	if err != nil {
		return "", err
	}
	defer func() { err = errors.Join(err, input.Close()) }()
	root, err := os.OpenRoot(dir)
	if err != nil {
		return "", err
	}
	defer func() { err = errors.Join(err, root.Close()) }()
	output, err := root.OpenFile("src.tar", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return "", err
	}
	hash := sha256.New()
	_, copyErr := io.Copy(io.MultiWriter(output, hash), input)
	if err := errors.Join(copyErr, output.Close()); err != nil {
		return "", err
	}
	digest = hex.EncodeToString(hash.Sum(nil))
	checksum, err := root.OpenFile("src.tar.sha256", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return "", err
	}
	_, writeErr := io.WriteString(checksum, digest+"  src.tar\n")
	return digest, errors.Join(writeErr, checksum.Close())
}

func readSuiteExit(dir string, info harvestInfo) (code int, err error) {
	if !info.names["suite.exit"] || !info.names[".complete"] {
		return -1, errors.New("boxrun: missing suite exit or completion marker")
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return -1, err
	}
	defer func() { err = errors.Join(err, root.Close()) }()
	file, err := openRegular(root, "suite.exit")
	if err != nil {
		return -1, err
	}
	data, readErr := io.ReadAll(io.LimitReader(file, 129))
	if err := errors.Join(readErr, file.Close()); err != nil {
		return -1, err
	}
	if len(data) > 128 {
		return -1, errors.New("boxrun: suite exit is too large")
	}
	code, err = strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil || code < 0 || code > 255 {
		return -1, errors.New("boxrun: invalid harvested suite exit")
	}
	return code, nil
}

func writeRunJSON(result boxcore.RunResult) (err error) {
	root, err := openOutput(result.OutDir)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, root.Close()) }()
	file, err := root.OpenFile("run.json", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	return errors.Join(encoder.Encode(result), file.Close())
}
