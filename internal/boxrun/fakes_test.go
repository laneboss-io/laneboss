package boxrun

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/boxcore"
)

type callTrace struct {
	items []string
}

func (c *callTrace) add(name string) {
	c.items = append(c.items, name)
}

type fakeClock struct {
	now   time.Time
	steps []time.Duration
}

func (c *fakeClock) Now() time.Time { return c.now }

func (c *fakeClock) Sleep(ctx context.Context, duration time.Duration) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	c.steps = append(c.steps, duration)
	c.now = c.now.Add(duration)
	return nil
}

type fakeLedger struct {
	trace       *callTrace
	writableErr error
	eventsErr   error
	failAppend  int
	appends     []map[string]any
	events      []map[string]any
}

func (l *fakeLedger) Writable() error {
	l.trace.add("ledger:writable")
	return l.writableErr
}

func (l *fakeLedger) Append(event string, fields map[string]any) (map[string]any, error) {
	l.trace.add("ledger:" + event)
	copy := make(map[string]any, len(fields)+1)
	for key, value := range fields {
		copy[key] = value
	}
	copy["event"] = event
	l.appends = append(l.appends, copy)
	if l.failAppend == len(l.appends) {
		return nil, errors.New("scripted append failure")
	}
	l.events = append(l.events, copy)
	return copy, nil
}

func (l *fakeLedger) Events() ([]map[string]any, error) {
	l.trace.add("ledger:events")
	return append([]map[string]any(nil), l.events...), l.eventsErr
}

type fakeGuest struct {
	specs []boxcore.GuestSpec
}

func (g *fakeGuest) Render(spec boxcore.GuestSpec) boxcore.Guest {
	g.specs = append(g.specs, spec)
	return boxcore.Guest{Startup: fmt.Sprintf("guard %s %d %d", spec.RunID, spec.IdleMin, spec.HardMin)}
}

type launchCall struct {
	req   boxcore.Request
	c     boxcore.Candidate
	guest boxcore.Guest
}

type fakeProvider struct {
	name           string
	clock          *fakeClock
	trace          *callTrace
	calls          map[string]int
	candidates     []boxcore.Candidate
	prepareErr     error
	prepares       []boxcore.Request
	candidateErr   error
	picks          []boxcore.Request
	launchErrs     []error
	launches       []launchCall
	box            boxcore.Box
	wait           func(context.Context, boxcore.Box) (boxcore.Box, error)
	waited         []boxcore.Box
	describe       func(context.Context, boxcore.Box, time.Time) (boxcore.State, error)
	described      []boxcore.Box
	teardownErr    error
	teardowns      []boxcore.Box
	dry            boxcore.DryResult
	dryErr         error
	dryCalls       []launchCall
	tr             boxcore.Transport
	transports     []boxcore.TransportOptions
	transportBoxes []boxcore.Box
	boxes          []boxcore.Box
	filters        []boxcore.ListFilter
	fetchErr       error
	fetchRuns      []string
	fetchDirs      []string
	fetched        []boxcore.Box
}

func (p *fakeProvider) called(method string) {
	p.calls[method]++
	p.trace.add("provider:" + method)
}

func (p *fakeProvider) Name() string {
	p.called("Name")
	return p.name
}

func (p *fakeProvider) Prepare(ctx context.Context, req boxcore.Request) error {
	p.called("Prepare")
	p.prepares = append(p.prepares, req)
	return errors.Join(ctx.Err(), p.prepareErr)
}

func (p *fakeProvider) Candidates(ctx context.Context, req boxcore.Request) ([]boxcore.Candidate, error) {
	p.called("Candidates")
	p.picks = append(p.picks, req)
	return p.candidates, errors.Join(ctx.Err(), p.candidateErr)
}

func (p *fakeProvider) DryRun(ctx context.Context, req boxcore.Request,
	c boxcore.Candidate, g boxcore.Guest) (boxcore.DryResult, error) {
	p.called("DryRun")
	p.dryCalls = append(p.dryCalls, launchCall{req: req, c: c, guest: g})
	return p.dry, errors.Join(ctx.Err(), p.dryErr)
}

func (p *fakeProvider) Launch(ctx context.Context, req boxcore.Request,
	c boxcore.Candidate, g boxcore.Guest) (boxcore.Box, error) {
	p.called("Launch")
	p.launches = append(p.launches, launchCall{req: req, c: c, guest: g})
	if err := ctx.Err(); err != nil {
		return boxcore.Box{}, err
	}
	index := len(p.launches) - 1
	if index < len(p.launchErrs) && p.launchErrs[index] != nil {
		return boxcore.Box{}, p.launchErrs[index]
	}
	b := p.box
	b.Type, b.Zone, b.Region = c.Type, c.Zone, c.Region
	return b, nil
}

func (p *fakeProvider) WaitRunning(ctx context.Context, b boxcore.Box) (boxcore.Box, error) {
	p.called("WaitRunning")
	p.waited = append(p.waited, b)
	if p.wait != nil {
		return p.wait(ctx, b)
	}
	b.Address, b.QuoteUSDHour = "127.0.0.1", 0
	return b, ctx.Err()
}

func (p *fakeProvider) Describe(ctx context.Context, b boxcore.Box) (boxcore.State, error) {
	p.called("Describe")
	p.described = append(p.described, b)
	if err := ctx.Err(); err != nil {
		return boxcore.State{}, err
	}
	if p.describe == nil {
		return boxcore.State{}, errors.New("Describe has no script")
	}
	state, err := p.describe(ctx, b, p.clock.Now())
	if err == nil {
		p.trace.add("state:" + state.Name)
	}
	return state, err
}

func (p *fakeProvider) Transport(b boxcore.Box, opts boxcore.TransportOptions) boxcore.Transport {
	p.called("Transport")
	p.transportBoxes = append(p.transportBoxes, b)
	p.transports = append(p.transports, opts)
	return p.tr
}

func (p *fakeProvider) Teardown(ctx context.Context, b boxcore.Box) error {
	p.called("Teardown")
	p.teardowns = append(p.teardowns, b)
	return errors.Join(ctx.Err(), p.teardownErr)
}

func (p *fakeProvider) List(ctx context.Context, filter boxcore.ListFilter) ([]boxcore.Box, error) {
	p.called("List")
	p.filters = append(p.filters, filter)
	return append([]boxcore.Box(nil), p.boxes...), ctx.Err()
}

func (p *fakeProvider) FetchHarvest(ctx context.Context, b boxcore.Box, runID, dir string) (int, error) {
	p.called("FetchHarvest")
	p.fetched = append(p.fetched, b)
	p.fetchRuns = append(p.fetchRuns, runID)
	p.fetchDirs = append(p.fetchDirs, dir)
	if err := errors.Join(ctx.Err(), p.fetchErr); err != nil {
		return 0, err
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return 0, err
	}
	err := os.WriteFile(filepath.Join(dir, "partial.txt"), []byte("partial "+runID), 0600)
	if err != nil {
		return 0, err
	}
	return 1, nil
}

type shellCall struct {
	command   string
	input     []byte
	fileInput bool
	canceled  bool
}

type shellTransport struct {
	root         string
	home         string
	trace        *callTrace
	calls        []shellCall
	failFirst    int
	before       func(context.Context, string) error
	after        func(context.Context, string) error
	craftedTar   []byte
	harvestCode  int
	replacements *strings.Replacer
}

func (tr *shellTransport) Exec(ctx context.Context, command string, input io.Reader,
	output, stderr io.Writer) (int, error) {
	call := shellCall{command: command, canceled: ctx.Err() != nil}
	var payload bytes.Buffer
	if input != nil {
		_, call.fileInput = input.(*os.File)
		if strings.Contains(command, remoteWrapper) || strings.Contains(command, remoteSuite) {
			data, err := io.ReadAll(input)
			if err != nil {
				return -1, err
			}
			payload.Write(data)
			// Only the script paths are remapped for the temporary box root.
			input = strings.NewReader(tr.replacements.Replace(string(data)))
		} else {
			input = io.TeeReader(input, &payload)
		}
	}
	index := len(tr.calls)
	tr.calls = append(tr.calls, call)
	defer func() { tr.calls[index].input = append([]byte(nil), payload.Bytes()...) }()
	tr.trace.add("transport:" + commandKind(command))
	if len(tr.calls) <= tr.failFirst {
		return -1, fault(boxcore.KindTransport)
	}
	if err := ctx.Err(); err != nil {
		return -1, err
	}
	if tr.before != nil {
		if err := tr.before(ctx, command); err != nil {
			return -1, err
		}
	}
	if strings.HasPrefix(command, "tar -C ") && tr.craftedTar != nil {
		if output == nil {
			return -1, errors.New("harvest stdout was not streamed")
		}
		_, err := io.Copy(output, bytes.NewReader(tr.craftedTar))
		return tr.harvestCode, err
	}
	cmd := exec.CommandContext(ctx, "sh", "-c", tr.replacements.Replace(command))
	cmd.Dir = tr.root
	cmd.Env = []string{"PATH=/usr/bin:/bin", "HOME=" + tr.home, "LC_ALL=C"}
	cmd.Stdin, cmd.Stdout, cmd.Stderr = input, output, stderr
	cmd.WaitDelay = 2 * time.Second
	err := cmd.Run()
	code := -1
	if cmd.ProcessState != nil {
		code = cmd.ProcessState.ExitCode()
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		err = nil
	}
	if err == nil && tr.after != nil {
		err = tr.after(ctx, command)
	}
	return code, errors.Join(err, ctx.Err())
}

func commandKind(command string) string {
	switch {
	case command == "true":
		return "ready"
	case strings.Contains(command, "setsid bash"):
		return "start"
	case strings.Contains(command, "kill -TERM --"):
		return "kill"
	case strings.HasPrefix(command, "tar -C "):
		return "harvest"
	case strings.HasPrefix(command, "if [ -f "):
		return "poll"
	case strings.Contains(command, "cat > "):
		return "upload"
	default:
		return "done"
	}
}

func fault(kind boxcore.ErrorKind) error {
	return boxcore.NewError(kind, "scripted", "", kind.String(), nil)
}

type fixture struct {
	s     boxcore.Service
	d     boxcore.Deps
	p     *fakeProvider
	l     *fakeLedger
	g     *fakeGuest
	tr    *shellTransport
	clock *fakeClock
	trace *callTrace
	err   *bytes.Buffer
	req   boxcore.Request
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	dir := t.TempDir()
	trace := &callTrace{}
	clock := &fakeClock{now: time.Date(2026, 10, 14, 6, 0, 0, 0, time.UTC)}
	cfg := &boxcore.Config{Org: "example-org",
		Defaults: boxcore.Defaults{HardMin: 60, DiskUSDGBMonth: 0.1, RunDir: filepath.Join(dir, "runs")},
		Guest: boxcore.GuestConfig{OutDir: filepath.Join(dir, "box", "out"),
			DoneFiles: []string{filepath.Join(dir, "box", "done")},
			BusyFiles: []string{filepath.Join(dir, "box", "busy")}},
	}
	tr := &shellTransport{root: filepath.Join(dir, "box"), home: filepath.Join(dir, "box", "home"), trace: trace}
	for _, folder := range []string{tr.root, tr.home, filepath.Join(tr.root, "tmp")} {
		if err := os.MkdirAll(folder, 0700); err != nil {
			t.Fatal(err)
		}
	}
	tr.replacements = strings.NewReplacer(
		remoteSource, filepath.Join(tr.root, "tmp", "lb-box-src.tar"),
		remoteSuite, filepath.Join(tr.root, "tmp", "lb-box-suite.sh"),
		remoteWrapper, filepath.Join(tr.root, "tmp", "lb-box-wrapper.sh"),
	)
	tr.after = func(ctx context.Context, command string) error {
		if commandKind(command) == "start" || commandKind(command) == "kill" {
			return awaitFile(ctx, filepath.Join(cfg.Guest.OutDir, ".complete"), false)
		}
		return nil
	}
	start := clock.Now()
	p := &fakeProvider{name: "aws", clock: clock, trace: trace, calls: make(map[string]int), tr: tr,
		box: boxcore.Box{Provider: "aws", ID: "i-demo1", Name: "lb-work-demo",
			Image: "img-demo", LaunchTimeUTC: boxcore.FormatUTC(start), Project: "example-project"},
		candidates: []boxcore.Candidate{
			{Type: "small-a", Zone: "demo-a", Region: "demo", PriceUSDHour: 1},
			{Type: "small-b", Zone: "demo-b", Region: "demo", PriceUSDHour: 1.1},
			{Type: "small-c", Zone: "other-a", Region: "other", PriceUSDHour: 1.2},
		}, teardownErr: fault(boxcore.KindUnsupported), dry: boxcore.DryResult{Allowed: true},
	}
	p.describe = func(ctx context.Context, b boxcore.Box, now time.Time) (boxcore.State, error) {
		if now.Sub(start) >= 45*time.Second {
			return boxcore.State{Name: boxcore.StateTerminated, Reason: "guard-ended",
				TransitionUTC: boxcore.FormatUTC(start.Add(40 * time.Second))}, nil
		}
		return boxcore.State{Name: boxcore.StateRunning}, nil
	}
	l := &fakeLedger{trace: trace}
	g := &fakeGuest{}
	stderr := &bytes.Buffer{}
	d := boxcore.Deps{Config: cfg, Providers: map[string]boxcore.Provider{"aws": p}, Ledger: l,
		Guest: g, Now: clock.Now, Sleep: clock.Sleep, NewRunID: func() string { return "run-demo1" },
		Out: io.Discard, Err: stderr, Version: "demo-version", SelfSHA: "demo-sha"}
	f := &fixture{d: d, p: p, l: l, g: g, tr: tr, clock: clock, trace: trace, err: stderr,
		req: boxcore.Request{Provider: "aws", Purpose: "work", RootGB: 10, IdleMin: 5, HardMin: 60, CostCapUSD: 10}}
	f.s = New(d)
	t.Cleanup(func() {
		data, err := os.ReadFile(filepath.Join(cfg.Guest.OutDir, ".wrapper.pid"))
		if errors.Is(err, os.ErrNotExist) {
			return
		}
		if err != nil {
			t.Error(err)
			return
		}
		pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
		if err != nil || pid <= 1 {
			t.Error("invalid wrapper pid during cleanup")
			return
		}
		if err := syscall.Kill(-pid, syscall.SIGKILL); err != nil && !errors.Is(err, syscall.ESRCH) {
			t.Error(err)
		}
	})
	return f
}

func awaitFile(ctx context.Context, name string, nonempty bool) error {
	bound, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	for {
		data, err := os.ReadFile(name)
		if err == nil && (!nonempty || len(bytes.TrimSpace(data)) > 0) {
			return nil
		}
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		if err := bound.Err(); err != nil {
			return err
		}
		// Synchronize with the real child; the orchestrator's time stays fake.
		runtime.Gosched()
	}
}

func eventNames(l *fakeLedger) []string {
	var names []string
	for _, event := range l.events {
		names = append(names, text(event, "event"))
	}
	return names
}

func assertEvents(t *testing.T, l *fakeLedger, expected ...string) {
	t.Helper()
	got := eventNames(l)
	if strings.Join(got, ",") != strings.Join(expected, ",") {
		t.Fatalf("ledger events %v, want %v", got, expected)
	}
}

func requireFile(t *testing.T, name, expected string) {
	t.Helper()
	data, err := os.ReadFile(name)
	if err != nil || string(data) != expected {
		t.Fatalf("file %s does not contain the expected bytes: %v", filepath.Base(name), err)
	}
}

func traceIndex(trace *callTrace, name string) int {
	for i, item := range trace.items {
		if item == name {
			return i
		}
	}
	return -1
}

func countCommands(tr *shellTransport, kind string) int {
	count := 0
	for _, call := range tr.calls {
		if commandKind(call.command) == kind {
			count++
		}
	}
	return count
}
