package box

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/boxcfg"
	"laneboss.io/laneboss/internal/boxcore"
	"laneboss.io/laneboss/internal/boxexec"
)

type recordService struct {
	launches []boxcore.LaunchOptions
	runs     []boxcore.RunOptions
	ends     []boxcore.EndOptions
	lists    []boxcore.ListOptions
	sweeps   []boxcore.SweepOptions
	launch   boxcore.LaunchResult
	run      boxcore.RunResult
	end      boxcore.EndResult
	listed   []boxcore.Listed
	sweep    boxcore.SweepResult
	err      error
	during   func(context.Context, boxcore.RunOptions)
}

func (s *recordService) Launch(ctx context.Context, o boxcore.LaunchOptions) (boxcore.LaunchResult, error) {
	s.launches = append(s.launches, o)
	return s.launch, s.err
}

func (s *recordService) Run(ctx context.Context, o boxcore.RunOptions) (boxcore.RunResult, error) {
	s.runs = append(s.runs, o)
	if s.during != nil {
		s.during(ctx, o)
	}
	return s.run, s.err
}

func (s *recordService) End(ctx context.Context, o boxcore.EndOptions) (boxcore.EndResult, error) {
	s.ends = append(s.ends, o)
	return s.end, s.err
}

func (s *recordService) List(ctx context.Context, o boxcore.ListOptions) ([]boxcore.Listed, error) {
	s.lists = append(s.lists, o)
	return s.listed, s.err
}

func (s *recordService) Sweep(ctx context.Context, o boxcore.SweepOptions) (boxcore.SweepResult, error) {
	s.sweeps = append(s.sweeps, o)
	return s.sweep, s.err
}

type testLedger struct {
	path       string
	events     []map[string]any
	eventsErr  error
	writeErr   error
	writeCalls int
}

func (l *testLedger) Writable() error {
	l.writeCalls++
	return l.writeErr
}

func (l *testLedger) Append(string, map[string]any) (map[string]any, error) {
	return nil, errors.New("unexpected test ledger append")
}

func (l *testLedger) Events() ([]map[string]any, error) {
	if l.eventsErr != nil {
		return nil, l.eventsErr
	}
	if l.path == "" {
		return l.events, nil
	}
	f, err := os.Open(l.path)
	if err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(f)
	var events []map[string]any
	for {
		var event map[string]any
		err := decoder.Decode(&event)
		if errors.Is(err, io.EOF) {
			return events, f.Close()
		}
		if err != nil {
			closeErr := f.Close()
			return nil, errors.Join(err, closeErr)
		}
		events = append(events, event)
	}
}

type runnerFunc func(context.Context, boxexec.Cmd) (boxexec.Result, error)

func (f runnerFunc) Run(ctx context.Context, c boxexec.Cmd) (boxexec.Result, error) {
	return f(ctx, c)
}

type fixture struct {
	t        *testing.T
	cfg      *boxcore.Config
	env      environment
	vars     map[string]string
	svc      *recordService
	ledger   *testLedger
	file     string
	loaded   string
	built    int
	buildErr error
	openErr  error
	out      bytes.Buffer
	notes    bytes.Buffer
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	dir := t.TempDir()
	h := &fixture{
		t: t, vars: make(map[string]string), svc: &recordService{}, ledger: &testLedger{},
		cfg: &boxcore.Config{
			Org: "example-org", AWS: &boxcore.AWSConfig{}, GCP: &boxcore.GCPConfig{},
			Defaults: boxcore.Defaults{
				Provider: "aws", VCPU: 4, MemGiB: 8, Arch: "any", RootGB: 20,
				IdleMin: 15, HardMin: 120, CostCapUSD: 2,
			},
			Ledger: boxcore.LedgerConfig{Path: filepath.Join(dir, "boxes.jsonl")},
		},
	}
	h.file = writeTemp(t, dir, "box.toml", "org = \"example-org\"\n")
	h.env = environment{
		getenv: func(key string) string { return h.vars[key] }, userHome: dir,
		now: func() time.Time { return time.Unix(100, 0) }, signals: make(chan os.Signal, 2),
		load: func(file string, env boxcfg.Env) (*boxcore.Config, error) {
			h.loaded = file
			if _, err := os.Stat(file); err != nil {
				return nil, errors.New("the test config cannot be read")
			}
			return h.cfg, nil
		},
		openLedger: func(cfg *boxcore.Config, notes io.Writer) (boxcore.Ledger, error) {
			return h.ledger, h.openErr
		},
		archiveRun: runnerFunc(func(context.Context, boxexec.Cmd) (boxexec.Result, error) {
			t.Error("unexpected git invocation")
			return boxexec.Result{Code: -1}, errors.New("unexpected git invocation")
		}),
	}
	return h
}

func writeTemp(t *testing.T, dir, name, data string) string {
	t.Helper()
	file := filepath.Join(dir, name)
	if err := os.WriteFile(file, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	return file
}

func (h *fixture) direct(args ...string) int {
	h.out.Reset()
	h.notes.Reset()
	return run(args, bytes.NewReader(nil), &h.out, &h.notes, h.env,
		func(cfg *boxcore.Config, deps buildDeps) (boxcore.Service, error) {
			h.built++
			if cfg != h.cfg {
				h.t.Error("the builder did not receive the loaded config")
			}
			return h.svc, h.buildErr
		})
}

func (h *fixture) call(args ...string) int {
	h.t.Helper()
	if len(args) == 0 {
		return h.direct()
	}
	withConfig := []string{args[0], "--box-config", h.file}
	// Positional purpose must remain the first token after the subcommand.
	if len(args) > 1 && (args[0] == "launch" || args[0] == "run") && !strings.HasPrefix(args[1], "-") {
		withConfig = []string{args[0], args[1], "--box-config", h.file}
		return h.direct(append(withConfig, args[2:]...)...)
	}
	return h.direct(append(withConfig, args[1:]...)...)
}

func (h *fixture) request(command string) boxcore.Request {
	h.t.Helper()
	if command == "launch" && len(h.svc.launches) == 1 {
		return h.svc.launches[0].Request
	}
	if command == "run" && len(h.svc.runs) == 1 {
		return h.svc.runs[0].Request
	}
	h.t.Fatal("the expected service method was not called once")
	return boxcore.Request{}
}
