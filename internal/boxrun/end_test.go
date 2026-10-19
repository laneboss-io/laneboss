package boxrun

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/boxcore"
)

func launchedEnd(t *testing.T, f *fixture) boxcore.EndOptions {
	t.Helper()
	result, err := f.s.Launch(context.Background(), boxcore.LaunchOptions{Request: f.req})
	if err != nil || result.ExitCode != 0 {
		t.Fatalf("fixture launch: %+v, %v", result, err)
	}
	return boxcore.EndOptions{Provider: f.req.Provider, ID: result.Box.ID, Address: result.Box.Address}
}

func TestEndKnownHostsFile(t *testing.T) {
	f := newFixture(t)
	opts := launchedEnd(t, f)
	before := len(f.p.transports)
	if _, err := f.s.End(context.Background(), opts); err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(f.d.Config.Defaults.RunDir, "run-demo1", "known_hosts.i-demo1")
	if len(f.p.transports) != before+1 || f.p.transports[before].KnownHostsFile != want {
		t.Fatalf("a standalone end did not pin the host key in the run directory: %+v", f.p.transports)
	}
}

// TestEndRunLabel: a standalone end hands the provider the run the ledger recorded for the box, so a provider that
// reads the machine's own run label can refuse a machine of another run.
func TestEndRunLabel(t *testing.T) {
	f := newFixture(t)
	opts := launchedEnd(t, f)
	if _, err := f.s.End(context.Background(), opts); err != nil {
		t.Fatal(err)
	}
	if len(f.p.teardowns) != 1 || f.p.teardowns[0].Labels["lb-run"] != "run-demo1" {
		t.Fatalf("teardown did not get the ledger's run: %+v", f.p.teardowns)
	}
	if n := len(f.p.transportBoxes); n == 0 || f.p.transportBoxes[n-1].Labels["lb-run"] != "run-demo1" {
		t.Fatalf("the done marker did not get the ledger's run: %+v", f.p.transportBoxes)
	}
}

func TestEndPending(t *testing.T) {
	f := newFixture(t)
	opts := launchedEnd(t, f)
	opts.BoundSec, opts.PollSec = 30, 10
	f.p.describe = func(ctx context.Context, b boxcore.Box, now time.Time) (boxcore.State, error) {
		return boxcore.State{Name: boxcore.StateRunning}, nil
	}
	result, err := f.s.End(context.Background(), opts)
	if err != nil || result.ExitCode != 3 || !result.Pending || result.State != "running" || f.p.calls["Describe"] != 4 {
		t.Fatalf("end pending: %+v, %v", result, err)
	}
	assertEvents(t, f.l, "LAUNCHED", "DONE_SENT", "END_PENDING")
	if traceIndex(f.trace, "ledger:DONE_SENT") >= traceIndex(f.trace, "provider:Describe") ||
		number(f.l.events[2], "bound_sec") != 30 || text(f.l.events[2], "state") != "running" {
		t.Fatal("marker was recorded late or pending evidence is wrong")
	}
	requireFile(t, f.d.Config.Guest.DoneFiles[0], "")
}

func TestEndFacts(t *testing.T) {
	f := newFixture(t)
	opts := launchedEnd(t, f)
	result, err := f.s.End(context.Background(), opts)
	if err != nil || result.ExitCode != 0 || result.Pending || result.BilledSeconds != 40 ||
		result.Basis != "describe:transition-time" || result.TerminatedUTC != "2026-10-14T06:00:40Z" {
		t.Fatalf("end transition facts: %+v, %v", result, err)
	}
	assertEvents(t, f.l, "LAUNCHED", "DONE_SENT", "TERMINATED_CONFIRMED")
	if len(f.p.teardowns) != 1 || f.p.teardowns[0].Region != "demo" || f.p.teardowns[0].Zone != "demo-a" ||
		f.p.teardowns[0].Image != "img-demo" || f.p.teardowns[0].Project != "example-project" ||
		text(f.l.events[2], "state_transition_reason") != "guard-ended" {
		t.Fatal("end did not rebuild provider facts from LAUNCHED")
	}
}

func TestEndNoTransport(t *testing.T) {
	f := newFixture(t)
	f.p.wait = func(ctx context.Context, b boxcore.Box) (boxcore.Box, error) { return b, ctx.Err() }
	opts := launchedEnd(t, f)
	f.p.tr = nil
	result, err := f.s.End(context.Background(), opts)
	if err != nil || result.ExitCode != 0 || text(f.l.events[1], "result") != "no-address" || f.p.calls["Describe"] == 0 {
		t.Fatalf("no-address marker failure aborted the poll: %+v, %v", result, err)
	}
	assertEvents(t, f.l, "LAUNCHED", "DONE_SENT", "TERMINATED_CONFIRMED")
}

func TestEndExecFailure(t *testing.T) {
	f := newFixture(t)
	opts := launchedEnd(t, f)
	parent := filepath.Join(t.TempDir(), "file-parent")
	if err := os.WriteFile(parent, []byte("file"), 0600); err != nil {
		t.Fatal(err)
	}
	f.d.Config.Guest.DoneFiles = []string{filepath.Join(parent, "done")}
	result, err := f.s.End(context.Background(), opts)
	if err != nil || result.ExitCode != 0 || text(f.l.events[1], "result") != "exec-failed:rc=1" ||
		f.p.calls["Teardown"] != 1 || f.p.calls["Describe"] == 0 {
		t.Fatalf("nonzero marker was hidden or aborted cleanup: %+v, %v", result, err)
	}
}

func TestEndTransportFail(t *testing.T) {
	f := newFixture(t)
	opts := launchedEnd(t, f)
	f.tr.before = func(ctx context.Context, command string) error { return fault(boxcore.KindTransport) }
	result, err := f.s.End(context.Background(), opts)
	if err != nil || result.ExitCode != 0 || text(f.l.events[1], "result") != "transport-failed" ||
		f.p.calls["Describe"] == 0 || f.p.calls["Teardown"] != 1 {
		t.Fatalf("marker transport failure aborted cleanup: %+v, %v", result, err)
	}
}

func TestEndStopped(t *testing.T) {
	f := newFixture(t)
	opts := launchedEnd(t, f)
	f.p.teardownErr = nil
	start := f.clock.Now()
	f.p.describe = func(ctx context.Context, b boxcore.Box, now time.Time) (boxcore.State, error) {
		if now.Sub(start) < 45*time.Second {
			return boxcore.State{Name: boxcore.StateStopped}, nil
		}
		return boxcore.State{Name: boxcore.StateGone}, nil
	}
	result, err := f.s.End(context.Background(), opts)
	if err != nil || result.ExitCode != 0 || f.p.calls["Teardown"] != 2 || result.State != "gone" ||
		result.Basis != "describe:not-found" || result.BilledSeconds != 45 {
		t.Fatalf("stopped box was not deleted exactly once more: %+v, %v", result, err)
	}
	assertEvents(t, f.l, "LAUNCHED", "DONE_SENT", "TERMINATED_CONFIRMED")
}

func TestEndDenied(t *testing.T) {
	f := newFixture(t)
	opts := launchedEnd(t, f)
	f.p.teardownErr = fault(boxcore.KindDenied)
	result, err := f.s.End(context.Background(), opts)
	if err != nil || result.ExitCode != 0 || !strings.Contains(text(f.l.events[2], "done_result"), "teardown-denied") ||
		!strings.Contains(f.err.String(), "teardown denied") || f.p.calls["Describe"] == 0 {
		t.Fatalf("teardown denial was hidden or prevented observation: %+v, %v", result, err)
	}
}

func TestEndReadFailure(t *testing.T) {
	f := newFixture(t)
	opts := launchedEnd(t, f)
	opts.BoundSec = 30
	f.p.describe = func(ctx context.Context, b boxcore.Box, now time.Time) (boxcore.State, error) {
		return boxcore.State{}, errors.New("scripted read failure")
	}
	result, err := f.s.End(context.Background(), opts)
	if err == nil || result.ExitCode != 3 || !result.Pending || f.p.calls["Describe"] != 3 || result.TerminatedUTC != "" {
		t.Fatalf("unobserved end was confirmed or not retried: %+v, %v", result, err)
	}
	assertEvents(t, f.l, "LAUNCHED", "DONE_SENT")
}

func TestEndLedgerFailure(t *testing.T) {
	f := newFixture(t)
	opts := launchedEnd(t, f)
	f.l.failAppend = 2
	result, err := f.s.End(context.Background(), opts)
	if err == nil || result.ExitCode != 2 || result.State != "terminated" || f.p.calls["Teardown"] != 1 ||
		f.p.calls["Describe"] == 0 || len(f.l.appends) != 3 {
		t.Fatalf("ledger failure was swallowed or prevented ending: %+v, %v", result, err)
	}
	assertEvents(t, f.l, "LAUNCHED", "TERMINATED_CONFIRMED")
}

func TestEndMissingLaunch(t *testing.T) {
	f := newFixture(t)
	result, err := f.s.End(context.Background(), boxcore.EndOptions{Provider: "aws", ID: "i-demo1", Address: "127.0.0.1"})
	if err != nil || result.ExitCode != 0 || result.BilledSeconds != 0 || f.p.calls["Teardown"] != 1 ||
		!strings.Contains(f.err.String(), "no LAUNCHED ledger line for i-demo1") {
		t.Fatalf("missing launch prevented ending: %+v, %v", result, err)
	}
	assertEvents(t, f.l, "DONE_SENT", "TERMINATED_CONFIRMED")
}

func TestEndMarkerPanic(t *testing.T) {
	f := newFixture(t)
	opts := launchedEnd(t, f)
	f.tr.before = func(ctx context.Context, command string) error { panic("scripted marker panic") }
	result, err := f.s.End(context.Background(), opts)
	if err != nil || result.ExitCode != 0 || f.p.calls["Teardown"] != 1 || f.p.calls["Describe"] == 0 ||
		text(f.l.events[1], "result") != "transport-failed" || !strings.Contains(f.err.String(), "marker panic") {
		t.Fatalf("marker panic skipped teardown or observations: %+v, %v", result, err)
	}
	assertEvents(t, f.l, "LAUNCHED", "DONE_SENT", "TERMINATED_CONFIRMED")
}
