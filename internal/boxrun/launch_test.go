package boxrun

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"laneboss.io/laneboss/internal/boxcore"
)

func TestLaunchCapacity(t *testing.T) {
	f := newFixture(t)
	f.p.launchErrs = []error{fault(boxcore.KindCapacity)}
	result, err := f.s.Launch(context.Background(), boxcore.LaunchOptions{Request: f.req})
	if err != nil || result.ExitCode != 0 || len(f.p.launches) != 2 || result.Candidate.Type != "small-b" {
		t.Fatalf("capacity retry: result %+v, calls %d, error %v", result, len(f.p.launches), err)
	}
	assertEvents(t, f.l, "LAUNCHED")
	if f.p.launches[0].c.Type != "small-a" || f.p.launches[1].c.Type != "small-b" ||
		result.Box.QuoteUSDHour != 1.1 || !strings.Contains(f.err.String(), "capacity") {
		t.Fatal("candidate order, preserved quote or capacity diagnostic is wrong")
	}
}

func TestLaunchQuota(t *testing.T) {
	f := newFixture(t)
	f.p.launchErrs = []error{fault(boxcore.KindQuota)}
	result, err := f.s.Launch(context.Background(), boxcore.LaunchOptions{Request: f.req})
	if err != nil || result.ExitCode != 0 || len(f.p.launches) != 2 ||
		f.p.launches[1].c.Region != "other" || result.Candidate.Type != "small-c" {
		t.Fatalf("regional quota retry: %+v, calls %+v, error %v", result, f.p.launches, err)
	}
	assertEvents(t, f.l, "LAUNCHED")
}

func TestLaunchDenied(t *testing.T) {
	f := newFixture(t)
	f.p.launchErrs = []error{fault(boxcore.KindDenied)}
	result, err := f.s.Launch(context.Background(), boxcore.LaunchOptions{Request: f.req})
	if boxcore.KindOf(err) != boxcore.KindDenied || result.ExitCode != 1 || len(f.p.launches) != 1 {
		t.Fatalf("denial did not stop: %+v, calls %d, error %v", result, len(f.p.launches), err)
	}
	assertEvents(t, f.l)
}

func TestCapUnknown(t *testing.T) {
	f := newFixture(t)
	f.p.candidates = []boxcore.Candidate{{Type: "unknown", Zone: "demo-a", Region: "demo"}}
	result, err := f.s.Launch(context.Background(), boxcore.LaunchOptions{Request: f.req})
	if result.ExitCode != 14 || !errors.Is(err, boxcore.ErrPriceUnknown) || f.p.calls["Launch"] != 0 ||
		len(f.g.specs) != 0 || !strings.Contains(f.err.String(), "price unknown") {
		t.Fatalf("unknown compute quote bypassed the cap: %+v, error %v", result, err)
	}
	assertEvents(t, f.l)
}

func TestCapReduced(t *testing.T) {
	f := newFixture(t)
	f.req.HardMin, f.req.CostCapUSD = 120, 0.5
	f.req.RootGB = 0
	result, err := f.s.Launch(context.Background(), boxcore.LaunchOptions{Request: f.req})
	if err != nil || result.ExitCode != 0 || len(f.p.launches) != 1 || len(f.g.specs) != 1 {
		t.Fatalf("launch failed: %+v, error %v", result, err)
	}
	assertEvents(t, f.l, "LAUNCHED")
	if f.p.launches[0].req.HardMin != 30 || f.g.specs[0].HardMin != 30 ||
		number(f.l.events[0], "hard_min") != 30 || f.req.HardMin != 120 ||
		f.p.launches[0].guest.Startup != "guard run-demo1 5 30" {
		t.Fatal("effective cap is absent from request, guest or ledger, or mutated the caller")
	}
	fields := f.l.events[0]
	if text(fields, "run_id") != "run-demo1" || text(fields, "org") != "example-org" ||
		text(fields, "lane") != "work" || text(fields, "owner_l5") != "unknown" ||
		text(fields, "owner_basis") != "unknown" || text(fields, "launcher_version") != "demo-version" ||
		text(fields, "launcher_sha256") != "demo-sha" || number(fields, "quote_usd_per_hour") != 1 {
		t.Fatal("launch facts are missing or use wrong ledger keys")
	}
}

func TestCapTooLow(t *testing.T) {
	f := newFixture(t)
	f.req.CostCapUSD = 0.01
	result, err := f.s.Launch(context.Background(), boxcore.LaunchOptions{Request: f.req})
	if result.ExitCode != 14 || !errors.Is(err, boxcore.ErrCapTooLow) || f.p.calls["Launch"] != 0 || len(f.g.specs) != 0 {
		t.Fatalf("low cap created a box: %+v, error %v", result, err)
	}
	assertEvents(t, f.l)
}

func TestLedgerClosed(t *testing.T) {
	f := newFixture(t)
	f.l.writableErr = errors.New("closed ledger")
	result, err := f.s.Launch(context.Background(), boxcore.LaunchOptions{Request: f.req})
	if result.ExitCode != 2 || !errors.Is(err, f.l.writableErr) || len(f.p.calls) != 0 || len(f.tr.calls) != 0 {
		t.Fatalf("provider called before ledger check: %+v, calls %v, error %v", result, f.p.calls, err)
	}
	assertEvents(t, f.l)
}

func TestLaunchUnrecorded(t *testing.T) {
	f := newFixture(t)
	f.l.failAppend = 1
	result, err := f.s.Launch(context.Background(), boxcore.LaunchOptions{Request: f.req})
	if result.ExitCode != 4 || err == nil || result.Box.ID != "i-demo1" || f.p.calls["Launch"] != 1 ||
		!strings.Contains(f.err.String(), "box is UP but NOT recorded: i-demo1") {
		t.Fatalf("unrecorded launch was hidden: %+v, error %v", result, err)
	}
	if len(f.l.appends) != 1 || text(f.l.appends[0], "event") != "LAUNCHED" {
		t.Fatal("creation was not offered to the ledger exactly once")
	}
	assertEvents(t, f.l)
}

func TestDryAllowed(t *testing.T) {
	f := newFixture(t)
	result, err := f.s.Launch(context.Background(), boxcore.LaunchOptions{Request: f.req, DryRun: true})
	if err != nil || result.ExitCode != 0 || result.Dry == nil || !result.Dry.Allowed ||
		f.p.calls["DryRun"] != 1 || f.p.calls["Launch"] != 0 || f.p.calls["WaitRunning"] != 0 {
		t.Fatalf("dry run created a box or failed: %+v, error %v", result, err)
	}
	assertEvents(t, f.l)
}

func TestDryDenied(t *testing.T) {
	f := newFixture(t)
	f.p.dry = boxcore.DryResult{Code: "Denied", Detail: "scripted denial"}
	result, err := f.s.Launch(context.Background(), boxcore.LaunchOptions{Request: f.req, DryRun: true})
	if err != nil || result.ExitCode != 6 || result.Dry == nil || result.Dry.Code != "Denied" ||
		f.p.calls["DryRun"] != 1 || f.p.calls["Launch"] != 0 {
		t.Fatalf("dry denial: %+v, error %v", result, err)
	}
	assertEvents(t, f.l)
}

func TestDryError(t *testing.T) {
	f := newFixture(t)
	f.p.dryErr = errors.New("unexpected dry failure")
	result, err := f.s.Launch(context.Background(), boxcore.LaunchOptions{Request: f.req, DryRun: true})
	if result.ExitCode != 7 || !errors.Is(err, f.p.dryErr) || f.p.calls["Launch"] != 0 {
		t.Fatalf("dry error: %+v, error %v", result, err)
	}
	assertEvents(t, f.l)
}

func TestRegistryWritten(t *testing.T) {
	f := newFixture(t)
	f.d.Config.Ledger.Registry = filepath.Join(t.TempDir(), "registry")
	result, err := f.s.Launch(context.Background(), boxcore.LaunchOptions{Request: f.req})
	if err != nil || result.ExitCode != 0 {
		t.Fatalf("registry launch: %+v, error %v", result, err)
	}
	expected := "work i-demo1 127.0.0.1 " + f.clock.Now().Local().Format("2006-01-02 15:04:05") + "\n"
	requireFile(t, f.d.Config.Ledger.Registry, expected)
	if _, err := f.s.Launch(context.Background(), boxcore.LaunchOptions{Request: f.req}); err != nil {
		t.Fatal(err)
	}
	requireFile(t, f.d.Config.Ledger.Registry, expected+expected)
}

func TestRegistryFailed(t *testing.T) {
	f := newFixture(t)
	f.d.Config.Ledger.Registry = t.TempDir()
	result, err := f.s.Launch(context.Background(), boxcore.LaunchOptions{Request: f.req})
	if result.ExitCode != 5 || err == nil || result.Box.ID != "i-demo1" || f.p.calls["Launch"] != 1 {
		t.Fatalf("registry failure: %+v, error %v", result, err)
	}
	assertEvents(t, f.l, "LAUNCHED")
	if _, err := os.Stat(f.d.Config.Ledger.Registry); err != nil {
		t.Fatal("registry directory was changed")
	}
}

func TestLaunchWaitFailure(t *testing.T) {
	f := newFixture(t)
	f.p.wait = func(ctx context.Context, b boxcore.Box) (boxcore.Box, error) {
		return boxcore.Box{}, errors.New("wait failed")
	}
	result, err := f.s.Launch(context.Background(), boxcore.LaunchOptions{Request: f.req})
	if result.ExitCode != 1 || err == nil || result.Box.ID != "i-demo1" || f.p.calls["Launch"] != 1 {
		t.Fatalf("failed wait retried or lost creation: %+v, error %v", result, err)
	}
	assertEvents(t, f.l, "LAUNCHED")
}

func TestGuestBucket(t *testing.T) {
	f := newFixture(t)
	f.d.Providers["gcp"] = f.p
	f.d.Config.GCP = &boxcore.GCPConfig{ResultsBucket: "example-bucket", ObjectPrefix: "runs"}
	f.req.Provider = "gcp"
	result, err := f.s.Launch(context.Background(), boxcore.LaunchOptions{Request: f.req, DryRun: true})
	if err != nil || result.ExitCode != 0 || len(f.g.specs) != 1 {
		t.Fatalf("guest render failed: %+v, %v", result, err)
	}
	spec := f.g.specs[0]
	if spec.Provider != "gcp" || spec.Bucket != "example-bucket" || spec.ObjectPrefix != "runs/run-demo1" ||
		spec.SyncSeconds != 60 || spec.Tag != "lb-box" || spec.OutDir != f.d.Config.Guest.OutDir ||
		len(spec.DoneFiles) != 1 || len(spec.BusyFiles) != 1 {
		t.Fatal("guest spec dropped provider configuration")
	}
}
