package boxrun

import (
	"context"
	"strings"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/boxcore"
)

func orphanFixture(t *testing.T) *fixture {
	t.Helper()
	f := newFixture(t)
	makeBox := func(id string, age int) boxcore.Box {
		return boxcore.Box{Provider: "aws", ID: id, Name: "lb-" + id,
			LaunchTimeUTC: boxcore.FormatUTC(f.clock.Now().Add(-time.Duration(age) * time.Minute))}
	}
	f.p.boxes = []boxcore.Box{makeBox("box-old", 106), makeBox("box-young", 25),
		makeBox("box-ended", 130), makeBox("box-gone", 130), makeBox("box-unrecorded", 76), makeBox("box-edge", 75)}
	f.l.events = []map[string]any{
		{"event": "LAUNCHED", "provider": "aws", "instance_id": "box-old", "run_id": "run-old", "hard_min": float64(30)},
		{"event": "END_UNKNOWN", "instance_id": "box-ended"},
	}
	f.p.describe = func(ctx context.Context, b boxcore.Box, now time.Time) (boxcore.State, error) {
		if b.ID == "box-gone" {
			return boxcore.State{Name: boxcore.StateGone}, nil
		}
		return boxcore.State{Name: boxcore.StateRunning}, nil
	}
	return f
}

func TestListOrphans(t *testing.T) {
	f := orphanFixture(t)
	rows, err := f.s.List(context.Background(), boxcore.ListOptions{Provider: "aws"})
	if err != nil || len(rows) != 6 || len(f.p.filters) != 1 || !f.p.filters[0].ManagedOnly || f.p.filters[0].Org != "example-org" {
		t.Fatalf("managed list: %v, %v", rows, err)
	}
	for i, row := range rows {
		want := i == 0 || i == 4
		if row.Orphan != want || row.LedgerEnded != (i == 2) {
			t.Fatalf("wrong orphan/ended rule for %s", row.Box.ID)
		}
	}
	if rows[0].AgeMin != 106 || rows[4].AgeMin != 76 || rows[5].AgeMin != 75 {
		t.Fatal("age did not use each box's launch time")
	}
	rows, err = f.s.List(context.Background(), boxcore.ListOptions{Orphans: true, OlderThanMin: 100})
	if err != nil || len(rows) != 1 || rows[0].Box.ID != "box-old" {
		t.Fatal("OlderThanMin did not increase the orphan threshold")
	}
	rows, err = f.s.List(context.Background(), boxcore.ListOptions{Orphans: true, OlderThanMin: 120})
	if err != nil || len(rows) != 0 {
		t.Fatal("orphan filter included boxes below the requested threshold")
	}
}

func TestSweepReport(t *testing.T) {
	f := orphanFixture(t)
	result, err := f.s.Sweep(context.Background(), boxcore.SweepOptions{})
	if err != nil || result.Examined != 6 || len(result.Orphans) != 2 || len(result.Deleted) != 0 ||
		len(result.Refused) != 0 || f.p.calls["Teardown"] != 0 || len(f.l.appends) != 0 {
		t.Fatalf("report sweep changed boxes: %+v, %v", result, err)
	}
}

func TestSweepDenied(t *testing.T) {
	f := orphanFixture(t)
	f.p.teardownErr = fault(boxcore.KindDenied)
	result, err := f.s.Sweep(context.Background(), boxcore.SweepOptions{Delete: true})
	if err != nil || len(result.Refused) != 2 || len(result.Deleted) != 0 || len(f.l.appends) != 0 || f.p.calls["Teardown"] != 2 {
		t.Fatalf("denied deletion claimed success: %+v, %v", result, err)
	}
	for _, refusal := range result.Refused {
		if !strings.Contains(refusal, "denied") {
			t.Fatal("sweep refusal omitted its reason")
		}
	}
}

func TestSweepConfirmed(t *testing.T) {
	f := orphanFixture(t)
	f.p.teardownErr = nil
	f.p.describe = func(ctx context.Context, b boxcore.Box, now time.Time) (boxcore.State, error) {
		if b.ID == "box-gone" {
			return boxcore.State{Name: boxcore.StateGone}, nil
		}
		for _, deleted := range f.p.teardowns {
			if deleted.ID == b.ID {
				return boxcore.State{Name: boxcore.StateGone}, nil
			}
		}
		return boxcore.State{Name: boxcore.StateRunning}, nil
	}
	result, err := f.s.Sweep(context.Background(), boxcore.SweepOptions{Delete: true})
	if err != nil || len(result.Deleted) != 2 || len(result.Refused) != 0 || f.p.calls["Teardown"] != 2 || len(f.l.appends) != 2 {
		t.Fatalf("sweep confirmation: %+v, %v", result, err)
	}
	for _, event := range f.l.appends {
		if text(event, "event") != "TERMINATED_CONFIRMED" || text(event, "basis") != "sweep" || text(event, "state") != "gone" {
			t.Fatal("sweep wrote unsupported or unobserved evidence")
		}
	}
	if result.Deleted[0] != "box-old" || result.Deleted[1] != "box-unrecorded" ||
		text(f.l.appends[0], "run_id") != "run-old" {
		t.Fatal("sweep lost launch identity or deleted another box")
	}
}

func TestSweepUnconfirmed(t *testing.T) {
	f := orphanFixture(t)
	f.p.teardownErr = nil
	start := f.clock.Now()
	result, err := f.s.Sweep(context.Background(), boxcore.SweepOptions{Delete: true})
	if err == nil || len(result.Deleted) != 0 || len(result.Refused) != 2 || len(f.l.appends) != 0 ||
		f.clock.Now().Sub(start) != 240*time.Second {
		t.Fatalf("sweep fabricated deletion or ignored the bound: %+v, %v", result, err)
	}
}
