package lifecycle

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
)

func TestStatusUnowned(t *testing.T) {
	for _, mode := range []string{"latest", "zero", "live"} {
		t.Run(mode, func(t *testing.T) {
			f := newFixture(t)
			lane := f.store.lanes[f.target.LifeID]
			lane.Cleaned = mode != "live"
			f.store.lanes[lane.LifeID] = lane
			before, err := json.Marshal(lane)
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Contains(before, []byte(`"unowned_retained"`)) {
				t.Fatal("status field changed stored lane bytes")
			}
			old := api.CleanEvent{RemovedObjectIDs: []api.ID{}, RetainedObjectIDs: []api.ID{},
				UnownedRetained: api.UnownedRetained{Objects: 1, Bytes: 9}}
			f.add("lane.cleaned", old, f.target.Run, "service", f.parent)
			// The latest clean is beyond the first history page.
			for range 201 {
				f.add("run.observed", f.launcher.observation, f.target.Run, "service", f.parent)
			}
			want := api.UnownedRetained{Objects: 2, Bytes: 3}
			if mode == "zero" {
				want = api.UnownedRetained{}
			}
			latest := old
			latest.UnownedRetained = want
			f.add("lane.cleaned", latest, f.target.Run, "service", f.parent)
			f.add("lane.cleaned", old, f.target.Run, "observation", f.parent)
			f.add("lane.cleaned", old, f.target.Run-1, "service", f.parent)
			f.add("lane.cleaned", old, f.target.Run, "service", f.parent)
			f.store.events[len(f.store.events)-1].LifeID = "sibling"
			status, err := f.service.LaneStatus(context.Background(),
				f.scope("lane.status", f.target, f.parent), f.target)
			if err != nil {
				t.Fatal(err)
			}
			raw, err := json.Marshal(status)
			if err != nil {
				t.Fatal(err)
			}
			var fields map[string]json.RawMessage
			if err := json.Unmarshal(raw, &fields); err != nil {
				t.Fatal(err)
			}
			if mode == "live" {
				if _, exists := fields["unowned_retained"]; exists || f.store.eventCalls != 0 {
					t.Fatal("uncleaned status reported or read cleanup totals")
				}
			} else {
				var got api.UnownedRetained
				if err := json.Unmarshal(fields["unowned_retained"], &got); err != nil || got != want {
					t.Fatalf("status lost latest measured unowned totals: got %+v, want %+v: %v", got, want, err)
				}
			}
			after, err := json.Marshal(f.store.lanes[lane.LifeID])
			if err != nil || !bytes.Equal(before, after) {
				t.Fatal("status changed the stored projection or its canonical input", err)
			}
		})
	}
}
