//go:build linux

package codex

import (
	"context"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
	fx "laneboss.io/laneboss/internal/v2/store/testfx"
)

func TestReviewCodexIssuedProfileParent(t *testing.T) {
	for _, child := range []bool{false, true} {
		t.Run(map[bool]string{false: "root", true: "child"}[child], func(t *testing.T) {
			var f *fx.Fixture
			if child {
				f = fx.ControlledChild(t)
			} else {
				f = fx.New(t)
				f.Start.Grants.Profiles[0].ExpiresAt = f.Start.Grants.Data[0].ExpiresAt
				f.Admit(t, "lane.start", f.Start)
				f.Reserve(t)
				f.Source(t)
				f.BuildPlan(t, true)
				f.Spec(t)
				f.Bind(t)
			}
			s := &Service{deps: Dependencies{Store: f.State, ReadScope: f.Execution}}
			ctx := context.Background()
			original, err := s.originalLaunch(ctx, f.Reservation)
			if err != nil {
				t.Fatal(err)
			}
			request := api.RunnerRequest{Slot: f.Plan.Runner.Slot, Model: f.Start.Model, Effort: f.Start.Effort, Budget: f.Start.Budget}
			if _, err := s.launchRequest(ctx, f.Reservation, original, request, f.Record.Inputs.Sources); err != nil {
				t.Fatal("actual original profile mapping failed", err)
			}
			issued, err := f.State.Grants(ctx, f.Reservation.GrantSetID)
			if err != nil {
				t.Fatal(err)
			}
			issued.Profiles[0].ParentGrantID = fx.ID(t)
			f.Replace(t, "grants", issued.ID, issued.Generation, issued)
			s.deps.Store = f.State
			if _, err := api.IssuedLaunchProfile(f.Reservation, original, issued); err == nil {
				t.Fatal("corruption control did not challenge the shared mapping invariant")
			}
			if _, err := s.launchRequest(ctx, f.Reservation, original, request, f.Record.Inputs.Sources); err == nil {
				t.Fatal("Codex accepted a profile parent that the shared issued-profile guard refuses")
			}
		})
	}
}
