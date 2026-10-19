package lifecycle

import (
	"context"
	"encoding/json"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/reviewjob"
)

// Component guard for the actual native consumption/result generation changes
// and the fixed verifier's complete sealed input. No kernel claim is made.
func TestReviewNativeHandoff(t *testing.T) {
	for _, mode := range []string{"generation", "envelope"} {
		t.Run(mode, func(t *testing.T) {
			f := newFixture(t)
			f.ended()
			candidate := fixtureReview(f)
			c := f.service.deps.ReviewControl.(*fixtureReviewControl)
			request := reviewRequest(candidate, f.target)
			if mode == "generation" {
				consumer := c.lease.ConsumedBy
				c.lease.ConsumedBy = ""
				f.store.reviewWorkers[c.lease.ID] = c.lease
				c.verifyHook = func(*api.ReviewEvidence) {
					actual := f.store.reviewWorkers[c.lease.ID]
					actual.Generation += 2
					actual.ConsumedBy = consumer
					f.store.reviewWorkers[actual.ID] = actual
				}
			} else {
				input := reviewjob.Input{Schema: "laneboss.review-input.v2", Subject: c.subject, Request: request,
					Required: c.required, Base: c.subject.Snapshot, Checks: c.evidence.Checks,
					Inventory: c.evidence.Inventory, Resolutions: c.evidence.Resolutions}
				raw, err := json.Marshal(input)
				if err != nil {
					t.Fatal(err)
				}
				c.lease.Input = f.measuredBlob(c.lease.Input.ID, "manifest", raw, c.lease.OperationID, f.target)
				f.store.reviewWorkers[c.lease.ID] = c.lease
				effect := f.store.reviewEffects[c.lease.EffectID]
				effect.Effect.Worker.Input = c.lease.Input
				f.store.reviewEffects[c.lease.EffectID] = effect
			}
			receipt, err := f.service.LaneReview(context.Background(), f.scope("lane.review", request, f.parent), request)
			if err != nil || receipt.Evidence == nil || c.calls != 1 || len(f.store.transactions) != 1 {
				t.Fatalf("native review handoff was rejected: %s: %v", mode, err)
			}
		})
	}
}
