package lifecycle

import (
	"context"
	"testing"
)

// These are component guards over retained native facts, not kernel evidence.
func TestReviewWorkerExecution(t *testing.T) {
	for _, job := range []string{"verifier", "check"} {
		for _, mode := range []string{"unconsumed", "no-launch", "foreign-launch", "running", "unknown", "survivor", "failed-exit", "no-result", "foreign-input", "foreign-effect"} {
			t.Run(job+"/"+mode, func(t *testing.T) {
				f := newFixture(t)
				f.ended()
				candidate := fixtureReview(f)
				control := f.service.deps.ReviewControl.(*fixtureReviewControl)
				id := control.lease.ID
				if job == "check" {
					id = control.evidence.Checks[0].WorkerLeaseID
				}
				worker := f.store.reviewWorkers[id]
				effect := f.store.reviewEffects[worker.EffectID]
				switch mode {
				case "unconsumed":
					worker.ConsumedBy = ""
					f.store.reviewWorkers[id] = worker
					if job == "verifier" {
						control.lease = worker
					}
				case "no-launch":
					delete(f.store.launches, worker.ConsumedBy)
				case "foreign-launch":
					record := f.store.launches[worker.ConsumedBy]
					record.Target.Run++
					f.store.launches[record.ID] = record
				case "running":
					effect.Outcome.Observation.State = "running"
				case "unknown":
					effect.Outcome.Observation.Survivors = nil
				case "survivor":
					one := uint64(1)
					effect.Outcome.Observation.Survivors = &one
				case "failed-exit":
					code := 7
					effect.Outcome.Observation.ExitCode = &code
				case "no-result":
					effect.Outcome.Output = nil
				case "foreign-input":
					effect.Effect.Worker.Input.SHA256 = digestOf([]byte("foreign input"))
				case "foreign-effect":
					effect.Effect.OperationID = "foreign-operation"
				}
				f.store.reviewEffects[worker.EffectID] = effect
				request := reviewRequest(candidate, f.target)
				_, err := f.service.LaneReview(context.Background(), f.scope("lane.review", request, f.parent), request)
				if err == nil || len(f.store.transactions) != 0 {
					t.Fatalf("unmeasured worker execution authorized review: %s/%s: %v", job, mode, err)
				}
				if f.store.lanes[f.target.LifeID].State != "verifying" {
					t.Fatal("failed worker measurement changed lifecycle state")
				}
			})
		}
	}
}
