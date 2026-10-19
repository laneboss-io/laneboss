package lifecycle

import (
	"context"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
)

func TestRefusedCaptureReview(t *testing.T) {
	for _, method := range []string{"review", "mark"} {
		t.Run(method, func(t *testing.T) {
			f := newLaunchFixture(t)
			f.ports.refuseCapture = true
			f.allowCaptureRefusal()
			plan, lane := f.endedPlan(t)
			planned := 0
			for _, event := range f.store.events {
				if event.Kind != "launch.planned" || event.LifeID != lane.LifeID {
					continue
				}
				planned++
				var retained api.LaunchPlanRecord
				if err := api.DecodeObject(event.Payload, &retained); err != nil || retained.Plan == nil || retained.Plan.Capture.Status != "refused" || retained.Plan.Capture.ID != plan.Capture.ID ||
					api.ValidateCapturePolicy(retained.Plan.Capture, f.store.policy) != nil {
					t.Fatalf("refused plan retained invalid wire fields: %v", err)
				}
			}
			if planned != 1 {
				t.Fatal("refused capture has no unique committed plan")
			}
			receipt := fixtureReviewFor(f.fixture, lane)
			f.fixture.addTo(lane, "lane.reviewed", receipt, "service", f.parent)
			before := len(f.store.transactions)
			var err error
			if method == "review" {
				request := api.ReviewRequest{Target: plan.Reservation.Target, Diff: receipt.Diff, Checks: receipt.Checks,
					RecordInventory: receipt.RecordInventory, RefusalResolution: receipt.RefusalResolution}
				_, err = f.service.LaneReview(context.Background(), f.fixture.scope("lane.review", request, f.parent), request)
			} else {
				request := api.MarkRequest{Target: plan.Reservation.Target, ExpectedGeneration: lane.Generation, State: "accepted", Review: receipt}
				_, err = f.service.LaneMark(context.Background(), f.fixture.scope("lane.mark", request, f.parent), request)
			}
			if typed, ok := err.(*api.Error); !ok || typed.Code != api.CodeUnsupported ||
				len(f.store.transactions) != before || f.store.lanes[lane.LifeID].State != "verifying" {
				t.Fatalf("refused capture became reviewable or acceptable evidence: %v", err)
			}
		})
	}
}

func TestRegisteredCaptureMark(t *testing.T) {
	f := newLaunchFixture(t)
	plan, lane := f.endedPlan(t)
	receipt := fixtureReviewFor(f.fixture, lane)
	f.fixture.addTo(lane, "lane.reviewed", receipt, "service", f.parent)
	request := api.MarkRequest{Target: plan.Reservation.Target, ExpectedGeneration: lane.Generation, State: "accepted", Review: receipt}
	operation, err := f.service.LaneMark(context.Background(), f.fixture.scope("lane.mark", request, f.parent), request)
	if err != nil || operation.Status != "succeeded" || f.store.lanes[lane.LifeID].State != "accepted" {
		t.Fatalf("registered capture with a trusted independent review could not be marked: %v", err)
	}
}
