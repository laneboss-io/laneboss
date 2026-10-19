package service

import (
	"context"
	"encoding/json"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
)

func TestCheckCaller(t *testing.T) {
	for _, fault := range []string{"current", "frame", "self", "method", "request", "owner"} {
		t.Run(fault, func(t *testing.T) {
			host, base, caller := reviewContextFixture(t)
			request := api.TestChildRequest{Child: base.subject.Target, Candidate: base.subject.Snapshot, TestPlan: base.subject.Snapshot}
			caller.Request = requestFor(t, "grants.test-child", request)
			raw, err := json.Marshal(caller.Request)
			if err != nil {
				t.Fatal(err)
			}
			caller.Frame = sessionDispatchFrame{raw: raw}
			key := api.RequestKey{Method: caller.Request.Method, IdempotencyKey: caller.Request.IdempotencyKey, RequestSHA256: caller.Request.RequestSHA256}
			state := &reviewPreparingState{reviewContextState: base, receipt: api.MutationReceipt{Key: key, Operation: api.Operation{ID: "actual-child-test-operation", Status: "pending"}}}
			host.deps.Store = state
			switch fault {
			case "frame":
				caller.Frame = nil
			case "self":
				request.Child.LifeID = caller.Actor.LifeID
			case "method":
				caller.Request.Method = "lane.review"
			case "request":
				request.Child.Run++
			case "owner":
				state.mode = "owner"
			}
			retained, control, err := host.pendingCheck(context.Background(), caller, request)
			if fault == "current" {
				if err != nil || retained.Operation.ID != state.receipt.Operation.ID || control.Actor.Kind != "service" || control.Connection != nil || control.Frame != nil {
					t.Fatal("native checker lost original caller and pending operation", err)
				}
			} else if err == nil {
				t.Fatal("native checker accepted relabelled caller request or unowned operation", fault)
			}
		})
	}
}
