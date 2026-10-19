package admin

import (
	"context"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
)

func TestAbortUnstartedLease(t *testing.T) {
	ctx := context.Background()
	m, store, resources := testManager()
	resources.ensureErr = failure(api.CodePrerequisite, "injected failure before cgroup creation")
	_, err := m.allocate(ctx, testAllocation())
	requireCode(t, err, api.CodePrerequisite)
	lease := store.records[0].Lease
	cause := testCause(api.InternalHelperAbort, "life-a")
	request := api.HelperAbortRequest{Cause: cause, LeaseID: lease.ID, OperationID: cause.CauseOperationID, EffectID: cause.EffectID}
	resources.quietErr = failure(api.CodeContainmentUnknown, "injected survivor")
	_, err = m.abort(ctx, request)
	if err == nil || store.records[0].Phase != "reserved" || len(resources.removed) != 0 {
		t.Fatal("acceptance: abort ignored quiescence")
	}
	resources.quietErr, resources.ensureErr = nil, nil
	receipt, err := m.abort(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	if receipt.AgentExecuted || receipt.Quiescence.Handle.ID != "" || receipt.Quiescence.ExitCode != nil ||
		receipt.Quiescence.Signal != nil || receipt.Quiescence.State != "not_started" || store.records[0].Phase != "aborted" {
		t.Fatal("abort invented a process or lost its receipt")
	}
	replayed, err := m.abort(ctx, request)
	if err != nil || replayed.ID != receipt.ID {
		t.Fatal("abort replay changed its receipt")
	}
	next := testAllocation()
	next.LifeID, next.Cause.Target.LifeID, next.Cause.EffectID = "next-life", "next-life", "next-effect"
	reused, err := m.allocate(ctx, next)
	if err != nil || reused.UID != lease.UID {
		t.Fatal("aborted unopened reservation was not collected")
	}
}
