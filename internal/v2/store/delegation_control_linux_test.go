//go:build linux

package store_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"slices"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/store"
	fx "laneboss.io/laneboss/internal/v2/store/testfx"
)

type grantRevoker interface {
	RevokeGrants(context.Context, api.Scope, api.GrantRevokeRequest, []api.TransactionGuard) (api.Commit, error)
}

type delegationReader interface {
	VerifyDelegationLease(context.Context, api.Scope, api.ID, api.ID) (api.Digest, error)
}

func cascadeInput(t *testing.T, f *fx.Fixture, class string, owner api.Actor, life api.ID) api.BlobRef {
	t.Helper()
	raw := []byte("retained cascade input " + string(fx.ID(t)))
	cause := f.Intent(t, api.InternalObjectRetain)
	ref, err := f.State.RetainObject(context.Background(), f.Execution, api.RetainObjectRequest{Intent: cause, Object: api.ObjectWrite{
		ObjectKey: fx.ID(t), Class: class, Bytes: raw, SHA256: fx.Digest(raw), Origin: "service", ACL: api.ObjectACL{Config: f.Deps.Config, Owner: owner, LifeID: life, Audience: "owner", Generation: 1}}})
	if err != nil {
		t.Fatal(err)
	}
	return ref
}

func cascadeChild(t *testing.T, parent *fx.Fixture, level int) *fx.Fixture {
	t.Helper()
	f := *parent
	controller := parent.LaneScope(t)
	f.Ceiling = parent.Plan.Inputs.Grants
	f.Start.Lane, f.Start.Level, f.Start.Role, f.Start.RootTicketID = string(fx.ID(t)), level, "executor", ""
	f.Start.Task = cascadeInput(t, &f, "task", controller.Actor, controller.Actor.LifeID)
	f.Start.Grants.Data = append([]api.DataGrantRequest{}, parent.Start.Grants.Data...)
	f.Start.Grants.Profiles = append([]api.ProfileDelegation{}, parent.Start.Grants.Profiles...)
	f.Start.Grants.Data[0].ParentGrantID = f.Ceiling.Data[0].ID
	f.Start.Grants.Profiles[0].ParentGrantID = f.Ceiling.Profiles[0].ID
	f.Start.ProfileGrantID = f.Ceiling.Profiles[0].ID
	expires := api.Timestamp(time.Now().Add(time.Duration(level) * time.Minute).UTC().Format(time.RFC3339Nano))
	f.Start.Grants.Data[0].ExpiresAt, f.Start.Grants.Profiles[0].ExpiresAt = expires, expires
	f.Human = controller
	f.Admit(t, "lane.start", f.Start)
	f.Reserve(t)
	f.Source(t)
	f.BuildPlan(t, true)
	f.Spec(t)
	f.PreparedClaim = api.EffectLease{}
	f.Bind(t)
	f.Opened(t)
	return &f
}

func TestGrantCascadeDescendants(t *testing.T) {
	root := fx.Ready(t, true)
	root.Opened(t)
	child := cascadeChild(t, root, 4)
	grandchild := cascadeChild(t, child, 3)
	sibling := cascadeChild(t, root, 3)
	request := api.GrantRevokeRequest{GrantSetID: child.Lane.GrantSetID, ExpectedGeneration: child.Plan.Inputs.Grants.Generation, Reason: child.Start.Task}
	foreign := *sibling
	foreign.Human = sibling.LaneScope(t)
	foreignRequest := request
	foreignRequest.Reason = cascadeInput(t, &foreign, "report", foreign.Human.Actor, foreign.Lane.LifeID)
	foreign.Admit(t, "grants.revoke", foreignRequest)
	if _, err := child.State.RevokeGrants(context.Background(), foreign.Human, foreignRequest, nil); err == nil {
		t.Fatal("authentic sibling revoked a foreign subtree")
	}
	child.Admit(t, "grants.revoke", request)
	commit, err := child.State.RevokeGrants(context.Background(), child.Human, request, nil)
	if err != nil || commit.Operation.Status != "pending" {
		t.Fatal("atomic descendant cascade failed", err)
	}
	for _, f := range []*fx.Fixture{child, grandchild} {
		set, err := child.State.Grants(context.Background(), f.Lane.GrantSetID)
		if err != nil || !set.Revoked {
			t.Fatal("cascade left a descendant grant set live", err)
		}
		lane, err := child.State.Lane(context.Background(), child.Execution, f.Reservation.Target)
		if err != nil || lane.State != "stopping" || lane.CancellationEpoch != f.Lane.CancellationEpoch+1 {
			t.Fatal("cascade left descendant execution authority live", err)
		}
	}
	unaffected, err := child.State.Grants(context.Background(), root.Lane.GrantSetID)
	if err != nil || unaffected.Revoked {
		t.Fatal("cascade widened upward into its controller", err)
	}
	unaffected, err = child.State.Grants(context.Background(), sibling.Lane.GrantSetID)
	if err != nil || unaffected.Revoked {
		t.Fatal("cascade widened sideways into an unrelated sibling", err)
	}
}

func TestIndependentGrantCollection(t *testing.T) {
	for _, collector := range []string{"parent", "self"} {
		t.Run(collector, func(t *testing.T) {
			root := fx.Ready(t, true)
			root.Opened(t)
			child := cascadeChild(t, root, 4)
			ctx := context.Background()
			ended := child.Observation(t, "exited")
			if err := child.State.RecordLaunchObservation(ctx, child.Reservation.LaunchID, ended); err != nil {
				t.Fatal(err)
			}
			childLane := child.Lane
			childLane.State = "verifying"
			child.Replace(t, "lane", childLane.LifeID, childLane.Generation, childLane)
			root.State = child.State
			port, ok := any(child.State).(grantRevoker)
			if !ok {
				t.Fatal("missing grantRevoker")
			}
			allowed := store.CaptureAllowed(t)
			if collector == "parent" {
				parent := *root
				parent.Human = root.LaneScope(t)
				parentReq := api.GrantRevokeRequest{GrantSetID: child.Lane.GrantSetID, ExpectedGeneration: child.Plan.Inputs.Grants.Generation, Reason: child.Start.Task}
				parent.Admit(t, "grants.revoke", parentReq)
				// Owner R181-R192: a parent collecting a finished child's grants is allowed and logged instead of refused.
				commit, err := port.RevokeGrants(ctx, parent.Human, parentReq, nil)
				if err != nil || commit.Operation.Status != "pending" || !slices.Equal(allowed(), []string{"grant_collection_owner"}) {
					t.Fatalf("parent collection of a finished child's grants was not allowed and logged: %v %v", err, allowed())
				}
			} else {
				child.Human = child.LaneScope(t)
				childReq := api.GrantRevokeRequest{GrantSetID: child.Lane.GrantSetID, ExpectedGeneration: child.Plan.Inputs.Grants.Generation, Reason: cascadeInput(t, child, "report", child.Human.Actor, child.Lane.LifeID)}
				child.Admit(t, "grants.revoke", childReq)
				commit, err := port.RevokeGrants(ctx, child.Human, childReq, nil)
				if err != nil || commit.Operation.Status != "pending" || len(allowed()) != 0 {
					t.Fatalf("finished lane could not collect its own grants: %v %v", err, allowed())
				}
			}
			set, err := child.State.Grants(ctx, child.Lane.GrantSetID)
			if err != nil || !set.Revoked {
				t.Fatal("finished lane grants were not revoked", collector, err)
			}
		})
	}
}

func TestUnboundLaunchCleanup(t *testing.T) {
	root := fx.Ready(t, true)
	root.Opened(t)
	child := *root
	controller := root.LaneScope(t)
	cause := child.Intent(t, api.InternalObjectRetain)
	raw := []byte("parent controlled task " + string(fx.ID(t)))
	task, err := child.State.RetainObject(context.Background(), child.Execution, api.RetainObjectRequest{Intent: cause, Object: api.ObjectWrite{ObjectKey: fx.ID(t), Class: "task", Bytes: raw, SHA256: fx.Digest(raw), Origin: "service", ACL: api.ObjectACL{Config: child.Deps.Config, Owner: controller.Actor, Audience: "owner", Generation: 1}}})
	if err != nil {
		t.Fatal(err)
	}
	child.Ceiling = root.Plan.Inputs.Grants
	child.Start.Lane = string(fx.ID(t))
	child.Start.Level, child.Start.Role, child.Start.RootTicketID, child.Start.Task = 3, "executor", "", task
	child.Start.Grants.Data = append([]api.DataGrantRequest{}, root.Start.Grants.Data...)
	child.Start.Grants.Profiles = append([]api.ProfileDelegation{}, root.Start.Grants.Profiles...)
	child.Start.Grants.Data[0].ParentGrantID = child.Ceiling.Data[0].ID
	child.Start.Grants.Profiles[0].ParentGrantID = child.Ceiling.Profiles[0].ID
	expires := api.Timestamp(time.Now().Add(10 * time.Minute).UTC().Format(time.RFC3339Nano))
	child.Start.Grants.Data[0].ExpiresAt, child.Start.Grants.Profiles[0].ExpiresAt = expires, expires
	child.Start.ProfileGrantID = child.Ceiling.Profiles[0].ID
	child.Human = controller
	child.Admit(t, "lane.start", child.Start)
	child.Reserve(t)
	child.Source(t)
	child.BuildPlan(t, true)
	child.Spec(t)
	child.PrepareJob(t)

	ctx := context.Background()
	port, ok := any(root.State).(grantRevoker)
	if !ok {
		t.Fatal("missing grantRevoker")
	}
	parent := *root
	parent.Human = controller
	req := api.GrantRevokeRequest{GrantSetID: child.Reservation.GrantSetID, ExpectedGeneration: 1, Reason: task}
	parent.Admit(t, "grants.revoke", req)
	if _, err := port.RevokeGrants(ctx, parent.Human, req, nil); err == nil {
		t.Fatal("revocation succeeded before unbound plan failure")
	}

	r := child.Reservation
	slot := child.Plan.Runner.Slot
	inputSlot := retainCleanupStage(t, &child, "input-credential-slot", struct{ Target api.LifeRef }{r.Target})
	wrapResult := func(in api.BlobRef, value any) any {
		return struct {
			Schema string          `json:"schema"`
			Input  api.Digest      `json:"input"`
			Value  json.RawMessage `json:"value"`
		}{"laneboss.launch-stage.v2", in.SHA256, fx.JSON(t, value)}
	}
	slotResult := retainCleanupStage(t, &child, "result-credential-slot", wrapResult(inputSlot, slot))
	injection := child.Record.Plan.Injection
	var in, out api.BlobRef
	if child.Record.Plan != nil && len(child.Record.Plan.Data.Materialization.Objects) != 0 {
		in = retainCleanupStage(t, &child, "input-injection", struct{ Target api.LifeRef }{r.Target})
		out = retainCleanupStage(t, &child, "result-injection", wrapResult(in, injection))
	}
	cause = child.Intent(t, api.InternalLaunchPlan)
	cause.ID = cleanupID(r.ID, "cleanup-cause")
	cause.LogicalTurnID = child.Claim.Record.Effect.Context.LogicalTurnID
	failedPlan := child.Record
	failedPlan.Phase, failedPlan.Generation, failedPlan.Error = "failed", child.Record.Generation+1, &api.Error{Code: api.CodeCancelled, Owner: "lb-v2-lifecycle", Message: "unbound launch cleanup"}
	failTx := api.Transaction{Scope: child.Execution, Internal: &cause, Compare: []api.Compare{{Kind: api.CompareLaunchPlan, ID: r.ID, Generation: child.Record.Generation}},
		Guards: []api.TransactionGuard{{Cancellation: &api.CancellationCheck{LifeID: r.Target.LifeID, Epoch: r.CancellationEpoch}}},
		Writes: api.StateWrites{LaunchPlans: []api.LaunchPlanRecord{failedPlan}}}
	jobRelease := api.PlanCleanup{ID: cleanupID(r.ID, "cleanup-release"), Kind: "release", ReservationID: r.ID, LaunchID: r.LaunchID, SlotKnown: true, Slot: slot, SlotResult: slotResult, Injection: &injection}
	if in.ID != "" {
		jobRelease.InjectionIn = &in
	}
	if out.ID != "" {
		jobRelease.InjectionOut = &out
	}
	jobRelease.Cause = cause
	jobRelease.Cause.ID, jobRelease.Cause.EffectID, jobRelease.Cause.Kind = cleanupID(r.ID, "cause-cleanup-release"), jobRelease.ID, api.InternalHelperRelease
	jobRevoke := api.PlanCleanup{ID: cleanupID(r.ID, "cleanup-revoke_injection"), Kind: "revoke_injection", ReservationID: r.ID, LaunchID: r.LaunchID, SlotKnown: true, Slot: slot, SlotResult: slotResult, Injection: &injection}
	if in.ID != "" {
		jobRevoke.InjectionIn = &in
	}
	if out.ID != "" {
		jobRevoke.InjectionOut = &out
	}
	jobRevoke.Cause = cause
	jobRevoke.Cause.ID, jobRevoke.Cause.EffectID, jobRevoke.Cause.Kind = cleanupID(r.ID, "cause-cleanup-revoke_injection"), jobRevoke.ID, api.InternalHelperRelease
	jobs := []api.PlanCleanup{jobRelease, jobRevoke}

	if _, err := child.State.FailPlan(ctx, failTx, jobs); err != nil {
		t.Fatal("fail plan failed", err)
	}

	parent.Admit(t, "grants.revoke", req)
	if _, err := port.RevokeGrants(ctx, parent.Human, req, nil); err == nil {
		t.Fatal("revocation succeeded while plan cleanup was still pending")
	}

	scope := child.Execution
	clock := child.Deps.Clock
	cleanupStore := any(child.State).(api.PlanCleanupStore)
	owner := &cleanupComponentOwner{t: t, f: &child, store: cleanupStore, clock: clock, receipts: map[api.ID]api.PlanCleanupReceipt{}}
	for _, job := range jobs {
		status, err := cleanupStore.PlanCleanupStatus(ctx, scope, job.ID)
		if err != nil {
			t.Fatal(err)
		}
		deadline := api.Timestamp(clock.Now().Add(20 * time.Second).UTC().Format(time.RFC3339Nano))
		claim, err := cleanupStore.ClaimPlanCleanup(ctx, scope, job, api.EffectClaimRequest{EffectID: job.ID, ExpectedGeneration: status.Generation, ClaimantID: scope.Actor.ID, Deadline: deadline})
		if err != nil {
			t.Fatal(err)
		}
		receipt, err := owner.ExecutePlanCleanup(ctx, scope, claim)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := cleanupStore.CompletePlanCleanup(ctx, scope, claim, receipt, owner); err != nil {
			t.Fatal(err)
		}
	}

	parent.Admit(t, "grants.revoke", req)
	commit, err := port.RevokeGrants(ctx, parent.Human, req, nil)
	if err != nil || commit.Operation.Status != "pending" && commit.Operation.Status != "succeeded" {
		t.Fatalf("revocation failed after unbound launch cleanup completed: %v", err)
	}
	set, err := child.State.Grants(ctx, child.Reservation.GrantSetID)
	if err != nil || !set.Revoked {
		t.Fatal("unbound launch grants were not revoked after cleanup", err)
	}
}

func TestGrantCascadeRealStore(t *testing.T) {
	f := fx.ControlledChild(t)
	f.Opened(t)
	port, ok := any(f.State).(grantRevoker)
	if !ok {
		t.Fatal("durable grant cascade port is missing")
	}
	ctx := context.Background()
	inside := f.LaneScope(t)
	view, err := f.State.BeginRead(ctx, inside)
	if err != nil {
		t.Fatal("live grant authority control could not open a read", err)
	}
	if err := view.Close(); err != nil {
		t.Fatal(err)
	}
	set := f.Plan.Inputs.Grants
	req := api.GrantRevokeRequest{GrantSetID: set.ID, ExpectedGeneration: set.Generation, Reason: f.Start.Task}
	f.Admit(t, "grants.revoke", req)
	commit, err := port.RevokeGrants(ctx, f.Human, req, nil)
	if err != nil {
		t.Fatal("authentic ancestor revocation failed", err)
	}
	if commit.Operation.Status != "pending" {
		t.Fatal("revocation claimed completion before measured collection")
	}
	view, readErr := f.State.BeginRead(ctx, inside)
	if view != nil {
		if err := view.Close(); err != nil {
			t.Fatal(err)
		}
	}
	if readErr == nil {
		t.Fatal("revoked grants opened a new authenticated read before outbox invalidation")
	}
	current, err := f.State.Grants(ctx, set.ID)
	if err != nil || !current.Revoked || current.Generation != set.Generation+1 {
		t.Fatal("grant revocation was not durable", err)
	}
	lane, err := f.State.Lane(ctx, f.Execution, f.Reservation.Target)
	if err != nil || lane.State != "stopping" || lane.CancellationEpoch != f.Lane.CancellationEpoch+1 {
		t.Fatal("revocation did not cancel the affected run", err)
	}
	replay, err := port.RevokeGrants(ctx, f.Human, req, nil)
	if err != nil || !replay.Replayed || !reflect.DeepEqual(commit.Reply, replay.Reply) || replay.Operation.ID != commit.Operation.ID {
		t.Fatal("revocation replay changed its original result", err)
	}
	changed, changedScope := req, f.Human
	changed.ExpectedGeneration++
	changedScope.Request.Params = fx.JSON(t, changed)
	changedScope.Request.RequestID = fx.ID(t)
	changedScope.Request.RequestSHA256, err = api.RequestDigest(changedScope.Request)
	if err != nil {
		t.Fatal(err)
	}
	changedScope.Frame = &fx.Frame{Raw: fx.JSON(t, changedScope.Request)}
	if _, err := port.RevokeGrants(ctx, changedScope, changed, nil); err == nil {
		t.Fatal("revocation reused an idempotency key for changed input")
	} else {
		var typed *api.Error
		if !errors.As(err, &typed) || typed.Code != api.CodeIdempotencyConflict {
			t.Fatal("changed replay lost its exact conflict", err)
		}
	}
	page, err := f.State.PendingEffects(ctx, api.CursorRequest{Limit: 200})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, e := range page {
		if e.OperationID != commit.Operation.ID {
			continue
		}
		found = e.Stop != nil && *e.Stop == f.Process && e.Context != nil && e.Context.RequestedBy == f.Human.Actor
	}
	if !found {
		t.Fatal("revocation has no pinned causal stop effect")
	}
}

func TestGrantCascadeFences(t *testing.T) {
	for _, bad := range []string{"stale", "foreign", "reason", "body", "ended_controller", "unobserved", "independent_worker"} {
		t.Run(bad, func(t *testing.T) {
			f := fx.ControlledChild(t)
			if bad != "unobserved" {
				f.Opened(t)
			}
			port, ok := any(f.State).(grantRevoker)
			if !ok {
				t.Fatal("durable grant cascade port is missing")
			}
			set := f.Plan.Inputs.Grants
			if bad == "independent_worker" {
				worker, err := f.State.Launch(context.Background(), f.Worker.LaunchID)
				if err != nil {
					t.Fatal(err)
				}
				worker.ID, worker.Actor.ID, worker.UIDLeaseID, worker.ContainmentID = fx.ID(t), fx.ID(t), fx.ID(t), fx.ID(t)
				cause := f.Intent(t, api.InternalLifecycleEffect)
				if _, err := f.State.Transact(context.Background(), api.Transaction{Scope: f.Execution, Internal: &cause, Events: []api.Event{f.Event(t, "identity.bound", worker)}}); err != nil {
					t.Fatal(err)
				}
			}
			if bad == "ended_controller" {
				delegationParent(t, f).Ended(t)
			}
			req := api.GrantRevokeRequest{GrantSetID: set.ID, ExpectedGeneration: set.Generation, Reason: f.Start.Task}
			if bad == "stale" {
				req.ExpectedGeneration++
			}
			if bad == "reason" {
				req.Reason.ID = fx.ID(t)
			}
			f.Admit(t, "grants.revoke", req)
			scope := f.Human
			if bad == "foreign" {
				scope.Actor.LifeID = fx.ID(t)
			}
			if bad == "body" {
				req.ExpectedGeneration++
			}
			if _, err := port.RevokeGrants(context.Background(), scope, req, nil); err == nil {
				t.Fatal("revocation accepted " + bad)
			}
			current, err := f.State.Grants(context.Background(), set.ID)
			if err != nil || !reflect.DeepEqual(current, set) {
				t.Fatal("refused cascade changed grant authority", err)
			}
		})
	}
}

func TestGrantCascadeWaitReceipt(t *testing.T) {
	f := fx.ControlledChild(t)
	f.Opened(t)
	request := api.GrantRevokeRequest{GrantSetID: f.Lane.GrantSetID, ExpectedGeneration: f.Plan.Inputs.Grants.Generation, Reason: f.Start.Task}
	f.Admit(t, "grants.revoke", request)
	wait := &api.Error{Code: api.CodePrerequisite, Owner: "lb-v2-grants", Message: "independent native collection is still pending", Instead: "Retain the original owner measurement before retrying."}
	commit, err := f.State.Transact(context.Background(), api.Transaction{Scope: f.Human, RawRequest: f.Raw, Reply: &api.RPCReply{Error: wait}})
	if err != nil || commit.Reply == nil || !reflect.DeepEqual(commit.Reply.Error, wait) || commit.Operation.Status != "failed" {
		t.Fatal("typed grant wait could not retain its exact failure receipt", err)
	}
	again, err := f.State.RevokeGrants(context.Background(), f.Human, request, nil)
	// RawMessage nil encodes as null and decodes as the literal bytes "null".
	// Compare the exact retained serialization and error, not that Go detail.
	if err != nil || !again.Replayed || again.Reply == nil || !reflect.DeepEqual(again.Reply.Error, wait) || !bytes.Equal(fx.JSON(t, again.Reply), fx.JSON(t, commit.Reply)) {
		t.Fatal("grant wait replay lost its exact refusal", err)
	}
	set, err := f.State.Grants(context.Background(), f.Lane.GrantSetID)
	if err != nil || set.Revoked {
		t.Fatal("uncompleted grant wait changed authority", err)
	}
}

func TestSealedDelegationCorruption(t *testing.T) {
	f := fx.ControlledChild(t)
	f.Opened(t)
	parent := delegationParent(t, f)
	parent.Ended(t)
	if _, err := f.State.VerifyDelegationLease(context.Background(), f.Execution, parent.Lane.LifeID, f.Lane.GrantSetID); err != nil {
		t.Fatal(err)
	}
	// The corruption primitive preserves the generic projection history hash.
	// State verification must independently recover the lease's authority.
	f.Corrupt(t, "delegation_lease", f.Lane.GrantSetID, 1, map[string]any{"SHA256": fx.Digest([]byte("substituted delegation"))})
	reopened, err := store.New(f.Deps)
	if reopened != nil {
		if closeErr := reopened.Close(); closeErr != nil {
			t.Fatal(closeErr)
		}
	}
	var typed *api.Error
	if !errors.As(err, &typed) || typed.Code != api.CodeIntegrity {
		t.Fatal("state reopen accepted a lease detached from immutable authority", err)
	}
}

// Recover the parent's actual retained component facts; no new launch or lane
// is inserted. Its measured end is committed by the ordinary production port.
func delegationParent(t *testing.T, child *fx.Fixture) *fx.Fixture {
	t.Helper()
	ctx := context.Background()
	lane, err := child.State.Lane(ctx, child.Execution, api.LifeRef{LifeID: child.Lane.ParentLifeID})
	if err != nil {
		t.Fatal(err)
	}
	binding, err := child.State.LaunchBinding(ctx, lane.LaunchID)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := child.State.LaunchPlan(ctx, child.Execution, binding.Recovery.PlanID)
	if err != nil || plan.Plan == nil {
		t.Fatal("missing authentic parent plan", err)
	}
	parent := *child
	parent.Lane, parent.Binding, parent.Record, parent.Reservation, parent.Plan, parent.Prepared = lane, binding, plan, plan.Reservation, *plan.Plan, binding.Prepared
	// The parent's completed planning effect retains the exact observed process.
	claim, err := child.State.Effect(ctx, child.Execution, plan.Handoff.Cause.EffectID)
	if err != nil || claim.Outcome == nil || claim.Outcome.Process == nil {
		t.Fatal("missing parent process outcome", err)
	}
	parent.Process = *claim.Outcome.Process
	return &parent
}

func TestSealedDelegationRealStore(t *testing.T) {
	f := fx.ControlledChild(t)
	f.Opened(t)
	port, ok := any(f.State).(delegationReader)
	if !ok {
		t.Fatal("sealed post-exit delegation lease port is missing")
	}
	ctx := context.Background()
	parent := delegationParent(t, f)
	if _, err := port.VerifyDelegationLease(ctx, f.Execution, parent.Lane.LifeID, f.Lane.GrantSetID); err == nil {
		t.Fatal("running parent fabricated a post-exit lease")
	}
	parent.Ended(t)
	seal, err := port.VerifyDelegationLease(ctx, f.Execution, parent.Lane.LifeID, f.Lane.GrantSetID)
	if err != nil || seal == "" {
		t.Fatal("measured parent end did not seal prior child authority", err)
	}
	again, err := port.VerifyDelegationLease(ctx, f.Execution, parent.Lane.LifeID, f.Lane.GrantSetID)
	if err != nil || seal != again {
		t.Fatal("lease read-back changed its immutable seal", err)
	}
	if _, err := port.VerifyDelegationLease(ctx, f.Execution, fx.ID(t), f.Lane.GrantSetID); err == nil {
		t.Fatal("foreign parent acquired delegated authority")
	}
	if _, err := port.VerifyDelegationLease(ctx, f.Execution, parent.Lane.LifeID, parent.Lane.GrantSetID); err == nil {
		t.Fatal("parent grants substituted for child scope")
	}
	if err := f.State.Close(); err != nil {
		t.Fatal(err)
	}
	f.State, err = store.New(f.Deps)
	if err != nil {
		t.Fatal("sealed authority did not survive writer restart", err)
	}
	if actual, err := f.State.VerifyDelegationLease(ctx, f.Execution, parent.Lane.LifeID, f.Lane.GrantSetID); err != nil || actual != seal {
		t.Fatal("restart changed its prior sealed scope", err)
	}
	originalClock := f.Deps.Clock
	if err := f.State.Close(); err != nil {
		t.Fatal(err)
	}
	f.Deps.Clock = delegationExpiryClock{now: originalClock.Now().Add(2 * time.Hour)}
	f.State, err = store.New(f.Deps)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.State.VerifyDelegationLease(ctx, f.Execution, parent.Lane.LifeID, f.Lane.GrantSetID); err == nil {
		t.Fatal("expired lease retained delegated authority")
	}
	if err := f.State.Close(); err != nil {
		t.Fatal(err)
	}
	f.Deps.Clock = originalClock
	f.State, err = store.New(f.Deps)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.State.VerifyDelegationLease(ctx, f.Execution, parent.Lane.LifeID, f.Lane.GrantSetID); err != nil {
		t.Fatal("unexpired control lost its sealed scope", err)
	}
	publishFixturePolicy(t, f)
	if _, err := f.State.VerifyDelegationLease(ctx, f.Execution, parent.Lane.LifeID, f.Lane.GrantSetID); err == nil {
		t.Fatal("old policy retained delegated lease authority")
	}
}

type delegationExpiryClock struct{ now time.Time }

func (c delegationExpiryClock) Now() time.Time { return c.now }
