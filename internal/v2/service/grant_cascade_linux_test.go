//go:build linux

package service

import (
	"context"
	"net"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/identity"
	"laneboss.io/laneboss/internal/v2/lifecycle"
	fx "laneboss.io/laneboss/internal/v2/store/testfx"
)

// Only unused peer discovery is a component dependency here. Revocation uses
// the real identity read-back and Server's actual connection invalidation.
type cascadePeers struct{ api.PeerVerifier }
type cascadeRegistry struct{ api.ContainmentRegistry }

func grantStop(t *testing.T, priorRelease ...bool) (*fx.Fixture, *Server, api.EffectLease, api.ProcessObservation, api.Operation) {
	t.Helper()
	f := fx.ControlledChild(t)
	f.Opened(t)
	ctx := context.Background()
	if len(priorRelease) != 0 && priorRelease[0] {
		ordinary := launchServer(t, f)
		coordinator, err := lifecycle.New(lifecycle.Dependencies{Store: f.State, Identity: &authFixture{}, Clock: f.Deps.Clock})
		if err != nil {
			t.Fatal(err)
		}
		ordinary.runtime.Lifecycle = coordinator
		ordinary.runtime.Launcher = &endedRunLauncher{observation: f.Observation(t, "exited").Observation}
		cause := f.Intent(t, api.InternalLifecycleEffect)
		cause.ID, cause.EffectID, cause.CauseOperationID, cause.CauseRequestID = fx.ID(t), fx.ID(t), fx.ID(t), fx.ID(t)
		claim := claimControl(t, f, api.Effect{ID: cause.EffectID, OperationID: cause.CauseOperationID, Context: &cause, Stop: &f.Process})
		outcome, err := ordinary.runEffect(ctx, f.Execution, claim)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.State.CompleteEffect(ctx, f.Execution, outcome); err != nil {
			t.Fatal(err)
		}
	}
	request := api.GrantRevokeRequest{GrantSetID: f.Lane.GrantSetID, ExpectedGeneration: f.Plan.Inputs.Grants.Generation, Reason: f.Start.Task}
	f.Admit(t, "grants.revoke", request)
	commit, err := f.State.RevokeGrants(ctx, f.Human, request, nil)
	if err != nil {
		t.Fatal(err)
	}
	s := launchServer(t, f)
	auth, err := identity.New(identity.Dependencies{Store: f.State, Clock: f.Deps.Clock, Peers: &cascadePeers{}, Registry: &cascadeRegistry{}})
	if err != nil {
		t.Fatal(err)
	}
	if err := auth.BindConnections(s); err != nil {
		t.Fatal(err)
	}
	coordinator, err := lifecycle.New(lifecycle.Dependencies{Store: f.State, Identity: auth, Clock: f.Deps.Clock})
	if err != nil {
		t.Fatal(err)
	}
	s.runtime.Lifecycle = coordinator
	ended := f.Observation(t, "exited").Observation
	s.runtime.Launcher = &endedRunLauncher{observation: ended}
	effects, err := f.State.PendingEffects(ctx, api.CursorRequest{Limit: 200})
	if err != nil {
		t.Fatal(err)
	}
	var stop api.Effect
	for _, e := range effects {
		if e.OperationID == commit.Operation.ID && e.Stop != nil {
			stop = e
		}
	}
	if stop.ID == "" {
		t.Fatal("cascade has no durable stop")
	}
	lease, err := f.State.ClaimEffect(ctx, f.Execution, api.EffectClaimRequest{EffectID: stop.ID, ExpectedGeneration: 1, ClaimantID: f.Execution.Actor.ID, Deadline: api.Timestamp(time.Now().Add(time.Minute).UTC().Format(time.RFC3339Nano))})
	if err != nil {
		t.Fatal(err)
	}
	return f, s, lease, ended, commit.Operation
}

func TestGrantCascadePriorRelease(t *testing.T) {
	f, s, stop, _, operation := grantStop(t, true)
	ctx := context.Background()
	outcome, err := s.runEffect(ctx, f.Execution, stop)
	if err != nil {
		t.Fatal("revocation could not adopt the actual already-ended run", err)
	}
	if _, err := f.State.CompleteEffect(ctx, f.Execution, outcome); err == nil {
		t.Fatal("revocation ignored a pending release owned by another operation")
	}
	lane, err := f.State.Lane(ctx, f.Execution, f.Reservation.Target)
	if err != nil || lane.State != "verifying" {
		t.Fatal("revocation stranded the already-ended run in stopping", err)
	}
	effects, err := f.State.PendingEffects(ctx, api.CursorRequest{Limit: 200})
	if err != nil {
		t.Fatal(err)
	}
	var release api.Effect
	for _, e := range effects {
		if e.HelperRelease != nil && e.Context.Target == f.Reservation.Target {
			release = e
		}
	}
	if release.ID == "" || release.OperationID == operation.ID {
		t.Fatal("revocation replaced the original release cause")
	}
	s.runtime.Helper = &measuredRunHelper{drainHelperFixture: runDrainHelper(t, f, *release.HelperRelease), receipt: runReceipt(t, release)}
	claim, err := f.State.ClaimEffect(ctx, f.Execution, api.EffectClaimRequest{EffectID: release.ID, ExpectedGeneration: 1, ClaimantID: f.Execution.Actor.ID, Deadline: fx.Expiry()})
	if err != nil {
		t.Fatal("original ended release could not be claimed", err)
	}
	released, err := s.runEffect(ctx, f.Execution, claim)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.State.CompleteEffect(ctx, f.Execution, released); err != nil {
		t.Fatal(err)
	}
	again, err := s.runEffect(ctx, f.Execution, stop)
	if err != nil {
		t.Fatal("same revocation claim could not replay after collection", err)
	}
	commit, err := f.State.CompleteEffect(ctx, f.Execution, again)
	if err != nil || commit.Operation.ID != operation.ID || commit.Operation.Status != "succeeded" {
		t.Fatal("revocation did not finish after original release read-back", err)
	}
}

func TestGrantCascadeCollection(t *testing.T) {
	f, s, stop, ended, operation := grantStop(t)
	ctx := context.Background()
	// A measured exited process alone is insufficient to finish revocation.
	before := api.EffectOutcome{EffectID: stop.Record.Effect.ID, ClaimID: stop.ClaimID, ExpectedGeneration: stop.Record.Generation, Status: "succeeded", Observation: &ended}
	if _, err := f.State.CompleteEffect(ctx, f.Execution, before); err == nil {
		t.Fatal("grant cascade completed before causal transport and helper collection")
	}
	left, right := net.Pipe()
	t.Cleanup(func() { left.Close(); right.Close() })
	connection := &connectionContext{conn: left, binding: api.InstalledBinding{LaunchID: f.Lane.LaunchID}, finished: make(chan struct{}), id: fx.ID(t)}
	if s.connections == nil {
		s.connections = make(map[api.ID]*connectionContext)
	}
	s.connections[connection.id] = connection
	go func() {
		var data [1]byte
		if _, err := left.Read(data[:]); err == nil {
			t.Error("revoked connection unexpectedly delivered input")
		}
		s.mu.Lock()
		delete(s.connections, connection.id)
		s.mu.Unlock()
		close(connection.finished)
	}()
	outcome, err := s.runEffect(ctx, f.Execution, stop)
	if err != nil {
		t.Fatal("causal grant stop could not run", err)
	}
	if _, err := right.Write([]byte("revoked connection probe")); err == nil {
		t.Fatal("revoked transport retained a writable connection")
	}
	revoked, err := f.State.LaunchRevocation(ctx, f.Lane.LaunchID)
	if err != nil || revoked.Cause.RequestedBy != f.Human.Actor || revoked.Cause.CauseOperationID != operation.ID {
		t.Fatal("revocation lost its original requester and operation", err)
	}
	commit, err := f.State.CompleteEffect(ctx, f.Execution, outcome)
	if err != nil || commit.Operation.Status != "pending" {
		t.Fatal("stop bypassed pending helper collection", err)
	}
	effects, err := f.State.PendingEffects(ctx, api.CursorRequest{Limit: 200})
	if err != nil {
		t.Fatal(err)
	}
	var release api.Effect
	for _, effect := range effects {
		if effect.OperationID == operation.ID && effect.HelperRelease != nil {
			release = effect
		}
	}
	if release.ID == "" {
		t.Fatal("grant stop did not retain a release under its original operation")
	}
	s.runtime.Helper = &measuredRunHelper{drainHelperFixture: runDrainHelper(t, f, *release.HelperRelease), receipt: runReceipt(t, release)}
	claim, err := f.State.ClaimEffect(ctx, f.Execution, api.EffectClaimRequest{EffectID: release.ID, ExpectedGeneration: 1, ClaimantID: f.Execution.Actor.ID, Deadline: fx.Expiry()})
	if err != nil {
		t.Fatal(err)
	}
	actual, err := s.runEffect(ctx, f.Execution, claim)
	if err != nil {
		t.Fatal("measured grant release failed", err)
	}
	commit, err = f.State.CompleteEffect(ctx, f.Execution, actual)
	if err != nil || commit.Operation.Status != "succeeded" {
		t.Fatal("measured grant collection did not complete its original operation", err)
	}
	worker, err := f.State.Launch(ctx, f.Worker.LaunchID)
	if err != nil || !worker.Revoked {
		t.Fatal("grant collection left its captured worker identity live", err)
	}
	verification, err := f.State.Verify(ctx, api.VerifyRequest{Scope: "all"})
	if err != nil || !verification.OK {
		t.Fatal("grant collection did not verify against its journal", err)
	}
}

func TestGrantCascadeClaimControls(t *testing.T) {
	for _, bad := range []string{"claim", "actor", "generation"} {
		t.Run(bad, func(t *testing.T) {
			f, s, lease, _, _ := grantStop(t)
			scope := f.Execution
			switch bad {
			case "claim":
				lease.ClaimID = fx.ID(t)
			case "actor":
				scope.Actor.ID = fx.ID(t)
			case "generation":
				lease.Record.Generation++
			}
			if _, err := s.runEffect(context.Background(), scope, lease); err == nil {
				t.Fatal("grant stop accepted " + bad)
			}
			if _, err := f.State.LaunchRevocation(context.Background(), f.Lane.LaunchID); err == nil {
				t.Fatal("refused stop committed revocation")
			}
		})
	}
}
