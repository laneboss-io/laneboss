//go:build linux && laneboss_root_canary && laneboss_gate_integration

package service

import (
	"context"
	"os"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/identity"
	"laneboss.io/laneboss/internal/v2/lifecycle"
	fx "laneboss.io/laneboss/internal/v2/store/testfx"
)

type grantCanaryPeers struct{ api.PeerVerifier }
type grantCanaryRegistry struct{ api.ContainmentRegistry }

// The ancestor is explicit component authority. The affected child executes
// and is stopped/collected by the actual native helper in its delegated unit.
// No owner proof, vendor service or installed administrator ceremony is used.
func ExerciseGrantCascadeCanary(t *testing.T, exchange func(string, any, any) error) {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Fatal("grant canary writer must be unprivileged")
	}
	ctx := context.Background()
	var native struct {
		UID    uint32
		Config string
	}
	if err := exchange("identity", api.Empty{}, &native); err != nil {
		t.Fatal(err)
	}
	f := fx.New(t, native.Config)
	f.Reserve(t)
	f.Source(t)
	f.BuildPlan(t, true)
	f.Spec(t)
	f.Bind(t)
	f.Opened(t)
	parent := f.LaneScope(t)
	f.Ceiling = f.Plan.Inputs.Grants
	f.Start.Lane, f.Start.Level, f.Start.Role, f.Start.RootTicketID = string(fx.ID(t)), 3, "executor", ""
	task := []byte("native delegated grant collection")
	var err error
	f.Start.Task, err = f.State.RetainObject(ctx, f.Execution, api.RetainObjectRequest{Intent: f.Intent(t, api.InternalObjectRetain), Object: api.ObjectWrite{
		ObjectKey: fx.ID(t), Class: "task", Bytes: task, SHA256: fx.Digest(task), Origin: "service", ACL: api.ObjectACL{Config: f.Deps.Config, Owner: parent.Actor, LifeID: parent.Actor.LifeID, Audience: "owner", Generation: 1}}})
	if err != nil {
		t.Fatal(err)
	}
	f.Start.Grants.Data = append([]api.DataGrantRequest{}, f.Start.Grants.Data...)
	f.Start.Grants.Profiles = append([]api.ProfileDelegation{}, f.Start.Grants.Profiles...)
	f.Start.Grants.Data[0].ParentGrantID = f.Ceiling.Data[0].ID
	f.Start.Grants.Profiles[0].ParentGrantID = f.Ceiling.Profiles[0].ID
	expires := api.Timestamp(time.Now().Add(10 * time.Minute).UTC().Format(time.RFC3339Nano))
	f.Start.Grants.Data[0].ExpiresAt, f.Start.Grants.Profiles[0].ExpiresAt = expires, expires
	f.Start.ProfileGrantID = f.Ceiling.Profiles[0].ID
	f.Human = parent
	f.Admit(t, "lane.start", f.Start)
	f.Reserve(t)
	f.Source(t)
	f.CaptureSetup = func(binding api.CaptureBinding) api.CaptureBinding {
		var actual api.CaptureBinding
		if err := exchange("capture", binding, &actual); err != nil {
			t.Fatal(err)
		}
		return actual
	}
	f.BuildPlanForIdentity(t, true, native.UID, native.UID)
	f.Spec(t)
	f.PreparedClaim = api.EffectLease{}
	f.PrepareJob(t)
	policy, err := f.State.Policy(ctx, f.Execution)
	if err != nil {
		t.Fatal(err)
	}
	input := struct {
		Plan       api.LaunchPlan
		Handoff    api.PreparedSpecHandoff
		Prepared   api.PreparedLaunch
		Request    api.HelperLaunchRequest
		Allocation api.HelperLeaseRequest
		Worker     api.WorkerLease
		Policy     api.EffectivePolicy
	}{f.Plan, *f.Record.Handoff, f.Prepared, *f.PreparedClaim.Record.Effect.HelperPrepare, f.Allocation, f.WorkerLease, policy}
	if err := exchange("prepare", input, &f.Prepared); err != nil {
		t.Fatal("native delegated preparation failed", err)
	}
	f.Bind(t)
	var opened api.LaunchReconciliation
	if err := exchange("open", f.Binding, &opened); err != nil {
		t.Fatal(err)
	}
	f.Process = api.ProcessHandle{}
	f.Opened(t, opened)
	req := api.GrantRevokeRequest{GrantSetID: f.Lane.GrantSetID, ExpectedGeneration: f.Plan.Inputs.Grants.Generation, Reason: f.Start.Task}
	f.Admit(t, "grants.revoke", req)
	commit, err := f.State.RevokeGrants(ctx, f.Human, req, nil)
	if err != nil || commit.Operation.Status != "pending" {
		t.Fatal("native revocation did not retain pending intent", err)
	}
	h := &nativeReleaseTransport{fixture: f, exchange: exchange}
	launcher := &nativeGrantObserver{nativeReleaseObserver: nativeReleaseObserver{transport: h}}
	host := &Server{options: Options{Config: f.Deps.Config}, deps: Dependencies{Store: f.State, Clock: f.Deps.Clock}, controller: fx.ID(t)}
	auth, err := identity.New(identity.Dependencies{Store: f.State, Clock: f.Deps.Clock, Peers: &grantCanaryPeers{}, Registry: &grantCanaryRegistry{}})
	if err != nil {
		t.Fatal(err)
	}
	if err := auth.BindConnections(host); err != nil {
		t.Fatal(err)
	}
	coordinator, err := lifecycle.New(lifecycle.Dependencies{Store: f.State, Identity: auth, Clock: f.Deps.Clock})
	if err != nil {
		t.Fatal(err)
	}
	host.runtime = api.RuntimeServices{Store: f.State, Helper: h, Launcher: launcher, Lifecycle: coordinator}
	effects, err := f.State.PendingEffects(ctx, api.CursorRequest{Limit: 200})
	if err != nil {
		t.Fatal(err)
	}
	var stop api.Effect
	for _, effect := range effects {
		if effect.OperationID == commit.Operation.ID && effect.Stop != nil {
			stop = effect
		}
	}
	if stop.ID == "" {
		t.Fatal("native cascade lost its stable stop")
	}
	if result := host.reconcileEffect(ctx, stop, make(effectRetries)); result != attemptNext || host.fault != nil {
		t.Fatal("native grant stop failed", host.fault)
	}
	if _, err := f.State.LaunchRevocation(ctx, f.Lane.LaunchID); err != nil {
		t.Fatal("native grant transport lacks committed causal revocation", err)
	}
	stopped, err := f.State.Effect(ctx, f.Execution, stop.ID)
	if err != nil || stopped.Outcome == nil || stopped.Outcome.Observation == nil || stopped.Outcome.Observation.State != "exited" || stopped.Outcome.Observation.Survivors == nil || *stopped.Outcome.Observation.Survivors != 0 {
		t.Fatal("native grant stop lacks measured quiescence", err)
	}
	var ready bool
	if err := exchange("unblock", api.Empty{}, &ready); err != nil || !ready {
		t.Fatal("native capture did not reach EOF", err)
	}
	effects, err = f.State.PendingEffects(ctx, api.CursorRequest{Limit: 200})
	if err != nil {
		t.Fatal(err)
	}
	var release api.Effect
	for _, effect := range effects {
		if effect.OperationID == commit.Operation.ID && effect.HelperRelease != nil {
			release = effect
		}
	}
	if release.ID == "" {
		t.Fatal("native grant stop lost its collection effect")
	}
	if result := host.reconcileEffect(ctx, release, make(effectRetries)); result != attemptNext || host.fault != nil {
		t.Fatal("native grant collection failed", host.fault)
	}
	collected, err := f.State.Effect(ctx, f.Execution, release.ID)
	if err != nil || collected.Outcome == nil || collected.Outcome.Release == nil {
		t.Fatal("native grant collection has no measured receipt", err)
	}
	if err := exchange("verify", *collected.Outcome.Release, &ready); err != nil || !ready {
		t.Fatal("native helper read-back failed", err)
	}
	operation, err := f.State.Operation(ctx, f.Execution, commit.Operation.ID)
	if err != nil || operation.Status != "succeeded" {
		t.Fatal("native grant revocation did not complete", err)
	}
	if verified, err := f.State.Verify(ctx, api.VerifyRequest{Scope: "all"}); err != nil || !verified.OK {
		t.Fatal("native grant journal did not verify", err)
	}
	worker, err := f.State.Launch(ctx, f.Worker.LaunchID)
	if err != nil || !worker.Revoked {
		t.Fatal("native collection retained a live capture worker identity", err)
	}
}

type nativeGrantObserver struct{ nativeReleaseObserver }

func (o *nativeGrantObserver) Stop(ctx context.Context, handle api.ProcessHandle, reason string) (api.ProcessObservation, error) {
	f := o.transport.fixture
	cause, _, err := f.State.LaunchControlIntent(ctx, api.InternalHelperStop, f.Lane.LaunchID)
	if err != nil {
		return api.ProcessObservation{}, err
	}
	request := api.HelperStopRequest{Cause: cause, Target: api.HelperObserveRequest{LeaseID: f.Plan.Lease.ID, Handle: handle}, OperationID: cause.CauseOperationID, EffectID: cause.EffectID, Reason: reason}
	var result api.ProcessObservation
	err = o.transport.exchange("grant-stop", request, &result)
	return result, err
}
