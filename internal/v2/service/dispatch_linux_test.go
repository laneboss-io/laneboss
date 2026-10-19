//go:build linux

package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/store"
)

// This watchdog is a component call ledger, not a scheduler/process canary.
type dispatchWatchdog struct {
	api.Watchdog
	targets []api.LifeRef
	err     error
}

func (w *dispatchWatchdog) Cancel(ctx context.Context, target api.LifeRef) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	w.targets = append(w.targets, target)
	return w.err
}

type hostDispatchFixture struct {
	host     *Server
	state    *store.Service
	scope    api.Scope
	request  api.FreezeRequest
	lease    api.EffectLease
	watchdog *dispatchWatchdog
	target   api.LifeRef
}

func newHostDispatchFixture(t *testing.T) hostDispatchFixture {
	t.Helper()
	ctx := context.Background()
	directory := privateHostDirectory(t)
	state, err := store.New(store.Dependencies{Config: "service-fixture", Directory: directory, Clock: fixtureClock{}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := state.Close(); err != nil {
			t.Error(err)
		}
	})
	_, record := socketRecord(t, &state, directory)
	target := api.LifeRef{LifeID: record.LifeID, Run: record.Run}
	scope := api.Scope{Config: "service-fixture", Actor: api.Actor{Kind: "service", ID: fixtureID(t)}, Source: "worker"}
	lane, err := state.Lane(ctx, scope, target)
	if err != nil {
		t.Fatal("dispatch target lane control failed", err)
	}
	op, effectID := fixtureID(t), fixtureID(t)
	intent := api.InternalIntent{ID: fixtureID(t), Kind: api.InternalLifecycleEffect, Config: scope.Config,
		Actor: scope.Actor, RequestedBy: scope.Actor, CauseOperationID: op, CauseRequestID: fixtureID(t), EffectID: effectID, Target: target, CancellationEpoch: lane.CancellationEpoch}
	effect := api.Effect{ID: effectID, OperationID: op, Context: &intent,
		Stop: &api.ProcessHandle{ID: fixtureID(t), Target: target, ContainmentID: fixtureID(t), Generation: "component-lifetime"}}
	if _, err := state.Transact(ctx, api.Transaction{Scope: scope, Internal: &intent, Effects: []api.Effect{effect}}); err != nil {
		t.Fatal("pending component effect control failed", err)
	}
	data := []byte(fixtureID(t))
	sum := sha256.Sum256(data)
	reason, err := state.RetainObject(ctx, scope, api.RetainObjectRequest{
		Intent: api.InternalIntent{ID: fixtureID(t), Kind: api.InternalObjectRetain, Config: scope.Config,
			Actor: scope.Actor, RequestedBy: scope.Actor, CauseOperationID: op},
		Object: api.ObjectWrite{ObjectKey: fixtureID(t), Class: "report", Bytes: data, SHA256: api.Digest(hex.EncodeToString(sum[:])), Origin: "service",
			ACL: api.ObjectACL{Config: scope.Config, Owner: scope.Actor, Audience: "owner", Generation: 1}}})
	if err != nil {
		t.Fatal(err)
	}
	phase := api.InternalIntent{ID: fixtureID(t), Kind: api.InternalUpgradeApply, Config: scope.Config,
		Actor: scope.Actor, RequestedBy: scope.Actor, CauseOperationID: op, CauseRequestID: intent.CauseRequestID}
	plan := api.DeploymentPlan{ID: fixtureID(t), Config: scope.Config, Actor: scope.Actor, InstallationGeneration: 1,
		EndpointGeneration: 1, Generation: 1, Phase: "freezing", OperationID: op}
	if _, err := state.Transact(ctx, api.Transaction{Scope: scope, Internal: &phase, Writes: api.StateWrites{Deployments: []api.DeploymentPlan{plan}}}); err != nil {
		t.Fatal("retained component deployment control failed", err)
	}
	lease, err := state.ClaimEffect(ctx, scope, api.EffectClaimRequest{EffectID: effectID, ExpectedGeneration: 1,
		ClaimantID: scope.Actor.ID, Deadline: api.Timestamp(time.Now().Add(time.Minute).UTC().Format(time.RFC3339Nano))})
	if err != nil {
		t.Fatal(err)
	}
	host := fixtureServer(t)
	host.deps.Store, host.verified = state, true
	host.deps.Binding.InstallationGeneration = 1
	watchdog := &dispatchWatchdog{}
	if err := host.BindRuntime(ctx, api.RuntimeServices{Store: state, Identity: host.deps.Authenticator,
		Config: scope.Config, Launcher: &healthLauncher{}, Watchdog: watchdog}); err != nil {
		t.Fatal("host runtime control failed", err)
	}
	return hostDispatchFixture{host: host, state: state, scope: scope, request: api.FreezeRequest{
		OperationID: op, ExpectedInstallationGeneration: 1, Reason: reason}, lease: lease, watchdog: watchdog, target: target}
}

func TestHostFreezeDrainThaw(t *testing.T) {
	f := newHostDispatchFixture(t)
	ctx := context.Background()
	request := requestFor(t, "blob.begin", api.BlobBeginRequest{Class: "report", SHA256: f.request.Reason.SHA256})
	pendingScope := f.scope
	pendingScope.Request = request
	raw, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.state.ReserveRequest(ctx, api.RequestReservation{Scope: pendingScope, RawRequest: raw,
		Deadline: api.Timestamp(time.Now().Add(time.Minute).UTC().Format(time.RFC3339Nano))}); err != nil {
		t.Fatal(err)
	}
	freeze, err := f.host.FreezeDispatch(ctx, f.scope, f.request)
	if err != nil || !f.host.dispatchPaused || f.host.freeze == nil || *f.host.freeze != freeze {
		t.Fatal("host failed to retain its durable freeze", err)
	}
	if len(f.watchdog.targets) != 1 || f.watchdog.targets[0] != f.target {
		t.Fatal("host did not cancel observed watchdog targets")
	}
	if _, err := f.host.DrainDispatch(ctx, f.scope, freeze); err == nil || err.Error() != "unavailable: drain still has reserved requests requiring reconciliation" {
		t.Fatal("drain ignored a retained reservation", err)
	}
	if _, err := f.state.Transact(ctx, api.Transaction{Scope: pendingScope, Reply: &api.RPCReply{
		Error: serviceError(api.CodeCancelled, "component request cancelled before execution")}}); err != nil {
		t.Fatal("admitted cancellation could not finish while frozen", err)
	}
	if _, err := f.host.DrainDispatch(ctx, f.scope, freeze); err == nil || err.Error() != "unavailable: drain still has incomplete or claimed effects" {
		t.Fatal("drain ignored an unexpired effect claim", err)
	}
	// A fresh host reads its state from SQLite. This is not a service restart.
	restored := fixtureServer(t)
	restored.deps.Store, restored.verified = f.state, true
	restored.deps.Binding.InstallationGeneration = 1
	if err := restored.BindRuntime(ctx, api.RuntimeServices{Store: f.state, Identity: restored.deps.Authenticator, Config: f.scope.Config}); err != nil {
		t.Fatal("frozen recovery host required an unready executor", err)
	}
	if !restored.dispatchPaused || restored.freeze == nil || *restored.freeze != freeze {
		t.Fatal("host binding lost the durable freeze")
	}
	codeIs(t, restored.ThawDispatch(ctx, f.scope, freeze), api.CodePrerequisite)
	if !restored.dispatchPaused {
		t.Fatal("unsupported pending effect opened dispatch")
	}
	// Inject an explicit component failure, never an unobserved process success.
	if _, err := f.state.CompleteEffect(ctx, f.scope, api.EffectOutcome{EffectID: f.lease.Record.Effect.ID,
		ClaimID: f.lease.ClaimID, ExpectedGeneration: f.lease.Record.Generation, Status: "failed",
		Error: serviceError(api.CodeCancelled, "component executor deliberately refused")}); err != nil {
		t.Fatal(err)
	}
	_, err = restored.DrainDispatch(ctx, f.scope, freeze)
	codeIs(t, err, api.CodeNotImplemented)
	var typed *api.Error
	if !errors.As(err, &typed) || typed.Message != "measured capture and process drain inventory is not implemented" {
		t.Fatal("empty dispatch queue invented measured quiescence", err)
	}
	if err := restored.ThawDispatch(ctx, f.scope, freeze); err != nil {
		t.Fatal("exact host thaw failed", err)
	}
	if restored.dispatchPaused || restored.freeze != nil {
		t.Fatal("host did not reopen after retained thaw")
	}
}

func TestFreezeCancelFailureStaysClosed(t *testing.T) {
	f := newHostDispatchFixture(t)
	f.watchdog.err = serviceError(api.CodeUnavailable, "component watchdog cancellation refused")
	freeze, err := f.host.FreezeDispatch(context.Background(), f.scope, f.request)
	codeIs(t, err, api.CodeUnavailable)
	active, readErr := f.state.ActiveDispatchFreeze(context.Background())
	if readErr != nil || active == nil || *active != freeze || !f.host.dispatchPaused {
		t.Fatal("watchdog failure discarded the durable barrier", readErr)
	}
	f.watchdog.err = nil
	retry, err := f.host.FreezeDispatch(context.Background(), f.scope, f.request)
	if err != nil || retry != freeze || len(f.watchdog.targets) != 2 {
		t.Fatal("watchdog recovery did not retry exact retained freeze", err)
	}
}
