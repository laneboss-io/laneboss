//go:build linux

package service

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/admin"
	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/dataworker"
	"laneboss.io/laneboss/internal/v2/lifecycle"
	"laneboss.io/laneboss/internal/v2/store"
	fx "laneboss.io/laneboss/internal/v2/store/testfx"
)

// Only the host/transport identity is a component fixture. Every launch,
// handoff, original byte range, binding and acknowledgement comes from the
// real store's reservation and transaction path. No helper executes an agent.
func launchServer(t *testing.T, f *fx.Fixture) *Server {
	t.Helper()
	s := fixtureServer(t)
	s.verified, s.bound, s.controller = true, true, fx.ID(t)
	s.options.Config = f.Deps.Config
	s.deps.Store = f.State
	s.deps.Clock = fx.Clock{}
	s.deps.Binding.Config = f.Deps.Config
	s.deps.Binding.Backend = f.Plan.Inputs.Sources.Runtime.Backend
	s.deps.Authenticator = &authFixture{scope: f.Worker, store: f.State}
	laneHostFixture(t, s)
	return s
}

// Native helper observations are component inputs here; the root admin twin
// measures real processes. Inventory, cleanup, recovery and Close are real.
type uidRecoveryHelper struct {
	api.HelperControl
	ledgers map[api.ID]*recoveryLedger
	faults  map[api.ID]error
}

func (h *uidRecoveryHelper) ReconcileGate(ctx context.Context, q api.HelperReconcileRequest) (api.LaunchReconciliation, error) {
	ledger := h.ledgers[q.LaunchID]
	if ledger == nil {
		return api.LaunchReconciliation{}, serviceError(api.CodeIntegrity, "recovery scanned a retired life after UID reuse")
	}
	actual, err := ledger.ReconcileGate(ctx, q)
	if err == nil {
		err = h.faults[q.LaunchID]
	}
	return actual, err
}

func (h *uidRecoveryHelper) ReconcileCapture(ctx context.Context, q api.CaptureBinding) (api.CaptureBinding, error) {
	ledger := h.ledgers[q.LaunchID]
	if ledger == nil {
		return api.CaptureBinding{}, serviceError(api.CodeIntegrity, "recovery scanned a retired capture after UID reuse")
	}
	return ledger.ReconcileCapture(ctx, q)
}

// Build the child with a distinct native identity before sealing its plan.
// The generic Child fixture uses the test UID, which is also this host's UID.
func uidChild(t *testing.T, f *fx.Fixture) fx.Fixture {
	t.Helper()
	f.Opened(t)
	parent := *f
	scope := f.LaneScope(t)
	raw := []byte("UID recovery child task")
	task, err := f.State.RetainObject(context.Background(), f.Execution, api.RetainObjectRequest{
		Intent: f.Intent(t, api.InternalObjectRetain), Object: api.ObjectWrite{ObjectKey: fx.ID(t), Class: "task",
			Bytes: raw, SHA256: fx.Digest(raw), Origin: "service",
			ACL: api.ObjectACL{Config: f.Deps.Config, Owner: scope.Actor, Audience: "owner", Generation: 1}}})
	if err != nil {
		t.Fatal(err)
	}
	f.Ceiling = f.Plan.Inputs.Grants
	f.Start.Lane = string(fx.ID(t))
	f.Start.Level, f.Start.Role, f.Start.RootTicketID, f.Start.Task = 3, "executor", "", task
	f.Start.Grants.Data = append([]api.DataGrantRequest{}, f.Start.Grants.Data...)
	f.Start.Grants.Profiles = append([]api.ProfileDelegation{}, f.Start.Grants.Profiles...)
	f.Start.Grants.Data[0].ParentGrantID = f.Ceiling.Data[0].ID
	f.Start.Grants.Profiles[0].ParentGrantID = f.Ceiling.Profiles[0].ID
	expires := api.Timestamp(time.Now().Add(10 * time.Minute).UTC().Format(time.RFC3339Nano))
	f.Start.Grants.Data[0].ExpiresAt, f.Start.Grants.Profiles[0].ExpiresAt = expires, expires
	f.Start.ProfileGrantID, f.Human = f.Ceiling.Profiles[0].ID, scope
	f.Admit(t, "lane.start", f.Start)
	f.Reserve(t)
	f.Source(t)
	f.BuildPlanForIdentity(t, true, parent.Plan.Lease.UID+1, parent.Plan.Lease.GID+1)
	f.Spec(t)
	f.PreparedClaim = api.EffectLease{}
	f.Bind(t)
	return parent
}

func TestUIDReuseRecoveryClose(t *testing.T) {
	for _, mode := range []string{"clean-reuse", "helper-survivor"} {
		t.Run(mode, func(t *testing.T) {
			ctx := context.Background()
			f := fx.ReadyForIdentity(t, true, uint32(os.Geteuid())+1000, uint32(os.Getegid())+1000)
			parent := uidChild(t, f)
			scene := f.PrepareCleanup(t, func(ctx context.Context, scope api.Scope, p api.WorkerPrincipal) (api.WorkerResultReceipt, error) {
				return dataworker.RunArchive(ctx, dataworker.ArchiveJob{Principal: p, Scope: scope, Bootstrap: f.State,
					Read: func(ctx context.Context, q api.BlobReadRequest) (api.BlobChunk, error) {
						return f.State.WorkerObject(ctx, scope, q)
					}, Sink: f.State, Clock: f.Deps.Clock})
			}, nil, true)
			host := launchServer(t, f)
			worker, err := dataworker.New(dataworker.Dependencies{Config: f.Deps.Config, Store: f.State,
				Helper: &recoveryGroup{}, Launcher: &reconcileObserver{}, Clock: f.Deps.Clock, Workspace: scene.Workspace})
			if err != nil {
				t.Fatal(err)
			}
			host.runtime = api.RuntimeServices{Store: f.State, Worker: worker}
			if host.reconcileEffect(ctx, scene.Effect, make(effectRetries)) != attemptNext || host.fault != nil {
				t.Fatal("dirty retention stopped the service", host.fault)
			}
			lane, err := f.State.Lane(ctx, f.Execution, f.Reservation.Target)
			if err != nil || lane.Cleaned {
				t.Fatal("dirty life was falsely cleaned", err)
			}
			old := &recoveryLedger{fixture: f, gate: f.Observation(t, "exited")}
			helper := &uidRecoveryHelper{ledgers: map[api.ID]*recoveryLedger{
				parent.Reservation.LaunchID: {fixture: &parent, gate: parent.Observation(t, "running")},
				f.Reservation.LaunchID:      old,
			}, faults: make(map[api.ID]error)}
			if mode == "helper-survivor" {
				refused := &api.Error{Code: api.CodeContainmentUnknown, Owner: "lb-v2-admin", Message: "lane UID still owns a live process; retain its lease"}
				helper.faults[f.Reservation.LaunchID] = refused
				host.runtime.Helper, host.launchConfigured = helper, true
				host.launchRecoveryLoop(ctx)
				if old.gateCalls != 1 || !errors.Is(host.fault, refused) {
					t.Fatal("recovery skipped or discarded its retained survivor refusal", host.fault)
				}
				if closed := host.Close(); !errors.Is(closed, refused) {
					t.Fatal("service close discarded its real recovery fault", closed)
				}
				return
			}
			if err := host.reconcileLaunches(ctx, api.RuntimeServices{Store: f.State, Helper: helper}); err != nil || old.gateCalls != 1 {
				t.Fatal("retained life left launch recovery", err)
			}
			scene.SetDirty(false)
			if host.reconcileEffect(ctx, scene.Request(t), make(effectRetries)) != attemptNext || host.fault != nil {
				t.Fatal("repaired retained life did not clean", host.fault)
			}
			lane, err = f.State.Lane(ctx, f.Execution, f.Reservation.Target)
			if err != nil || !lane.Cleaned {
				t.Fatal("cleanup did not commit its retired life", err)
			}
			next := fx.NewIn(t, f.State, f.Deps)
			f.State, parent.State, host.deps.Store = next.State, next.State, next.State
			next.Reserve(t)
			next.Source(t)
			next.BuildPlanForIdentity(t, true, f.Plan.Lease.UID, f.Plan.Lease.GID)
			next.Spec(t)
			next.Bind(t)
			next.Opened(t)
			if next.Plan.Lease.UID != f.Plan.Lease.UID || next.Plan.Lease.ID == f.Plan.Lease.ID {
				t.Fatal("successor did not use the same UID under a new lease")
			}
			delete(helper.ledgers, f.Reservation.LaunchID)
			helper.ledgers[next.Reservation.LaunchID] = &recoveryLedger{fixture: next, gate: next.Observation(t, "running")}
			if err := host.reconcileLaunches(ctx, api.RuntimeServices{Store: next.State, Helper: helper}); err != nil {
				t.Fatal("cleaned life caused a false survivor after UID reuse", err)
			}
			if old.gateCalls != 1 || helper.ledgers[next.Reservation.LaunchID].gateCalls != 1 {
				t.Fatal("recovery scanned the old life or omitted the new life")
			}
			if err := host.Close(); err != nil {
				t.Fatal("service did not close cleanly after UID reuse", err)
			}
		})
	}
}

func TestLaunchControlRetained(t *testing.T) {
	f := fx.New(t)
	f.Reserve(t)
	f.Source(t)
	f.BuildPlanForIdentity(t, true, uint32(os.Geteuid())+1000, uint32(os.Getegid())+1000)
	f.Spec(t)
	s := launchServer(t, f)
	ctx := context.Background()
	spec := f.Record.Handoff.Spec
	handoff, err := s.Handoff(ctx, spec)
	if err != nil || !reflect.DeepEqual(handoff, *f.Record.Handoff) {
		t.Fatal("control source did not load retained complete handoff", err)
	}
	original, err := s.Original(ctx, handoff.Original)
	canonical, encodeErr := api.CanonicalJSON(fx.JSON(t, spec))
	if err != nil || encodeErr != nil || !bytes.Equal(original, canonical) {
		t.Fatal("control source changed original committed spec bytes", err, encodeErr)
	}
	frame, err := s.Original(ctx, f.Reservation.OriginalRequest)
	if err != nil || !bytes.Equal(frame, f.Raw) {
		t.Fatal("control source re-encoded the original request frame", err)
	}
	bad := spec
	runner := *spec.Runner
	runner.Executable.ID = "/caller/executable"
	bad.Runner = &runner
	if _, err := s.Handoff(ctx, bad); err == nil {
		t.Fatal("control source accepted a caller executable")
	}
	ref := handoff.Original
	ref.ID = fx.ID(t)
	if _, err := s.Original(ctx, ref); err == nil {
		t.Fatal("control source read an unretained original object")
	} else {
		codeIs(t, err, api.CodeForbidden)
	}
	f.PrepareJob(t)
	intent, err := s.PrepareIntent(ctx, handoff)
	if err != nil || !reflect.DeepEqual(intent, f.PreparedClaim.Record.Effect.HelperPrepare.Cause) {
		t.Fatal("prepare intent did not use the actual current stage", err)
	}
	changed := handoff
	changed.Original.SHA256 = fx.Digest([]byte("different spec"))
	if _, err := s.PrepareIntent(ctx, changed); err == nil {
		t.Fatal("prepare accepted changed retained input")
	} else {
		codeIs(t, err, api.CodeConflict)
	}
	f.Bind(t)
	binding, err := s.Binding(ctx, f.Reservation.LaunchID)
	if err != nil || !reflect.DeepEqual(binding, f.Binding) {
		t.Fatal("control source did not reload the committed recovery binding", err)
	}
	permit := api.LaunchPermit{LaunchID: binding.Record.ID, PreparedID: binding.Prepared.ID, RecordSHA256: binding.Identity.RecordSHA256, CommittedSeq: binding.Identity.CommittedSeq}
	open, err := s.Open(ctx, f.Prepared, permit)
	if err != nil || open.Prepared != f.Prepared || open.Permit != permit || open.EffectID != f.Claim.Record.Effect.ID || open.Cause.RequestedBy != f.Human.Actor || open.Cause.Kind != api.InternalHelperOpen {
		t.Fatal("open did not bind the actual claim and original requester", err)
	}
	badPermit := permit
	badPermit.CommittedSeq++
	if _, err := s.Open(ctx, f.Prepared, badPermit); err == nil {
		t.Fatal("open accepted an uncommitted permit")
	} else {
		codeIs(t, err, api.CodeForbidden)
	}
	if err := f.State.Close(); err != nil {
		t.Fatal(err)
	}
	f.State, err = store.New(f.Deps)
	if err != nil {
		t.Fatal(err)
	}
	restarted := launchServer(t, f)
	read, err := restarted.Binding(ctx, binding.Record.ID)
	if err != nil || !reflect.DeepEqual(read, binding) {
		t.Fatal("fresh service instance lost durable launch binding", err)
	}
	if _, err := restarted.Open(ctx, f.Prepared, permit); err != nil {
		t.Fatal("fresh service could not recover the same prepared control request", err)
	}
}

func TestCaptureAuthenticatedIngress(t *testing.T) {
	f := fx.Ready(t, true)
	s := launchServer(t, f)
	ctx := context.Background()
	state, err := s.CaptureState(ctx, f.Worker, f.Plan.Capture.ID)
	if err != nil || !reflect.DeepEqual(state.Binding, f.Plan.Capture) {
		t.Fatal("fixed capture ingress did not read retained worker binding", err)
	}
	ref, err := s.RetainCapture(ctx, f.Worker, f.Plan.Capture.ID, []byte("private outside bytes "+string(fx.ID(t))))
	if err != nil {
		t.Fatal("fixed capture byte ingress did not retain actual bytes", err)
	}
	request := f.AppendRequest(t, &ref, false)
	request.Intent = api.InternalIntent{}
	transport := f.Worker
	transport.Actor = api.Actor{Kind: "human", ID: fx.ID(t)}
	receipt, err := s.AppendCapture(ctx, transport, request)
	if err != nil || receipt.NextOffset != ref.Bytes {
		t.Fatal("capture ingress did not derive scope from its authenticated connection", err)
	}
	forged := request
	forged.Intent = api.InternalIntent{Actor: f.Human.Actor}
	if _, err := s.AppendCapture(ctx, f.Worker, forged); err == nil {
		t.Fatal("capture ingress accepted a body-supplied principal")
	} else {
		codeIs(t, err, api.CodeForbidden)
	}
	missing := f.Worker
	missing.Frame = nil
	if _, err := s.CaptureState(ctx, missing, f.Plan.Capture.ID); err == nil {
		t.Fatal("capture ingress accepted missing authenticated frame")
	} else {
		codeIs(t, err, api.CodeUnauthenticated)
	}
	wrong := f.Worker
	wrong.Connection = f.Human.Connection
	if _, err := s.CaptureState(ctx, wrong, f.Plan.Capture.ID); err == nil {
		t.Fatal("human endpoint entered the fixed worker capture channel")
	} else {
		codeIs(t, err, api.CodeUnauthenticated)
	}
	s.deps.Authenticator = &authFixture{scope: f.Human}
	if _, err := s.AppendCapture(ctx, f.Worker, request); err == nil {
		t.Fatal("worker label bypassed authenticated human identity")
	} else {
		codeIs(t, err, api.CodeUnauthenticated)
	}
}

func claimControl(t *testing.T, f *fx.Fixture, effect api.Effect) api.EffectLease {
	t.Helper()
	ctx := context.Background()
	if _, err := f.State.Transact(ctx, api.Transaction{Scope: f.Execution, Internal: effect.Context, Effects: []api.Effect{effect}}); err != nil {
		t.Fatal("control effect was not retained", err)
	}
	claim, err := f.State.ClaimEffect(ctx, f.Execution, api.EffectClaimRequest{EffectID: effect.ID, ExpectedGeneration: 1, ClaimantID: f.Execution.Actor.ID, Deadline: fx.Expiry()})
	if err != nil {
		t.Fatal("control effect was not claimed", err)
	}
	return claim
}

func TestLaunchStopReleaseReceipts(t *testing.T) {
	f := fx.Ready(t, true)
	ctx := context.Background()
	s := launchServer(t, f)
	measured := f.Observation(t, "running")
	if err := f.State.RecordLaunchObservation(ctx, f.Reservation.LaunchID, measured); err != nil {
		t.Fatal(err)
	}
	stop := f.Intent(t, api.InternalLifecycleEffect)
	stop.ID, stop.EffectID, stop.CauseOperationID, stop.CauseRequestID = fx.ID(t), fx.ID(t), fx.ID(t), fx.ID(t)
	stop.RequestedBy = f.Execution.Actor
	stopEffect := api.Effect{ID: stop.EffectID, OperationID: stop.CauseOperationID, Context: &stop, Stop: &f.Process}
	stopClaim := claimControl(t, f, stopEffect)
	observed, err := s.Observe(ctx, f.Process)
	if err != nil || observed.Handle != f.Process || observed.LeaseID != f.Plan.Lease.ID {
		t.Fatal("observation did not resolve the actual process and stage", err)
	}
	request, err := s.Stop(ctx, f.Process, "component committed stop")
	if err != nil || request.EffectID != stopEffect.ID || request.OperationID != stopEffect.OperationID || request.Cause.RequestedBy != f.Execution.Actor || request.Target != observed {
		t.Fatal("stop relabelled its real causal requester or process", err)
	}
	foreign := f.Process
	foreign.ContainmentID = fx.ID(t)
	if _, err := s.Stop(ctx, foreign, "component stop"); err == nil {
		t.Fatal("stop accepted a caller process binding")
	} else {
		codeIs(t, err, api.CodeConflict)
	}
	ended := f.Observation(t, "exited").Observation
	if _, err := f.State.CompleteEffect(ctx, f.Execution, api.EffectOutcome{EffectID: stopEffect.ID, ClaimID: stopClaim.ClaimID, ExpectedGeneration: stopClaim.Record.Generation, Status: "succeeded", Observation: &ended}); err != nil {
		t.Fatal(err)
	}
	release := f.Intent(t, api.InternalHelperRelease)
	release.ID, release.EffectID, release.CauseOperationID, release.CauseRequestID = fx.ID(t), fx.ID(t), fx.ID(t), fx.ID(t)
	release.RequestedBy = f.Execution.Actor
	releaseRequest := api.HelperReleaseRequest{Cause: release, LeaseID: f.Plan.Lease.ID, Observation: ended}
	effect := api.Effect{ID: release.EffectID, OperationID: release.CauseOperationID, Context: &release, HelperRelease: &releaseRequest}
	claimControl(t, f, effect)
	loaded, err := s.Release(ctx, f.Plan.Lease.ID, ended)
	if err != nil || !reflect.DeepEqual(loaded, releaseRequest) {
		t.Fatal("release did not load its exact retained request", err)
	}
	zero := uint64(0)
	receipt := api.ReleaseReceipt{ID: fx.ID(t), LeaseID: f.Plan.Lease.ID, ContainmentID: f.Process.ContainmentID, Backend: f.Plan.Inputs.Sources.Runtime.Backend, OperationID: effect.OperationID, EffectID: effect.ID,
		Quiescence: ended, LiveConnections: &zero, QueuedJobs: &zero, WritableExports: &zero, ObservedAt: ended.ObservedAt}
	badReceipt := receipt
	badReceipt.LiveConnections = nil
	if err := s.RecordRelease(ctx, loaded, badReceipt); err == nil {
		t.Fatal("unknown connection count released the lease")
	} else {
		codeIs(t, err, api.CodeContainmentUnknown)
	}
	if err := s.RecordRelease(ctx, loaded, receipt); err != nil {
		t.Fatal("actual helper release receipt was not retained", err)
	}
	if err := s.RecordRelease(ctx, loaded, receipt); err != nil {
		t.Fatal("exact release receipt did not replay", err)
	}
	badRequest := loaded
	badRequest.LeaseID = fx.ID(t)
	if err := s.RecordRelease(ctx, badRequest, receipt); err == nil {
		t.Fatal("another release request completed this effect")
	} else {
		codeIs(t, err, api.CodeConflict)
	}
}

func TestLaunchAbortReceipt(t *testing.T) {
	f := fx.Ready(t, true)
	s := launchServer(t, f)
	ctx := context.Background()
	cause := f.Intent(t, api.InternalHelperAbort)
	cause.EffectID = fx.ID(t)
	request := api.HelperAbortRequest{Cause: cause, LeaseID: f.Plan.Lease.ID, PreparedID: f.Prepared.ID, SpecSHA256: f.Prepared.SpecSHA256, OperationID: f.Reservation.OperationID, EffectID: cause.EffectID}
	claimControl(t, f, api.Effect{ID: cause.EffectID, OperationID: request.OperationID, Context: &cause, HelperAbort: &request})
	loaded, err := s.Abort(ctx, f.Prepared)
	if err != nil || !reflect.DeepEqual(loaded, request) {
		t.Fatal("abort did not load its retained nonexecuting gate", err)
	}
	zero := uint64(0)
	receipt := api.AbortReceipt{ID: fx.ID(t), LeaseID: request.LeaseID, PreparedID: request.PreparedID, Quiescence: api.ProcessObservation{Handle: api.ProcessHandle{ID: f.Prepared.ID, Target: f.Prepared.Target, ContainmentID: f.Prepared.ContainmentID, Generation: f.Prepared.ProcessGeneration}, State: "exited", Survivors: &zero, PromptStatus: "not_written", ObservedAt: fx.Expiry()}, ObservedAt: fx.Expiry()}
	executed := receipt
	executed.AgentExecuted = true
	if err := s.RecordAbort(ctx, loaded, executed); err == nil {
		t.Fatal("executed agent was credited as a nonexecuting abort")
	} else {
		codeIs(t, err, api.CodeContainmentUnknown)
	}
	if err := s.RecordAbort(ctx, loaded, receipt); err != nil {
		t.Fatal("actual helper abort receipt was not retained", err)
	}
	if err := s.RecordAbort(ctx, loaded, receipt); err != nil {
		t.Fatal("exact abort receipt did not replay", err)
	}
	changed := loaded
	changed.PreparedID = fx.ID(t)
	if err := s.RecordAbort(ctx, changed, receipt); err == nil {
		t.Fatal("changed abort input completed the original effect")
	} else {
		codeIs(t, err, api.CodeConflict)
	}
}

type independentProbe struct {
	observation api.IsolationCapabilities
	err         error
	calls       int
}

func (p *independentProbe) IsolationEvidence(ctx context.Context) (api.IsolationCapabilities, error) {
	p.calls++
	if err := ctx.Err(); err != nil {
		return api.IsolationCapabilities{}, err
	}
	return p.observation, p.err
}

func TestLaunchProbeIsIndependent(t *testing.T) {
	f := fx.Ready(t, true)
	s := launchServer(t, f)
	measured := &independentProbe{observation: api.IsolationCapabilities{Backend: f.Plan.Inputs.Sources.Runtime.Backend, Available: true, Kernel: "component-kernel", Checks: []api.Capability{{Name: "measured-helper-check", Available: true, Reason: "component evidence"}}}}
	s.deps.IsolationEvidence = measured
	observed, err := s.Probe(context.Background())
	if err != nil || !reflect.DeepEqual(observed, measured.observation) || measured.calls != 1 {
		t.Fatal("probe did not use independent helper evidence", err)
	}
	measured.err = api.NotImplemented("lb-v2-admin", "component unavailable helper evidence")
	if _, err := s.Probe(context.Background()); err != measured.err {
		t.Fatal("probe swallowed the helper's actual typed failure", err)
	}
}

func TestPlannerDependencyPropagates(t *testing.T) {
	f := fx.New(t)
	f.Reserve(t)
	s := launchServer(t, f)
	s.runtime = api.RuntimeServices{Store: f.State, Helper: &admin.Service{}, Worker: &dataworker.Service{}, LaunchPlanner: &lifecycle.Service{}, Launcher: &healthLauncher{}}
	_, err := s.runEffect(context.Background(), f.Execution, f.Claim)
	var typed *api.Error
	if !errors.As(err, &typed) || typed.Code != api.CodeNotImplemented || typed.Owner != "lb-v2-lifecycle" {
		t.Fatal("planner dependency did not propagate its owning refusal", err)
	}
	actual, err := f.State.Effect(context.Background(), f.Execution, f.Claim.Record.Effect.ID)
	if err != nil || actual.Outcome != nil {
		t.Fatal("missing planner was credited as a measured completion", err)
	}
}

func TestLaunchRuntimeReadiness(t *testing.T) {
	f := fx.New(t)
	f.Reserve(t)
	makeHost := func() *Server { s := launchServer(t, f); s.bound = false; return s }
	s := makeHost()
	runtime := api.RuntimeServices{Store: f.State, Identity: s.deps.Authenticator, Config: f.Deps.Config, Socket: s.deps.Binding.Socket, ArtifactSHA256: s.deps.Binding.ArtifactSHA256, Helper: &admin.Service{}, Worker: &dataworker.Service{}, Launcher: &healthLauncher{}}
	if err := s.BindRuntime(context.Background(), runtime); err == nil {
		t.Fatal("pending launch bound without LaunchPlanner")
	} else {
		codeIs(t, err, api.CodePrerequisite)
	}
	s = makeHost()
	runtime.Identity = s.deps.Authenticator
	runtime.Socket, runtime.ArtifactSHA256 = s.deps.Binding.Socket, s.deps.Binding.ArtifactSHA256
	runtime.LaunchPlanner = &lifecycle.Service{}
	if err := s.BindRuntime(context.Background(), runtime); err != nil {
		t.Fatal("complete launch dependency binding failed", err)
	}
	encoded := fx.JSON(t, api.Health{Protocol: api.Protocol, Schema: api.SchemaVersion, ServiceVersion: "component", ArtifactSHA256: fx.Digest([]byte("component")), Ready: true, Capabilities: []api.Capability{}})
	data, err := s.observedHealth(context.Background(), encoded)
	if err != nil {
		t.Fatal(err)
	}
	var health api.Health
	if err := json.Unmarshal(data, &health); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, capability := range health.Capabilities {
		if capability.Name == "launch-recovery-capture" {
			found = true
			if capability.Available {
				t.Fatal("bound dependencies advertised launch readiness without active recovery/capture jobs")
			}
		}
	}
	if !found {
		t.Fatal("launch readiness observation is absent")
	}
}

// This ledger supplies explicit helper receipt observations and checks every
// selector. It neither executes a helper nor supplies the source's binding.
type recoveryLedger struct {
	api.HelperControl
	fixture      *fx.Fixture
	gate         api.LaunchReconciliation
	capture      *api.CaptureBinding
	err          error
	opens        int
	gateCalls    int
	captureCalls int
}

func (h *recoveryLedger) ReconcileGate(ctx context.Context, request api.HelperReconcileRequest) (api.LaunchReconciliation, error) {
	h.gateCalls++
	if err := ctx.Err(); err != nil {
		return api.LaunchReconciliation{}, err
	}
	f := h.fixture
	if request.LeaseID != f.Plan.Lease.ID || request.LaunchID != f.Reservation.LaunchID || request.PreparedID != f.Prepared.ID || request.OperationID != f.Reservation.OperationID {
		return api.LaunchReconciliation{}, serviceError(api.CodeConflict, "recovery changed its actual retained gate selectors")
	}
	return h.gate, h.err
}
func (h *recoveryLedger) ReconcileCapture(ctx context.Context, request api.CaptureBinding) (api.CaptureBinding, error) {
	h.captureCalls++
	if err := ctx.Err(); err != nil {
		return api.CaptureBinding{}, err
	}
	if !reflect.DeepEqual(request, h.fixture.Plan.Capture) {
		return api.CaptureBinding{}, serviceError(api.CodeConflict, "recovery changed its actual retained producer or pipes")
	}
	if h.capture != nil {
		return *h.capture, h.err
	}
	return request, h.err
}
func (h *recoveryLedger) OpenGate(context.Context, api.HelperOpenRequest) (api.ProcessHandle, error) {
	h.opens++
	return api.ProcessHandle{}, serviceError(api.CodeIntegrity, "recovery attempted a speculative open")
}

func TestLaunchRecoveryJobs(t *testing.T) {
	f := fx.ReadyForIdentity(t, true, uint32(os.Geteuid())+1000, uint32(os.Getegid())+1000)
	s := launchServer(t, f)
	helper := &recoveryLedger{fixture: f, gate: f.Observation(t, "running")}
	s.runtime = api.RuntimeServices{Store: f.State, Helper: helper, LaunchPlanner: &lifecycle.Service{}, Worker: &dataworker.Service{}, Launcher: &healthLauncher{}}
	s.launchConfigured = true
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); s.launchRecoveryLoop(ctx) }()
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		s.mu.RLock()
		healthy := s.launchJobsActive && s.launchJobsHealthy
		failure := s.fault
		s.mu.RUnlock()
		if failure != nil {
			cancel()
			<-done
			t.Fatal("actual retained recovery job failed", failure)
		}
		if healthy {
			break
		}
		select {
		case <-ticker.C:
		case <-deadline.C:
			cancel()
			<-done
			t.Fatal("actual recovery/capture jobs did not become healthy")
		}
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("recovery job did not join")
	}
	if helper.gateCalls == 0 || helper.captureCalls == 0 || helper.opens != 0 {
		t.Fatal("recovery skipped actual jobs or opened a second gate")
	}
	binding, err := f.State.RetainedProcess(context.Background(), f.Process)
	if err != nil || binding.Record.ID != f.Reservation.LaunchID {
		t.Fatal("recovery did not retain the same observed process", err)
	}
	s.mu.RLock()
	active := s.launchJobsActive
	s.mu.RUnlock()
	if active {
		t.Fatal("joined recovery job still advertised active")
	}
}

func TestCaptureRecoveryKeepsFailure(t *testing.T) {
	f := fx.Ready(t, true)
	s := launchServer(t, f)
	failure := api.NotImplemented("lb-v2-admin", "component unavailable spool reconciliation")
	helper := &recoveryLedger{fixture: f, gate: f.Observation(t, "running"), err: failure}
	runtime := api.RuntimeServices{Store: f.State, Helper: helper}
	if err := s.reconcileLaunches(context.Background(), runtime); err != failure {
		t.Fatal("capture recovery replaced its actual helper refusal", err)
	}
	state, err := f.State.CaptureState(context.Background(), f.Execution, f.Plan.Capture.ID)
	if err != nil || state.Binding.Status != "registered" || !reflect.DeepEqual(state.Binding, f.Plan.Capture) {
		t.Fatal("capture failure was laundered into refused registration", err)
	}
	page, err := f.State.Events(context.Background(), f.Execution, api.EventTailRequest{LifeID: f.Reservation.Target.LifeID, Run: f.Reservation.Target.Run})
	if err != nil {
		t.Fatal(err)
	}
	gaps := 0
	for _, event := range page.Events {
		if event.Kind != "capture.gap" {
			continue
		}
		var gap api.CaptureGap
		if err := json.Unmarshal(event.Payload, &gap); err != nil {
			t.Fatal(err)
		}
		if gap.BindingID != f.Plan.Capture.ID || gap.EndOffset != nil || event.RequestedBy != f.Human.Actor || event.OperationID != f.Reservation.OperationID {
			t.Fatal("capture gap invented a range end or changed the original requester")
		}
		gaps++
	}
	if gaps != len(f.Plan.Capture.Streams) {
		t.Fatal("producer failure lost the explicit gaps for open pipes")
	}
}
