//go:build linux

package service

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"laneboss.io/laneboss/internal/v2/admin"
	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/assembly/credn"
	"laneboss.io/laneboss/internal/v2/dataworker"
	"laneboss.io/laneboss/internal/v2/grants"
	"laneboss.io/laneboss/internal/v2/identity"
	"laneboss.io/laneboss/internal/v2/lifecycle"
	"laneboss.io/laneboss/internal/v2/runner/codex"
	"laneboss.io/laneboss/internal/v2/secrets"
	"laneboss.io/laneboss/internal/v2/secrets/bstate"
	"laneboss.io/laneboss/internal/v2/store"
	fx "laneboss.io/laneboss/internal/v2/store/testfx"
)

// The store, encrypted broker, grants, planner and reconciler are real.
// Native helper identity/holding measurements are explicit component inputs;
// these tests neither execute an agent nor claim root-helper acceptance.
type credentialPipeline struct {
	api.HelperControl
	api.CredentialProjectionIdentity
	t          *testing.T
	f          *fx.Fixture
	p          *successfulPlanPorts
	clock      *planReconcileClock
	owner      api.Scope
	meta       api.CredentialProjectionAuthority
	request    api.CredentialProjectionRequest
	held       api.CredentialProjectionReceipt
	withdrawal api.CredentialWithdrawalReceipt
	first      api.ID
	calls      int
	prepareErr error
	source     *credn.Source
}

type credentialPipelineControl struct {
	api.LaunchControlSource
	n *credentialPipeline
}

type credentialPipelinePeers struct{ n *credentialPipeline }

func (*credentialPipelinePeers) Verify(context.Context, net.Conn, api.InstalledBinding) (api.VerifiedPeer, error) {
	return nil, serviceError(api.CodeForbidden, "component cannot authenticate ordinary native connections")
}
func (p *credentialPipelinePeers) VerifyCredentialProjection(ctx context.Context, peer api.VerifiedPeer, authority api.CredentialProjectionAuthority) error {
	facts, err := peer.Facts(ctx)
	if err != nil {
		return err
	}
	if facts != p.n.meta.HelperPeer || authority.Helper != p.n.meta.Helper || authority.Broker != p.n.meta.Broker ||
		authority.HelperPeer != p.n.meta.HelperPeer || authority.BrokerPeer != p.n.meta.BrokerPeer || authority.BootID != p.n.meta.BootID || authority.InstallationGeneration != p.n.meta.InstallationGeneration {
		return serviceError(api.CodeForbidden, "component credential peer differs from its installed pins")
	}
	return peer.Alive(ctx)
}

func (c *credentialPipelineControl) Handoff(ctx context.Context, spec api.LaunchSpec) (api.PreparedSpecHandoff, error) {
	return c.n.Handoff(ctx, spec)
}

type credentialDispatchStore struct {
	*planningPolicyStore
	plan  api.ID
	clock api.Clock
}

func (s *credentialDispatchStore) ClaimEffect(ctx context.Context, scope api.Scope, r api.EffectClaimRequest) (api.EffectLease, error) {
	if r.EffectID == s.plan {
		r.Deadline = api.Timestamp(s.clock.Now().Add(4 * time.Minute).UTC().Format(time.RFC3339Nano))
	}
	return s.Service.ClaimEffect(ctx, scope, r)
}

func (n *credentialPipeline) ResolveCredentialProjection(ctx context.Context, scope api.Scope, request api.CredentialProjectionRequest) (api.CredentialProjectionAuthority, error) {
	if scope.Actor != n.owner.Actor || request.Prepared != n.request.Prepared || request.Lease != n.request.Lease || !reflect.DeepEqual(request.Handoff, n.request.Handoff) {
		return api.CredentialProjectionAuthority{}, serviceError(api.CodeForbidden, "native metadata selector differs from the owned gate")
	}
	meta := n.meta
	projection := n.first
	sources, err := n.p.broker.CredentialSourceVersions(ctx, &fx.Peer{FactsValue: n.meta.HelperPeer}, request, projection)
	if err != nil {
		return api.CredentialProjectionAuthority{}, err
	}
	meta.Sources = sources
	return meta, nil
}

// Sample the actual encrypted inventory before taking the broker's transfer
// journal. The native metadata fixture is independent of that journal lock.
func (n *credentialPipeline) inventory(ctx context.Context, request api.CredentialProjectionRequest) error {
	n.meta.Sources = []api.CredentialSourceVersion{}
	targets, err := api.CredentialTargets(request, n.clock.Now())
	if err != nil {
		return err
	}
	err = n.p.backend.WithBroker(ctx, func(j bstate.Journal) error {
		for _, target := range targets {
			var slot bstate.Slot
			if err := j.Read("slot", target.SlotID, &slot); err != nil {
				return err
			}
			defer clear(slot.Material)
			defer clear(slot.Returned)
			material, err := j.Fetch(ctx, slot.Grant)
			clear(material.Bytes)
			if err != nil {
				return err
			}
			var login bstate.Login
			if err := j.Read("login", slot.LoginID, &login); err != nil {
				return err
			}
			clear(login.Material)
			n.meta.Sources = append(n.meta.Sources, api.CredentialSourceVersion{Key: target.Key, Generation: login.Generation, Version: slot.Grant.Version})
		}
		return nil
	})
	return err
}

func (n *credentialPipeline) ObserveCredentialProjection(ctx context.Context, a api.CredentialProjectionAuthority) (api.CredentialProjectionReceipt, error) {
	return n.ObserveCredentials(ctx, a.ID)
}
func (n *credentialPipeline) Handoff(ctx context.Context, spec api.LaunchSpec) (api.PreparedSpecHandoff, error) {
	record, err := n.f.State.LaunchPlan(ctx, n.owner, spec.PlanID)
	if err != nil {
		return api.PreparedSpecHandoff{}, err
	}
	if record.Handoff == nil || !reflect.DeepEqual(record.Handoff.Spec, spec) {
		return api.PreparedSpecHandoff{}, serviceError(api.CodeForbidden, "handoff differs from actual retained spec")
	}
	return *record.Handoff, nil
}
func (n *credentialPipeline) ResolveLaunchSources(ctx context.Context, r api.LaunchSourceRequest) (api.LaunchSources, error) {
	return n.p.ResolveLaunchSources(ctx, r)
}
func (n *credentialPipeline) ResolveLaunchStorage(ctx context.Context, r api.LaunchDataRequest) (api.LaunchStorage, error) {
	return n.p.ResolveLaunchStorage(ctx, r)
}
func (n *credentialPipeline) ResolveRuntime(ctx context.Context, h api.PreparedSpecHandoff) (api.ResolvedRuntime, error) {
	chunk, err := n.f.State.Blob(ctx, n.owner, api.BlobReadRequest{ObjectID: h.Spec.RuntimeManifest.ID, Limit: api.MaxChunkBytes})
	if err != nil {
		return api.ResolvedRuntime{}, err
	}
	var manifest api.RuntimeManifest
	if err := api.DecodeObject(chunk.Data, &manifest); err != nil {
		return api.ResolvedRuntime{}, err
	}
	return api.ResolvedRuntime{Manifest: manifest, SpecReceipt: api.PreparedSpecReceipt{Config: h.Config, Target: h.Spec.Target, OperationID: h.OperationID,
		SpecSHA256: h.SpecSHA256, LeaseID: h.Spec.UIDLeaseID, SpecID: h.Spec.ID, RuntimeManifest: h.Spec.RuntimeManifest}, Home: n.request.Home.Home, Workspace: h.Spec.Workspace}, nil
}
func (n *credentialPipeline) ObserveCredentials(ctx context.Context, id api.ID) (api.CredentialProjectionReceipt, error) {
	if err := ctx.Err(); err != nil {
		return api.CredentialProjectionReceipt{}, err
	}
	if id != n.held.ProjectionID {
		return api.CredentialProjectionReceipt{}, serviceError(api.CodeNotFound, "component holding is absent")
	}
	observed := n.held
	observed.ObservedAt = api.Timestamp(n.clock.Now().UTC().Format(time.RFC3339Nano))
	return observed, nil
}
func (n *credentialPipeline) WithdrawCredentials(ctx context.Context, record api.CredentialProjectionRecord) (api.CredentialWithdrawalReceipt, error) {
	if err := ctx.Err(); err != nil {
		return api.CredentialWithdrawalReceipt{}, err
	}
	if record.Fence == nil || record.Authority.ID != n.withdrawal.ProjectionID || record.Authority.Request.Prepared != n.withdrawal.Prepared || record.Fence.Cause != n.withdrawal.Cause {
		return api.CredentialWithdrawalReceipt{}, serviceError(api.CodeForbidden, "native cleanup selected another fenced projection")
	}
	return n.withdrawal, nil
}
func (n *credentialPipeline) Prepare(ctx context.Context, r api.HelperLaunchRequest) (api.PreparedLaunch, error) {
	n.calls++
	lease, ok := api.EffectLeaseFromContext(ctx)
	if !ok {
		return api.PreparedLaunch{}, serviceError(api.CodeForbidden, "prepare has no actual reconciler claim")
	}
	if n.request.Prepared.ID == "" {
		n.request = api.CredentialProjectionRequest{Cause: r.Cause, Claim: lease, Handoff: *n.f.Record.Handoff, Lease: n.f.Plan.Lease, Home: n.f.Plan.Data.Home,
			Prepared: api.PreparedLaunch{ID: fx.ID(n.t), SpecSHA256: r.SpecSHA256, Target: n.f.Reservation.Target, ContainmentID: n.f.Plan.Lease.ContainmentID,
				ProcessGeneration: string(fx.ID(n.t)), EndpointGeneration: n.f.Plan.Lease.EndpointGeneration, GateID: fx.ID(n.t)}}
	}
	n.request.Claim = lease
	if n.calls == 1 {
		_, err := n.f.State.ReserveCredentialProjection(ctx, n.owner, n.request)
		var refusal *api.Error
		if !errors.As(err, &refusal) || refusal.Code != api.CodePrerequisite || refusal.Owner != "lb-v2-service" || refusal.Message != "credential projection requires its installed native metadata source" {
			return api.PreparedLaunch{}, serviceError(api.CodeIntegrity, "build without native credential source did not preserve its exact refusal")
		}
		if err := n.source.BindNative(n); err != nil {
			return api.PreparedLaunch{}, err
		}
	}
	if err := n.inventory(ctx, n.request); err != nil {
		n.prepareErr = err
		return api.PreparedLaunch{}, err
	}
	reserved, err := n.f.State.ReserveCredentialProjection(ctx, n.owner, n.request)
	if err != nil {
		n.prepareErr = err
		return api.PreparedLaunch{}, err
	}
	if n.first == "" {
		n.first = reserved.Authority.ID
		n.clock.advance(31 * time.Second)
		return api.PreparedLaunch{}, serviceError(api.CodeConflict, "component deferred before credential export")
	}
	if reserved.Authority.ID != n.first {
		return api.PreparedLaunch{}, serviceError(api.CodeIntegrity, "retry allocated another projection")
	}
	transfer, err := n.p.broker.TransferCredentials(ctx, &fx.Peer{FactsValue: n.meta.HelperPeer}, n.request)
	if err != nil {
		n.prepareErr = err
		return api.PreparedLaunch{}, err
	}
	zero, count := uint64(0), uint64(len(transfer.Files))
	n.held = api.CredentialProjectionReceipt{ProjectionID: transfer.Authority.ID, Generation: transfer.Authority.Generation + 1, Prepared: n.request.Prepared,
		HelperLeaseID: n.request.Lease.ID, SpecSHA256: n.request.Handoff.SpecSHA256, Home: n.request.Home, CancellationEpoch: n.request.Cause.CancellationEpoch,
		GateClosed: true, HeldDescriptors: &count, InheritedSources: &zero, ObservedAt: api.Timestamp(n.clock.Now().UTC().Format(time.RFC3339Nano))}
	for i, file := range transfer.Files {
		var stat unix.Stat_t
		if err := unix.Fstat(int(file.Fd()), &stat); err != nil {
			return api.PreparedLaunch{}, err
		}
		target := transfer.Authority.Targets[i]
		n.held.Targets = append(n.held.Targets, api.CredentialHeldTarget{Target: target, SourceObjectID: fmt.Sprintf("%d:%d", uint64(stat.Dev), stat.Ino), ObjectID: string(fx.ID(n.t)),
			RootID: n.request.Home.RootID, HomeGeneration: n.request.Home.Generation, OwnerUID: n.request.Lease.UID, Mode: target.FileMode, ParentMode: 0700, Links: 1})
	}
	committed, err := n.p.broker.AcknowledgeCredentials(ctx, n.held)
	if err != nil {
		n.prepareErr = err
		return api.PreparedLaunch{}, err
	}
	if replay, err := n.p.broker.AcknowledgeCredentials(ctx, n.held); err != nil || !reflect.DeepEqual(replay, committed) {
		return api.PreparedLaunch{}, serviceError(api.CodeIntegrity, "lost acknowledgement did not replay the original durable holding")
	}
	n.f.Prepared, n.f.PreparedClaim = n.request.Prepared, n.request.Claim
	n.f.Execution.Actor = api.Actor{Kind: "service", ID: lease.Record.ClaimantID}
	turn, err := n.f.State.Turn(ctx, n.f.Execution, n.request.Prepared.Target, n.request.Cause.LogicalTurnID)
	if err != nil {
		return api.PreparedLaunch{}, err
	}
	// Bind while this actual prepare claim is live. The fixture contributes
	// identity/native facts; the real writer still owns its policy/CAS checks.
	n.f.Bind(n.t, turn)
	return n.request.Prepared, nil
}
func (n *credentialPipeline) ReconcileGate(ctx context.Context, _ api.HelperReconcileRequest) (api.LaunchReconciliation, error) {
	lease, ok := api.EffectLeaseFromContext(ctx)
	if !ok || lease.Record.Effect.HelperPrepare == nil {
		return api.LaunchReconciliation{}, serviceError(api.CodeForbidden, "recovery has no original prepare stage")
	}
	prepared, err := n.Prepare(ctx, *lease.Record.Effect.HelperPrepare)
	return api.LaunchReconciliation{Prepared: &prepared, GateState: "prepared", Observation: api.ProcessObservation{State: "prepared"}}, err
}

func credentialProjectionPipelineFixture(t *testing.T, configure ...func(*credentialPipeline, *secrets.Dependencies)) (*fx.Fixture, *credentialPipeline, *lifecycle.Service, api.CredentialProjectionRecord) {
	t.Helper()
	f, reservation, effect := scopePlanningFixture(t)
	clock := &planReconcileClock{}
	n := &credentialPipeline{t: t, f: f, clock: clock, owner: f.Execution}
	proc, err := os.ReadFile("/proc/self/stat")
	if err != nil {
		t.Fatal(err)
	}
	fields := strings.Fields(string(proc[strings.LastIndex(string(proc), ")")+2:]))
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil || len(fields) < 20 {
		t.Fatal("cannot measure owned broker process scope", err)
	}
	n.meta = api.CredentialProjectionAuthority{Helper: api.Executable{ID: fx.ID(t), SHA256: fx.Digest([]byte("component-helper")), Version: "component"},
		Broker:     api.Executable{ID: fx.ID(t), SHA256: fx.Digest([]byte("component-broker")), Version: "component"},
		HelperPeer: api.PeerFacts{HostPID: os.Getpid() + 1, ProcessGeneration: "component-helper"},
		BrokerPeer: api.PeerFacts{HostUID: uint32(os.Geteuid()), HostGID: uint32(os.Getegid()), HostPID: os.Getpid(), ProcessGeneration: fields[19], ContainmentID: fx.ID(t)},
		ServiceUID: uint32(os.Geteuid()) + 2000, InstallationGeneration: 1, BootID: strings.TrimSpace(string(boot))}
	n.meta.HelperPeer.ProcessGeneration = n.meta.BootID + ":" + n.meta.HelperPeer.ProcessGeneration
	n.meta.BrokerPeer.ProcessGeneration = n.meta.BootID + ":" + n.meta.BrokerPeer.ProcessGeneration
	if err := f.State.Close(); err != nil {
		t.Fatal(err)
	}
	nativeSource := credn.New()
	n.source = nativeSource
	f.Deps.Clock, f.Deps.CredentialProjection = clock, nativeSource
	f.State, err = store.New(f.Deps)
	if err != nil {
		t.Fatal(err)
	}
	n.CredentialProjectionIdentity, err = identity.New(identity.Dependencies{Store: f.State, Clock: clock, Peers: &credentialPipelinePeers{n: n}, Registry: &admin.Service{}})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	state := &planningPolicyStore{Service: f.State, effect: effect.ID}
	planner := successfulScopePlannerGrants(t, state, f, effect, func(resolver *grants.Service) api.GrantResolver {
		n.p = state.sourcePorts
		n.p.configureBroker = func(d *secrets.Dependencies) {
			d.Helper = n
			d.Control = &credentialPipelineControl{n: n}
			d.ProjectionIdentity = n
			d.CodexValidator = codex.CredentialValidator{}
			for _, apply := range configure {
				apply(n, d)
			}
		}
		return resolver
	})
	host := fixtureServer(t)
	dispatch := &credentialDispatchStore{planningPolicyStore: state, plan: effect.ID, clock: clock}
	host.options.Config, host.deps.Store, host.deps.Clock = f.Deps.Config, dispatch, clock
	host.runtime = api.RuntimeServices{Store: dispatch, LaunchPlanner: &observeSuccessfulPlanning{LaunchPlanner: planner, state: state, stop: cancel}, Helper: &admin.Service{}, Worker: &dataworker.Service{}, Launcher: &healthLauncher{}}
	host.reconcileLoop(ctx)
	if state.planned == nil || host.fault != nil {
		t.Fatal("real root planner did not retain its credentialed spec", state.planningErr, host.fault)
	}
	f.Plan = *state.planned
	f.Record, err = f.State.LaunchPlan(context.Background(), f.Execution, reservation.ID)
	if err != nil {
		t.Fatal(err)
	}
	cause := f.Intent(t, api.InternalHelperPrepare)
	cause.ID, cause.EffectID = fx.ID(t), fx.ID(t)
	cause.LogicalTurnID = effect.Context.LogicalTurnID
	request := api.HelperLaunchRequest{Cause: cause, LeaseID: f.Plan.Lease.ID, PreparedSpecID: reservation.SpecID, SpecSHA256: f.Record.Handoff.SpecSHA256}
	prepare := api.Effect{ID: cause.EffectID, OperationID: reservation.OperationID, Context: &cause, HelperPrepare: &request}
	emit := cause
	emit.ID = fx.ID(t)
	if _, err := f.State.Transact(context.Background(), api.Transaction{Scope: f.Execution, Internal: &emit, Effects: []api.Effect{prepare}}); err != nil {
		t.Fatal(err)
	}
	ctx, stop := context.WithTimeout(context.Background(), 8*time.Second)
	defer stop()
	state.effect, state.stop = prepare.ID, stop
	host.runtime = api.RuntimeServices{Store: dispatch, Helper: n}
	host.reconcileLoop(ctx)
	if host.fault != nil || n.prepareErr != nil || n.calls != 2 {
		t.Fatal("credential prepare did not recover through actual broker and store", host.fault, n.prepareErr, n.calls)
	}
	record, err := f.State.CredentialProjection(context.Background(), f.Deps.Config, n.request.Prepared.ID)
	if err != nil || record.State != "held" || record.Authority.ID != n.first || record.Receipt == nil || !reflect.DeepEqual(*record.Receipt, n.held) {
		t.Fatal("credentialed root did not reach its original durable projected state", err)
	}
	checked, err := planner.CheckLaunchCredentials(context.Background(), f.Binding)
	if err != nil || !reflect.DeepEqual(checked, record) {
		t.Fatal("lifecycle did not check the actual held projection and issued grants", err)
	}
	if checked, err := n.CheckLaunchCredentials(context.Background(), f.Binding); err != nil || !reflect.DeepEqual(checked, record) {
		t.Fatal("identity did not check completed prepare history against the actual held record", err)
	}
	other := f.Binding
	other.Record.UIDLeaseID = fx.ID(t)
	if _, err := planner.CheckLaunchCredentials(context.Background(), other); err == nil {
		t.Fatal("lifecycle accepted another launch binding")
	}
	return f, n, planner, record
}

func TestCredentialRootProjection(t *testing.T) {
	f, n, planner, record := credentialProjectionPipelineFixture(t)
	clock := n.clock
	if err := n.p.backend.Revoke(context.Background(), n.p.sourceInfo); err != nil {
		t.Fatal("actual encrypted source revocation failed", err)
	}
	if err := n.inventory(context.Background(), n.request); err == nil {
		t.Fatal("revoked encrypted source remained readable to the broker")
	}
	// The installed metadata port reports the source owner's observed refusal.
	n.meta.Sources = append([]api.CredentialSourceVersion{}, record.Authority.Sources...)
	n.meta.Sources[0].Revoked = true
	if _, err := planner.CheckLaunchCredentials(context.Background(), f.Binding); err == nil {
		t.Fatal("lifecycle accepted revoked native source inventory")
	}
	cleanupCtx, cleanup := f.CredentialAbort(t, n.request.Prepared)
	fenced, err := n.p.broker.BeginCredentialWithdrawal(cleanupCtx, api.CredentialWithdrawalRequest{ProjectionID: record.Authority.ID, ExpectedGeneration: record.Generation, Cause: cleanup, Reason: "revoked"})
	if err != nil || fenced.State != "withdrawing" || fenced.Generation != record.Generation+1 {
		t.Fatal("actual broker did not durably fence revocation", err)
	}
	if _, err := planner.CheckLaunchCredentials(context.Background(), f.Binding); err == nil {
		t.Fatal("lifecycle opened after withdrawal fence")
	}
	zero := uint64(0)
	stamp := api.Timestamp(clock.Now().UTC().Format(time.RFC3339Nano))
	n.withdrawal = api.CredentialWithdrawalReceipt{ProjectionID: record.Authority.ID, Generation: fenced.Generation + 1, Cause: cleanup,
		Prepared: n.request.Prepared, HelperLeaseID: n.request.Lease.ID, Home: n.request.Home, ObservedAt: stamp,
		Observation: api.ProcessObservation{Handle: api.ProcessHandle{Target: n.request.Prepared.Target, ContainmentID: n.request.Prepared.ContainmentID, Generation: n.request.Prepared.ProcessGeneration},
			State: "absent", Survivors: &zero, ObservedAt: stamp}, HelperDescriptors: &zero, ProjectedFiles: &zero, EnvironmentBuffers: &zero, OpenGates: &zero}
	done, err := n.p.broker.FinishCredentialWithdrawal(cleanupCtx, fenced, n.withdrawal)
	if err != nil || done.State != "withdrawn" || done.Withdrawal == nil || done.Withdrawal.BrokerDescriptors == nil || *done.Withdrawal.BrokerDescriptors != 0 || done.Withdrawal.RefreshLeases == nil || *done.Withdrawal.RefreshLeases != 0 {
		t.Fatal("actual broker did not retire descriptors and refresh leases", err)
	}
	if replay, err := n.p.broker.FinishCredentialWithdrawal(cleanupCtx, fenced, n.withdrawal); err != nil || !reflect.DeepEqual(replay, done) {
		t.Fatal("broker withdrawal retry changed the durable completion", err)
	}
	if verified, err := f.State.Verify(context.Background(), api.VerifyRequest{Scope: "all"}); err != nil || !verified.OK {
		t.Fatal("projected root did not verify", err)
	}
}
