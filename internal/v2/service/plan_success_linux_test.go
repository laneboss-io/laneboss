//go:build linux

package service

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"reflect"
	"testing"
	"time"

	release "laneboss.io/laneboss/internal/identity"
	"laneboss.io/laneboss/internal/v2/admin"
	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client/wire"
	"laneboss.io/laneboss/internal/v2/dataworker"
	"laneboss.io/laneboss/internal/v2/grants"
	"laneboss.io/laneboss/internal/v2/guidance"
	"laneboss.io/laneboss/internal/v2/judge"
	"laneboss.io/laneboss/internal/v2/lifecycle"
	"laneboss.io/laneboss/internal/v2/policy"
	"laneboss.io/laneboss/internal/v2/secrets"
	"laneboss.io/laneboss/internal/v2/secrets/native"
	fx "laneboss.io/laneboss/internal/v2/store/testfx"
	"laneboss.io/laneboss/internal/v2/templates"
)

func installPlanningOrg(t *testing.T, f *fx.Fixture) {
	t.Helper()
	ctx := context.Background()
	objects := []api.ObjectWrite{}
	keep := func(class string, raw []byte) api.BlobRef {
		ref := api.BlobRef{ID: fx.ID(t), Class: class, Bytes: int64(len(raw)), SHA256: fx.Digest(raw)}
		objects = append(objects, api.ObjectWrite{ObjectKey: ref.ID, Class: class, Bytes: raw, SHA256: ref.SHA256, Origin: "service",
			ACL: api.ObjectACL{Config: f.Deps.Config, Owner: f.Execution.Actor, Audience: "owner", Generation: 1}})
		return ref
	}
	body := []byte("## Scope\n" + string(fx.ID(t)) + "\n## Responsibilities\nUse the retained task.\n## Deliverable\nRetain evidence.\n## Must not\nWiden grants.\n")
	files := []api.ResourceFile{}
	for _, item := range []struct {
		path, kind string
		raw        []byte
	}{
		{templates.OrgTemplatePath, "prompt", body},
		{templates.OrgDriversPath, "drivers", []byte("drivers = [\"claudock-cli\", \"codex\"]\n")},
		{fmt.Sprintf(".laneboss/L%d/roles/%s.md", f.Start.Level, f.Start.Role), "prompt", body},
		{fmt.Sprintf(".laneboss/L%d/roles/%s.toml", f.Start.Level, f.Start.Role), "drivers", []byte(fmt.Sprintf("drivers = [%q]\n", f.Start.Driver))},
	} {
		ref := keep("artifact", item.raw)
		files = append(files, api.ResourceFile{Source: api.SourceRef{ID: fx.ID(t), Path: item.path, SHA256: ref.SHA256, Generation: 1},
			Content: ref, Kind: item.kind, Mode: 0444, RevisionGeneration: 1})
	}
	ownership := keep("manifest", fx.JSON(t, api.ObjectManifest{Schema: "laneboss.objects.v2", Entries: []api.ObjectEntry{}}))
	inventory := keep("manifest", fx.JSON(t, files))
	snapshot := api.OrgSnapshot{Config: f.Deps.Config, Ref: api.OrgSnapshotRef{OrgID: api.ID(f.Deps.Config), Generation: 1, ManifestSHA256: inventory.SHA256},
		Sources: files, Derived: []api.ResourceFile{}, OwnershipManifest: ownership,
		Renderer:    api.Executable{ID: fx.ID(t), SHA256: fx.Digest(body), Version: "component-renderer"},
		PublishedBy: fx.ID(t), PublishedAt: api.Timestamp(time.Now().UTC().Format(time.RFC3339Nano))}
	cause := f.Intent(t, api.InternalOrgBootstrap)
	if _, err := f.State.Transact(ctx, api.Transaction{Scope: f.Execution, Internal: &cause,
		Writes: api.StateWrites{Objects: objects, OrgSnapshots: []api.OrgSnapshot{snapshot}}}); err != nil {
		t.Fatal("planning fixture could not retain actual approved template sources", err)
	}
	p, err := f.State.Policy(ctx, f.Execution)
	if err != nil {
		t.Fatal(err)
	}
	p.Context, p.GuidanceHalfLifeSeconds, p.GuidanceMinRelevance = api.RoleContext{Level: f.Start.Level, Role: f.Start.Role}, 3600, .5
	p.SHA256 = ""
	raw, err := api.CanonicalJSON(fx.JSON(t, p))
	if err != nil {
		t.Fatal(err)
	}
	p.SHA256 = fx.Digest(raw)
	f.Replace(t, "policy", api.ID(f.Deps.Config), p.Generation, p)
}

// These are explicit external helper/kernel/runner component
// fixtures. They validate their actual requests and retain all stage receipts
// in the real store. They execute no agent and prove no native boundary.
// Reconciler, store, grants, templates, guidance, credential broker and admin
// reservation authority are real. Enrollment and native execution are fixtures.
type successfulPlanPorts struct {
	api.Helper
	api.CredentialBroker
	api.Runner
	api.DataWorker
	state                    *planningPolicyStore
	t                        *testing.T
	f                        *fx.Fixture
	effect                   api.Effect
	enrollment               api.BlobRef
	runtime                  api.LaunchRuntime
	allocation               api.HelperLease
	data                     *fx.DataFixture
	slot                     api.CredentialSlot
	template                 *templates.Service
	guide                    *guidance.Service
	afterSources             func() error
	broker                   *secrets.Service
	backend                  *native.Service
	sourceInfo               api.SecretInfo
	configureBroker          func(*secrets.Dependencies)
	profileMode              string
	materializeData          func(context.Context, api.LaunchDataRequest) (api.LaunchData, error)
	storageBeforeCredentials bool
	runner                   func(api.GrantResolver, api.CredentialBroker) api.Runner
}

type successfulPlanAdmin struct {
	api.Helper
	p *successfulPlanPorts
}

func (a *successfulPlanAdmin) Allocate(ctx context.Context, request api.HelperLeaseRequest) (api.HelperLease, error) {
	return a.p.Allocate(ctx, request)
}
func (a *successfulPlanAdmin) ResolveLaunchSources(ctx context.Context, request api.LaunchSourceRequest) (api.LaunchSources, error) {
	return a.p.ResolveLaunchSources(ctx, request)
}
func (a *successfulPlanAdmin) ResolveLaunchStorage(ctx context.Context, request api.LaunchDataRequest) (api.LaunchStorage, error) {
	return a.p.ResolveLaunchStorage(ctx, request)
}

type successfulPlanBroker struct {
	*secrets.Service
	p *successfulPlanPorts
}

func (b *successfulPlanBroker) AcquireLaunch(ctx context.Context, request api.LaunchProfileRequest) (api.CredentialSlot, error) {
	if err := b.p.sync(ctx); err != nil {
		return api.CredentialSlot{}, err
	}
	b.p.state.credentialClaims = append(b.p.state.credentialClaims, request.Claim)
	slot, err := b.Service.AcquireLaunch(ctx, request)
	if err == nil {
		b.p.slot = slot
	}
	return slot, err
}
func (b *successfulPlanBroker) InjectLaunch(ctx context.Context, request api.LaunchInjectionRequest) (api.Injection, error) {
	if err := b.p.sync(ctx); err != nil {
		return api.Injection{}, err
	}
	b.p.state.credentialClaims = append(b.p.state.credentialClaims, request.Claim)
	return b.Service.InjectLaunch(ctx, request)
}

func (p *successfulPlanPorts) sync(ctx context.Context) error {
	current, err := p.f.State.Effect(ctx, p.f.Execution, p.effect.ID)
	if err != nil {
		return err
	}
	if current.ClaimantID == "" || current.Effect.PlanLaunch == nil {
		return serviceError(api.CodeConflict, "component launch has no actual planning claimant")
	}
	p.f.Execution.Actor = api.Actor{Kind: "service", ID: current.ClaimantID}
	p.f.Claim = api.EffectLease{Record: current, ClaimID: current.ClaimID, ExpiresAt: current.ClaimExpiresAt}
	p.f.Record, err = p.f.State.LaunchPlan(ctx, p.f.Execution, current.Effect.PlanLaunch.ReservationID)
	if err == nil {
		p.f.Reservation = p.f.Record.Reservation
	}
	return err
}

func (p *successfulPlanPorts) ResolveLaunchSources(ctx context.Context, request api.LaunchSourceRequest) (api.LaunchSources, error) {
	if err := p.sync(ctx); err != nil {
		return api.LaunchSources{}, err
	}
	r := p.f.Reservation
	if err := p.authority(ctx, request.Claim); err != nil {
		return api.LaunchSources{}, err
	}
	if request.ReservationID != r.ID || request.GrantSetID != r.GrantSetID {
		return api.LaunchSources{}, serviceError(api.CodeForbidden, "component source selector differs from actual reservation")
	}
	selected, err := admin.ResolveCommittedLaunchSources(ctx, p.state, p.f.Deps.Config, request, p.enrollment, p.runtime.Manifest)
	if err == nil {
		p.state.sourceSelections = append(p.state.sourceSelections, selected)
		if p.afterSources != nil {
			if err := p.afterSources(); err != nil {
				return api.LaunchSources{}, err
			}
		}
	}
	return selected, err
}

func (p *successfulPlanPorts) Allocate(ctx context.Context, request api.HelperLeaseRequest) (api.HelperLease, error) {
	if err := p.sync(ctx); err != nil {
		return api.HelperLease{}, err
	}
	if request.ReservationID != p.f.Reservation.ID || request.LifeID != p.f.Reservation.Target.LifeID || request.Budget != p.f.Start.Budget || request.RuntimeManifestID != p.runtime.Manifest.ID {
		return api.HelperLease{}, serviceError(api.CodeForbidden, "component allocation differs from retained source or budget")
	}
	if p.allocation.ID == "" {
		p.allocation = api.HelperLease{ID: fx.ID(p.t), UID: uint32(os.Geteuid()) + 1000, GID: uint32(os.Getegid()) + 1000, ContainmentID: fx.ID(p.t), EndpointGeneration: 1}
	}
	return p.allocation, nil
}

func (p *successfulPlanPorts) MaterializeLaunch(ctx context.Context, request api.LaunchDataRequest) (api.LaunchData, error) {
	if err := p.sync(ctx); err != nil {
		return api.LaunchData{}, err
	}
	if request.ReservationID != p.f.Reservation.ID || request.GrantSetID != p.f.Reservation.GrantSetID || request.LeaseID != p.allocation.ID {
		return api.LaunchData{}, serviceError(api.CodeForbidden, "component data selected another allocation")
	}
	if p.materializeData != nil {
		return p.materializeData(ctx, request)
	}
	p.data = fx.DataForLaunch(p.t, p.f, request)
	p.data.Open(p.t)
	data, raw := p.data.Result(p.t)
	receipt, err := p.f.State.WorkerResult(ctx, p.data.Worker, p.data.Submission(raw))
	if err != nil {
		return api.LaunchData{}, err
	}
	zero, survivors := 0, uint64(0)
	observation := api.ProcessObservation{Handle: p.data.Stage.Process, State: "exited", ExitCode: &zero, Survivors: &survivors,
		PromptStatus: "completed", ObservedAt: api.Timestamp(p.f.Deps.Clock.Now().UTC().Format(time.RFC3339Nano))}
	result := api.LaunchDataResult{StageID: p.data.Stage.ID, WorkerLeaseID: p.data.Stage.Worker.ID, EffectID: p.data.Stage.Worker.EffectID,
		OperationID: p.f.Reservation.OperationID, InputSHA256: p.data.Stage.Worker.Input.SHA256, Data: data, Manifest: data.Materialization.Manifest,
		ReadBackSHA256: data.Materialization.Manifest.SHA256, Observation: observation, ResultReceipt: receipt}
	if _, err := p.f.State.CompleteMaterialization(ctx, p.f.Execution, p.data.Stage.ID, result); err != nil {
		return api.LaunchData{}, err
	}
	return data, nil
}

func (p *successfulPlanPorts) ResolveLaunchStorage(ctx context.Context, request api.LaunchDataRequest) (api.LaunchStorage, error) {
	if err := p.sync(ctx); err != nil {
		return api.LaunchStorage{}, err
	}
	if err := p.authority(ctx, request.Claim); err != nil {
		return api.LaunchStorage{}, err
	}
	if p.data == nil || request.ReservationID != p.data.Request.ReservationID ||
		request.GrantSetID != p.data.Request.GrantSetID || request.LeaseID != p.data.Request.LeaseID {
		return api.LaunchStorage{}, serviceError(api.CodeForbidden, "component storage differs from original data job")
	}
	stage, err := p.f.State.LaunchDataStage(ctx, p.f.Execution, request)
	if err != nil {
		return api.LaunchStorage{}, err
	}
	if len(p.state.credentialClaims) == 0 {
		p.storageBeforeCredentials = true
	}
	return stage.Storage.Storage, nil
}

func (p *successfulPlanPorts) Start(ctx context.Context, request api.RunnerRequest) (api.RunnerPlan, error) {
	if err := p.sync(ctx); err != nil {
		return api.RunnerPlan{}, err
	}
	if p.data == nil || request.Target != p.f.Reservation.Target || request.Home != p.data.Stage.Storage.Storage.Home.Home || request.Slot != p.slot || request.Executable != p.runtime.Executable ||
		request.Session.Driver != p.runtime.Driver || request.Session.HomeID != request.Home.ID || request.Session.HistoryID != request.Home.HistoryID {
		return api.RunnerPlan{}, serviceError(api.CodeForbidden, "component runner differs from measured data or slot")
	}
	chunk, err := p.f.State.Blob(ctx, p.f.Execution, api.BlobReadRequest{ObjectID: request.Prompt.ID, Limit: api.MaxChunkBytes})
	if err != nil || !bytes.Contains(chunk.Data, []byte("## Scope")) || !bytes.Contains(chunk.Data, []byte("Component launch")) {
		return api.RunnerPlan{}, serviceError(api.CodeIntegrity, "real template or original task is absent from runner input")
	}
	session := request.Session
	session.VendorVersion = request.Executable.Version
	return api.RunnerPlan{Driver: session.Driver, Executable: request.Executable, Argv: []string{"/runtime/agent", "component-plan"}, InnerSandbox: "off",
		CWD: request.Session.LogicalCWD, EnvironmentNames: []string{}, Prompt: request.Prompt, Home: request.Home, Slot: request.Slot, Session: session, AdapterVersion: "component"}, nil
}

func (p *successfulPlanPorts) RegisterCapture(ctx context.Context, request api.CaptureRegistrationRequest) (api.CaptureBinding, error) {
	if err := p.sync(ctx); err != nil {
		return api.CaptureBinding{}, err
	}
	r := p.f.Reservation
	if err := p.authority(ctx, request.Claim); err != nil {
		return api.CaptureBinding{}, err
	}
	if request.ReservationID != r.ID || request.HelperLeaseID != p.allocation.ID || request.Cause.Target != r.Target {
		return api.CaptureBinding{}, serviceError(api.CodeForbidden, "component capture differs from retained allocation")
	}
	worker, err := p.f.State.WorkerLease(ctx, p.f.Execution, request.WorkerLeaseID)
	if err != nil {
		return api.CaptureBinding{}, err
	}
	if worker.Kind != "capture_supervisor" || worker.Target != r.Target || worker.EffectID != request.Cause.EffectID ||
		worker.OperationID != r.OperationID || worker.GrantSetID != r.GrantSetID || worker.ConsumedBy != "" {
		return api.CaptureBinding{}, serviceError(api.CodeForbidden, "component capture worker differs from requested narrow supervisor")
	}
	binding := api.CaptureBinding{ID: fx.ID(p.t), Config: r.Config, ReservationID: r.ID, Target: r.Target, LaunchID: r.LaunchID,
		HelperLeaseID: p.allocation.ID, OperationID: r.OperationID, RequestID: r.RequestID, RequestedBy: r.RequestedBy, Generation: 1,
		Status: "registered", WorkerLeaseID: worker.ID, EffectID: request.Cause.EffectID, ProducerID: fx.ID(p.t), ProducerGeneration: string(fx.ID(p.t)), BootID: string(fx.ID(p.t)),
		Supervisor: &p.runtime.Executable, Streams: []api.CaptureStreamBinding{{ID: fx.ID(p.t), Stream: "stdout", PipeID: fx.ID(p.t)}, {ID: fx.ID(p.t), Stream: "stderr", PipeID: fx.ID(p.t)}}}
	// The planner alone commits capture.bound together with launch.planned.
	// This helper fixture supplies the external producer receipt, without
	// repairing its input lease or pre-committing a duplicate binding event.
	return binding, nil
}

func (p *successfulPlanPorts) ReconcileCapture(ctx context.Context, request api.CaptureBinding) (api.CaptureBinding, error) {
	state, err := p.f.State.CaptureState(ctx, p.f.Execution, request.ID)
	if err != nil {
		return api.CaptureBinding{}, err
	}
	if !reflect.DeepEqual(state.Binding, request) {
		return api.CaptureBinding{}, serviceError(api.CodeIntegrity, "component capture changed its retained binding")
	}
	return state.Binding, nil
}

func planningSourcePorts(t *testing.T, state *planningPolicyStore, f *fx.Fixture, effect api.Effect) *successfulPlanPorts {
	t.Helper()
	p := &successfulPlanPorts{t: t, f: f, effect: effect, state: state}
	state.sourcePorts = p
	digest, err := wire.ArtifactDigest()
	if err != nil {
		t.Fatal(err)
	}
	agentBytes := []byte("unexecuted component agent " + string(fx.ID(t)))
	agentRef := api.BlobRef{ID: fx.ID(t), Class: "artifact", Bytes: int64(len(agentBytes)), SHA256: fx.Digest(agentBytes)}
	executable := api.Executable{ID: fx.ID(t), SHA256: agentRef.SHA256, Version: "component-vendor"}
	runtime := api.RuntimeManifest{Schema: "laneboss.runtime.v2", Generation: 1,
		Artifact:  api.Executable{ID: fx.ID(t), SHA256: digest, Version: release.Version},
		Bootstrap: api.Executable{ID: fx.ID(t), SHA256: digest, Version: release.Version},
		Objects:   []api.RuntimeObject{{ID: executable.ID, Role: "agent", RootID: "component-runtime", RelativePath: "agent", Content: agentRef, Mode: 0555}}, Bindings: []api.InstalledBinding{}}
	raw := fx.JSON(t, runtime)
	ref := api.BlobRef{ID: fx.ID(t), Class: "manifest", Bytes: int64(len(raw)), SHA256: fx.Digest(raw)}
	// This stand-in is a direct runner, so the same manifest-pinned executable
	// owns its session history. Retain that exact pin in protected enrollment,
	// as the installer does for a separately pinned vendor executable.
	p.runtime = api.LaunchRuntime{EnrollmentID: fx.ID(t), Generation: 1, Backend: "linux-bwrap-landlock", Driver: f.Start.Driver,
		Executable: executable, SessionExecutable: executable, Manifest: ref}
	source, err := f.State.ObjectMetadata(context.Background(), f.Execution, f.Ceiling.Data[0].SourceObjectID)
	if err != nil {
		t.Fatal(err)
	}
	enrollment := api.LaunchEnrollment{Schema: "laneboss.launch-enrollment.v2", Config: f.Deps.Config, Generation: 1,
		Projects: []api.ProjectEnrollment{{ID: fx.ID(t), Generation: 1, ProjectID: f.Start.ProjectID, Object: source.Ref, Base: string(source.Ref.SHA256), HistoryScope: "tree"}},
		Runtimes: []api.LaunchRuntime{p.runtime}}
	enrollmentBytes := fx.JSON(t, enrollment)
	p.enrollment = api.BlobRef{ID: fx.ID(t), Class: "manifest", Bytes: int64(len(enrollmentBytes)), SHA256: fx.Digest(enrollmentBytes)}
	objects := []api.ObjectWrite{}
	for _, value := range []struct {
		ref   api.BlobRef
		bytes []byte
	}{{agentRef, agentBytes}, {ref, raw}, {p.enrollment, enrollmentBytes}} {
		objects = append(objects, api.ObjectWrite{ObjectKey: value.ref.ID, Class: value.ref.Class, Bytes: value.bytes, SHA256: value.ref.SHA256, Origin: "service",
			ACL: api.ObjectACL{Config: f.Deps.Config, Owner: f.Execution.Actor, Audience: "owner", Generation: 1}})
	}
	cause := f.Intent(t, api.InternalOrgBootstrap)
	if _, err := f.State.Transact(context.Background(), api.Transaction{Scope: f.Execution, Internal: &cause, Writes: api.StateWrites{Objects: objects}}); err != nil {
		t.Fatal(err)
	}
	return p
}

func successfulScopePlanner(t *testing.T, state *planningPolicyStore, f *fx.Fixture, effect api.Effect) *lifecycle.Service {
	return successfulScopePlannerGrants(t, state, f, effect, nil)
}

func successfulScopePlannerGrants(t *testing.T, state *planningPolicyStore, f *fx.Fixture, effect api.Effect, decorate func(*grants.Service) api.GrantResolver) *lifecycle.Service {
	return scopePlanSetup(t, state, f, effect, decorate, nil)
}

func scopePlanSetup(t *testing.T, state *planningPolicyStore, f *fx.Fixture, effect api.Effect, decorate func(*grants.Service) api.GrantResolver, setup func(*successfulPlanPorts)) *lifecycle.Service {
	t.Helper()
	p := planningSourcePorts(t, state, f, effect)
	if setup != nil {
		setup(p)
	}
	resolver, err := grants.New(grants.Dependencies{Config: f.Deps.Config, Store: state, Worker: &dataworker.Service{}, Clock: f.Deps.Clock})
	if err != nil {
		t.Fatal(err)
	}
	var selectedGrants api.GrantResolver = resolver
	if decorate != nil {
		selectedGrants = decorate(resolver)
	}
	p.template, err = templates.New(templates.Dependencies{Store: state, Policy: &policy.Service{}, Clock: f.Deps.Clock})
	if err != nil {
		t.Fatal(err)
	}
	p.guide, err = guidance.New(guidance.Dependencies{Store: state, Judge: &judge.Service{}, Clock: f.Deps.Clock})
	if err != nil {
		t.Fatal(err)
	}
	broker := planningBroker(t, f, p)
	var claude api.Runner = p
	if p.runner != nil {
		claude = p.runner(selectedGrants, broker)
	}
	planner, err := lifecycle.New(lifecycle.Dependencies{Store: state, Identity: &authFixture{}, Grants: selectedGrants, Sources: &successfulPlanAdmin{p: p},
		Worker: p, Credentials: &successfulPlanBroker{Service: broker, p: p}, Codex: p, Claudock: claude, Templates: p.template, Guidance: p.guide, Capture: p, Clock: f.Deps.Clock})
	if err != nil {
		t.Fatal(err)
	}
	return planner
}

func (p *successfulPlanPorts) authority(ctx context.Context, claim api.LaunchClaim) error {
	record, err := admin.CheckLaunchPlanningAuthority(ctx, p.state, p.f.Deps.Config, claim)
	if err != nil {
		return err
	}
	if record.Reservation.ID != p.f.Reservation.ID {
		return serviceError(api.CodeForbidden, "real administrator authority selected another reservation")
	}
	p.state.authorityClaims = append(p.state.authorityClaims, claim)
	return nil
}
