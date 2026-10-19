package claudock

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
)

// This fixture persists selectors, enrollment, helper journals, requests and
// object bytes separately. Consumers perform the real adapter and shared
// validators. It supplies no live vendor or kernel attestation claim.
type launchFixtureStore struct {
	api.StateStore
	api.GrantResolver
	api.CredentialBroker
	api.CaptureControl
	dir    string
	f      *runnerFixture
	t      *testing.T
	policy api.EffectivePolicy
}

func (d *launchFixtureStore) write(name string, value any) {
	d.t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		d.t.Fatal(err)
	}
	put(d.t, filepath.Join(d.dir, name+".json"), data)
}

func (d *launchFixtureStore) read(name string, value any) error {
	data, err := os.ReadFile(filepath.Join(d.dir, name+".json"))
	if err != nil {
		return failure(api.CodeNotFound, "fixture retained object is absent")
	}
	if err := json.Unmarshal(data, value); err != nil {
		return failure(api.CodeIntegrity, "fixture retained object is malformed")
	}
	return nil
}

func (d *launchFixtureStore) object(id api.ID, class string, data []byte, operation, life api.ID) api.BlobRef {
	ref := api.BlobRef{ID: id, Class: class, Bytes: int64(len(data)), SHA256: contentDigest(data)}
	if _, err := os.Lstat(filepath.Join(d.dir, "meta-"+string(id)+".json")); err == nil {
		var retained api.ObjectMetadata
		if err := d.read("meta-"+string(id), &retained); err != nil {
			d.t.Fatal(err)
		}
		kept, err := os.ReadFile(filepath.Join(d.dir, string(id)+".bytes"))
		if err != nil || retained.Ref != ref || retained.SourceOperationID != operation || retained.ACL.LifeID != life || !bytes.Equal(data, kept) {
			d.t.Fatal("fixture attempted to replace immutable object bytes or provenance", id, err)
		}
		return retained.Ref
	} else if !os.IsNotExist(err) {
		d.t.Fatal(err)
	}
	put(d.t, filepath.Join(d.dir, string(id)+".bytes"), data)
	d.write("meta-"+string(id), api.ObjectMetadata{Ref: ref, ACL: api.ObjectACL{Config: "demo", LifeID: life, Owner: api.Actor{Kind: "service", ID: "service-a"}, Audience: "service", Participants: []api.ID{}, Generation: 1},
		Origin: "service", SourceOperationID: operation, CommittedAt: "2026-10-15T12:00:00Z"})
	return ref
}

func (d *launchFixtureStore) scope(scope api.Scope) error {
	if scope.Config != "demo" || scope.Actor != (api.Actor{Kind: "service", ID: "service-a"}) {
		return failure(api.CodeForbidden, "fixture reader scope is foreign")
	}
	return nil
}

func (d *launchFixtureStore) selectRun(ctx context.Context, target api.LifeRef) (LaunchSelector, error) {
	var selector LaunchSelector
	err := d.read(fmt.Sprintf("index-%s-%d", target.LifeID, target.Run), &selector)
	return selector, err
}

func (d *launchFixtureStore) retainRun(request api.RunnerRequest) {
	d.write(fmt.Sprintf("runner-%s-%d", request.Target.LifeID, request.Target.Run), request)
}

func (d *launchFixtureStore) run(ctx context.Context, target api.LifeRef) (api.RunnerRequest, error) {
	var request api.RunnerRequest
	if err := d.read(fmt.Sprintf("runner-%s-%d", target.LifeID, target.Run), &request); err != nil {
		return request, err
	}
	if request.Target != target {
		return api.RunnerRequest{}, failure(api.CodeIntegrity, "fixture durable runner target changed")
	}
	return request, nil
}

func (d *launchFixtureStore) profile(ctx context.Context, slot api.CredentialSlot) (api.ProfileGrant, error) {
	var retained api.CredentialSlot
	if err := d.read("slot-"+string(slot.ID), &retained); err != nil {
		return api.ProfileGrant{}, err
	}
	if retained != slot {
		return api.ProfileGrant{}, failure(api.CodeForbidden, "fixture retained credential lease changed")
	}
	grants, err := d.Grants(ctx, "grants-a")
	if err != nil {
		return api.ProfileGrant{}, err
	}
	for _, grant := range grants.Profiles {
		if grant.ID == slot.ProfileGrantID && grant.ProfileID == slot.ProfileID {
			return grant, nil
		}
	}
	return api.ProfileGrant{}, failure(api.CodeForbidden, "fixture profile is outside retained grants")
}

func (d *launchFixtureStore) LaunchPlan(ctx context.Context, scope api.Scope, id api.ID) (api.LaunchPlanRecord, error) {
	var record api.LaunchPlanRecord
	if err := d.scope(scope); err != nil {
		return record, err
	}
	err := d.read("plan-"+string(id), &record)
	return record, err
}

func (d *launchFixtureStore) Effect(ctx context.Context, scope api.Scope, id api.ID) (api.EffectRecord, error) {
	var effect api.EffectRecord
	if err := d.scope(scope); err != nil {
		return effect, err
	}
	err := d.read("effect-"+string(id), &effect)
	return effect, err
}

func (d *launchFixtureStore) Policy(ctx context.Context, scope api.Scope) (api.EffectivePolicy, error) {
	var policy api.EffectivePolicy
	if err := d.scope(scope); err != nil {
		return policy, err
	}
	err := d.read("policy", &policy)
	return policy, err
}

func (d *launchFixtureStore) Grants(ctx context.Context, id api.ID) (api.GrantSet, error) {
	var grants api.GrantSet
	err := d.read("grants-"+string(id), &grants)
	return grants, err
}

func (d *launchFixtureStore) Resolve(ctx context.Context, scope api.Scope, request api.GrantResolveRequest) (api.GrantSet, error) {
	record, err := d.LaunchPlan(ctx, scope, request.ReservationID)
	if err != nil {
		return api.GrantSet{}, err
	}
	if record.Inputs == nil {
		return api.GrantSet{}, failure(api.CodePrerequisite, "fixture reserved grants have not been selected")
	}
	return d.Revalidate(ctx, record.Inputs.Grants)
}

func (d *launchFixtureStore) Revalidate(ctx context.Context, claim api.GrantSet) (api.GrantSet, error) {
	current, err := d.Grants(ctx, claim.ID)
	if err != nil {
		return api.GrantSet{}, err
	}
	var policy api.EffectivePolicy
	if err := d.read("policy", &policy); err != nil {
		return api.GrantSet{}, err
	}
	if !reflect.DeepEqual(current, claim) || current.Revoked || current.PolicyGeneration != policy.Generation {
		return api.GrantSet{}, failure(api.CodeForbidden, "fixture current grants changed")
	}
	return current, nil
}

func (d *launchFixtureStore) ResolveLaunchSources(ctx context.Context, request api.LaunchSourceRequest) (api.LaunchSources, error) {
	var sources api.LaunchSources
	var record api.LaunchPlanRecord
	if err := d.read("plan-"+string(request.ReservationID), &record); err != nil {
		return sources, err
	}
	if record.Reservation.GrantSetID != request.GrantSetID {
		return sources, failure(api.CodeForbidden, "fixture source selection is foreign")
	}
	err := d.read("enrolled-"+string(request.ReservationID), &sources)
	return sources, err
}

func (d *launchFixtureStore) ResolveLaunchStorage(ctx context.Context, request api.LaunchDataRequest) (api.LaunchStorage, error) {
	var storage api.LaunchStorage
	if err := d.read("storage-"+string(request.ReservationID), &storage); err != nil {
		return storage, err
	}
	var record api.LaunchPlanRecord
	if err := d.read("plan-"+string(request.ReservationID), &record); err != nil {
		return storage, err
	}
	if request.GrantSetID != record.Reservation.GrantSetID || request.LeaseID != storage.LeaseID {
		return api.LaunchStorage{}, failure(api.CodeForbidden, "fixture storage selector is foreign")
	}
	return storage, nil
}

func (d *launchFixtureStore) homePath(ctx context.Context, binding api.PrivateHomeBinding) (string, error) {
	var registry struct {
		Binding  api.PrivateHomeBinding
		Path     string
		Identity string
	}
	if err := d.read("root-"+string(binding.RootID), &registry); err != nil {
		return "", err
	}
	info, err := os.Lstat(registry.Path)
	if err != nil {
		return "", failure(api.CodeIntegrity, "fixture home registry object disappeared")
	}
	key, err := homeKey(info)
	if err != nil || registry.Binding != binding || registry.Identity != key {
		return "", failure(api.CodeIntegrity, "fixture home registry identity changed")
	}
	return registry.Path, nil
}

func (d *launchFixtureStore) ObjectMetadata(ctx context.Context, scope api.Scope, id api.ID) (api.ObjectMetadata, error) {
	var metadata api.ObjectMetadata
	if err := d.scope(scope); err != nil {
		return metadata, err
	}
	err := d.read("meta-"+string(id), &metadata)
	return metadata, err
}

func (d *launchFixtureStore) Blob(ctx context.Context, scope api.Scope, request api.BlobReadRequest) (api.BlobChunk, error) {
	if err := d.scope(scope); err != nil {
		return api.BlobChunk{}, err
	}
	data, err := os.ReadFile(filepath.Join(d.dir, string(request.ObjectID)+".bytes"))
	if err != nil {
		return api.BlobChunk{}, failure(api.CodeNotFound, "fixture immutable bytes are absent")
	}
	if request.Offset < 0 || request.Offset > int64(len(data)) || request.Limit <= 0 {
		return api.BlobChunk{}, failure(api.CodeInvalid, "fixture byte range is invalid")
	}
	end := min(int64(len(data)), request.Offset+int64(request.Limit))
	data = data[request.Offset:end]
	return api.BlobChunk{ObjectID: request.ObjectID, Offset: request.Offset, Data: data, SHA256: contentDigest(data)}, nil
}

func (d *launchFixtureStore) LaunchBinding(ctx context.Context, id api.ID) (api.LaunchBindingRequest, error) {
	var binding api.LaunchBindingRequest
	err := d.read("binding-"+string(id), &binding)
	return binding, err
}

func (d *launchFixtureStore) CaptureState(ctx context.Context, scope api.Scope, id api.ID) (api.CaptureState, error) {
	var state api.CaptureState
	if err := d.scope(scope); err != nil {
		return state, err
	}
	err := d.read("capture-"+string(id), &state)
	return state, err
}

func (d *launchFixtureStore) ReconcileCapture(ctx context.Context, binding api.CaptureBinding) (api.CaptureBinding, error) {
	var journal api.CaptureBinding
	if err := d.read("producer-"+string(binding.ID), &journal); err != nil {
		return api.CaptureBinding{}, err
	}
	if journal.ID != binding.ID {
		return api.CaptureBinding{}, failure(api.CodeIntegrity, "fixture capture journal selector changed")
	}
	if err := api.ValidateCaptureBinding(journal); err != nil {
		return api.CaptureBinding{}, err
	}
	return journal, nil
}

func (f *runnerFixture) sourceLaunch(t *testing.T, mode string) {
	t.Helper()
	d, request := f.launch, f.request
	suffix := fmt.Sprint(request.Target.Run)
	if request.Target.Run > 1 {
		suffix += "-" + mode
		request.Prompt.ID = api.ID("brief-" + suffix)
		f.request.Prompt = request.Prompt
	}
	id := api.ID("plan-" + suffix)
	op, req := api.ID("operation-"+suffix), api.ID("request-"+suffix)
	scope := api.Scope{Config: "demo", Actor: api.Actor{Kind: "service", ID: "service-a"}, PolicyGeneration: 3}
	selector := LaunchSelector{Scope: scope, ReservationID: id, EffectID: api.ID("effect-" + suffix), ClaimID: api.ID("claim-" + suffix), HelperLeaseID: api.ID("helper-" + suffix)}
	r := api.LaunchReservation{ID: id, Config: "demo", Mode: mode, Target: request.Target, LaunchID: api.ID("launch-" + suffix), SpecID: api.ID("spec-" + suffix), GrantSetID: "grants-a", Generation: 1,
		Level: 3, Role: "executor", Driver: api.DriverClaudock, Authority: api.LaunchAuthority{Kind: "ticket", ID: "root-ticket"},
		PolicyGeneration: 3, RootLifeID: request.Target.LifeID, StarterChain: []api.ID{}, OperationID: op, RequestID: req, RequestedBy: api.Actor{Kind: "human", ID: "human-a"}}
	if request.Target.Run > 1 {
		previous, err := d.selectRun(context.Background(), api.LifeRef{LifeID: request.Target.LifeID, Run: request.Target.Run - 1})
		if err != nil {
			t.Fatal(err)
		}
		prior, err := d.LaunchPlan(context.Background(), previous.Scope, previous.ReservationID)
		if err != nil {
			t.Fatal(err)
		}
		r.BaseGeneration, r.Generation, r.PreviousLaunchID = api.Generation(request.Target.Run-1), api.Generation(request.Target.Run), prior.Reservation.LaunchID
		r.Level, r.Role, r.Driver = prior.Reservation.Level, prior.Reservation.Role, prior.Reservation.Driver
		r.Authority = api.LaunchAuthority{Kind: "proof", ID: api.ID("proof-" + suffix)}
	}
	manifest := d.object("source-object", "manifest", []byte("retained project bytes"), "project-publish", request.Target.LifeID)
	project := api.ProjectLaunchSource{EnrollmentID: "project-enrollment", Generation: 1, ProjectID: "project-a", GrantID: "main-data", Object: manifest, Base: strings.Repeat("a", 40), HistoryScope: "tree"}
	runtimeRef := d.object("runtime-object", "manifest", []byte("retained installed runtime"), "runtime-install", "")
	sources := api.LaunchSources{ReservationID: id, Project: project, Runtime: api.LaunchRuntime{EnrollmentID: "runtime-enrollment", Generation: 1, Backend: "linux-bwrap-landlock", Driver: api.DriverClaudock, Executable: request.Executable, Manifest: runtimeRef}}
	grants := api.GrantSet{ID: r.GrantSetID, LifeID: request.Target.LifeID, Generation: 1, PolicyGeneration: 3, SHA256: contentDigest([]byte("retained grants")), ExpiresAt: "2026-10-15T14:00:00Z",
		Resources: []api.ResourceGrant{}, Secrets: []api.SecretGrant{}, Network: []api.NetworkGrant{}, Channels: []api.ChannelGrant{},
		Data: []api.DataGrant{{ID: project.GrantID, SourceObjectID: manifest.ID, SourceSHA256: manifest.SHA256, RelativePath: ".", Access: "rw", Delivery: "copy", Destination: "/work/main", HistoryScope: "tree", ExpiresAt: "2026-10-15T14:00:00Z"}},
		Profiles: []api.ProfileGrant{{ID: "grant-a", ProfileID: "profile-a", Driver: api.DriverClaudock, Provider: "anthropic", ExpiresAt: "2026-10-15T14:00:00Z"},
			{ID: "grant-b", ProfileID: "profile-b", Driver: api.DriverClaudock, Provider: "anthropic", ExpiresAt: "2026-10-15T14:00:00Z"}}}
	requestedProfiles := make([]api.ProfileDelegation, 0, len(grants.Profiles))
	for _, profile := range grants.Profiles {
		requestedProfiles = append(requestedProfiles, api.ProfileDelegation{ParentGrantID: api.ID("template-" + string(profile.ID)), ProfileID: profile.ProfileID,
			Delegate: profile.Delegate, ExpiresAt: profile.ExpiresAt})
	}
	var params any
	method := api.Method("lane." + mode)
	switch mode {
	case "start":
		params = api.StartRequest{Lane: "demo", ProjectID: project.ProjectID, Level: r.Level, Role: r.Role, Task: request.Prompt, Driver: r.Driver, ProfileGrantID: api.ID("template-" + string(request.Slot.ProfileGrantID)), Model: request.Model, Effort: request.Effort, Budget: request.Budget, RootTicketID: r.Authority.ID, ExpectedPolicyGeneration: 3,
			Grants: api.GrantRequest{Resources: []api.ResourceDelegation{}, Data: []api.DataGrantRequest{}, Secrets: []api.SecretDelegation{}, Profiles: requestedProfiles, Network: []api.NetworkDelegation{}, Channels: []api.ChannelDelegation{}}}
	case "turn":
		params = api.TurnRequest{Target: api.LifeRef{LifeID: request.Target.LifeID, Run: request.Target.Run - 1}, ExpectedGeneration: r.BaseGeneration, MailIDs: []api.ID{}, IdleMessage: &request.Prompt, Budget: request.Budget}
	default:
		params = api.ResumeRequest{Target: api.LifeRef{LifeID: request.Target.LifeID, Run: request.Target.Run - 1}, ExpectedGeneration: r.BaseGeneration, Message: request.Prompt, Budget: request.Budget}
		method = "lane.resume"
	}
	raw, err := json.Marshal(params)
	if err != nil {
		t.Fatal(err)
	}
	frame := api.Request{Protocol: api.Protocol, Schema: api.SchemaVersion, Config: "demo", RequestID: req, IdempotencyKey: "retained-key-" + api.ID(suffix), Method: method, Params: raw}
	frame.RequestSHA256, err = api.RequestDigest(frame)
	if err != nil {
		t.Fatal(err)
	}
	raw, err = json.Marshal(frame)
	if err != nil {
		t.Fatal(err)
	}
	r.OriginalRequest, r.RequestSHA256 = d.object(api.ID("original-"+suffix), "launch_request", raw, op, ""), frame.RequestSHA256
	d.object(request.Prompt.ID, "prompt", []byte("kept brief\n"), op, request.Target.LifeID)
	storage := api.LaunchStorage{ReservationID: id, Target: request.Target, LeaseID: selector.HelperLeaseID, WorkspaceID: request.Home.WorkspaceID,
		Home: api.PrivateHomeBinding{LifeID: request.Target.LifeID, RootID: "home-root", Generation: 1, Home: request.Home}}
	d.write("root-home-root", struct {
		Binding  api.PrivateHomeBinding
		Path     string
		Identity string
	}{storage.Home, f.home.path, f.home.key})
	d.write("storage-"+string(id), storage)
	d.retainRun(request)
	d.write("slot-"+string(request.Slot.ID), request.Slot)
	d.write("enrolled-"+string(id), sources)
	d.write("grants-"+string(grants.ID), grants)
	if request.Target.Run == 1 {
		d.policy = api.EffectivePolicy{Generation: 3, ProfileExclusions: []api.ID{}}
	} else if err := d.read("policy", &d.policy); err != nil {
		t.Fatal(err)
	}
	d.write("policy", d.policy)
	d.write("plan-"+string(id), api.LaunchPlanRecord{Reservation: r, Generation: 2, Phase: "sourced", Inputs: &api.LaunchInputs{Grants: grants, Sources: sources}})
	cause := api.InternalIntent{ID: "plan-intent", Kind: api.InternalLaunchPlan, Config: r.Config, Actor: scope.Actor, RequestedBy: r.RequestedBy, Target: r.Target, CauseOperationID: op, CauseRequestID: req, EffectID: selector.EffectID, CancellationEpoch: r.CancellationEpoch}
	d.write("effect-"+string(selector.EffectID), api.EffectRecord{Effect: api.Effect{ID: selector.EffectID, OperationID: op, Context: &cause, PlanLaunch: &api.LaunchPlanEffect{ReservationID: id}}, Generation: 1, State: "claimed", ClaimID: selector.ClaimID, ClaimantID: scope.Actor.ID, ClaimExpiresAt: "2026-10-15T13:00:00Z"})
	d.write(fmt.Sprintf("index-%s-%d", request.Target.LifeID, request.Target.Run), selector)
	f.seedUsage(t, r, sources)
	d.write("bootstrap", struct{ Umask uint32 }{RequiredUmask})
}

func fixtureHash(t *testing.T, value any) (api.Digest, []byte) {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := api.CanonicalJSON(encoded)
	if err != nil {
		t.Fatal(err)
	}
	return contentDigest(canonical), canonical
}

func (f *runnerFixture) opened(t *testing.T, runner api.RunnerPlan) api.LaunchPlan {
	t.Helper()
	d := f.launch
	selector, err := d.selectRun(context.Background(), f.request.Target)
	if err != nil {
		t.Fatal(err)
	}
	record, err := d.LaunchPlan(context.Background(), selector.Scope, selector.ReservationID)
	if err != nil {
		t.Fatal(err)
	}
	r := record.Reservation
	storage, err := d.ResolveLaunchStorage(context.Background(), api.LaunchDataRequest{ReservationID: r.ID, GrantSetID: r.GrantSetID, LeaseID: selector.HelperLeaseID})
	if err != nil {
		t.Fatal(err)
	}
	lease := api.HelperLease{ID: storage.LeaseID, UID: 12001, GID: 12001, ContainmentID: "containment-a", EndpointGeneration: 1}
	workspace := api.Workspace{ID: storage.WorkspaceID, ProjectID: record.Inputs.Sources.Project.ProjectID, Base: record.Inputs.Sources.Project.Base, Branch: "lane/" + string(r.Target.LifeID), LogicalCWD: "/work/main", Snapshot: record.Inputs.Sources.Project.Object}
	data := api.LaunchData{ReservationID: r.ID, Target: r.Target, LeaseID: lease.ID, Source: record.Inputs.Sources.Project, Workspace: workspace, Home: storage.Home,
		Materialization: api.Materialization{GrantSetID: r.GrantSetID, Manifest: workspace.Snapshot, Objects: []api.MaterializedObject{{GrantID: record.Inputs.Sources.Project.GrantID, WorkspaceID: workspace.ID, SourceIdentity: "fixture-source-inode", DestinationIdentity: "fixture-destination-inode", SnapshotSHA256: workspace.Snapshot.SHA256}}}}
	supervisor := api.Executable{ID: "capture-supervisor", Version: "fixture", SHA256: contentDigest([]byte("retained supervisor"))}
	capture := api.CaptureBinding{ID: api.ID(fmt.Sprintf("capture-binding-%d", r.Target.Run)), Config: r.Config, ReservationID: r.ID, Target: r.Target, LaunchID: r.LaunchID, HelperLeaseID: lease.ID,
		OperationID: r.OperationID, RequestID: r.RequestID, RequestedBy: r.RequestedBy, Generation: 1, Status: "registered", WorkerLeaseID: "capture-worker", EffectID: "capture-effect", ProducerID: "capture-producer", ProducerGeneration: "producer-generation", BootID: "fixture-boot", Supervisor: &supervisor,
		Streams: []api.CaptureStreamBinding{{ID: "stream-out", Stream: "stdout", PipeID: "pipe-out"}, {ID: "stream-err", Stream: "stderr", PipeID: "pipe-err"}, {ID: "stream-vendor", Stream: "vendor", PipeID: "pipe-vendor"}}}
	plan := api.LaunchPlan{Reservation: r, Inputs: *record.Inputs, Lease: lease, Data: data, Runner: runner, Budget: f.request.Budget, Capture: capture,
		Injection: api.Injection{Target: r.Target, SlotIDs: []api.ID{runner.Slot.ID}, TaskSecretNames: []string{}, TaskSecretFileNames: []string{}, GrantIDs: []api.ID{}, SourceVersions: []string{}, Outcome: "injected"}}
	spec := api.LaunchSpec{Kind: "agent", PlanID: r.ID, Capture: &capture, ID: r.SpecID, Target: r.Target, LaunchID: r.LaunchID, UIDLeaseID: lease.ID, Backend: "linux-bwrap-landlock", EndpointGeneration: 1, PolicyGeneration: r.PolicyGeneration,
		Workspace: workspace, Materialization: data.Materialization, Grants: plan.Inputs.Grants, Runner: &runner, Injection: plan.Injection, Budget: plan.Budget, RuntimeManifest: plan.Inputs.Sources.Runtime.Manifest}
	specHash, specBytes := fixtureHash(t, spec)
	handoff := api.PreparedSpecHandoff{Config: r.Config, Spec: spec, Original: d.object(api.ID("spec-object-"+string(r.ID)), "launch_spec", specBytes, r.OperationID, r.Target.LifeID), SpecSHA256: specHash, OperationID: r.OperationID, RequestID: r.RequestID,
		Cause: api.InternalIntent{ID: "register-intent", Kind: api.InternalHelperRegister, Config: r.Config, Actor: selector.Scope.Actor, RequestedBy: r.RequestedBy, Target: r.Target, CauseOperationID: r.OperationID, CauseRequestID: r.RequestID, EffectID: "register-effect", CancellationEpoch: r.CancellationEpoch}}
	launch := api.LaunchRecord{Kind: "agent", ID: r.LaunchID, Config: r.Config, Target: r.Target, RootLifeID: r.RootLifeID, StarterChain: r.StarterChain, Actor: api.Actor{Kind: "lane", ID: "child-principal", LifeID: r.Target.LifeID, Level: r.Level, Role: r.Role}, UIDLeaseID: lease.ID, HostUID: lease.UID,
		ProcessGeneration: "generation-a", ContainmentID: lease.ContainmentID, GrantSetID: r.GrantSetID, GrantsSHA256: plan.Inputs.Grants.SHA256, PolicyGeneration: r.PolicyGeneration, EndpointGeneration: 1}
	launchHash, _ := fixtureHash(t, launch)
	binding := api.LaunchBindingRequest{Record: launch, Prepared: api.PreparedLaunch{ID: "prepared-a", SpecSHA256: specHash, Target: r.Target, ContainmentID: lease.ContainmentID, ProcessGeneration: launch.ProcessGeneration, EndpointGeneration: 1, GateID: "gate-a"},
		Identity: api.IdentityCommit{LaunchID: r.LaunchID, EventID: "identity-a", CommittedSeq: 10, RecordSHA256: launchHash}, Recovery: &api.LaunchRecovery{PlanID: r.ID, OriginalRequest: r.OriginalRequest, Handoff: handoff, Home: storage.Home, Capture: capture}}
	if err := api.ValidateLaunchBindingPlan(binding, plan); err != nil {
		t.Fatal("fixture failed the real recovery validator", err)
	}
	d.write("binding-"+string(r.LaunchID), binding)
	d.write("plan-"+string(r.ID), api.LaunchPlanRecord{Reservation: r, Inputs: &plan.Inputs, Plan: &plan, Handoff: &handoff, Generation: 5, Phase: "opened"})
	d.write("producer-"+string(capture.ID), capture)
	d.write("capture-"+string(capture.ID), api.CaptureState{Binding: capture, Generation: 1, Positions: []api.CapturePosition{{StreamID: "stream-out"}, {StreamID: "stream-err"}, {StreamID: "stream-vendor"}}, LastSeq: 10})
	return plan
}
