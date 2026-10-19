package codex

import (
	"context"
	"encoding/json"
	"strconv"
	"strings"

	"laneboss.io/laneboss/internal/v2/api"
)

// These are retained-byte unit fixtures, not a working service/helper. Reads
// validate selectors and decode actual objects; missing methods still panic.
type launchMemory struct {
	plans           map[api.ID]api.LaunchPlanRecord
	effects         map[api.ID]api.EffectRecord
	bindings        map[api.ID]api.LaunchBindingRequest
	captures        map[api.ID]api.CaptureState
	journal         map[api.ID]api.BlobRef
	dataStages      map[api.ID]api.BlobRef
	dataResults     map[api.ID]api.BlobRef
	receipts        map[api.RequestKey]api.MutationReceipt
	turns           map[api.LifeRef]api.TurnSnapshot
	metadata        map[api.ID]api.ObjectMetadata
	policy          api.EffectivePolicy
	approvedPolicy  *api.EffectivePolicy
	cause           api.InternalIntent
	sequence        api.Sequence
	setupEvents     []api.Event
	enrollment      api.BlobRef
	runtimeManifest api.BlobRef
	home            *Home
}

func fixtureCopy[T any](value T) T {
	data, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	var result T
	if err := json.Unmarshal(data, &result); err != nil {
		panic(err)
	}
	return result
}

func (m *memoryStore) Effect(ctx context.Context, scope api.Scope, id api.ID) (api.EffectRecord, error) {
	if m.readError != nil {
		return api.EffectRecord{}, m.readError
	}
	value, ok := m.effects[id]
	if scope.Config != "case-codex" || !ok {
		return api.EffectRecord{}, problem(api.CodeNotFound, "test effect absent")
	}
	return fixtureCopy(value), nil
}

func (m *memoryStore) LaunchPlan(ctx context.Context, scope api.Scope, id api.ID) (api.LaunchPlanRecord, error) {
	if m.readError != nil {
		return api.LaunchPlanRecord{}, m.readError
	}
	value, ok := m.plans[id]
	if scope.Config != "case-codex" || !ok {
		return api.LaunchPlanRecord{}, problem(api.CodeNotFound, "test plan absent")
	}
	return fixtureCopy(value), nil
}

func (m *memoryStore) LaunchBinding(ctx context.Context, id api.ID) (api.LaunchBindingRequest, error) {
	if m.readError != nil {
		return api.LaunchBindingRequest{}, m.readError
	}
	value, ok := m.bindings[id]
	if !ok {
		return api.LaunchBindingRequest{}, problem(api.CodeNotFound, "test binding absent")
	}
	return fixtureCopy(value), nil
}

func (m *memoryStore) CaptureState(ctx context.Context, scope api.Scope, id api.ID) (api.CaptureState, error) {
	if m.readError != nil {
		return api.CaptureState{}, m.readError
	}
	value, ok := m.captures[id]
	if scope.Config != "case-codex" || !ok {
		return api.CaptureState{}, problem(api.CodeNotFound, "test capture state absent")
	}
	return fixtureCopy(value), nil
}

func (m *memoryStore) LookupReceipt(ctx context.Context, scope api.Scope, key api.RequestKey) (api.MutationReceipt, error) {
	if m.readError != nil {
		return api.MutationReceipt{}, m.readError
	}
	value, ok := m.receipts[key]
	if scope.Config != "case-codex" || !ok {
		return api.MutationReceipt{}, problem(api.CodeNotFound, "test operation absent")
	}
	return fixtureCopy(value), nil
}

func (m *memoryStore) LaunchReceipt(ctx context.Context, scope api.Scope, request api.LaunchReceiptRequest) (api.MutationReceipt, error) {
	record, err := m.LaunchPlan(ctx, scope, request.ReservationID)
	if err != nil {
		return api.MutationReceipt{}, err
	}
	var original api.Request
	if err := decode(m.blobs[record.Reservation.OriginalRequest.ID], &original); err != nil {
		return api.MutationReceipt{}, err
	}
	key := api.RequestKey{Method: original.Method, IdempotencyKey: original.IdempotencyKey, RequestSHA256: original.RequestSHA256}
	value, ok := m.receipts[key]
	if !ok || value.Actor != record.Reservation.RequestedBy || value.Operation.ID != record.Reservation.OperationID {
		return api.MutationReceipt{}, problem(api.CodeNotFound, "test reserved operation absent")
	}
	return fixtureCopy(value), nil
}

func (m *memoryStore) Policy(ctx context.Context, scope api.Scope) (api.EffectivePolicy, error) {
	if m.readError != nil {
		return api.EffectivePolicy{}, m.readError
	}
	if scope.Config != "case-codex" {
		return api.EffectivePolicy{}, problem(api.CodeForbidden, "test policy scope differs")
	}
	return fixtureCopy(m.policy), nil
}

func (m *memoryStore) CurrentApprovedPolicy(ctx context.Context, scope api.Scope) (api.EffectivePolicy, error) {
	if m.readError != nil {
		return api.EffectivePolicy{}, m.readError
	}
	if m.approvedPolicy != nil {
		return fixtureCopy(*m.approvedPolicy), nil
	}
	return m.Policy(ctx, scope)
}

func (m *memoryStore) Turn(ctx context.Context, scope api.Scope, target api.LifeRef, turn api.ID) (api.TurnSnapshot, error) {
	if m.readError != nil {
		return api.TurnSnapshot{}, m.readError
	}
	value, ok := m.turns[target]
	if scope.Config != "case-codex" || !ok || value.LogicalTurnID != turn {
		return api.TurnSnapshot{}, problem(api.CodeNotFound, "test turn absent")
	}
	return fixtureCopy(value), nil
}

func (m *memoryStore) retainedObject(ref api.BlobRef, destination any) error {
	data, ok := m.blobs[ref.ID]
	if !ok || m.refs[ref.ID] != ref || hashBytes(data) != ref.SHA256 || int64(len(data)) != ref.Bytes {
		return problem(api.CodeIntegrity, "test retained object differs")
	}
	return decode(data, destination)
}

func (m *memoryStore) ResolveLaunchSources(ctx context.Context, request api.LaunchSourceRequest) (api.LaunchSources, error) {
	if m.readError != nil {
		return api.LaunchSources{}, m.readError
	}
	record, ok := m.plans[request.ReservationID]
	if !ok || record.Inputs == nil || record.Reservation.GrantSetID != request.GrantSetID {
		return api.LaunchSources{}, problem(api.CodeForbidden, "test source reservation differs")
	}
	var enrollment api.LaunchEnrollment
	if err := m.retainedObject(m.enrollment, &enrollment); err != nil {
		return api.LaunchSources{}, err
	}
	if err := api.ValidateLaunchEnrollment(enrollment, record.Reservation.Config, m.runtimeManifest); err != nil {
		return api.LaunchSources{}, err
	}
	var source api.LaunchSources
	source.ReservationID = record.Reservation.ID
	for _, project := range enrollment.Projects {
		if project.ProjectID != record.Inputs.Sources.Project.ProjectID {
			continue
		}
		for _, grant := range m.grants.Data {
			if grant.SourceObjectID == project.Object.ID && grant.SourceSHA256 == project.Object.SHA256 && grant.Destination == "/work/main" {
				source.Project = api.ProjectLaunchSource{EnrollmentID: project.ID, Generation: project.Generation, ProjectID: project.ProjectID,
					GrantID: grant.ID, Object: project.Object, Base: project.Base, HistoryScope: project.HistoryScope}
			}
		}
	}
	for _, runtime := range enrollment.Runtimes {
		if runtime.Driver == api.DriverCodex {
			source.Runtime = runtime
		}
	}
	if source.Project.ProjectID == "" || source.Runtime.Executable.ID == "" {
		return api.LaunchSources{}, problem(api.CodeNotFound, "test enrolled source absent")
	}
	return source, nil
}

func (m *memoryStore) ResolveLaunchStorage(ctx context.Context, request api.LaunchDataRequest) (api.LaunchStorage, error) {
	if m.readError != nil {
		return api.LaunchStorage{}, m.readError
	}
	ref, ok := m.journal[request.ReservationID]
	if !ok {
		return api.LaunchStorage{}, problem(api.CodeNotFound, "test allocation journal absent")
	}
	var storage api.LaunchStorage
	if err := m.retainedObject(ref, &storage); err != nil {
		return storage, err
	}
	record, ok := m.plans[request.ReservationID]
	if !ok || request.GrantSetID != record.Reservation.GrantSetID || request.LeaseID != storage.LeaseID {
		return api.LaunchStorage{}, problem(api.CodeForbidden, "test storage allocation differs")
	}
	if err := sameRoot(m.home.path, m.home.root); err != nil {
		return api.LaunchStorage{}, err
	}
	return storage, nil
}

func (f *runnerFixture) keepJSON(value any, class string) api.BlobRef {
	f.t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		f.t.Fatal(err)
	}
	canonical, err := api.CanonicalJSON(data)
	if err != nil {
		f.t.Fatal(err)
	}
	return f.store.keepClass(canonical, class)
}

func (f *runnerFixture) prepareLaunch(mode string, level int) {
	f.t.Helper()
	m := f.store
	if m.plans == nil {
		m.plans = map[api.ID]api.LaunchPlanRecord{}
		m.effects = map[api.ID]api.EffectRecord{}
		m.bindings = map[api.ID]api.LaunchBindingRequest{}
		m.captures = map[api.ID]api.CaptureState{}
		m.journal = map[api.ID]api.BlobRef{}
		m.dataStages, m.dataResults = map[api.ID]api.BlobRef{}, map[api.ID]api.BlobRef{}
		m.receipts = map[api.RequestKey]api.MutationReceipt{}
		m.turns = map[api.LifeRef]api.TurnSnapshot{}
		m.home = f.home
	}
	f.plannedRequest = f.request
	suffix := strconv.FormatUint(uint64(f.request.Target.Run), 10)
	r := api.LaunchReservation{ID: api.ID("reservation_" + suffix), Config: "case-codex", Mode: mode,
		Level: level, Role: "executor", Driver: api.DriverCodex, Authority: api.LaunchAuthority{Kind: "ticket", ID: "ticket_one"}, Target: f.request.Target,
		LaunchID: api.ID("launch_" + suffix), SpecID: api.ID("spec_" + suffix), GrantSetID: m.grants.ID, Generation: 1,
		CancellationEpoch: 1, PolicyGeneration: 1, RootLifeID: f.request.Target.LifeID, StarterChain: []api.ID{},
		OperationID: api.ID("operation_" + suffix), RequestID: api.ID("request_" + suffix), RequestedBy: api.Actor{Kind: "human", ID: "human_one"}}
	if f.request.Target.Run > 1 {
		r.BaseGeneration = m.lane.Generation
		r.Generation = r.BaseGeneration + 1
		r.PreviousLaunchID = m.lane.LaunchID
		r.Level, r.Role, r.Driver = m.lane.Level, m.lane.Role, m.lane.Session.Driver
		r.Authority = api.LaunchAuthority{Kind: "proof", ID: api.ID("proof_" + suffix)}
	}
	m.cause = api.InternalIntent{ID: api.ID("intent_" + suffix), Kind: api.InternalLaunchPlan, Config: r.Config,
		Actor: f.service.deps.ReadScope.Actor, RequestedBy: r.RequestedBy, CauseOperationID: r.OperationID, CauseRequestID: r.RequestID,
		EffectID: api.ID("plan_effect_" + suffix), Target: r.Target, LogicalTurnID: f.request.LogicalTurnID, CancellationEpoch: r.CancellationEpoch}
	if m.runtimeManifest.ID == "" {
		m.runtimeManifest = m.keepClass([]byte("synthetic installed runtime manifest bytes"), "manifest")
		project := m.keepClass([]byte("synthetic immutable project source bytes"), "manifest")
		enrollment := api.LaunchEnrollment{Schema: "laneboss.launch-enrollment.v2", Config: r.Config, Generation: 1,
			Projects: []api.ProjectEnrollment{{ID: "project_enrollment", Generation: 1, ProjectID: "project_one", Object: project, Base: strings.Repeat("a", 40), HistoryScope: "tree"}},
			Runtimes: []api.LaunchRuntime{{EnrollmentID: "runtime_enrollment", Generation: 1, Backend: "linux-bwrap-landlock", Driver: api.DriverCodex,
				Executable: f.request.Executable, Manifest: m.runtimeManifest}}}
		m.enrollment = f.keepJSON(enrollment, "manifest")
		m.grants.Generation = 1
		m.grants.SHA256 = hashBytes([]byte("synthetic grant source"))
		m.grants.Resources = []api.ResourceGrant{}
		m.grants.Secrets = []api.SecretGrant{}
		m.grants.Network = []api.NetworkGrant{}
		m.grants.Channels = []api.ChannelGrant{}
		m.grants.Data = []api.DataGrant{{ID: "data_one", SourceObjectID: project.ID, SourceSHA256: project.SHA256, RelativePath: ".", Access: "rw",
			Delivery: "copy", Destination: "/work/main", HistoryScope: "tree", ExpiresAt: m.grants.ExpiresAt}}
	}
	var enrollment api.LaunchEnrollment
	if err := m.retainedObject(m.enrollment, &enrollment); err != nil {
		f.t.Fatal(err)
	}
	project := enrollment.Projects[0]
	sources := api.LaunchSources{ReservationID: r.ID, Project: api.ProjectLaunchSource{EnrollmentID: project.ID, Generation: project.Generation,
		ProjectID: project.ProjectID, GrantID: m.grants.Data[0].ID, Object: project.Object, Base: project.Base, HistoryScope: project.HistoryScope}, Runtime: enrollment.Runtimes[0]}
	var params any
	switch mode {
	case "start":
		profiles := make([]api.ProfileDelegation, 0, len(m.grants.Profiles))
		for _, member := range m.grants.Profiles {
			profiles = append(profiles, api.ProfileDelegation{ParentGrantID: member.ID, ProfileID: member.ProfileID,
				ExpiresAt: member.ExpiresAt, Delegate: member.Delegate})
		}
		params = api.StartRequest{Lane: "fixture", ProjectID: project.ProjectID, Level: r.Level, Role: r.Role, Task: f.request.Prompt,
			Driver: r.Driver, ProfileGrantID: f.request.Slot.ProfileGrantID, Model: f.request.Model, Effort: f.request.Effort, Budget: f.request.Budget,
			RootTicketID: r.Authority.ID, ExpectedPolicyGeneration: 1, Grants: api.GrantRequest{Resources: []api.ResourceDelegation{}, Data: []api.DataGrantRequest{},
				Secrets: []api.SecretDelegation{}, Profiles: profiles, Network: []api.NetworkDelegation{}, Channels: []api.ChannelDelegation{}}}
	case "resume":
		params = api.ResumeRequest{Target: api.LifeRef{LifeID: r.Target.LifeID, Run: r.Target.Run - 1}, ExpectedGeneration: r.BaseGeneration, Message: f.request.Prompt, Budget: f.request.Budget}
	case "turn":
		params = api.TurnRequest{Target: api.LifeRef{LifeID: r.Target.LifeID, Run: r.Target.Run - 1}, ExpectedGeneration: r.BaseGeneration, MailIDs: []api.ID{}, IdleMessage: &f.request.Prompt, Budget: f.request.Budget}
	default:
		f.t.Fatal("unsupported unit fixture launch mode")
	}
	encoded, err := json.Marshal(params)
	if err != nil {
		f.t.Fatal(err)
	}
	original := api.Request{Protocol: api.Protocol, Schema: api.SchemaVersion, Config: r.Config, RequestID: r.RequestID, IdempotencyKey: api.ID("key_" + suffix), Method: api.Method("lane." + mode), Params: encoded}
	original.RequestSHA256, err = api.RequestDigest(original)
	if err != nil {
		f.t.Fatal(err)
	}
	r.RequestSHA256 = original.RequestSHA256
	// These synthetic references establish contract shape, not real ticket or
	// proof consumption. Keep the authenticated frame and guard correlation valid.
	reservationRequest := api.LaunchReservationRequest{OperationID: r.OperationID}
	if mode == "start" {
		reservationRequest.Guards = []api.TransactionGuard{{Ticket: &api.TicketUse{TicketID: r.Authority.ID,
			PrincipalID: r.RequestedBy.ID, Config: r.Config, EndpointGeneration: 1, Level: r.Level, Role: r.Role, GrantSetID: r.GrantSetID}}}
	} else {
		original.Proof = &api.ProofRef{ID: r.Authority.ID, RequestSHA256: r.RequestSHA256, ExpiresAt: f.request.Slot.ExpiresAt}
		reservationRequest.Guards = []api.TransactionGuard{{Cancellation: &api.CancellationCheck{LifeID: r.Target.LifeID, Epoch: r.CancellationEpoch}},
			{Proof: &api.ProofUse{Proof: *original.Proof, Target: api.HumanChallengeRequest{Method: original.Method, TargetID: r.Target.LifeID,
				RequestSHA256: r.RequestSHA256, BaseGeneration: r.BaseGeneration}}}}
	}
	if err := api.ValidateLaunchReservationRequest(api.Scope{Config: r.Config, Actor: r.RequestedBy, Request: original,
		PolicyGeneration: r.PolicyGeneration, EndpointGeneration: 1}, reservationRequest); err != nil {
		f.t.Fatal("invalid fixture reservation authority", err)
	}
	r.OriginalRequest = f.keepJSON(original, "launch_request")
	key := api.RequestKey{Method: original.Method, IdempotencyKey: original.IdempotencyKey, RequestSHA256: original.RequestSHA256}
	m.receipts[key] = api.MutationReceipt{Config: r.Config, Key: key, Actor: r.RequestedBy, RawRequest: append([]byte{}, m.blobs[r.OriginalRequest.ID]...), Operation: api.Operation{ID: r.OperationID, Status: "pending"}}
	inputs := api.LaunchInputs{Grants: fixtureCopy(m.grants), Sources: sources}
	preparedPlan := api.LaunchPlanRecord{Reservation: r, Generation: 2, Phase: "sourced", Inputs: &inputs}
	if err := api.ValidateLaunchPlanRecord(preparedPlan); err != nil {
		f.t.Fatal("invalid fixture reservation", err)
	}
	m.plans[r.ID] = preparedPlan
	claim := api.EffectRecord{Effect: api.Effect{ID: m.cause.EffectID, OperationID: r.OperationID, Context: &m.cause, PlanLaunch: &api.LaunchPlanEffect{ReservationID: r.ID}},
		Generation: 1, State: api.EffectClaimed, ClaimID: api.ID("claim_" + suffix), ClaimantID: m.cause.Actor.ID, ClaimExpiresAt: f.request.Slot.ExpiresAt}
	m.effects[claim.Effect.ID] = fixtureCopy(claim)
	f.service.deps.Planning = api.LaunchPlanRequest{Lease: api.EffectLease{Record: fixtureCopy(claim), ClaimID: claim.ClaimID, ExpiresAt: claim.ClaimExpiresAt}}
	f.service.deps.Sources, f.service.deps.Storage = m, m
	allocate := m.cause
	allocate.ID = api.ID("allocate_intent_" + suffix)
	allocate.Kind = api.InternalHelperAllocate
	allocate.EffectID = api.ID("allocate_effect_" + suffix)
	helper := api.HelperLease{ID: api.ID("helper_" + suffix), UID: 12001, GID: 12001, ContainmentID: api.ID("containment_" + suffix), EndpointGeneration: 1}
	m.effects[allocate.EffectID] = api.EffectRecord{Effect: api.Effect{ID: allocate.EffectID, OperationID: r.OperationID, Context: &allocate,
		HelperAllocate: &api.HelperLeaseRequest{ReservationID: r.ID, Cause: allocate, Config: r.Config, LifeID: r.Target.LifeID, Backend: sources.Runtime.Backend, Budget: f.request.Budget, RuntimeManifestID: m.runtimeManifest.ID}},
		Generation: 1, State: api.EffectCompleted, Outcome: &api.EffectOutcome{EffectID: allocate.EffectID, Status: "succeeded", HelperLease: &helper}}
	f.service.deps.AllocationEffectID = allocate.EffectID
	storage := api.LaunchStorage{ReservationID: r.ID, Target: r.Target, LeaseID: helper.ID, WorkspaceID: f.request.Home.WorkspaceID,
		Home: api.PrivateHomeBinding{LifeID: r.Target.LifeID, RootID: api.ID("root_" + f.home.key), Generation: 1, Home: f.request.Home}}
	m.journal[r.ID] = f.keepJSON(storage, "record")
	f.prepareDataStage(r, inputs, helper, storage)
	m.turns[r.Target] = api.TurnSnapshot{Target: r.Target, LogicalTurnID: f.request.LogicalTurnID, Task: f.request.Prompt, Prompt: &f.request.Prompt, PolicyGeneration: 1, Generation: 1}
	m.policy.Generation = 1
	f.home.record.Session = f.request.Session
	f.home.record.Model = f.request.Model
	if err := f.home.save(); err != nil {
		f.t.Fatal(err)
	}
}

func (f *runnerFixture) sealCapture() api.CaptureBinding {
	f.t.Helper()
	m := f.store
	r := m.plans[f.service.deps.Planning.Lease.Record.Effect.PlanLaunch.ReservationID].Reservation
	if state, ok := m.captures[api.ID("capture_binding_"+strconv.FormatUint(uint64(r.Target.Run), 10))]; ok {
		return state.Binding
	}
	record := m.plans[r.ID]
	mode := r.Mode
	runner, err := f.service.plan(context.Background(), f.plannedRequest, mode)
	if err != nil {
		f.t.Fatal("capture setup could not build the real adapter plan", err)
	}
	allocation := m.effects[f.service.deps.AllocationEffectID]
	helper := *allocation.Outcome.HelperLease
	storage, err := m.ResolveLaunchStorage(context.Background(), api.LaunchDataRequest{ReservationID: r.ID, GrantSetID: r.GrantSetID, LeaseID: helper.ID})
	if err != nil {
		f.t.Fatal(err)
	}
	completed, err := m.AwaitMaterialization(context.Background(), record.DataStageID)
	if err != nil {
		f.t.Fatal(err)
	}
	workspace, materialization := completed.Data.Workspace, completed.Data.Materialization
	suffix := strconv.FormatUint(uint64(r.Target.Run), 10)
	supervisor := f.request.Executable
	supervisor.ID = "capture_supervisor"
	binding := api.CaptureBinding{ID: api.ID("capture_binding_" + suffix), Config: r.Config, ReservationID: r.ID, Target: r.Target, LaunchID: r.LaunchID,
		HelperLeaseID: helper.ID, OperationID: r.OperationID, RequestID: r.RequestID, RequestedBy: r.RequestedBy, Generation: 1, Status: "registered",
		WorkerLeaseID: api.ID("capture_lease_" + suffix), EffectID: api.ID("capture_effect_" + suffix), ProducerID: "producer_one", ProducerGeneration: "synthetic_kernel_generation", BootID: "synthetic_boot", Supervisor: &supervisor,
		Streams: []api.CaptureStreamBinding{{ID: api.ID("stdout_" + suffix), Stream: "stdout", PipeID: api.ID("pipe_out_" + suffix)}, {ID: api.ID("stderr_" + suffix), Stream: "stderr", PipeID: api.ID("pipe_err_" + suffix)}}}
	plan := api.LaunchPlan{Reservation: r, Inputs: *record.Inputs, Lease: helper, Data: api.LaunchData{ReservationID: r.ID, Target: r.Target, LeaseID: helper.ID,
		Source: record.Inputs.Sources.Project, Workspace: workspace, Home: storage.Home, Materialization: materialization}, Runner: runner,
		Injection: api.Injection{Target: r.Target, SlotIDs: []api.ID{runner.Slot.ID}, TaskSecretNames: []string{}, TaskSecretFileNames: []string{}, GrantIDs: []api.ID{}, SourceVersions: []string{}, Outcome: "prepared"}, Budget: f.plannedRequest.Budget, Capture: binding}
	spec := api.LaunchSpec{Kind: "agent", PlanID: r.ID, Capture: &binding, ID: r.SpecID, Target: r.Target, LaunchID: r.LaunchID, Backend: record.Inputs.Sources.Runtime.Backend,
		UIDLeaseID: helper.ID, Workspace: workspace, Materialization: materialization, Grants: plan.Inputs.Grants, Runner: &runner, Injection: plan.Injection, Budget: plan.Budget,
		EndpointGeneration: helper.EndpointGeneration, RuntimeManifest: record.Inputs.Sources.Runtime.Manifest, PolicyGeneration: r.PolicyGeneration}
	ref := f.keepJSON(spec, "launch_spec")
	cause := m.cause
	cause.Kind = api.InternalHelperRegister
	cause.ID = api.ID("register_" + suffix)
	cause.EffectID = api.ID("register_effect_" + suffix)
	handoff := api.PreparedSpecHandoff{Cause: cause, Config: r.Config, Spec: spec, Original: ref, SpecSHA256: ref.SHA256, OperationID: r.OperationID, RequestID: r.RequestID}
	launch := api.LaunchRecord{Kind: "agent", ID: r.LaunchID, Config: r.Config, Target: r.Target, ParentLifeID: r.ParentLifeID,
		RootLifeID: r.RootLifeID, StarterChain: r.StarterChain, StarterEventSeq: r.StarterEventSeq,
		Actor:      api.Actor{Kind: "lane", ID: "lane_principal", LifeID: r.Target.LifeID, Level: r.Level, Role: r.Role},
		UIDLeaseID: helper.ID, HostUID: helper.UID, ProcessGeneration: "synthetic_gate_generation", ContainmentID: helper.ContainmentID, GrantSetID: r.GrantSetID, GrantsSHA256: plan.Inputs.Grants.SHA256, PolicyGeneration: r.PolicyGeneration, EndpointGeneration: helper.EndpointGeneration}
	launchRef := f.keepJSON(launch, "record")
	start := len(m.events)
	m.event(r.Target, "capture.bound", binding)
	m.event(r.Target, "identity.bound", launch)
	identityEvent := m.events[len(m.events)-1]
	m.setupEvents = append(m.setupEvents, m.events[start:]...)
	m.events = m.events[:start]
	bound := api.LaunchBindingRequest{Record: launch, Prepared: api.PreparedLaunch{ID: api.ID("prepared_" + suffix), SpecSHA256: ref.SHA256, Target: r.Target, ContainmentID: helper.ContainmentID, ProcessGeneration: launch.ProcessGeneration, EndpointGeneration: helper.EndpointGeneration, GateID: api.ID("gate_" + suffix)},
		Identity: api.IdentityCommit{LaunchID: r.LaunchID, EventID: identityEvent.ID, CommittedSeq: identityEvent.Seq, RecordSHA256: launchRef.SHA256},
		Recovery: &api.LaunchRecovery{PlanID: r.ID, OriginalRequest: r.OriginalRequest, Handoff: handoff, Home: storage.Home, Capture: binding}}
	record.Phase, record.Plan, record.Handoff = "opened", &plan, &handoff
	if err := api.ValidateLaunchPlanRecord(record); err != nil {
		f.t.Fatal("invalid retained capture fixture", err)
	}
	if err := api.ValidateLaunchBindingPlan(bound, plan); err != nil {
		f.t.Fatal("invalid retained binding fixture", err)
	}
	m.plans[r.ID], m.bindings[r.LaunchID] = record, bound
	m.captures[binding.ID] = api.CaptureState{Binding: binding, Generation: 1, LastSeq: identityEvent.Seq,
		Positions: []api.CapturePosition{{StreamID: binding.Streams[0].ID}, {StreamID: binding.Streams[1].ID}}}
	if m.lane.Run != r.Target.Run {
		m.lane.Session = f.plannedRequest.Session
	}
	m.lane.LifeID, m.lane.Run, m.lane.Generation, m.lane.LaunchID = r.Target.LifeID, r.Target.Run, r.Generation, r.LaunchID
	m.lane.Workspace, m.lane.CancellationEpoch = workspace, r.CancellationEpoch
	m.lane.Level, m.lane.Role = r.Level, r.Role
	return binding
}

// This is a synthetic protected-policy fixture, not a consumed real D6 approval.
func (f *runnerFixture) fixtureRefusalPolicy() *api.CaptureRefusalPolicy {
	f.store.policy.AllowCaptureRefusal = true
	f.store.policy.CaptureRefusalApprovalID = "capture_approval"
	return &api.CaptureRefusalPolicy{Allowed: true, PolicyGeneration: f.store.policy.Generation,
		ApprovalID: f.store.policy.CaptureRefusalApprovalID}
}

// Retain every correlated byte after a test changes capture disposition. This
// uses the same plan/spec/recovery validators as a registered fixture and never
// turns a shape-valid synthetic policy into authenticated runtime evidence.
func (f *runnerFixture) retainCaptureDisposition(state api.CaptureState) {
	f.t.Helper()
	m, binding := f.store, state.Binding
	record := fixtureCopy(m.plans[binding.ReservationID])
	record.Plan.Capture = binding
	if binding.Status == "refused" {
		policy := fixtureCopy(m.policy)
		record.Plan.CapturePolicy = &policy
		state.Positions = []api.CapturePosition{}
	}
	handoff := fixtureCopy(*record.Handoff)
	handoff.Spec.Capture = &binding
	handoff.Original = f.keepJSON(handoff.Spec, "launch_spec")
	metadata := m.metadata[handoff.Original.ID]
	metadata.SourceOperationID, metadata.ACL.LifeID = record.Reservation.OperationID, record.Reservation.Target.LifeID
	m.metadata[handoff.Original.ID] = metadata
	handoff.SpecSHA256 = handoff.Original.SHA256
	record.Handoff = &handoff
	bound := fixtureCopy(m.bindings[binding.LaunchID])
	bound.Prepared.SpecSHA256 = handoff.SpecSHA256
	bound.Recovery.Handoff, bound.Recovery.Capture = handoff, binding
	if err := api.ValidateLaunchPlanRecord(record); err != nil {
		f.t.Fatal("invalid capture disposition plan fixture", err)
	}
	if err := api.ValidateLaunchBindingPlan(bound, *record.Plan); err != nil {
		f.t.Fatal("invalid capture disposition binding fixture", err)
	}
	for i := range m.setupEvents {
		event := &m.setupEvents[i]
		if event.LifeID == binding.Target.LifeID && event.Run == binding.Target.Run &&
			(event.Kind == "capture.bound" || event.Kind == "capture.refused") {
			var err error
			event.Payload, err = json.Marshal(binding)
			if err != nil {
				f.t.Fatal(err)
			}
			event.Kind = "capture.refused"
		}
	}
	m.plans[binding.ReservationID], m.bindings[binding.LaunchID], m.captures[binding.ID] = record, bound, fixtureCopy(state)
}

func (f *runnerFixture) closeCapture(record api.CaptureRecord) {
	f.t.Helper()
	state := f.store.captures[record.BindingID]
	state.Generation++
	state.Positions[0].EOF = true
	end := state.Positions[0].NextOffset
	receipt := api.CaptureAppendReceipt{BindingID: record.BindingID, StreamID: state.Positions[0].StreamID, Offset: end, NextOffset: end,
		Generation: state.Generation, LastSeq: f.store.sequence + 1, EOF: true}
	f.store.event(record.Target, "capture.closed", receipt)
	state.LastSeq = f.store.sequence
	f.store.captures[record.BindingID] = state
}
