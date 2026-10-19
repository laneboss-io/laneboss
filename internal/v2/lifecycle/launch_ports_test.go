package lifecycle

import (
	"context"
	"encoding/json"
	"reflect"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
)

type launchFixturePorts struct {
	api.GrantResolver
	api.CredentialBroker
	api.Runner
	api.TemplatesAPI
	api.GuidanceAPI
	f              *fixture
	store          *launchFixtureStore
	enrollment     api.LaunchEnrollment
	delegated      api.GrantSet
	allocations    map[api.ID]api.HelperLease
	storage        map[api.ID]api.LaunchStorage
	slots          map[api.LifeRef]api.CredentialSlot
	captures       map[api.ID]api.CaptureBinding
	prepared       map[api.ID]api.PreparedLaunch
	materialized   map[api.ID]api.LaunchData
	workspaceBytes map[api.ID][]byte
	calls          map[string]int
	failStage      string
	failure        *api.Error
	grantHook      func(*api.GrantSet)
	sourceHook     func(*api.LaunchSources)
	dataHook       func(*api.LaunchData)
	runnerHook     func(*api.RunnerPlan)
	captureHook    func(*api.CaptureBinding)
	reconcileHook  func(*api.CaptureBinding)
	guidanceItems  []api.GuidanceItem
	guidanceHook   func(*api.Guidance)
	onStage        func(string)
	refuseCapture  bool
}

type launchFixtureAdmin struct {
	api.Helper
	ports *launchFixturePorts
}

type launchFixtureWorker struct {
	api.DataWorker
	ports *launchFixturePorts
}

func (admin *launchFixtureAdmin) ResolveLaunchStorage(_ context.Context, selector api.LaunchDataRequest) (api.LaunchStorage, error) {
	p := admin.ports
	if err := p.stage("storage"); err != nil {
		return api.LaunchStorage{}, err
	}
	storage, ok := p.storage[selector.LeaseID]
	record, reserved := p.store.plans[selector.ReservationID]
	if !ok || !reserved || storage.ReservationID != selector.ReservationID ||
		record.Reservation.GrantSetID != selector.GrantSetID || storage.Target != record.Reservation.Target {
		return api.LaunchStorage{}, launchMissing()
	}
	return storage, nil
}

func (worker *launchFixtureWorker) MaterializeLaunch(ctx context.Context, request api.LaunchDataRequest) (api.LaunchData, error) {
	return worker.materializeStage(ctx, request)
}

func (p *launchFixturePorts) stage(name string) error {
	p.calls[name]++
	if p.onStage != nil {
		p.onStage(name)
	}
	if name == p.failStage {
		return p.failure
	}
	return nil
}

func (p *launchFixturePorts) original(r api.LaunchReservation) (api.StartRequest, error) {
	if r.Mode == "resume" || r.Mode == "turn" || r.Mode == "continue" {
		lane := p.store.lanes[r.Target.LifeID]
		input := api.StartRequest{ProjectID: lane.Workspace.ProjectID, Task: lane.Task, Level: lane.Level, Role: lane.Role,
			Driver: lane.Session.Driver, ProfileGrantID: lane.ProfileGrantID, Model: lane.Model, Effort: lane.Effort,
			Budget: lane.BudgetRemaining, ExpectedPolicyGeneration: p.store.policy.Generation}
		if r.Loop != nil {
			input.Task, input.Budget = *r.Loop.Setting.IdleMessage, r.Loop.BudgetRemaining
		}
		return input, nil // Normalized private selection; never a public frame.
	}
	var request api.Request
	if err := api.DecodeObject(p.store.blobs[r.OriginalRequest.ID], &request); err != nil {
		return api.StartRequest{}, err
	}
	if r.Mode == "adopt" {
		var value api.AdoptRequest
		if err := api.DecodeObject(request.Params, &value); err != nil {
			return api.StartRequest{}, err
		}
		var manifest api.AdoptionManifest
		if err := api.DecodeObject(p.store.blobs[value.ImportManifest.ID], &manifest); err != nil {
			return api.StartRequest{}, err
		}
		return api.StartRequest{ProjectID: manifest.Workspace.ProjectID, Task: value.Task,
			Level: value.Level, Role: value.Role, Driver: value.Driver, ProfileGrantID: value.ProfileGrantID,
			Model: value.Model, Effort: value.Effort, Budget: value.Budget, Grants: value.Grants,
			ExpectedPolicyGeneration: value.ExpectedPolicyGeneration}, nil
	}
	var input api.StartRequest
	if err := api.DecodeObject(request.Params, &input); err != nil {
		return input, err
	}
	return input, nil
}

func (p *launchFixturePorts) Resolve(_ context.Context, scope api.Scope, selector api.GrantResolveRequest) (api.GrantSet, error) {
	if err := p.stage("grants"); err != nil {
		return api.GrantSet{}, err
	}
	record, ok := p.store.plans[selector.ReservationID]
	if !ok || record.Reservation.Config != scope.Config {
		return api.GrantSet{}, launchMissing()
	}
	r := record.Reservation
	if retained, exists := p.store.grants[r.GrantSetID]; exists {
		result := launchClone(p.f.t, retained)
		if p.grantHook != nil {
			p.grantHook(&result)
		}
		return result, nil
	}
	if r.PreviousLaunchID != "" {
		previous, ok := p.store.bindings[r.PreviousLaunchID]
		if !ok {
			return api.GrantSet{}, launchMissing()
		}
		grants, ok := p.store.grants[previous.Record.GrantSetID]
		if !ok {
			return api.GrantSet{}, launchMissing()
		}
		grants = launchClone(p.f.t, grants)
		if grants.Revoked {
			return api.GrantSet{}, launchConflict()
		}
		grants.ID, grants.Generation, grants.PolicyGeneration, grants.SHA256 = r.GrantSetID, 1, r.PolicyGeneration, ""
		raw, err := json.Marshal(grants)
		if err != nil {
			return api.GrantSet{}, err
		}
		grants.SHA256 = digestOf(raw)
		if p.grantHook != nil {
			p.grantHook(&grants)
		}
		return grants, nil
	}
	request, err := p.original(r)
	if err != nil {
		return api.GrantSet{}, err
	}
	if len(request.Grants.Data) != 1 || len(request.Grants.Profiles) == 0 {
		return api.GrantSet{}, launchConflict()
	}
	data := request.Grants.Data[0]
	var dataParent *api.DataGrant
	for i := range p.delegated.Data {
		if p.delegated.Data[i].ID == data.ParentGrantID {
			dataParent = &p.delegated.Data[i]
		}
	}
	if dataParent == nil || !dataParent.Delegate || data.RelativePath != dataParent.RelativePath || data.Destination != dataParent.Destination ||
		data.Delivery != dataParent.Delivery || data.Access != dataParent.Access {
		return api.GrantSet{}, launchConflict()
	}
	profiles := []api.ProfileGrant{}
	selected := false
	for _, requested := range request.Grants.Profiles {
		matched := false
		for _, parent := range p.delegated.Profiles {
			if parent.ID != requested.ParentGrantID || parent.ProfileID != requested.ProfileID || parent.Driver != request.Driver || !parent.Delegate {
				continue
			}
			child := parent
			child.ParentGrantID, child.Delegate, child.ExpiresAt = parent.ID, requested.Delegate, requested.ExpiresAt
			profiles, matched = append(profiles, child), true
			selected = selected || child.ID == request.ProfileGrantID
		}
		if !matched {
			return api.GrantSet{}, launchConflict()
		}
	}
	if !selected {
		return api.GrantSet{}, launchConflict()
	}
	source := p.enrollment.Projects[0]
	grants := api.GrantSet{ID: r.GrantSetID, LifeID: r.Target.LifeID, ParentLifeID: r.ParentLifeID,
		Generation: 1, PolicyGeneration: r.PolicyGeneration, ExpiresAt: data.ExpiresAt,
		Resources: []api.ResourceGrant{}, Secrets: []api.SecretGrant{}, Network: []api.NetworkGrant{}, Channels: []api.ChannelGrant{},
		Data: []api.DataGrant{{ID: data.ParentGrantID, ParentGrantID: data.ParentGrantID, SourceObjectID: source.Object.ID,
			SourceSHA256: source.Object.SHA256, RelativePath: data.RelativePath, Destination: data.Destination, Delivery: data.Delivery,
			Access: data.Access, ExpiresAt: data.ExpiresAt, HistoryScope: source.HistoryScope}},
		Profiles: profiles}
	encoded, err := json.Marshal(grants)
	if err != nil {
		return api.GrantSet{}, err
	}
	grants.SHA256 = digestOf(encoded)
	if p.grantHook != nil {
		p.grantHook(&grants)
	}
	return grants, nil
}

func (p *launchFixturePorts) Revalidate(_ context.Context, grants api.GrantSet) (api.GrantSet, error) {
	if err := p.stage("revalidate"); err != nil {
		return api.GrantSet{}, err
	}
	if grants.Revoked || grants.PolicyGeneration > p.store.policy.Generation {
		return api.GrantSet{}, launchConflict()
	}
	return grants, nil
}

func (admin *launchFixtureAdmin) ResolveLaunchSources(_ context.Context, selector api.LaunchSourceRequest) (api.LaunchSources, error) {
	p := admin.ports
	if err := p.stage("sources"); err != nil {
		return api.LaunchSources{}, err
	}
	record, ok := p.store.plans[selector.ReservationID]
	if !ok || record.Reservation.GrantSetID != selector.GrantSetID {
		return api.LaunchSources{}, launchMissing()
	}
	request, err := p.original(record.Reservation)
	if err != nil {
		return api.LaunchSources{}, err
	}
	if err := api.ValidateLaunchEnrollment(p.enrollment, record.Reservation.Config, p.enrollment.Runtimes[0].Manifest); err != nil {
		return api.LaunchSources{}, err
	}
	project, runtime := p.enrollment.Projects[0], p.enrollment.Runtimes[0]
	if project.ProjectID != request.ProjectID || runtime.Driver != request.Driver {
		return api.LaunchSources{}, launchConflict()
	}
	grants, ok := p.store.grants[selector.GrantSetID]
	if !ok {
		return api.LaunchSources{}, launchMissing()
	}
	var granted *api.DataGrant
	for i := range grants.Data {
		candidate := &grants.Data[i]
		if candidate.SourceObjectID == project.Object.ID && candidate.SourceSHA256 == project.Object.SHA256 && candidate.Destination == "/work/main" {
			if granted != nil {
				return api.LaunchSources{}, launchConflict()
			}
			granted = candidate
		}
	}
	if granted == nil {
		return api.LaunchSources{}, launchConflict()
	}
	sources := api.LaunchSources{ReservationID: selector.ReservationID, Runtime: runtime,
		Project: api.ProjectLaunchSource{EnrollmentID: project.ID, Generation: project.Generation, ProjectID: project.ProjectID,
			GrantID: granted.ID, Object: project.Object, Base: project.Base, HistoryScope: project.HistoryScope}}
	if p.sourceHook != nil {
		p.sourceHook(&sources)
	}
	return sources, nil
}

func (admin *launchFixtureAdmin) Allocate(_ context.Context, request api.HelperLeaseRequest) (api.HelperLease, error) {
	p := admin.ports
	if err := p.stage("allocate"); err != nil {
		return api.HelperLease{}, err
	}
	record, ok := p.store.plans[request.ReservationID]
	if !ok || record.Phase != "sourced" || record.Inputs == nil || request.Config != record.Reservation.Config ||
		request.LifeID != record.Reservation.Target.LifeID || request.RuntimeManifestID != record.Inputs.Sources.Runtime.Manifest.ID ||
		request.Backend != record.Inputs.Sources.Runtime.Backend || request.Cause.Kind != api.InternalHelperAllocate {
		return api.HelperLease{}, launchConflict()
	}
	if lease, exists := p.allocations[record.Reservation.ID]; exists {
		return lease, nil
	}
	lease := api.HelperLease{ID: launchIDForTest(), UID: uint32(12000 + len(p.allocations)), GID: 12000,
		ContainmentID: launchIDForTest(), EndpointGeneration: api.Generation(len(p.allocations) + 1)}
	home := api.PrivateHomeBinding{LifeID: request.LifeID, RootID: launchIDForTest(), Generation: 1,
		Home: api.PrivateHome{ID: launchIDForTest(), WorkspaceID: launchIDForTest(), VendorDirectory: ".codex", HistoryID: launchIDForTest()}}
	if record.Reservation.Driver == api.DriverClaudock {
		home.Home.VendorDirectory = ".claude"
	}
	if record.Reservation.PreviousLaunchID != "" {
		binding, exists := p.store.bindings[record.Reservation.PreviousLaunchID]
		if !exists || binding.Recovery == nil {
			return api.HelperLease{}, launchMissing()
		}
		home = binding.Recovery.Home
	}
	p.allocations[record.Reservation.ID] = lease
	p.storage[lease.ID] = api.LaunchStorage{ReservationID: record.Reservation.ID, Target: record.Reservation.Target,
		LeaseID: lease.ID, WorkspaceID: home.Home.WorkspaceID, Home: home}
	return lease, nil
}

func (p *launchFixturePorts) MaterializeLaunch(_ context.Context, selector api.LaunchDataRequest) (api.LaunchData, error) {
	if err := p.stage("materialize"); err != nil {
		return api.LaunchData{}, err
	}
	record, ok := p.store.plans[selector.ReservationID]
	storage, allocated := p.storage[selector.LeaseID]
	if !ok || !allocated || record.Inputs == nil || selector.GrantSetID != record.Reservation.GrantSetID ||
		storage.ReservationID != selector.ReservationID || storage.Target != record.Reservation.Target {
		return api.LaunchData{}, launchConflict()
	}
	if prior, exists := p.materialized[selector.ReservationID]; exists {
		if prior.LeaseID != selector.LeaseID {
			return api.LaunchData{}, launchConflict()
		}
		return prior, nil
	}
	source := record.Inputs.Sources.Project
	metadata := p.store.metadata[source.Object.ID]
	content := p.store.blobs[source.Object.ID]
	if metadata.Ref != source.Object || digestOf(content) != source.Object.SHA256 {
		return api.LaunchData{}, launchConflict()
	}
	if p.workspaceBytes == nil {
		p.workspaceBytes = map[api.ID][]byte{}
	}
	if record.Reservation.PreviousLaunchID != "" {
		private, exists := p.workspaceBytes[storage.WorkspaceID]
		if !exists {
			return api.LaunchData{}, launchMissing()
		}
		content = append([]byte{}, private...)
	} else {
		p.workspaceBytes[storage.WorkspaceID] = append([]byte{}, content...)
	}
	if record.Reservation.Mode == "adopt" {
		var original api.Request
		if err := api.DecodeObject(p.store.blobs[record.Reservation.OriginalRequest.ID], &original); err != nil {
			return api.LaunchData{}, err
		}
		var request api.AdoptRequest
		if err := api.DecodeObject(original.Params, &request); err != nil {
			return api.LaunchData{}, err
		}
		var manifest api.AdoptionManifest
		if err := api.DecodeObject(p.store.blobs[request.ImportManifest.ID], &manifest); err != nil {
			return api.LaunchData{}, err
		}
		for _, ref := range []api.BlobRef{manifest.PrivateHistory, manifest.Quiescence} {
			if p.store.metadata[ref.ID].Ref != ref || digestOf(p.store.blobs[ref.ID]) != ref.SHA256 {
				return api.LaunchData{}, launchConflict()
			}
		}
	}
	// The fixture measures its source bytes into a distinct snapshot receipt.
	// The actual fixed worker must perform the confined Git/data job.
	snapshot := p.f.blob(launchIDForTest(), "manifest", append([]byte("snapshot\x00"), content...))
	materialization := p.f.blob(launchIDForTest(), "manifest", []byte(string(selector.LeaseID)+"\x00"+string(snapshot.SHA256)))
	data := api.LaunchData{ReservationID: selector.ReservationID, Target: record.Reservation.Target, LeaseID: selector.LeaseID,
		Source: source, Home: storage.Home, Workspace: api.Workspace{ID: storage.WorkspaceID, ProjectID: source.ProjectID,
			Base: source.Base, Branch: "lane/" + string(record.Reservation.Target.LifeID), LogicalCWD: "/work/main", Snapshot: snapshot},
		Materialization: api.Materialization{GrantSetID: selector.GrantSetID, Manifest: materialization,
			Objects: []api.MaterializedObject{{GrantID: source.GrantID, SourceIdentity: string(source.Object.ID),
				DestinationIdentity: string(storage.WorkspaceID), WorkspaceID: storage.WorkspaceID, SnapshotSHA256: snapshot.SHA256}}}}
	if p.materialized == nil {
		p.materialized = map[api.ID]api.LaunchData{}
	}
	p.materialized[selector.ReservationID] = data
	return data, nil
}

func (admin *launchFixtureAdmin) Prepare(_ context.Context, request api.HelperLaunchRequest) (api.PreparedLaunch, error) {
	p := admin.ports
	if err := p.stage("prepare"); err != nil {
		return api.PreparedLaunch{}, err
	}
	for _, record := range p.store.plans {
		if record.Handoff == nil || record.Handoff.Spec.ID != request.PreparedSpecID {
			continue
		}
		plan, handoff := record.Plan, record.Handoff
		if plan == nil || request.LeaseID != plan.Lease.ID || request.SpecSHA256 != handoff.SpecSHA256 ||
			api.ValidateAgentLaunchSpec(handoff.Spec, *plan) != nil || digestOf(p.store.blobs[handoff.Original.ID]) != request.SpecSHA256 {
			return api.PreparedLaunch{}, launchConflict()
		}
		if prior, ok := p.prepared[request.PreparedSpecID]; ok {
			return prior, nil
		}
		prepared := api.PreparedLaunch{ID: launchIDForTest(), SpecSHA256: request.SpecSHA256, Target: plan.Reservation.Target,
			ContainmentID: plan.Lease.ContainmentID, EndpointGeneration: plan.Lease.EndpointGeneration,
			GateID: launchIDForTest(), ProcessGeneration: string(launchIDForTest())}
		if p.prepared == nil {
			p.prepared = map[api.ID]api.PreparedLaunch{}
		}
		p.prepared[request.PreparedSpecID] = prepared
		return prepared, nil
	}
	return api.PreparedLaunch{}, launchMissing()
}

func (p *launchFixturePorts) BriefRender(_ context.Context, scope api.Scope, request api.TemplateRequest) (api.Briefing, error) {
	if err := p.stage("briefing"); err != nil {
		return api.Briefing{}, err
	}
	var matched bool
	for _, record := range p.store.plans {
		if record.Reservation.GrantSetID != request.GrantSetID {
			continue
		}
		input, err := p.original(record.Reservation)
		if err != nil {
			return api.Briefing{}, err
		}
		matched = request.Context == (api.RoleContext{Level: input.Level, Role: input.Role}) && request.Task == input.Task && scope.Actor.Kind == "service"
	}
	if !matched {
		return api.Briefing{}, launchConflict()
	}
	text := []byte("# Role " + request.Context.Role + "\nTask digest: " + string(request.Task.SHA256) + "\n")
	markdown := p.f.blob(launchIDForTest(), "artifact", text)
	return api.Briefing{Markdown: markdown, PolicyGeneration: p.store.policy.Generation,
		Template: api.TemplateRef{ID: launchIDForTest(), Generation: 1, SourceSHA256: digestOf(text), RenderedSHA256: markdown.SHA256},
		Sources:  []api.SourceRef{}, Checks: []api.Capability{},
		LaneGroups: api.LaneGroups{Running: []api.ID{}, Ended: []api.ID{}, Accepted: []api.ID{}, Lost: []api.ID{}, Idle: []api.ID{}, Others: []api.ID{}}}, nil
}

func (p *launchFixturePorts) GuidanceSelect(_ context.Context, scope api.Scope, request api.GuidanceRequest) (api.Guidance, error) {
	if err := p.stage("guidance"); err != nil {
		return api.Guidance{}, err
	}
	matched := false
	for _, record := range p.store.effects {
		if record.Effect.PlanLaunch != nil && record.State == api.EffectClaimed && record.ClaimantID == scope.Actor.ID &&
			record.Effect.Context.Target == request.Target && record.Effect.Context.LogicalTurnID == request.LogicalTurnID {
			input, err := p.original(p.store.plans[record.Effect.PlanLaunch.ReservationID].Reservation)
			if err != nil {
				return api.Guidance{}, err
			}
			matched = input.Task == request.Task
		}
	}
	if !matched {
		return api.Guidance{}, launchConflict()
	}
	result := api.Guidance{ID: launchIDForTest(), Target: request.Target, LogicalTurnID: request.LogicalTurnID, Task: request.Task,
		PolicyGeneration: p.store.policy.Generation, Status: "empty", CandidateSnapshotID: launchIDForTest(),
		ReservationID: launchIDForTest(), Items: append([]api.GuidanceItem{}, p.guidanceItems...), JudgmentIDs: []api.ID{}}
	if len(result.Items) > 0 {
		result.Status = "scored"
	}
	if p.guidanceHook != nil {
		p.guidanceHook(&result)
	}
	return result, nil
}

func (p *launchFixturePorts) Acquire(_ context.Context, target api.LifeRef, grant api.ProfileGrant) (api.CredentialSlot, error) {
	if err := p.stage("acquire"); err != nil {
		return api.CredentialSlot{}, err
	}
	matched := false
	for _, record := range p.store.plans {
		if record.Reservation.Target != target {
			continue
		}
		issued, exists := p.store.grants[record.Reservation.GrantSetID]
		for _, candidate := range issued.Profiles {
			matched = matched || candidate == grant
		}
		if !exists {
			matched = matched || p.retainedSlotGrant(record.Reservation, grant)
		}
	}
	if !matched {
		return api.CredentialSlot{}, launchConflict()
	}
	if _, exists := p.slots[target]; exists {
		return api.CredentialSlot{}, launchConflict()
	}
	slot := api.CredentialSlot{ID: launchIDForTest(), LeaseID: launchIDForTest(), ProfileGrantID: grant.ID,
		ProfileID: grant.ProfileID, Mode: "codex-file", ExpiresAt: grant.ExpiresAt}
	if grant.Driver == api.DriverClaudock {
		slot.Mode = "claudock-headless"
	}
	p.slots[target] = slot
	return slot, nil
}

// A watchdog can retain its selected slot before the planner issues the new
// grant snapshot. That authority comes from the original claimed intent and
// current retained life, never the absent fresh grant-set ID.
func (p *launchFixturePorts) retainedSlotGrant(r api.LaunchReservation, grant api.ProfileGrant) bool {
	lane, exists := p.store.lanes[r.Target.LifeID]
	epoch, fenced := p.store.fences[r.Target.LifeID]
	if r.Mode != "continue" || !exists || !fenced || lane.Run+1 != r.Target.Run || lane.LaunchID != r.PreviousLaunchID ||
		lane.Generation != r.BaseGeneration || lane.CancellationEpoch != r.CancellationEpoch || epoch != r.CancellationEpoch || r.PolicyGeneration != p.store.policy.Generation {
		return false
	}
	for _, intent := range p.store.continuations {
		if intent.Status != "claimed" || intent.OperationID != r.OperationID || intent.Target != (api.LifeRef{LifeID: lane.LifeID, Run: lane.Run}) ||
			intent.ExpectedGeneration != lane.Generation || intent.CancellationEpoch != epoch || intent.Swap.ContinuationRun != r.Target.Run ||
			intent.Swap.ProfileGrantID != grant.ID || intent.Swap.ToProfileID != grant.ProfileID || intent.Eligibility.Request.ToGrantID != grant.ID ||
			intent.Eligibility.Request.GrantSetID != lane.GrantSetID {
			continue
		}
		grants, ok := p.store.grants[lane.GrantSetID]
		if !ok || grants.Revoked {
			return false
		}
		for _, candidate := range grants.Profiles {
			if candidate == grant {
				return true
			}
		}
	}
	return false
}

func (p *launchFixturePorts) Inject(_ context.Context, target api.LifeRef, grants []api.SecretGrant) (api.Injection, error) {
	if err := p.stage("inject"); err != nil {
		return api.Injection{}, err
	}
	slot, ok := p.slots[target]
	if !ok {
		return api.Injection{}, launchMissing()
	}
	for _, record := range p.store.plans {
		if record.Reservation.Target == target && reflect.DeepEqual(record.Inputs.Grants.Secrets, grants) {
			return api.Injection{Target: target, SlotIDs: []api.ID{slot.ID}, Outcome: "prepared",
				TaskSecretNames: []string{}, TaskSecretFileNames: []string{}, GrantIDs: []api.ID{}, SourceVersions: []string{}}, nil
		}
	}
	return api.Injection{}, launchConflict()
}

func (p *launchFixturePorts) runner(request api.RunnerRequest, mode string) (api.RunnerPlan, error) {
	if err := p.stage("runner-" + mode); err != nil {
		return api.RunnerPlan{}, err
	}
	var enrolled bool
	for _, runtime := range p.enrollment.Runtimes {
		enrolled = enrolled || runtime.Executable == request.Executable && runtime.Driver == request.Session.Driver
	}
	slot, acquired := p.slots[request.Target]
	if !enrolled || !acquired || slot != request.Slot || request.Home.ID != request.Session.HomeID ||
		request.Home.HistoryID != request.Session.HistoryID || request.Prompt != p.store.metadata[request.Prompt.ID].Ref {
		return api.RunnerPlan{}, launchConflict()
	}
	session := request.Session
	if session.VendorVersion == "" {
		session.VendorVersion = "vendor-pin-2"
	}
	plan := api.RunnerPlan{Driver: session.Driver, Executable: request.Executable,
		Argv: []string{string(request.Executable.ID), mode, "--model", request.Model, "--effort", request.Effort, "--prompt", string(request.Prompt.ID)},
		CWD:  request.Session.LogicalCWD, Prompt: request.Prompt, Home: request.Home, Slot: slot, Session: session,
		AdapterVersion: request.Executable.Version, EnvironmentNames: []string{}, InnerSandbox: "outer-boundary"}
	if p.runnerHook != nil {
		p.runnerHook(&plan)
	}
	return plan, nil
}
func (p *launchFixturePorts) Start(_ context.Context, request api.RunnerRequest) (api.RunnerPlan, error) {
	return p.runner(request, "start")
}
func (p *launchFixturePorts) Resume(_ context.Context, request api.RunnerRequest) (api.RunnerPlan, error) {
	return p.runner(request, "resume")
}
func (p *launchFixturePorts) Turn(_ context.Context, request api.RunnerRequest) (api.RunnerPlan, error) {
	return p.runner(request, "turn")
}

func (admin *launchFixtureAdmin) RegisterCapture(_ context.Context, request api.CaptureRegistrationRequest) (api.CaptureBinding, error) {
	p := admin.ports
	if err := p.stage("capture"); err != nil {
		return api.CaptureBinding{}, err
	}
	record, ok := p.store.plans[request.ReservationID]
	worker, leased := p.store.workers[request.WorkerLeaseID]
	allocation, allocated := p.allocations[request.ReservationID]
	if err := api.CheckPlanningClaim(p.store.effects[request.Claim.EffectID], request.Claim, record.Reservation.Config, (fixtureClock{}).Now()); err != nil {
		return api.CaptureBinding{}, err
	}
	if !ok || !leased || !allocated || allocation.ID != request.HelperLeaseID || worker.Kind != "capture_supervisor" ||
		worker.Target != record.Reservation.Target || worker.EffectID != request.Cause.EffectID ||
		worker.OperationID != record.Reservation.OperationID || request.Cause.Kind != api.InternalLaunchPlan {
		return api.CaptureBinding{}, launchConflict()
	}
	r := record.Reservation
	binding := api.CaptureBinding{ID: launchIDForTest(), Config: r.Config, ReservationID: r.ID, Target: r.Target,
		LaunchID: r.LaunchID, HelperLeaseID: allocation.ID, OperationID: r.OperationID, RequestID: r.RequestID,
		RequestedBy: r.RequestedBy, Generation: 1, Status: "registered", WorkerLeaseID: worker.ID, EffectID: worker.EffectID,
		ProducerID: launchIDForTest(), ProducerGeneration: string(launchIDForTest()), BootID: string(launchIDForTest()),
		Supervisor: p.enrollment.Supervisor, Streams: []api.CaptureStreamBinding{
			{ID: launchIDForTest(), Stream: "stdout", PipeID: launchIDForTest()}, {ID: launchIDForTest(), Stream: "stderr", PipeID: launchIDForTest()}}}
	if p.refuseCapture {
		binding.Status, binding.Streams, binding.Supervisor = "refused", []api.CaptureStreamBinding{}, nil
		binding.WorkerLeaseID, binding.EffectID, binding.ProducerID, binding.ProducerGeneration, binding.BootID = "", "", "", "", ""
		binding.Refusal = api.NotImplemented("lb-v2-admin", "explicit capture discard disposition")
		binding.Refusal.OperationID = r.OperationID
		binding.RefusalPolicy = &api.CaptureRefusalPolicy{Allowed: true, PolicyGeneration: p.store.policy.Generation,
			ApprovalID: p.store.policy.CaptureRefusalApprovalID}
	}
	if p.captureHook != nil {
		p.captureHook(&binding)
	}
	p.captures[binding.ID] = binding
	return binding, nil
}

func (admin *launchFixtureAdmin) ReconcileCapture(_ context.Context, binding api.CaptureBinding) (api.CaptureBinding, error) {
	p := admin.ports
	if err := p.stage("reconcile-capture"); err != nil {
		return api.CaptureBinding{}, err
	}
	retained, ok := p.captures[binding.ID]
	if !ok || !reflect.DeepEqual(binding, retained) {
		return api.CaptureBinding{}, launchConflict()
	}
	retained = launchClone(p.f.t, retained)
	if p.reconcileHook != nil {
		p.reconcileHook(&retained)
	}
	return retained, nil
}

var _ api.Helper = (*launchFixtureAdmin)(nil)
var _ api.CaptureControl = (*launchFixtureAdmin)(nil)
var _ api.LaunchSourceResolver = (*launchFixtureAdmin)(nil)
var _ api.DataWorker = (*launchFixtureWorker)(nil)
var _ api.GrantResolver = (*launchFixturePorts)(nil)
var _ api.CredentialBroker = (*launchFixturePorts)(nil)
var _ api.Runner = (*launchFixturePorts)(nil)

// Keep this file's fixture APIs checked when the Linux focused test runs.
func TestLaunchFixtureBoundaries(t *testing.T) {
	f := newLaunchFixture(t)
	_, err := f.ports.MaterializeLaunch(context.Background(), api.LaunchDataRequest{ReservationID: "caller", LeaseID: "caller"})
	if err == nil {
		t.Fatal("dependency fixture accepted a pre-resolved foreign selector")
	}
}
