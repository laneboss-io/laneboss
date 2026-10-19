package watchdog

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

type fixedClock struct{ at time.Time }

func (c *fixedClock) Now() time.Time { return c.at }

// These doubles provide read paths and a typed failing store mutation. The
// assessment tests require zero side effects; they do not simulate an E2E.
type readStore struct {
	api.StateStore
	t               *testing.T
	lane            api.Lane
	history         *api.Lane
	launch          api.LaunchRecord
	binding         api.LaunchBindingRequest
	plan            api.LaunchPlanRecord
	captureState    api.CaptureState
	launchError     error
	grants          api.GrantSet
	turn            api.TurnSnapshot
	policy          api.EffectivePolicy
	policyErr       error
	policyHistory   map[api.Generation]api.EffectivePolicy
	policyRefreshes []api.PolicyAdvanceRequest
	policyReply     func(api.PolicyAdvanceReceipt) api.PolicyAdvanceReceipt
	metadata        map[api.ID]api.ObjectMetadata
	usage           map[api.ID]UsageProvenance
	events          []api.Event
	blobs           map[api.ID][]byte
	classes         map[api.ID]string
	laneReads       int
	changeLane      bool
	writeCalls      int
	readError       error
	badPage         bool
	badChunk        bool
	onLane          func(int)
}

func (m *readStore) check(scope api.Scope) {
	m.t.Helper()
	if scope.Config != m.launch.Config || scope.Source != "watchdog" || scope.Actor.Kind != "watchdog" || scope.Actor.LifeID != "" {
		m.t.Fatal("watchdog borrowed an unauthenticated or lane actor")
	}
}

func (m *readStore) Lane(_ context.Context, scope api.Scope, target api.LifeRef) (api.Lane, error) {
	m.check(scope)
	if m.readError != nil {
		return api.Lane{}, m.readError
	}
	if target.LifeID != m.lane.LifeID {
		return api.Lane{}, problem(api.CodeNotFound, "test life is absent")
	}
	m.laneReads++
	if m.onLane != nil {
		m.onLane(m.laneReads)
	}
	result := m.lane
	if target.Run != 0 && m.history != nil && target.Run == m.history.Run {
		result = *m.history
	}
	if m.changeLane && m.laneReads > 1 {
		result.Generation++
	}
	return result, nil
}

func (m *readStore) Events(_ context.Context, scope api.Scope, request api.EventTailRequest) (api.EventPage, error) {
	m.check(scope)
	if request.LifeID != m.lane.LifeID || request.Follow || request.Run != 0 {
		m.t.Fatal("watchdog requested an unscoped or following event scan")
	}
	if m.readError != nil {
		return api.EventPage{}, m.readError
	}
	if m.badPage {
		return api.EventPage{Events: []api.Event{}, Complete: false}, nil
	}
	return api.EventPage{Events: m.events, Complete: true}, nil
}

func (m *readStore) Launch(_ context.Context, id api.ID) (api.LaunchRecord, error) {
	if id != m.launch.ID {
		return api.LaunchRecord{}, problem(api.CodeNotFound, "test launch is absent")
	}
	return m.launch, nil
}

func (m *readStore) Grants(_ context.Context, id api.ID) (api.GrantSet, error) {
	if id != m.grants.ID {
		return api.GrantSet{}, problem(api.CodeNotFound, "test grants are absent")
	}
	return m.grants, nil
}

func (m *readStore) LaunchBinding(_ context.Context, id api.ID) (api.LaunchBindingRequest, error) {
	if m.launchError != nil {
		return api.LaunchBindingRequest{}, m.launchError
	}
	if id != m.launch.ID {
		return api.LaunchBindingRequest{}, problem(api.CodeNotFound, "test binding is absent")
	}
	return m.binding, nil
}

func (m *readStore) LaunchPlan(_ context.Context, scope api.Scope, id api.ID) (api.LaunchPlanRecord, error) {
	m.check(scope)
	if m.launchError != nil {
		return api.LaunchPlanRecord{}, m.launchError
	}
	if id != m.plan.Reservation.ID {
		return api.LaunchPlanRecord{}, problem(api.CodeNotFound, "test plan is absent")
	}
	return m.plan, nil
}

func (m *readStore) CaptureState(_ context.Context, scope api.Scope, id api.ID) (api.CaptureState, error) {
	m.check(scope)
	if m.launchError != nil {
		return api.CaptureState{}, m.launchError
	}
	if id != m.captureState.Binding.ID {
		return api.CaptureState{}, problem(api.CodeNotFound, "test capture state is absent")
	}
	return m.captureState, nil
}

func (m *readStore) Policy(_ context.Context, scope api.Scope) (api.EffectivePolicy, error) {
	m.check(scope)
	if scope.LaunchID != m.lane.LaunchID || scope.PolicyGeneration != m.lane.PolicyGeneration {
		m.t.Fatal("policy read lost its trusted target launch or policy generation")
	}
	return m.policy, m.policyErr
}

func (m *readStore) PolicyAt(_ context.Context, scope api.Scope, generation api.Generation) (api.EffectivePolicy, error) {
	m.check(scope)
	policy, found := m.policyHistory[generation]
	if !found {
		return api.EffectivePolicy{}, problem(api.CodeNotFound, "test policy history is absent")
	}
	return policy, nil
}

func (m *readStore) RefreshLanePolicy(_ context.Context, scope api.Scope, request api.PolicyAdvanceRequest) (api.PolicyAdvanceReceipt, error) {
	m.check(scope)
	m.policyRefreshes = append(m.policyRefreshes, request)
	if request.Target != (api.LifeRef{LifeID: m.lane.LifeID, Run: m.lane.Run}) || request.ExpectedLaneGeneration != m.lane.Generation ||
		request.CancellationEpoch != m.lane.CancellationEpoch || request.FromGeneration != m.lane.PolicyGeneration || request.ToGeneration != m.policy.Generation {
		return api.PolicyAdvanceReceipt{}, problem(api.CodeConflict, "test policy refresh lost its current fence")
	}
	event := api.PolicyAdvanceEvent{FromGeneration: m.lane.PolicyGeneration, ToGeneration: m.policy.Generation,
		LaneGeneration: m.lane.Generation + 1, PolicySHA256: m.policy.SHA256, GrantSetID: m.lane.GrantSetID}
	m.lane.PolicyGeneration, m.lane.Generation = m.policy.Generation, m.lane.Generation+1
	m.lane.LastSeq = api.Sequence(len(m.events) + 1)
	payload, err := json.Marshal(event)
	if err != nil {
		m.t.Fatal(err)
	}
	id := api.ID("policy-advance")
	m.events = append(m.events, api.Event{Schema: api.SchemaVersion, Config: scope.Config, Kind: "lane.policy", ID: id,
		LifeID: m.lane.LifeID, Run: m.lane.Run, Seq: m.lane.LastSeq, Origin: "service", Actor: api.Actor{Kind: "service", ID: "policy-coordinator"}, Payload: payload})
	receipt := api.PolicyAdvanceReceipt{Changed: true, Lane: m.lane, Event: event, EventID: id, CommittedSeq: m.lane.LastSeq}
	if m.policyReply != nil {
		receipt = m.policyReply(receipt)
	}
	return receipt, nil
}

func (m *readStore) Blob(_ context.Context, scope api.Scope, request api.BlobReadRequest) (api.BlobChunk, error) {
	m.check(scope)
	data, found := m.blobs[request.ObjectID]
	if !found || request.Offset < 0 || request.Offset >= int64(len(data)) || request.Limit <= 0 {
		return api.BlobChunk{}, problem(api.CodeNotFound, "test evidence is absent")
	}
	end := min(int64(len(data)), request.Offset+int64(request.Limit))
	part := data[request.Offset:end]
	chunk := api.BlobChunk{ObjectID: request.ObjectID, Offset: request.Offset, Data: part, SHA256: digest(part)}
	if m.badChunk {
		chunk.Offset++
	}
	return chunk, nil
}

func (m *readStore) Transact(context.Context, api.Transaction) (api.Commit, error) {
	m.writeCalls++
	return api.Commit{}, api.NotImplemented("lb-v2-service", "store.Transact")
}

func (m *readStore) ContinuationIntent(_ context.Context, scope api.Scope, _ api.ID) (api.ContinuationIntent, error) {
	m.check(scope)
	if m.readError != nil {
		return api.ContinuationIntent{}, m.readError
	}
	return api.ContinuationIntent{}, problem(api.CodeNotFound, "test continuation is absent")
}

func (m *readStore) Turn(_ context.Context, scope api.Scope, target api.LifeRef, turn api.ID) (api.TurnSnapshot, error) {
	m.check(scope)
	if m.turn.Target != target || m.turn.LogicalTurnID != turn {
		return api.TurnSnapshot{}, problem(api.CodeNotFound, "test turn is absent")
	}
	return m.turn, nil
}

type outsideLauncher struct {
	api.Launcher
	observation api.ProcessObservation
	handle      api.ProcessHandle
	stopCalls   int
	err         error
	onObserve   func()
}

func (m *outsideLauncher) Observe(_ context.Context, handle api.ProcessHandle) (api.ProcessObservation, error) {
	if handle != m.handle {
		return api.ProcessObservation{}, problem(api.CodeIntegrity, "unexpected process handle")
	}
	if m.onObserve != nil {
		m.onObserve()
	}
	return m.observation, m.err
}

func (m *outsideLauncher) Stop(context.Context, api.ProcessHandle, string) (api.ProcessObservation, error) {
	m.stopCalls++
	return api.ProcessObservation{}, problem(api.CodeIntegrity, "unexpected unsynchronized stop")
}

type roomBroker struct {
	api.CredentialBroker
	grants           []api.ProfileGrant
	rooms            map[api.ID]api.Room
	checked          []api.ID
	acquireCalls     int
	err              error
	onRoom           func(api.ProfileGrant)
	eligibility      api.ProfileEligibility
	eligibilities    map[api.ID]api.ProfileEligibility
	eligibilityCalls int
	onEligibility    func()
	usageRead        func(context.Context, api.Scope, api.UsageWindowRequest) (api.UsageWindowEvidence, error)
}

func (m *roomBroker) ReadUsageWindow(ctx context.Context, scope api.Scope, request api.UsageWindowRequest) (api.UsageWindowEvidence, error) {
	if m.usageRead == nil {
		return api.UsageWindowEvidence{}, api.NotImplemented("lb-v2-secrets", "test outside usage source is unavailable")
	}
	return m.usageRead(ctx, scope, request)
}

func (m *roomBroker) Eligibility(_ context.Context, request api.ProfileEligibilityRequest) (api.ProfileEligibility, error) {
	m.eligibilityCalls++
	if m.onEligibility != nil {
		m.onEligibility()
	}
	if value, found := m.eligibilities[request.ToGrantID]; found {
		return value, m.err
	}
	return m.eligibility, m.err
}

func (m *roomBroker) Room(_ context.Context, grant api.ProfileGrant) (api.Room, error) {
	if m.err != nil {
		return api.Room{}, m.err
	}
	for _, known := range m.grants {
		if reflect.DeepEqual(known, grant) {
			m.checked = append(m.checked, grant.ProfileID)
			if m.onRoom != nil {
				m.onRoom(grant)
			}
			room, exists := m.rooms[grant.ProfileID]
			if !exists {
				return api.Room{}, problem(api.CodeNotFound, "test room is absent")
			}
			return room, nil
		}
	}
	return api.Room{}, problem(api.CodeForbidden, "profile was not explicitly granted")
}

func (m *roomBroker) Acquire(context.Context, api.LifeRef, api.ProfileGrant) (api.CredentialSlot, error) {
	m.acquireCalls++
	return api.CredentialSlot{}, problem(api.CodeIntegrity, "unexpected lease without durable handoff")
}

type captureRunner struct {
	api.Runner
	store         *readStore
	profile       api.ProfileGrant
	err           error
	mismatch      bool
	none          bool
	usageEvidence *api.BlobRef
}

func (m *captureRunner) LimitFromCapture(_ context.Context, capture api.CaptureRecord, exit api.ProcessObservation) (*api.LimitSignal, error) {
	if m.err != nil || m.none {
		return nil, m.err
	}
	if capture.Target != exit.Handle.Target || exit.State != "exited" || exit.ExitCode == nil {
		return nil, problem(api.CodeIntegrity, "test adapter received unrelated capture and exit")
	}
	data := m.store.blobs[capture.Data.ID]
	outcome, err := Classify(m.profile.Driver, JSONLines, data, nil, *exit.ExitCode)
	if err != nil {
		return nil, err
	}
	for _, diagnostic := range outcome.Signals {
		if diagnostic.Kind != UsageLimit && diagnostic.Kind != SessionLimit {
			continue
		}
		signal := &api.LimitSignal{
			UsageEvidence: m.usageEvidence,
			Target:        capture.Target, Kind: string(diagnostic.Kind), ProfileID: m.profile.ProfileID,
			Provider: m.profile.Provider, CaptureID: capture.ID, CaptureSHA256: capture.Data.SHA256,
			ExitCode: exit.ExitCode, AdapterVersion: "adapter-1", ObservedAt: capture.ObservedAt,
		}
		if m.mismatch {
			signal.AdapterVersion = "other-adapter"
		}
		return signal, nil
	}
	return nil, nil
}

type grantChecker struct {
	api.GrantResolver
	grants api.GrantSet
	err    error
	change bool
}

func (m *grantChecker) Revalidate(_ context.Context, grants api.GrantSet) (api.GrantSet, error) {
	if m.err != nil {
		return api.GrantSet{}, m.err
	}
	if !reflect.DeepEqual(grants, m.grants) {
		return api.GrantSet{}, problem(api.CodeIntegrity, "test resolver received a different grant set")
	}
	if m.change {
		grants.Generation++
	}
	return grants, nil
}

type blockedContinuation struct {
	calls int
}

func (m *blockedContinuation) Continue(context.Context, api.Scope, api.ContinuationRequest) (api.Operation, error) {
	m.calls++
	return api.Operation{}, api.NotImplemented("lb-v2-lifecycle", "lifecycle.Continue")
}

type testRig struct {
	t         *testing.T
	s         *Service
	store     *readStore
	launcher  *outsideLauncher
	broker    *roomBroker
	runner    *captureRunner
	grants    *grantChecker
	lifecycle *blockedContinuation
	clock     *fixedClock
	signal    api.LimitSignal
}

func newRig(t *testing.T) *testRig {
	t.Helper()
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	at := api.Timestamp(now.Add(-time.Second).Format(time.RFC3339Nano))
	expires := api.Timestamp(now.Add(time.Hour).Format(time.RFC3339Nano))
	target := api.LifeRef{LifeID: "life-one", Run: 7}
	profileA := api.ProfileGrant{ID: "grant-a", ProfileID: "profile-a", Driver: api.DriverClaudock, Provider: "provider-one", ExpiresAt: expires}
	profileB := profileA
	profileB.ID, profileB.ProfileID = "grant-b", "profile-b"
	grantHash := digest([]byte("granted_profiles"))
	grants := api.GrantSet{
		ID: "grant-set", LifeID: target.LifeID, SHA256: grantHash, Generation: 2,
		PolicyGeneration: 3, Profiles: []api.ProfileGrant{profileA, profileB}, ExpiresAt: expires,
	}
	lane := api.Lane{
		LifeID: target.LifeID, Run: target.Run, State: "verifying", Generation: 9, Level: 3, Role: "executor",
		LaunchID: "launch-one", CancellationEpoch: 3, Counters: api.TaskCounters{Failures: 2, Retries: 1},
		LogicalTurnID: "logical-turn", ProfileGrantID: profileA.ID, GrantSetID: grants.ID,
		PolicyGeneration: grants.PolicyGeneration, Model: "claude-sonnet-5-5", Effort: "high",
		Session:         api.Session{ID: "session-one", Driver: api.DriverClaudock, VendorID: "vendor-session", HomeID: "home-one", HistoryID: "history-one", LogicalCWD: "/work/main"},
		Workspace:       api.Workspace{ID: "workspace-one", LogicalCWD: "/work/main", Branch: "work"},
		BudgetRemaining: api.Budget{WallMS: 45000, SpendMicros: 1000, CPUSeconds: 10, MemoryBytes: 4096, Processes: 8, DiskBytes: 4096},
	}
	store := &readStore{t: t, lane: lane, grants: grants, blobs: map[api.ID][]byte{}, classes: map[api.ID]string{}}
	store.policy = api.EffectivePolicy{Generation: lane.PolicyGeneration, SHA256: digest([]byte("effective policy")),
		Context: api.RoleContext{Level: lane.Level, Role: lane.Role}}
	handle := api.ProcessHandle{ID: "process-one", Target: target, ContainmentID: "containment-one", Generation: "generation-one"}
	store.launch = api.LaunchRecord{
		ID: "launch-one", Config: "watchdog-test", Target: target, GrantSetID: grants.ID,
		GrantsSHA256: grantHash, PolicyGeneration: lane.PolicyGeneration,
		ContainmentID: handle.ContainmentID, ProcessGeneration: handle.Generation,
	}
	zero, exit := uint64(0), 0
	observation := api.ProcessObservation{Handle: handle, State: "exited", ExitCode: &exit, Survivors: &zero, PromptStatus: "written", ObservedAt: at}
	rig := &testRig{
		t: t, store: store, clock: &fixedClock{at: now},
		launcher: &outsideLauncher{handle: handle, observation: observation},
		grants:   &grantChecker{grants: grants}, lifecycle: &blockedContinuation{},
		broker: &roomBroker{grants: grants.Profiles, rooms: map[api.ID]api.Room{}},
		runner: &captureRunner{store: store, profile: profileA},
	}
	data := []byte(`{"type":"result","is_error":true,"result":"Usage limit reached"}` + "\n")
	lane.Task = rig.addClassBlob("original-task", []byte("Continue the existing task.\n"), "task")
	store.lane = lane
	store.turn = api.TurnSnapshot{Target: target, LogicalTurnID: lane.LogicalTurnID, Task: lane.Task,
		PolicyGeneration: lane.PolicyGeneration, Generation: 1, Status: "running"}
	capture := api.CaptureRecord{ID: "capture-one", Target: target, Stream: "stdout", Data: rig.addClassBlob("capture-bytes", data, "capture"), ObservedAt: at, Primary: true, Coverage: "complete"}
	rig.signal = api.LimitSignal{
		Target: target, Kind: string(UsageLimit), ProfileID: profileA.ProfileID, Provider: profileA.Provider,
		CaptureID: capture.ID, CaptureSHA256: capture.Data.SHA256, ExitCode: &exit, AdapterVersion: "adapter-1", ObservedAt: at,
	}
	rig.addEvent("lane.started", api.LaunchEvent{LaunchID: store.launch.ID, Lane: lane})
	rig.addEvent("run.observed", observation)
	rig.addEvent("capture.appended", capture)
	for _, grant := range grants.Profiles {
		roomData, err := json.Marshal(map[string]any{"profile_id": grant.ProfileID, "available": grant.ID == profileB.ID, "checked_at": at})
		if err != nil {
			t.Fatal(err)
		}
		rig.broker.rooms[grant.ProfileID] = api.Room{
			ProfileID: grant.ProfileID, Available: grant.ID == profileB.ID,
			CheckedAt: at, ExpiresAt: api.Timestamp(now.Add(30 * time.Second).Format(time.RFC3339Nano)),
			Evidence: rig.addBlob(api.ID("room-"+string(grant.ID)), roomData), Reason: "outside_usage",
		}
	}
	rig.broker.eligibility = api.ProfileEligibility{
		ID: "eligibility-b", Compatible: true,
		Request: api.ProfileEligibilityRequest{Target: target, GrantSetID: grants.ID,
			FromGrantID: profileA.ID, ToGrantID: profileB.ID, Driver: lane.Session.Driver,
			Model: lane.Model, Session: lane.Session, HistoryID: lane.Session.HistoryID},
		Evidence:  rig.addBlob("eligibility-bytes", []byte("compatible model, session and history\n")),
		CheckedAt: at, ExpiresAt: api.Timestamp(now.Add(30 * time.Second).Format(time.RFC3339Nano)),
	}
	rig.fix10Launch()
	rig.fix12Usage()
	var err error
	rig.s, err = New(Dependencies{
		Config: store.launch.Config, Store: store, Launcher: rig.launcher, Credentials: rig.broker,
		Claudock: rig.runner, Grants: rig.grants, Lifecycle: rig.lifecycle, Clock: rig.clock,
		ResolveUsage: rig.resolveUsage,
	})
	if err != nil {
		t.Fatal(err)
	}
	return rig
}

func (r *testRig) addBlob(id api.ID, data []byte) api.BlobRef {
	class := r.store.classes[id]
	if class == "" {
		class = "artifact"
	}
	return r.addClassBlob(id, data, class)
}

func (r *testRig) addClassBlob(id api.ID, data []byte, class string) api.BlobRef {
	r.store.blobs[id] = data
	r.store.classes[id] = class
	return api.BlobRef{ID: id, SHA256: digest(data), Bytes: int64(len(data)), Class: class}
}

func (r *testRig) addEvent(kind api.EventKind, payload any) {
	r.t.Helper()
	encoded, err := json.Marshal(payload)
	if err != nil {
		r.t.Fatal(err)
	}
	actor := api.Actor{Kind: "service", ID: "outside-supervisor"}
	if kind == "watchdog.limit" || kind == "watchdog.waiting" || kind == "watchdog.cancelled" {
		actor = api.Actor{Kind: "watchdog", ID: "watchdog"}
	}
	r.store.events = append(r.store.events, api.Event{
		Schema: api.SchemaVersion, Config: r.store.launch.Config, Seq: api.Sequence(len(r.store.events) + 1),
		Kind: kind, LifeID: r.signal.Target.LifeID, Run: r.signal.Target.Run,
		Origin: "service", Actor: actor, Payload: encoded,
		RequestedBy: api.Actor{Kind: "lane", ID: "parent-launch", LifeID: "parent-life", Level: 4, Role: "supervisor"},
		RequestID:   "request-origin", OperationID: "operation-origin",
		RecordedAt: api.Timestamp(r.clock.at.Format(time.RFC3339Nano)),
	})
}

func (r *testRig) capture(change func(*api.CaptureRecord)) {
	r.t.Helper()
	var capture api.CaptureRecord
	if err := json.Unmarshal(r.store.events[2].Payload, &capture); err != nil {
		r.t.Fatal(err)
	}
	change(&capture)
	encoded, err := json.Marshal(capture)
	if err != nil {
		r.t.Fatal(err)
	}
	r.store.events[2].Payload = encoded
}

// Change the actual referenced body without truncating it or changing its
// declared identity/size/hash. A trailing JSON newline becomes a space, so the
// quota record stays valid and recognizable if the blob hash guard is removed.
func (r *testRig) changeCaptureBytes() api.BlobRef {
	r.t.Helper()
	var ref api.BlobRef
	r.capture(func(c *api.CaptureRecord) {
		ref = c.Data
		if c.ID != r.signal.CaptureID || ref.SHA256 != r.signal.CaptureSHA256 {
			r.t.Fatal("changed-byte control must target the signal's selected capture")
		}
		original, found := r.store.blobs[ref.ID]
		if !found || int64(len(original)) != ref.Bytes || digest(original) != ref.SHA256 ||
			len(original) == 0 || original[len(original)-1] != '\n' {
			r.t.Fatal("changed-byte control requires the original complete capture body")
		}
		changed := bytes.Clone(original)
		changed[len(changed)-1] = ' '
		if !json.Valid(changed) || len(changed) != len(original) || digest(changed) == ref.SHA256 {
			r.t.Fatal("changed-byte control did not preserve valid same-length JSON with a different hash")
		}
		r.store.blobs[ref.ID] = changed
	})
	return ref
}

func requireCode(t *testing.T, err error, code api.ErrorCode) {
	t.Helper()
	var typed *api.Error
	if !errors.As(err, &typed) || typed.Code != code {
		t.Fatalf("wanted typed %s, got %v", code, err)
	}
}

func (r *testRig) noEffects() {
	r.t.Helper()
	if r.store.writeCalls != 0 || r.launcher.stopCalls != 0 || r.broker.acquireCalls != 0 || r.lifecycle.calls != 0 {
		r.t.Fatal("read-only validation performed a mutation, stop, slot acquisition or continuation")
	}
}

func TestAssessmentPreservesLife(t *testing.T) {
	r := newRig(t)
	before := r.store.lane
	plan, err := r.s.assess(context.Background(), r.signal)
	if err != nil || plan.Swap == nil {
		t.Fatal("valid evidence could not be assessed", err)
	}
	swap := plan.Swap
	if swap.FromProfileID != r.signal.ProfileID || swap.ToProfileID != "profile-b" ||
		swap.CausingRun != before.Run || swap.ContinuationRun != before.Run+1 || swap.LogicalTurnID != before.LogicalTurnID ||
		swap.OperationID != "" || !reflect.DeepEqual(swap.Limit, r.signal) || !reflect.DeepEqual(plan.Lane, before) ||
		!reflect.DeepEqual(r.store.lane, before) || !reflect.DeepEqual(r.broker.checked, []api.ID{"profile-a", "profile-b"}) {
		t.Fatal("assessment changed identity, turn, budget or delegated selection")
	}
	r.noEffects()
	op, err := r.s.ObserveLimit(context.Background(), r.signal)
	requireCode(t, err, api.CodeNotImplemented)
	if op.ID != "" || op.Status != "" {
		t.Fatal("unimplemented store returned a success/pending receipt")
	}
	if r.store.writeCalls != 1 || r.lifecycle.calls != 0 || r.broker.acquireCalls != 0 || r.launcher.stopCalls != 0 {
		t.Fatal("store failure was bypassed or a loose slot was acquired")
	}
}

func TestNoRoomAndRestoration(t *testing.T) {
	r := newRig(t)
	room := r.broker.rooms["profile-b"]
	room.Available = false
	r.broker.rooms["profile-b"] = room
	plan, err := r.s.assess(context.Background(), r.signal)
	if err != nil || plan.Swap != nil || len(plan.Rooms) != 2 {
		t.Fatal("exhausted delegated room was not distinguished from a worker error", err)
	}
	room.Available = true
	r.broker.rooms["profile-b"] = room
	plan, err = r.s.assess(context.Background(), r.signal)
	if err != nil || plan.Swap == nil || plan.Swap.ContinuationRun != r.signal.Target.Run+1 {
		t.Fatal("restored room was not freshly reassessed", err)
	}
	// This is deliberately an assessment test, not a claimed resume test.
	r.noEffects()
}

func TestEvidenceRedControls(t *testing.T) {
	cases := []struct {
		name string
		edit func(*testRig)
		code api.ErrorCode
	}{
		{"stale-run", func(r *testRig) { r.signal.Target.Run-- }, api.CodeConflict},
		{"cleaned", func(r *testRig) { r.store.lane.Cleaned = true }, api.CodeCancelled},
		{"stopping", func(r *testRig) { r.store.lane.State = "stopping" }, api.CodeCancelled},
		{"budget", func(r *testRig) { r.store.lane.BudgetRemaining.WallMS = 0 }, api.CodeBudget},
		{"codex", func(r *testRig) { r.store.lane.Session.Driver = api.DriverCodex }, api.CodeUnsupported},
		{"wrong-cwd", func(r *testRig) { r.store.lane.Session.LogicalCWD = "/work/other" }, api.CodeUnsupported},
		{"lane-capture", func(r *testRig) {
			r.store.events[2].Actor = api.Actor{Kind: "lane", ID: "lane", LifeID: r.signal.Target.LifeID}
		}, api.CodeIntegrity},
		{"imported-capture", func(r *testRig) { r.store.events[2].Origin = "legacy_import" }, api.CodeIntegrity},
		{"observation-capture", func(r *testRig) { r.store.events[2].Origin = "observation" }, api.CodeIntegrity},
		{"task-class", func(r *testRig) {
			r.store.lane.Task.Class, r.store.turn.Task.Class = "capture", "capture"
		}, api.CodeUnsupported},
		{"capture-class", func(r *testRig) { r.capture(func(c *api.CaptureRecord) { c.Data.Class = "artifact" }) }, api.CodeIntegrity},
		{"capture-binding", func(r *testRig) { r.capture(func(c *api.CaptureRecord) { c.BindingID = "" }) }, api.CodeIntegrity},
		{"unknown-class", func(r *testRig) {
			room := r.broker.rooms["profile-b"]
			room.Evidence.Class = "outside-evidence"
			r.broker.rooms["profile-b"] = room
		}, api.CodeIntegrity},
		{"secondary", func(r *testRig) { r.capture(func(c *api.CaptureRecord) { c.Primary = false }) }, api.CodeIntegrity},
		{"stderr", func(r *testRig) { r.capture(func(c *api.CaptureRecord) { c.Stream = "stderr" }) }, api.CodeIntegrity},
		{"partial", func(r *testRig) { r.capture(func(c *api.CaptureRecord) { c.Coverage = "partial" }) }, api.CodeIntegrity},
		{"offset", func(r *testRig) { r.capture(func(c *api.CaptureRecord) { c.Offset = 1 }) }, api.CodeIntegrity},
		{"bad-capture-hash", func(r *testRig) { r.signal.CaptureSHA256 = digest([]byte("other")) }, api.CodeIntegrity},
		{"changed-bytes", func(r *testRig) { r.changeCaptureBytes() }, api.CodeIntegrity},
		{"missing-blob", func(r *testRig) {
			r.capture(func(c *api.CaptureRecord) { delete(r.store.blobs, c.Data.ID) })
		}, api.CodeNotFound},
		{"bad-page", func(r *testRig) { r.store.badPage = true }, api.CodeIntegrity},
		{"bad-chunk", func(r *testRig) { r.store.badChunk = true }, api.CodeIntegrity},
		{"nil-survivors", func(r *testRig) { r.launcher.observation.Survivors = nil }, api.CodeContainmentUnknown},
		{"surviving", func(r *testRig) { count := uint64(1); r.launcher.observation.Survivors = &count }, api.CodeContainmentUnknown},
		{"unknown-process", func(r *testRig) { r.launcher.observation.State = "unknown" }, api.CodeContainmentUnknown},
		{"wrong-exit", func(r *testRig) { code := 1; r.launcher.observation.ExitCode = &code }, api.CodeIntegrity},
		{"pid-reuse", func(r *testRig) { r.launcher.observation.Handle.Generation = "other-generation" }, api.CodeIntegrity},
		{"launch-generation", func(r *testRig) { r.store.launch.ProcessGeneration = "other-generation" }, api.CodeIntegrity},
		{"uncertain-prompt", func(r *testRig) { r.launcher.observation.PromptStatus = "cut" }, api.CodeConflict},
		{"revoked-grants", func(r *testRig) { r.store.grants.Revoked = true }, api.CodeForbidden},
		{"changed-grants", func(r *testRig) { r.grants.change = true }, api.CodeConflict},
		{"no-adapter-limit", func(r *testRig) { r.runner.none = true }, api.CodeIntegrity},
		{"wrong-adapter", func(r *testRig) { r.runner.mismatch = true }, api.CodeIntegrity},
		{"not-exhausted", func(r *testRig) {
			room := r.broker.rooms["profile-a"]
			room.Available = true
			r.broker.rooms["profile-a"] = room
		}, api.CodeConflict},
		{"expired-room", func(r *testRig) {
			room := r.broker.rooms["profile-b"]
			room.ExpiresAt = r.signal.ObservedAt
			r.broker.rooms["profile-b"] = room
		}, api.CodeIntegrity},
		{"wrong-room", func(r *testRig) {
			room := r.broker.rooms["profile-b"]
			room.ProfileID = "other"
			r.broker.rooms["profile-b"] = room
		}, api.CodeIntegrity},
		{"missing-room-proof", func(r *testRig) {
			room := r.broker.rooms["profile-b"]
			room.Evidence = api.BlobRef{}
			r.broker.rooms["profile-b"] = room
		}, api.CodeIntegrity},
		{"manual-race", func(r *testRig) { r.store.changeLane = true }, api.CodeConflict},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := newRig(t)
			tc.edit(r)
			_, err := r.s.assess(context.Background(), r.signal)
			requireCode(t, err, tc.code)
			r.noEffects()
		})
	}
}

func TestCaptureBytesHash(t *testing.T) {
	r := newRig(t)
	ref := r.changeCaptureBytes()
	changed := r.store.blobs[ref.ID]
	// The mock supplies a truthful per-chunk hash of the changed bytes. Only
	// comparing the complete body to the retained BlobRef catches this change.
	chunk, err := r.store.Blob(context.Background(), r.s.readScope(), api.BlobReadRequest{
		ObjectID: ref.ID, Offset: 0, Limit: int(ref.Bytes),
	})
	if err != nil || int64(len(chunk.Data)) != ref.Bytes || !bytes.Equal(chunk.Data, changed) ||
		chunk.SHA256 != digest(changed) || chunk.SHA256 == ref.SHA256 {
		t.Fatal("changed body was not present at the referenced blob and full range", err)
	}
	outcome, err := Classify(api.DriverClaudock, JSONLines, chunk.Data, nil, *r.signal.ExitCode)
	if err != nil || !outcome.Complete || len(outcome.Signals) != 1 || outcome.Signals[0].Candidate ||
		!outcome.Signals[0].Structured || string(outcome.Signals[0].Kind) != r.signal.Kind {
		t.Fatal("changed-byte control broke quota classification instead of its retained hash", err)
	}
	body, err := r.s.blob(context.Background(), ref, maxCaptureBytes)
	requireCode(t, err, api.CodeIntegrity)
	var typed *api.Error
	if !errors.As(err, &typed) || typed.Message != "outside evidence blob failed exact byte verification" || body != nil {
		t.Fatal("changed bytes did not reach the complete-blob checksum guard", err)
	}
	r.noEffects()
}

func TestDependencyErrorsPreserved(t *testing.T) {
	for _, edit := range []func(*testRig, error){
		func(r *testRig, err error) { r.store.readError = err },
		func(r *testRig, err error) { r.store.launchError = err },
		func(r *testRig, err error) { r.launcher.err = err },
		func(r *testRig, err error) { r.runner.err = err },
		func(r *testRig, err error) { r.grants.err = err },
		func(r *testRig, err error) { r.broker.err = err },
	} {
		r := newRig(t)
		wanted := api.NotImplemented("dependency", "outside-worker")
		edit(r, wanted)
		op, err := r.s.ObserveLimit(context.Background(), r.signal)
		if err != wanted || op.ID != "" || op.Status != "" {
			t.Fatal("dependency failure was swallowed, changed or converted to success", err)
		}
		r.noEffects()
	}
}

func TestEligibilityDoesNotExpand(t *testing.T) {
	for _, edit := range []func(*api.ProfileGrant){
		func(g *api.ProfileGrant) { g.Driver = api.DriverCodex },
		func(g *api.ProfileGrant) { g.Provider = "other-provider" },
		func(g *api.ProfileGrant) { g.ExpiresAt = "2020-01-01T00:00:00Z" },
		func(g *api.ProfileGrant) { g.Paid = true },
	} {
		r := newRig(t)
		r.store.lane.BudgetRemaining.SpendMicros = 0
		edit(&r.store.grants.Profiles[1])
		if r.store.grants.Profiles[1].Paid {
			// Isolate the spend guard from draft.4's independent prohibition
			// on changing a free source to a paid destination.
			r.store.grants.Profiles[0].Paid = true
		}
		r.grants.grants = r.store.grants
		plan, err := r.s.assess(context.Background(), r.signal)
		if err != nil || plan.Swap != nil || !reflect.DeepEqual(r.broker.checked, []api.ID{"profile-a"}) {
			t.Fatal("room selection widened profile/provider/paid scope", err)
		}
		r.noEffects()
	}
}

func TestCancelAndReconcileStayClosed(t *testing.T) {
	r := newRig(t)
	if err := r.s.Cancel(context.Background(), r.signal.Target); err != nil || r.store.writeCalls != 0 {
		t.Fatal("cancel without a live intent wrote or failed", err)
	}
	_, err := r.s.Reconcile(context.Background(), r.signal.Target)
	requireCode(t, err, api.CodeNotFound)
	r.addEvent("watchdog.waiting", api.WatchdogEvent{Signal: &r.signal, RetryAfterMS: 5000})
	_, err = r.s.Reconcile(context.Background(), r.signal.Target)
	requireCode(t, err, api.CodeUnavailable)
	r.clock.at = r.clock.at.Add(5 * time.Second)
	_, err = r.s.Reconcile(context.Background(), r.signal.Target)
	requireCode(t, err, api.CodeNotImplemented)
	r.addEvent("watchdog.cancelled", api.WatchdogEvent{Signal: &r.signal, Reason: "manual_stop"})
	_, err = r.s.Reconcile(context.Background(), r.signal.Target)
	requireCode(t, err, api.CodeCancelled)
	if r.store.writeCalls != 1 || r.lifecycle.calls != 0 || r.broker.acquireCalls != 0 || r.launcher.stopCalls != 0 {
		t.Fatal("store prerequisite failure was bypassed during cancel/recovery")
	}
}

func TestBackoffAndInitialization(t *testing.T) {
	delay := int64(0)
	for attempt := 0; attempt < 50; attempt++ {
		next, err := nextBackoff(delay)
		if err != nil || next < 5000 || next > 300000 || next < delay || (delay != 0 && next != min(delay*2, int64(300000))) {
			t.Fatal("backoff wrapped, shrank or exceeded its bound", err)
		}
		delay = next
	}
	for _, invalid := range []int64{-1, 1, 4999, 300001, 1 << 62} {
		_, err := nextBackoff(invalid)
		requireCode(t, err, api.CodeIntegrity)
	}
	_, err := New(Dependencies{})
	requireCode(t, err, api.CodeInvalid)
	r := newRig(t)
	deps := r.s.deps
	var nilStore *readStore
	deps.Store = nilStore
	_, err = New(deps)
	requireCode(t, err, api.CodePrerequisite)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = r.s.ObserveLimit(ctx, r.signal)
	requireCode(t, err, api.CodeCancelled)
	var uninitialized Service
	_, err = uninitialized.ObserveLimit(context.Background(), r.signal)
	requireCode(t, err, api.CodePrerequisite)
}
