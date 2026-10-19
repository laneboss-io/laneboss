package grants

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/grants/manifest"
	"laneboss.io/laneboss/internal/v2/testjob"
)

// These are focused in-memory wiring fixtures, not service/OS acceptance.
// Unimplemented embedded methods panic if code unexpectedly uses them.
type fixedClock struct{ now time.Time }

func (c fixedClock) Now() time.Time { return c.now }

type fixtureStore struct {
	api.StateStore
	t             *testing.T
	sets          map[api.ID]api.GrantSet
	lanes         map[api.ID]api.Lane
	launch        api.LaunchRecord
	blobs         map[api.ID][]byte
	metadata      map[api.ID]api.ObjectMetadata
	policy        api.EffectivePolicy
	transactions  int
	readErr       error
	corruptChunk  bool
	events        []api.Event
	onBlob        func()
	onBlobObject  api.ID
	operation     api.Operation
	operationErr  error
	views         []*fixtureReadView
	target        api.HumanChallengeRequest
	onTransaction func(api.Transaction) (api.Commit, error)
	onPolicy      func(api.Scope)
	onGrantPolicy func(api.Scope, api.GrantPolicyRequest)
	onMetadata    func(api.Scope, api.ID)
	blobCalls     map[api.ID]int
	channels      map[api.ID]api.EnrolledChannel
}

func clone[T any](t *testing.T, value T) T {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	var result T
	if err := json.Unmarshal(raw, &result); err != nil {
		t.Fatal(err)
	}
	return result
}

func (s *fixtureStore) Grants(_ context.Context, id api.ID) (api.GrantSet, error) {
	value, found := s.sets[id]
	if !found {
		return api.GrantSet{}, &api.Error{Code: api.CodeNotFound, Message: "fixture grant is absent"}
	}
	return clone(s.t, value), nil
}
func (s *fixtureStore) Lane(_ context.Context, scope api.Scope, target api.LifeRef) (api.Lane, error) {
	if scope.Config != "case-grants" {
		s.t.Fatal("store read lost its configuration")
	}
	lanes := s.lanes
	if view, ok := scope.ReadView.(*fixtureReadView); ok {
		if view.closed {
			s.t.Fatal("store used a closed read view")
		}
		lanes = view.lanes
	}
	value, found := lanes[target.LifeID]
	if !found {
		return api.Lane{}, &api.Error{Code: api.CodeNotFound, Message: "fixture life is absent"}
	}
	return clone(s.t, value), nil
}

type fixtureReadView struct {
	actor    api.Actor
	snapshot api.ReadSnapshot
	lanes    map[api.ID]api.Lane
	policy   api.EffectivePolicy
	closed   bool
}

func (v *fixtureReadView) Snapshot() api.ReadSnapshot { return v.snapshot }
func (v *fixtureReadView) Close() error               { v.closed = true; return nil }

func (s *fixtureStore) BeginRead(_ context.Context, scope api.Scope) (api.ReadView, error) {
	if scope.Config != "case-grants" || scope.ReadView != nil {
		s.t.Fatal("fresh authority read reused a snapshot or lost its configuration")
	}
	view := &fixtureReadView{actor: scope.Actor, snapshot: api.ReadSnapshot{ID: "read-view", Config: scope.Config}, lanes: clone(s.t, s.lanes), policy: clone(s.t, s.policy)}
	s.views = append(s.views, view)
	return view, nil
}
func (s *fixtureStore) Launch(_ context.Context, id api.ID) (api.LaunchRecord, error) {
	if s.launch.ID != id {
		return api.LaunchRecord{}, &api.Error{Code: api.CodeNotFound, Message: "fixture launch is absent"}
	}
	return clone(s.t, s.launch), nil
}
func (s *fixtureStore) Policy(_ context.Context, scope api.Scope) (api.EffectivePolicy, error) {
	if scope.Config != "case-grants" {
		s.t.Fatal("policy read lost its configuration")
	}
	if s.onPolicy != nil {
		s.onPolicy(scope)
	}
	if view, ok := scope.ReadView.(*fixtureReadView); ok {
		if view.closed {
			s.t.Fatal("policy used a closed snapshot")
		}
		return view.policy, nil
	}
	return s.policy, nil
}

func (s *fixtureStore) GrantPolicy(ctx context.Context, scope api.Scope, request api.GrantPolicyRequest) (api.EffectivePolicy, error) {
	if view, ok := scope.ReadView.(*fixtureReadView); !ok || view.closed || view.actor != scope.Actor {
		s.t.Fatal("grant policy changed its pinned authenticated caller")
	}
	if s.onGrantPolicy != nil {
		s.onGrantPolicy(scope, request)
	}
	policy, err := s.Policy(ctx, scope)
	if err == nil && policy.Generation != request.PolicyGeneration {
		return api.EffectivePolicy{}, &api.Error{Code: api.CodeConflict}
	}
	return policy, err
}
func (s *fixtureStore) AuthorizationTarget(_ context.Context, _ api.Scope, _ api.Request) (api.HumanChallengeRequest, error) {
	return s.target, nil
}

func (s *fixtureStore) Channel(_ context.Context, scope api.Scope, id api.ID) (api.EnrolledChannel, error) {
	if scope.Config != "case-grants" {
		s.t.Fatal("channel lookup lost its configuration")
	}
	channel, exists := s.channels[id]
	if !exists {
		return api.EnrolledChannel{}, &api.Error{Code: api.CodeNotFound}
	}
	return channel, nil
}
func (s *fixtureStore) ObjectMetadata(_ context.Context, scope api.Scope, id api.ID) (api.ObjectMetadata, error) {
	if scope.Config != "case-grants" {
		s.t.Fatal("metadata read lost its configuration")
	}
	if s.onMetadata != nil {
		s.onMetadata(scope, id)
	}
	value, found := s.metadata[id]
	if !found {
		return api.ObjectMetadata{}, &api.Error{Code: api.CodeNotFound, Message: "fixture object is absent"}
	}
	return clone(s.t, value), nil
}

func (s *fixtureStore) retain(ref api.BlobRef) {
	if existing, found := s.metadata[ref.ID]; found {
		existing.Ref = ref
		s.metadata[ref.ID] = existing
		return
	}
	s.metadata[ref.ID] = api.ObjectMetadata{Ref: ref, Origin: "upload",
		ACL: api.ObjectACL{Config: "case-grants", Owner: api.Actor{Kind: "service", ID: "fixture"},
			Audience: "configuration", Generation: 1}}
}
func (s *fixtureStore) Blob(_ context.Context, scope api.Scope, request api.BlobReadRequest) (api.BlobChunk, error) {
	if scope.Config != "case-grants" {
		s.t.Fatal("source read lost its configuration")
	}
	if s.blobCalls == nil {
		s.blobCalls = map[api.ID]int{}
	}
	s.blobCalls[request.ObjectID]++
	if s.readErr != nil {
		return api.BlobChunk{}, s.readErr
	}
	if hook := s.onBlob; hook != nil && (s.onBlobObject == "" || s.onBlobObject == request.ObjectID) {
		s.onBlob = nil
		hook()
	}
	data, found := s.blobs[request.ObjectID]
	if !found {
		return api.BlobChunk{}, &api.Error{Code: api.CodeNotFound, Message: "fixture blob is absent"}
	}
	if request.Offset < 0 || request.Offset > int64(len(data)) || request.Limit <= 0 {
		s.t.Fatal("invalid blob range")
	}
	end := min(int(request.Offset)+request.Limit, len(data))
	part := append([]byte{}, data[int(request.Offset):end]...)
	result := api.BlobChunk{ObjectID: request.ObjectID, Offset: request.Offset,
		Data: part, SHA256: manifest.Hash(part)}
	if s.corruptChunk {
		result.Offset++
	}
	return result, nil
}
func (s *fixtureStore) Operation(_ context.Context, scope api.Scope, _ api.ID) (api.Operation, error) {
	if scope.Config != "case-grants" {
		s.t.Fatal("operation read lost its configuration")
	}
	return clone(s.t, s.operation), s.operationErr
}
func (s *fixtureStore) Transact(_ context.Context, transaction api.Transaction) (api.Commit, error) {
	s.transactions++
	if s.onTransaction != nil {
		return s.onTransaction(transaction)
	}
	return api.Commit{}, api.NotImplemented("fixture", "unexpected transaction")
}

func (s *fixtureStore) Events(_ context.Context, scope api.Scope, request api.EventTailRequest) (api.EventPage, error) {
	if scope.Config != "case-grants" {
		s.t.Fatal("event read lost its configuration")
	}
	page := api.EventPage{Events: []api.Event{}, Complete: true}
	for _, event := range s.events {
		if event.LifeID == request.LifeID && event.Run == request.Run {
			page.Events = append(page.Events, clone(s.t, event))
		}
	}
	return page, nil
}

type fixtureWorker struct {
	api.DataWorker
	materializeCalls int
	testCalls        int
	tested           api.GrantSet
	testCall         testjob.Call
	materialization  api.Materialization
	materializeErr   error
	operation        api.Operation
	testErr          error
	onMaterialize    func()
}

func (w *fixtureWorker) Materialize(_ context.Context, grants api.GrantSet) (api.Materialization, error) {
	w.materializeCalls++
	if w.onMaterialize != nil {
		w.onMaterialize()
	}
	return w.materialization, w.materializeErr
}
func (w *fixtureWorker) TestChild(ctx context.Context, _ api.TestChildRequest, grants api.GrantSet) (api.Operation, error) {
	w.testCalls++
	w.tested = grants
	w.testCall, _ = testjob.FromContext(ctx)
	if w.testErr != nil {
		return api.Operation{}, w.testErr
	}
	return w.operation, nil
}

type fixture struct {
	t       *testing.T
	service *Service
	store   *fixtureStore
	worker  *fixtureWorker
	clock   fixedClock
	scope   api.Scope
	request api.GrantValidateRequest
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	now := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	expiry := api.Timestamp(now.Add(4 * time.Hour).Format(time.RFC3339Nano))
	ref := api.BlobRef{ID: "input-bytes", SHA256: manifest.Hash([]byte("input")), Bytes: 5, Class: "artifact"}
	object := api.ObjectManifest{Schema: "laneboss.objects.v2", Entries: []api.ObjectEntry{
		{Path: "child/input.txt", Kind: "file", Mode: 0644, Content: &ref},
		{Path: "private/canary", Kind: "file", Mode: 0644, Content: &ref},
	}}
	raw, err := json.Marshal(object)
	if err != nil {
		t.Fatal(err)
	}
	set := api.GrantSet{ID: "parent-set", LifeID: "parent", Generation: 1,
		PolicyGeneration: 1, ExpiresAt: expiry,
		Data: []api.DataGrant{{ID: "data", SourceObjectID: "source-tree", SourceSHA256: manifest.Hash(raw),
			RelativePath: ".", Access: "rw", Delivery: "copy", Destination: "/work/main", Delegate: true,
			ExpiresAt: expiry, HistoryScope: "snapshot"}},
		Secrets: []api.SecretGrant{{ID: "secret", Name: "task-key", SourceHandle: "key-source", Version: "v1.0",
			Delivery: "env", Target: "TASK_KEY", Delegate: true, ExpiresAt: expiry}},
		Profiles: []api.ProfileGrant{{ID: "profile", ProfileID: "profile-one", Driver: api.DriverCodex,
			Provider: "example", Delegate: true, ExpiresAt: expiry}},
		Network:  []api.NetworkGrant{{ID: "network", EndpointID: "endpoint-one", Mode: "service", Delegate: true, ExpiresAt: expiry}},
		Channels: []api.ChannelGrant{{ID: "channel", ChannelID: "channel-one", Delegate: true, ExpiresAt: expiry}},
		Resources: []api.ResourceGrant{{ID: "resource", SourceHandle: "resource-source", Provider: "aws",
			Regions: []string{"region-a", "region-b"}, ImageIDs: []string{"image-a"}, MachineTypes: []string{"m7i.large"},
			MaxActive: 2, MaxHourlyMicros: 10, TotalBudgetMicros: 100, Delegate: true, ExpiresAt: expiry}}}
	if err := seal(&set); err != nil {
		t.Fatal(err)
	}
	store := &fixtureStore{t: t, sets: map[api.ID]api.GrantSet{set.ID: set},
		lanes: map[api.ID]api.Lane{set.LifeID: {LifeID: set.LifeID, RootLifeID: set.LifeID,
			StarterChain: []api.ID{}, Level: 5, Role: "supervisor", State: "running", Run: 1,
			Generation: 1, GrantSetID: set.ID, PolicyGeneration: 1}},
		blobs:    map[api.ID][]byte{"source-tree": raw, "input-bytes": []byte("input")},
		metadata: map[api.ID]api.ObjectMetadata{},
		policy:   api.EffectivePolicy{Generation: 1},
		launch: api.LaunchRecord{ID: "parent-launch", Config: "case-grants", Target: api.LifeRef{LifeID: set.LifeID, Run: 1},
			GrantSetID: set.ID, GrantsSHA256: set.SHA256, PolicyGeneration: 1, EndpointGeneration: 1}}
	store.retain(ref)
	store.retain(api.BlobRef{ID: "source-tree", SHA256: manifest.Hash(raw), Bytes: int64(len(raw)), Class: "manifest"})
	worker := &fixtureWorker{materializeErr: api.NotImplemented("fixture-worker", "materialize executor"),
		testErr: api.NotImplemented("fixture-worker", "test child executor")}
	clock := fixedClock{now: now}
	service, err := New(Dependencies{Config: "case-grants", Store: store, Worker: worker, Clock: clock})
	if err != nil {
		t.Fatal(err)
	}
	requested := api.GrantRequest{Data: []api.DataGrantRequest{{ParentGrantID: "data", RelativePath: "child", Access: "ro",
		Delivery: "copy", Destination: "/work/main", Delegate: false, ExpiresAt: expiry}},
		Secrets: []api.SecretDelegation{}, Profiles: []api.ProfileDelegation{}, Network: []api.NetworkDelegation{},
		Channels: []api.ChannelDelegation{}, Resources: []api.ResourceDelegation{}}
	return &fixture{t: t, service: service, store: store, worker: worker, clock: clock,
		scope: api.Scope{Config: "case-grants", Actor: api.Actor{Kind: "lane", ID: "actor", LifeID: "parent", Level: 5, Role: "supervisor"},
			LaunchID: "parent-launch", EndpointGeneration: 1, PolicyGeneration: 1},
		request: api.GrantValidateRequest{ParentLifeID: "parent", ChildLevel: 3, Requested: requested, ExpectedPolicyGeneration: 1}}
}

func (f *fixture) updateParent(mutate func(*api.GrantSet)) {
	f.t.Helper()
	set := clone(f.t, f.store.sets["parent-set"])
	mutate(&set)
	if err := seal(&set); err != nil {
		f.t.Fatal(err)
	}
	f.store.sets[set.ID] = set
	f.store.launch.GrantsSHA256 = set.SHA256
}

func (f *fixture) child() api.GrantSet {
	f.t.Helper()
	child, err := f.service.preview(context.Background(), f.scope, f.request)
	if err != nil {
		f.t.Fatal(err)
	}
	f.store.sets[child.ID] = clone(f.t, child)
	f.store.lanes[child.LifeID] = api.Lane{LifeID: child.LifeID, ParentLifeID: "parent", RootLifeID: "parent",
		StarterChain: []api.ID{"parent"}, Level: 3, Role: "executor", State: "verifying", Run: 1,
		Generation: 1, GrantSetID: child.ID, PolicyGeneration: 1}
	return child
}

func (f *fixture) testRequest(child api.GrantSet) api.TestChildRequest {
	f.t.Helper()
	budget := api.Budget{WallMS: 1000, CPUSeconds: 1, MemoryBytes: 4096, Processes: 4,
		DiskBytes: 8192, SpendMicros: 0, Currency: "USD"}
	input := api.ObjectManifest{Schema: "laneboss.objects.v2", Entries: []api.ObjectEntry{
		{Path: "task.sh", Kind: "file", Mode: 0700, Content: &api.BlobRef{ID: "input-bytes",
			SHA256: manifest.Hash([]byte("input")), Bytes: 5, Class: "artifact"}},
	}}
	put := func(id api.ID, value any) api.BlobRef {
		raw, err := json.Marshal(value)
		if err != nil {
			f.t.Fatal(err)
		}
		f.store.blobs[id] = raw
		ref := api.BlobRef{ID: id, SHA256: manifest.Hash(raw), Bytes: int64(len(raw)), Class: "manifest"}
		f.store.retain(ref)
		metadata := f.store.metadata[id]
		metadata.ACL.Owner = api.Actor{Kind: "lane", ID: child.LifeID, LifeID: child.LifeID, Level: 3}
		metadata.ACL.LifeID = child.LifeID
		f.store.metadata[id] = metadata
		payload, err := json.Marshal(ref)
		if err != nil {
			f.t.Fatal(err)
		}
		f.store.events = append(f.store.events, api.Event{Schema: api.SchemaVersion, Config: "case-grants",
			Kind: "blob.committed", Actor: api.Actor{Kind: "lane", ID: child.LifeID, LifeID: child.LifeID, Level: 3},
			LifeID: child.LifeID, Run: 1, Origin: "service", Payload: payload})
		return ref
	}
	candidate := put("candidate", input)
	plan := api.WorkerPlan{Schema: "laneboss.worker-plan.v2", Kind: "test", Executable: api.Executable{
		ID: "runtime-shell", SHA256: manifest.Hash([]byte("runtime")), Version: "1"},
		Argv: []string{"sh", "task.sh"}, Input: candidate, GrantSetID: child.ID, Budget: budget}
	return api.TestChildRequest{Child: api.LifeRef{LifeID: child.LifeID, Run: 1},
		Candidate: candidate, TestPlan: put("test-plan", plan), Budget: budget}
}
