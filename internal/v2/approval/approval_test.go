package approval

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

// These are focused dependency fixtures, not an authenticated service, confined
// renderer, durable store or E2E. Unused dependency methods have nil embedded
// interfaces so an unexpected call fails rather than returning fake success.
type fixtureStore struct {
	api.StateStore
	t            *testing.T
	launch       api.LaunchRecord
	currentLane  *api.Lane
	change       api.ChangeRequest
	blobs        map[api.ID][]byte
	launchErr    error
	changeErr    error
	blobErr      error
	launches     int
	changes      int
	reads        int
	mutations    int
	alterChunk   func(api.BlobChunk) api.BlobChunk
	snapshot     *api.OrgSnapshot
	lookup       func(api.Scope, api.RequestKey) (api.MutationReceipt, error)
	transact     func(api.Transaction) (api.Commit, error)
	await        func(api.Scope, api.RequestKey) (api.MutationReceipt, error)
	approval     *api.ChangeApproval
	approvalRead func(api.Scope, api.ID) (api.ChangeApproval, error)
	metadata     map[api.ID]api.BlobRef
	receipts     map[fixtureReceiptDomain]api.MutationReceipt
}

func (f *fixtureStore) Lane(_ context.Context, _ api.Scope, target api.LifeRef) (api.Lane, error) {
	if f.currentLane != nil {
		return *f.currentLane, nil
	}
	if target != f.launch.Target {
		return api.Lane{}, &api.Error{Code: api.CodeNotFound}
	}
	return api.Lane{LifeID: target.LifeID, Run: target.Run, LaunchID: f.launch.ID}, nil
}

type fixtureReceiptDomain struct {
	config    string
	kind      string
	principal api.ID
	life      api.ID
	method    api.Method
	key       api.ID
}

func fixtureDomain(scope api.Scope, key api.RequestKey) fixtureReceiptDomain {
	return fixtureReceiptDomain{config: scope.Config, kind: scope.Actor.Kind,
		principal: scope.Actor.ID, life: scope.Actor.LifeID, method: key.Method, key: key.IdempotencyKey}
}

func (f *fixtureStore) LookupReceipt(_ context.Context, scope api.Scope, key api.RequestKey) (api.MutationReceipt, error) {
	if f.lookup != nil {
		return f.lookup(scope, key)
	}
	receipt, exists := f.receipts[fixtureDomain(scope, key)]
	if !exists {
		return api.MutationReceipt{}, &api.Error{Code: api.CodeNotFound}
	}
	if receipt.Key.RequestSHA256 != key.RequestSHA256 {
		return api.MutationReceipt{}, &api.Error{Code: api.CodeIdempotencyConflict}
	}
	return receipt, nil
}

func (f *fixtureStore) OrgSnapshot(_ context.Context, scope api.Scope, request api.OrgSnapshotRequest) (api.OrgSnapshot, error) {
	if f.snapshot == nil {
		return api.OrgSnapshot{}, api.NotImplemented("lb-v2-service", "store.OrgSnapshot")
	}
	if request.Generation != f.change.BaseGeneration || scope.Config != f.launch.Config || request.OrgID != f.snapshot.Ref.OrgID {
		f.t.Fatal("snapshot read did not request the authentic approved base")
	}
	return *f.snapshot, nil
}

func (f *fixtureStore) ObjectMetadata(_ context.Context, scope api.Scope, id api.ID) (api.ObjectMetadata, error) {
	data, exists := f.blobs[id]
	if !exists || scope.Config != f.launch.Config {
		return api.ObjectMetadata{}, &api.Error{Code: api.CodeNotFound}
	}
	ref := testRef(string(id), data)
	if override, exists := f.metadata[id]; exists {
		ref = override
	}
	return api.ObjectMetadata{Ref: ref, ACL: api.ObjectACL{Config: scope.Config}}, nil
}

func (f *fixtureStore) Approval(_ context.Context, scope api.Scope, id api.ID) (api.ChangeApproval, error) {
	if f.approvalRead != nil {
		return f.approvalRead(scope, id)
	}
	if f.approval == nil {
		return api.ChangeApproval{}, api.NotImplemented("lb-v2-service", "store.Approval")
	}
	if f.approval.ID != id {
		return api.ChangeApproval{}, &api.Error{Code: api.CodeNotFound}
	}
	return *f.approval, nil
}

func (f *fixtureStore) AwaitReceipt(_ context.Context, scope api.Scope, key api.RequestKey) (api.MutationReceipt, error) {
	if f.await == nil {
		return api.MutationReceipt{}, api.NotImplemented("lb-v2-service", "store.AwaitReceipt")
	}
	return f.await(scope, key)
}

func (f *fixtureStore) Launch(_ context.Context, _ api.ID) (api.LaunchRecord, error) {
	f.launches++
	return f.launch, f.launchErr
}

func (f *fixtureStore) Change(_ context.Context, scope api.Scope, id api.ID) (api.ChangeRequest, error) {
	f.changes++
	if scope.Config != f.launch.Config || id != f.change.ID {
		return api.ChangeRequest{}, &api.Error{Code: api.CodeNotFound}
	}
	return f.change, f.changeErr
}

func (f *fixtureStore) Blob(_ context.Context, scope api.Scope, request api.BlobReadRequest) (api.BlobChunk, error) {
	f.reads++
	if f.blobErr != nil {
		return api.BlobChunk{}, f.blobErr
	}
	data, ok := f.blobs[request.ObjectID]
	if scope.Config != f.launch.Config || !ok {
		return api.BlobChunk{}, &api.Error{Code: api.CodeNotFound}
	}
	if request.Offset < 0 || request.Offset > int64(len(data)) || request.Limit < 1 || request.Limit > api.MaxChunkBytes {
		f.t.Fatal("blob reader issued an out-of-bound request")
	}
	end := min(request.Offset+int64(request.Limit), int64(len(data)))
	part := append([]byte{}, data[request.Offset:end]...)
	chunk := api.BlobChunk{ObjectID: request.ObjectID, Offset: request.Offset, Data: part, SHA256: testDigest(part)}
	if f.alterChunk != nil {
		chunk = f.alterChunk(chunk)
	}
	return chunk, nil
}

func (f *fixtureStore) Transact(_ context.Context, tx api.Transaction) (api.Commit, error) {
	f.mutations++
	if f.transact != nil {
		return f.transact(tx)
	}
	f.t.Error("mutation crossed an unresolved frozen contract boundary")
	return api.Commit{}, &api.Error{Code: api.CodeIntegrity}
}

type fixtureHuman struct {
	api.HumanVerifier
	t       *testing.T
	checked int
	check   func(api.Scope, api.ProofRef, api.HumanChallengeRequest) (api.VerifiedHumanProof, error)
}

func (f *fixtureHuman) CheckProof(_ context.Context, scope api.Scope, proof api.ProofRef, target api.HumanChallengeRequest) (api.VerifiedHumanProof, error) {
	f.checked++
	if f.check != nil {
		return f.check(scope, proof, target)
	}
	f.t.Error("proof was checked before resolving its approved org snapshot")
	return api.VerifiedHumanProof{}, &api.Error{Code: api.CodeIntegrity}
}

type fixturePublisher struct{ api.OrgPublisher }

type fixtureWorker struct {
	api.DataWorker
	t       *testing.T
	renders int
	render  func(api.ChangeRequest) (api.ChangeRequest, error)
}

func (f *fixtureWorker) Render(_ context.Context, request api.ChangeRequest) (api.ChangeRequest, error) {
	f.renders++
	if f.render != nil {
		return f.render(request)
	}
	f.t.Error("renderer ran before resolving the org/base/source inventory")
	return api.ChangeRequest{}, &api.Error{Code: api.CodeIntegrity}
}

type fixtureClock struct{ now time.Time }

func (f fixtureClock) Now() time.Time { return f.now }

type fixture struct {
	t       *testing.T
	service *Service
	store   *fixtureStore
	human   *fixtureHuman
	worker  *fixtureWorker
	scope   api.Scope
	request api.ChangeProposeRequest
	objects int
}

func (f *fixture) retainRendered(data []byte, class string) api.BlobRef {
	f.t.Helper()
	f.objects++
	ref := testClassRef("rendered-"+strconv.Itoa(f.objects), data, class)
	f.store.blobs[ref.ID] = append([]byte(nil), data...)
	if f.store.metadata == nil {
		f.store.metadata = make(map[api.ID]api.BlobRef)
	}
	f.store.metadata[ref.ID] = ref
	return ref
}

func testDigest(data []byte) api.Digest {
	sum := sha256.Sum256(data)
	return api.Digest(hex.EncodeToString(sum[:]))
}

func testRef(id string, data []byte) api.BlobRef {
	return testClassRef(id, data, "artifact")
}

func testClassRef(id string, data []byte, class string) api.BlobRef {
	return api.BlobRef{ID: api.ID(id), SHA256: testDigest(data), Bytes: int64(len(data)), Class: class}
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{t: t}
	f.scope = api.Scope{Config: "example", Source: "cli", LaunchID: "launch-six",
		Actor:              api.Actor{Kind: "lane", ID: "instance-six", LifeID: "life-six", Level: 6, Role: "policy"},
		EndpointGeneration: 2, PolicyGeneration: 4}
	reason, source, diff := []byte("review these exact bytes\n"), []byte("script bytes\n"), []byte("+script bytes\n")
	sourceRef := testRef("source", source)
	f.request = api.ChangeProposeRequest{OrgID: "org-one", BaseGeneration: 7,
		Reason: testRef("reason", reason), Files: []api.ResourceDelta{
			{Path: "shared/scripts/demo.sh", Action: "add", Mode: 0755, After: &sourceRef},
		}}
	f.store = &fixtureStore{t: t, launch: api.LaunchRecord{ID: f.scope.LaunchID,
		Config: f.scope.Config, Actor: f.scope.Actor, Target: api.LifeRef{LifeID: f.scope.Actor.LifeID, Run: 1},
		EndpointGeneration: f.scope.EndpointGeneration}, blobs: map[api.ID][]byte{
		"source": source, "reason": reason, "diff": diff,
	}}
	f.store.change = api.ChangeRequest{Config: f.scope.Config, Reason: f.request.Reason,
		SourceSnapshot: api.OrgSnapshotRef{OrgID: f.request.OrgID, Generation: f.request.BaseGeneration,
			ManifestSHA256: testDigest([]byte("approved source inventory"))},
		OwnershipManifest: testClassRef("ownership", []byte("source ownership inventory\n"), "manifest"),
		ID:                "change-one", OrgID: f.request.OrgID,
		Requester: f.scope.Actor, BaseGeneration: f.request.BaseGeneration, Files: f.request.Files,
		Derived: []api.ResourceDelta{}, Diff: testRef("diff", diff),
		Renderer: api.Executable{ID: "renderer", Version: "2.0", SHA256: testDigest([]byte("renderer artifact"))},
		Status:   "proposed", CreatedAt: "2026-10-15T08:00:00Z", ExpiresAt: "2026-10-16T08:00:00Z"}
	var err error
	f.store.change.ManifestSHA256, err = ManifestDigest(f.store.change)
	if err != nil {
		t.Fatal(err)
	}
	f.human = &fixtureHuman{t: t}
	f.worker = &fixtureWorker{t: t}
	f.service, err = New(Dependencies{Store: f.store, Human: f.human, Worker: f.worker,
		Publisher: &fixturePublisher{}, Clock: fixtureClock{now: time.Date(2026, 10, 15, 9, 0, 0, 0, time.UTC)}})
	if err != nil {
		t.Fatal(err)
	}
	return f
}

type fixtureFrame []byte

func (f fixtureFrame) Bytes() []byte { return []byte(f) }

func (fixtureFrame) Verify(context.Context, api.ConnectionContext) error {
	return api.NotImplemented("lb-v2-approval", "fixture transport is not authenticated")
}

func (f *fixture) bound(method api.Method, request any, human bool) api.Scope {
	f.t.Helper()
	scope := f.scope
	if human {
		scope.Actor = api.Actor{Kind: "human", ID: "person-one"}
		scope.LaunchID = ""
	}
	params, err := json.Marshal(request)
	if err != nil {
		f.t.Fatal(err)
	}
	scope.Request = api.Request{Protocol: api.Protocol, Schema: api.SchemaVersion,
		Config: scope.Config, Method: method, Params: params,
		RequestID: api.ID(strings.Repeat("r", 32)), IdempotencyKey: api.ID(strings.Repeat("k", 32))}
	digest, err := api.RequestDigest(scope.Request)
	if err != nil {
		f.t.Fatal(err)
	}
	scope.Request.RequestSHA256 = digest
	if human && method == "org.change.approve" {
		scope.Request.Proof = &api.ProofRef{ID: "proof-one", RequestSHA256: digest, ExpiresAt: "2026-10-15T09:02:00Z"}
	}
	frame, err := json.Marshal(scope.Request)
	if err != nil {
		f.t.Fatal(err)
	}
	scope.Frame = fixtureFrame(frame)
	if f.store.receipts == nil {
		f.store.receipts = make(map[fixtureReceiptDomain]api.MutationReceipt)
	}
	key := requestKey(scope)
	domain := fixtureDomain(scope, key)
	if _, exists := f.store.receipts[domain]; !exists {
		f.store.receipts[domain] = api.MutationReceipt{Config: scope.Config, Key: key, Actor: scope.Actor,
			RawRequest: append([]byte(nil), frame...), Operation: api.Operation{ID: "operation-one", Status: "pending"}}
	}
	return scope
}

func codeIs(t *testing.T, err error, code api.ErrorCode) {
	t.Helper()
	var typed *api.Error
	if !errors.As(err, &typed) || typed.Code != code {
		t.Fatalf("expected typed %s, got %v", code, err)
	}
}

func (f *fixture) noEffects() {
	f.t.Helper()
	if f.store.mutations != 0 || f.human.checked != 0 || f.worker.renders != 0 {
		f.t.Fatal("early refusal changed resources, checked proof or ran renderer")
	}
}

func TestNewDependencies(t *testing.T) {
	f := newFixture(t)
	for _, edit := range []func(*Dependencies){
		func(d *Dependencies) { d.Store = nil },
		func(d *Dependencies) { d.Human = nil },
		func(d *Dependencies) { d.Worker = nil },
		func(d *Dependencies) { d.Publisher = nil },
		func(d *Dependencies) { d.Clock = nil },
		func(d *Dependencies) { var store *fixtureStore; d.Store = store },
	} {
		deps := f.service.deps
		edit(&deps)
		service, err := New(deps)
		codeIs(t, err, api.CodePrerequisite)
		if service != nil {
			t.Fatal("missing dependency returned a service")
		}
	}
}

func TestL6Authority(t *testing.T) {
	for _, level := range []int{0, 3, 4, 5, 7} {
		t.Run("level_"+strconv.Itoa(level), func(t *testing.T) {
			f := newFixture(t)
			f.scope.Actor.Level = level
			f.store.launch.Actor = f.scope.Actor
			scope := f.bound("org.change.propose", f.request, false)
			_, err := f.service.OrgChangePropose(context.Background(), scope, f.request)
			codeIs(t, err, api.CodeForbidden)
			if f.store.launches != 0 || f.store.reads != 0 {
				t.Fatal("lower level reached protected resource reads")
			}
			f.noEffects()
		})
	}
	for name, alter := range map[string]func(*api.LaunchRecord){
		"revoked": func(r *api.LaunchRecord) { r.Revoked = true },
		"config":  func(r *api.LaunchRecord) { r.Config = "other" },
		"life":    func(r *api.LaunchRecord) { r.Target.LifeID = "other-life" },
		"actor":   func(r *api.LaunchRecord) { r.Actor.ID = "other-instance" },
		"launch":  func(r *api.LaunchRecord) { r.ID = "other-launch" },
		"binding": func(r *api.LaunchRecord) { r.EndpointGeneration++ },
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			alter(&f.store.launch)
			_, err := f.service.OrgChangePropose(context.Background(), f.bound("org.change.propose", f.request, false), f.request)
			codeIs(t, err, api.CodeForbidden)
			if f.store.reads != 0 {
				t.Fatal("stale launch reached source bytes")
			}
			f.noEffects()
		})
	}
}

func TestActorGate(t *testing.T) {
	for _, method := range []api.Method{"org.change.propose", "org.change.apply"} {
		t.Run(string(method), func(t *testing.T) {
			for _, name := range []string{"human", "l5"} {
				t.Run(name, func(t *testing.T) {
					f := newFixture(t)
					var request any = f.request
					if method == "org.change.apply" {
						request = api.ChangeApplyRequest{ChangeID: f.store.change.ID, ApprovalID: "approval-one", ExpectedGeneration: 7}
					}
					scope := f.bound(method, request, false)
					if name == "human" {
						// Even lane-shaped claims and the same role cannot turn
						// an authenticated human kind into a lane actor.
						scope.Actor.Kind = "human"
					} else {
						scope.Actor.Level = 5
					}
					// Match all recorded facts so a missing actor/level guard
					// cannot be hidden by a second stale-launch refusal.
					f.store.launch.Actor = scope.Actor
					lookups := 0
					f.store.lookup = func(api.Scope, api.RequestKey) (api.MutationReceipt, error) {
						lookups++
						return api.MutationReceipt{}, api.NotImplemented("lb-v2-service", "fixture reservation")
					}
					_, err := handlerForReplay(f, method)(context.Background(), scope, scope.Request.Params)
					codeIs(t, err, api.CodeForbidden)
					if f.store.launches != 0 || lookups != 0 || f.store.changes != 0 || f.store.reads != 0 {
						t.Fatal("non-L6 actor reached mutation authority or retained data")
					}
					f.noEffects()
				})
			}
		})
	}
}

func TestScopeIntent(t *testing.T) {
	for name, alter := range map[string]func(*api.Scope){
		"digest":  func(s *api.Scope) { s.Request.RequestSHA256 = testDigest([]byte("other")) },
		"config":  func(s *api.Scope) { s.Request.Config = "other" },
		"method":  func(s *api.Scope) { s.Request.Method = "org.change.apply" },
		"params":  func(s *api.Scope) { s.Request.Params = []byte(`{"org_id":"other"}`) },
		"schema":  func(s *api.Scope) { s.Request.Schema++ },
		"key":     func(s *api.Scope) { s.Request.IdempotencyKey = "short" },
		"request": func(s *api.Scope) { s.Request.RequestID = "short" },
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			scope := f.bound("org.change.propose", f.request, false)
			alter(&scope)
			_, err := f.service.OrgChangePropose(context.Background(), scope, f.request)
			codeIs(t, err, api.CodeInvalid)
			if f.store.launches != 0 || f.store.reads != 0 {
				t.Fatal("unbound request reached protected data")
			}
			f.noEffects()
		})
	}
}

func TestMutationContractStops(t *testing.T) {
	f := newFixture(t)
	proposed, err := f.service.OrgChangePropose(context.Background(), f.bound("org.change.propose", f.request, false), f.request)
	codeIs(t, err, api.CodeNotImplemented)
	if proposed.ID != "" || f.store.reads < 2 {
		t.Fatal("proposal did not verify its bytes before stopping at org resolution")
	}
	request := api.ChangeApproveRequest{ChangeID: f.store.change.ID, ManifestSHA256: f.store.change.ManifestSHA256,
		BaseGeneration: f.store.change.BaseGeneration}
	approved, err := f.service.OrgChangeApprove(context.Background(), f.bound("org.change.approve", request, true), request)
	codeIs(t, err, api.CodeNotImplemented)
	if approved.ID != "" {
		t.Fatal("unverified approval receipt was manufactured")
	}
	apply := api.ChangeApplyRequest{ChangeID: f.store.change.ID, ApprovalID: "approval-one", ExpectedGeneration: 7}
	receipt, err := f.service.OrgChangeApply(context.Background(), f.bound("org.change.apply", apply, false), apply)
	codeIs(t, err, api.CodeNotImplemented)
	if receipt.ID != "" {
		t.Fatal("application receipt was manufactured without publication")
	}
	f.noEffects()
}

func TestHumanPreflight(t *testing.T) {
	for name, alter := range map[string]func(*api.Scope){
		"lane":    func(s *api.Scope) { s.Actor.Kind = "lane" },
		"missing": func(s *api.Scope) { s.Request.Proof = nil },
		"digest":  func(s *api.Scope) { s.Request.Proof.RequestSHA256 = testDigest([]byte("wrong")) },
		"expiry":  func(s *api.Scope) { s.Request.Proof.ExpiresAt = "not-a-time" },
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			request := api.ChangeApproveRequest{ChangeID: f.store.change.ID,
				ManifestSHA256: f.store.change.ManifestSHA256, BaseGeneration: 7}
			scope := f.bound("org.change.approve", request, true)
			alter(&scope)
			_, err := f.service.OrgChangeApprove(context.Background(), scope, request)
			codeIs(t, err, api.CodeForbidden)
			if f.store.changes != 0 {
				t.Fatal("unconfirmed request read a protected change")
			}
			f.noEffects()
		})
	}
	for _, name := range []string{"staged_base", "staged_hash"} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			request := api.ChangeApproveRequest{ChangeID: f.store.change.ID,
				ManifestSHA256: f.store.change.ManifestSHA256, BaseGeneration: 7}
			if name == "staged_base" {
				request.BaseGeneration++
			} else {
				request.ManifestSHA256 = testDigest([]byte("unreviewed diff"))
			}
			_, err := f.service.OrgChangeApprove(context.Background(), f.bound("org.change.approve", request, true), request)
			codeIs(t, err, api.CodeConflict)
			f.noEffects()
		})
	}
}

func TestGetOwnerAndHistory(t *testing.T) {
	f := newFixture(t)
	request := api.ChangeGetRequest{ChangeID: f.store.change.ID}
	for _, human := range []bool{false, true} {
		scope := f.bound("org.change.get", request, human)
		if human {
			scope = bindRead(scope)
		}
		result, err := f.service.OrgChangeGet(context.Background(), scope, request)
		if err != nil || !reflect.DeepEqual(result, f.store.change) {
			t.Fatalf("authorized exact history read failed: %v", err)
		}
		result.Files[0].After.ID = "changed-by-reader"
		if f.store.change.Files[0].After.ID == "changed-by-reader" {
			t.Fatal("read returned an alias to retained state")
		}
	}
	f.scope.Actor.LifeID = "sibling-life"
	f.store.launch.Actor = f.scope.Actor
	f.store.launch.Target.LifeID = f.scope.Actor.LifeID
	_, err := f.service.OrgChangeGet(context.Background(), f.bound("org.change.get", request, false), request)
	codeIs(t, err, api.CodeNotFound)
	f.noEffects()
}

func TestGetTamperedManifest(t *testing.T) {
	f := newFixture(t)
	if err := ValidateChange(f.store.change); err != nil {
		t.Fatalf("original manifest fixture is invalid: %v", err)
	}
	f.store.change.Files[0].Mode = 0644
	digest, err := ManifestDigest(f.store.change)
	if err != nil || digest == f.store.change.ManifestSHA256 {
		t.Fatalf("tampered manifest fixture did not change only its digest binding: %v", err)
	}
	consistent, err := cloneChange(f.store.change)
	if err != nil {
		t.Fatal(err)
	}
	consistent.ManifestSHA256 = digest
	if err := ValidateChange(consistent); err != nil {
		t.Fatalf("tampered manifest fixture has another invalid field: %v", err)
	}
	request := api.ChangeGetRequest{ChangeID: f.store.change.ID}
	_, err = f.service.OrgChangeGet(context.Background(), f.bound("org.change.get", request, false), request)
	codeIs(t, err, api.CodeIntegrity)
	if err.(*api.Error).Message != "retained change manifest does not match its exact deltas" {
		t.Fatal("tampered manifest did not reach its digest comparison")
	}
	f.noEffects()
}

func TestDependencyErrors(t *testing.T) {
	f := newFixture(t)
	wanted := api.NotImplemented("lb-v2-service", "store.Launch")
	f.store.launchErr = wanted
	_, err := f.service.OrgChangePropose(context.Background(), f.bound("org.change.propose", f.request, false), f.request)
	if err != wanted {
		t.Fatalf("dependency refusal was changed: %v", err)
	}
	f.store.launchErr = nil
	wanted = api.NotImplemented("lb-v2-service", "store.Blob")
	f.store.blobErr = wanted
	_, err = f.service.OrgChangePropose(context.Background(), f.bound("org.change.propose", f.request, false), f.request)
	if err != wanted {
		t.Fatalf("blob dependency refusal was changed: %v", err)
	}
	f.noEffects()
}

func TestBlobIntegrity(t *testing.T) {
	for name, alter := range map[string]func(api.BlobChunk) api.BlobChunk{
		"hash":     func(c api.BlobChunk) api.BlobChunk { c.SHA256 = testDigest([]byte("wrong")); return c },
		"identity": func(c api.BlobChunk) api.BlobChunk { c.ObjectID = "another"; return c },
		"offset":   func(c api.BlobChunk) api.BlobChunk { c.Offset++; return c },
		"empty":    func(c api.BlobChunk) api.BlobChunk { c.Data = nil; c.SHA256 = testDigest(nil); return c },
		"overflow": func(c api.BlobChunk) api.BlobChunk {
			c.Data = append(c.Data, 'x')
			c.SHA256 = testDigest(c.Data)
			return c
		},
		"bytes": func(c api.BlobChunk) api.BlobChunk {
			c.Data[0] ^= 1
			c.SHA256 = testDigest(c.Data)
			return c
		},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			// Corrupt the data chunk only. A separate malformed EOF must not
			// mask a missing data-chunk hash check in the named red control.
			f.store.alterChunk = func(chunk api.BlobChunk) api.BlobChunk {
				if len(chunk.Data) == 0 {
					return chunk
				}
				return alter(chunk)
			}
			_, err := f.service.OrgChangePropose(context.Background(), f.bound("org.change.propose", f.request, false), f.request)
			codeIs(t, err, api.CodeIntegrity)
			f.noEffects()
		})
	}
	f := newFixture(t)
	f.store.blobs["empty"] = []byte{}
	if err := f.service.verifyBlob(context.Background(), f.scope, testRef("empty", nil)); err != nil || f.store.reads != 1 {
		t.Fatalf("empty blob existence was not checked: %v", err)
	}
	data := bytes.Repeat([]byte("content"), api.MaxChunkBytes/2)
	f.store.blobs["large"] = data
	if err := f.service.verifyBlob(context.Background(), f.scope, testRef("large", data)); err != nil || f.store.reads < 3 {
		t.Fatalf("multi-chunk blob verification failed: %v", err)
	}
	// The prefix has a valid local hash but is not the full committed object.
	prefix := testRef("large", data[:10])
	// Keep the projected metadata consistent with the prefix reference. The
	// underlying bytes are longer, so only the EOF check detects this defect.
	f.store.metadata = map[api.ID]api.BlobRef{"large": prefix}
	codeIs(t, f.service.verifyBlob(context.Background(), f.scope, prefix), api.CodeIntegrity)
}

func TestCancelled(t *testing.T) {
	f := newFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := f.service.OrgChangePropose(ctx, f.bound("org.change.propose", f.request, false), f.request)
	codeIs(t, err, api.CodeCancelled)
	if f.store.launches != 0 || f.store.reads != 0 {
		t.Fatal("cancelled operation reached dependencies")
	}
	f.noEffects()
}

func TestDeadline(t *testing.T) {
	f := newFixture(t)
	ctx, cancel := context.WithDeadline(context.Background(), time.Unix(1, 0))
	defer cancel()
	_, err := f.service.OrgChangePropose(ctx, f.bound("org.change.propose", f.request, false), f.request)
	codeIs(t, err, api.CodeDeadline)
	codeIs(t, f.service.verifyBlob(ctx, f.scope, f.request.Reason), api.CodeDeadline)
	if f.store.launches != 0 || f.store.reads != 0 {
		t.Fatal("expired deadline reached dependencies")
	}
	f.noEffects()
}

func TestBlobCancelled(t *testing.T) {
	for _, name := range []string{"empty", "nonempty"} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			data := []byte("source bytes\n")
			if name == "empty" {
				data = []byte{}
			}
			f.store.blobs["cancel-source"] = data
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			f.store.alterChunk = func(chunk api.BlobChunk) api.BlobChunk {
				cancel()
				return chunk
			}
			codeIs(t, f.service.verifyBlob(ctx, f.scope, testRef("cancel-source", data)), api.CodeCancelled)
			if f.store.reads != 1 {
				t.Fatal("cancelled blob verification performed another read")
			}
			f.noEffects()
		})
	}
}

type fixtureRegistry struct {
	methods map[api.Method]api.Handler
	failAt  int
	err     error
}

func (f *fixtureRegistry) Register(method api.Method, handler api.Handler) error {
	if len(f.methods) == f.failAt && f.err != nil {
		return f.err
	}
	if f.methods == nil {
		f.methods = make(map[api.Method]api.Handler)
	}
	if _, exists := f.methods[method]; exists {
		return &api.Error{Code: api.CodeConflict}
	}
	f.methods[method] = handler
	return nil
}

func (f *fixtureRegistry) RegisterStream(api.Method, api.StreamHandler) error {
	return &api.Error{Code: api.CodeUnsupported}
}

func TestRegisterAndDecode(t *testing.T) {
	f := newFixture(t)
	registry := &fixtureRegistry{}
	if err := f.service.Register(registry); err != nil || len(registry.methods) != 4 {
		t.Fatalf("frozen methods were not registered: %v", err)
	}
	for _, method := range []api.Method{"org.change.propose", "org.change.get", "org.change.approve", "org.change.apply"} {
		handler, ok := registry.methods[method]
		if !ok {
			t.Fatal("frozen method missing")
		}
		result, err := handler(context.Background(), f.scope, []byte(`{"unexpected":true}`))
		codeIs(t, err, api.CodeInvalid)
		if result != nil {
			t.Fatal("malformed parameters returned a successful object")
		}
	}
	request := api.ChangeGetRequest{ChangeID: f.store.change.ID}
	scope := f.bound("org.change.get", request, false)
	result, err := registry.methods["org.change.get"](context.Background(), scope, scope.Request.Params)
	if err != nil {
		t.Fatal(err)
	}
	var got api.ChangeRequest
	if err = DecodeJSON(result, &got); err != nil || got.ID != request.ChangeID {
		t.Fatalf("registered read did not return exact typed object: %v", err)
	}
	wanted := &api.Error{Code: api.CodeConflict, Message: "registry conflict"}
	failed := &fixtureRegistry{failAt: 1, err: wanted}
	if err = f.service.Register(failed); err != wanted || len(failed.methods) != 1 {
		t.Fatal("registration error was swallowed or later methods were registered")
	}
}
