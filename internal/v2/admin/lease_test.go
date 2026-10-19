package admin

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/identity"
	"laneboss.io/laneboss/internal/v2/api"
)

func testDigest(data string) api.Digest {
	sum := sha256.Sum256([]byte(data))
	return api.Digest(hex.EncodeToString(sum[:]))
}

func testBinding() installation {
	artifact := api.ReleaseArtifact{OS: "linux", Arch: runtime.GOARCH, Bytes: 12, SHA256: testDigest("artifact")}
	return installation{
		Schema: adminSchema, Revision: api.ContractRevision, Config: "admin-case", Generation: 1,
		Release: api.ReleaseManifest{Version: identity.Version, Protocol: api.Protocol, Schema: api.SchemaVersion,
			Artifacts: []api.ReleaseArtifact{artifact}, SourceSHA256: testDigest("source"),
			VendorManifest: api.BlobRef{ID: "vendors", SHA256: testDigest("vendors"), Bytes: 12, Class: "manifest"}},
		Artifact: artifact, Service: account{Name: "lb-service", UID: 61000, GID: 61000},
		Lanes: []account{{Name: "lb-lane-a", UID: 61001, GID: 61001}, {Name: "lb-lane-b", UID: 61002, GID: 61002}},
	}
}

func testAllocation() api.HelperLeaseRequest {
	return api.HelperLeaseRequest{Config: "admin-case", LifeID: "life-a", Backend: "linux-bwrap-landlock",
		Cause:             testCause(api.InternalHelperAllocate, "life-a"),
		RuntimeManifestID: "runtime", Budget: api.Budget{WallMS: 1000, MemoryBytes: 1048576, Processes: 8, DiskBytes: 1048576}}
}

func testCause(kind api.InternalKind, life api.ID) api.InternalIntent {
	return api.InternalIntent{ID: "intent-a", Kind: kind, Config: "admin-case",
		Actor: api.Actor{Kind: "service", ID: "service-a"}, RequestedBy: api.Actor{Kind: "human", ID: "human-a"},
		CauseOperationID: "operation-a", CauseRequestID: "request-a", EffectID: "effect-a",
		Target: api.LifeRef{LifeID: life, Run: 1}, LogicalTurnID: "turn-a"}
}

func testRelease(lease api.HelperLease, observation api.ProcessObservation) api.HelperReleaseRequest {
	return api.HelperReleaseRequest{LeaseID: lease.ID, Observation: observation,
		Cause: testCause(api.InternalHelperRelease, observation.Handle.Target.LifeID)}
}

type memoryLeases struct {
	records   []leaseRecord
	saveCount int
	failSave  int
	failRead  bool
}

func (s *memoryLeases) Records() ([]leaseRecord, error) {
	if s.failRead {
		return nil, failure(api.CodeIntegrity, "injected read failure")
	}
	return append([]leaseRecord{}, s.records...), nil
}

func (s *memoryLeases) Save(record leaseRecord) error {
	s.saveCount++
	if s.failSave == s.saveCount {
		return failure(api.CodeIntegrity, "injected durable write failure")
	}
	for index := range s.records {
		if s.records[index].Lease.ID == record.Lease.ID {
			s.records[index] = record
			return nil
		}
	}
	s.records = append(s.records, record)
	return nil
}

type observedResources struct {
	measureErr error
	facts      *releaseFacts
	ensureErr  error
	quietErr   error
	removeErr  error
	ensured    []api.ID
	quiet      []api.ID
	removed    []api.ID
}

func (r *observedResources) ObserveRelease(_ context.Context, record leaseRecord) (releaseFacts, error) {
	if r.measureErr != nil {
		return releaseFacts{}, r.measureErr
	}
	if r.facts != nil {
		return *r.facts, nil
	}
	zero := uint64(0)
	return releaseFacts{Observation: testObservation(record.Lease),
		LiveConnections: &zero, QueuedJobs: &zero, WritableExports: &zero}, nil
}

func releaseError(ctx context.Context, m *leaseManager, request api.HelperReleaseRequest) error {
	_, err := m.release(ctx, request)
	return err
}

func (r *observedResources) Ensure(_ context.Context, record leaseRecord) error {
	r.ensured = append(r.ensured, record.Lease.ID)
	return r.ensureErr
}
func (r *observedResources) Quiescent(_ context.Context, record leaseRecord) error {
	r.quiet = append(r.quiet, record.Lease.ID)
	return r.quietErr
}
func (r *observedResources) Remove(_ context.Context, record leaseRecord) error {
	r.removed = append(r.removed, record.Lease.ID)
	return r.removeErr
}

func testManager() (*leaseManager, *memoryLeases, *observedResources) {
	store := &memoryLeases{}
	resources := &observedResources{}
	return &leaseManager{binding: testBinding(), bootID: "boot-a", store: store, resources: resources}, store, resources
}

func requireCode(t *testing.T, err error, code api.ErrorCode) {
	t.Helper()
	var typed *api.Error
	if !errors.As(err, &typed) || typed.Code != code {
		t.Fatalf("want typed %s, got %v", code, err)
	}
}

func testObservation(lease api.HelperLease) api.ProcessObservation {
	survivors, exit := uint64(0), 0
	return api.ProcessObservation{Handle: api.ProcessHandle{ID: "run-handle", Target: api.LifeRef{LifeID: "life-a", Run: 1},
		ContainmentID: lease.ContainmentID, Generation: "kernel-generation"}, State: "exited",
		Survivors: &survivors, ExitCode: &exit, PromptStatus: "completed", ObservedAt: api.Timestamp(time.Now().UTC().Format(time.RFC3339Nano))}
}

func TestLeaseReservation(t *testing.T) {
	ctx := context.Background()
	m, store, resources := testManager()
	store.failSave = 1
	lease, err := m.allocate(ctx, testAllocation())
	requireCode(t, err, api.CodeIntegrity)
	if lease.ID != "" || len(store.records) != 0 || len(resources.ensured) != 0 {
		t.Fatal("a failed durable reservation created resources or returned a lease")
	}
	store.failSave = 0
	resources.ensureErr = failure(api.CodePrerequisite, "injected kernel refusal")
	lease, err = m.allocate(ctx, testAllocation())
	requireCode(t, err, api.CodePrerequisite)
	if lease.ID != "" || len(store.records) != 1 || store.records[0].Phase != "reserved" {
		t.Fatal("kernel failure lost its durable reservation or returned success")
	}
	reserved := store.records[0].Lease
	resources.ensureErr = nil
	lease, err = m.allocate(ctx, testAllocation())
	if err != nil {
		t.Fatal(err)
	}
	if lease != reserved || store.records[0].Phase != "active" {
		t.Fatal("recovery changed the reservation identity")
	}
	before := store.saveCount
	replayed, err := m.allocate(ctx, testAllocation())
	if err != nil || replayed != lease || store.saveCount != before {
		t.Fatal("identical replay allocated or rewrote a lease")
	}
	changed := testAllocation()
	changed.Budget.Processes++
	_, err = m.allocate(ctx, changed)
	requireCode(t, err, api.CodeIdempotencyConflict)
}

func TestPoolAndStoreFailures(t *testing.T) {
	m, store, _ := testManager()
	request := testAllocation()
	first, err := m.allocate(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	request.LifeID = "life-b"
	request.Cause.Target.LifeID = request.LifeID
	second, err := m.allocate(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if first.UID == second.UID || first.ID == second.ID || first.ContainmentID == second.ContainmentID || first.UID == m.binding.Service.UID {
		t.Fatal("concurrent lives share an account or containment")
	}
	request.LifeID = "life-c"
	request.Cause.Target.LifeID = request.LifeID
	_, err = m.allocate(context.Background(), request)
	requireCode(t, err, api.CodeUnavailable)
	store.failRead = true
	_, err = m.allocate(context.Background(), request)
	requireCode(t, err, api.CodeIntegrity)
	store.failRead = false
	m.bootID = "another-boot"
	_, err = m.allocate(context.Background(), testAllocation())
	requireCode(t, err, api.CodeContainmentUnknown)
	if _, err := m.records(); err != nil {
		t.Fatal("prior boot prevented helper recovery startup")
	}
}

func TestReleaseRetainsUnknown(t *testing.T) {
	ctx := context.Background()
	m, store, resources := testManager()
	lease, err := m.allocate(ctx, testAllocation())
	if err != nil {
		t.Fatal(err)
	}
	observation := testObservation(lease)
	observation.Survivors = nil
	err = releaseError(ctx, m, testRelease(lease, observation))
	requireCode(t, err, api.CodeContainmentUnknown)
	if len(resources.quiet) != 0 {
		t.Fatal("invalid observation reached collection")
	}
	observation = testObservation(lease)
	resources.quietErr = failure(api.CodeContainmentUnknown, "kernel reports survivors")
	err = releaseError(ctx, m, testRelease(lease, observation))
	requireCode(t, err, api.CodeContainmentUnknown)
	if store.records[0].Phase != "active" || len(resources.removed) != 0 {
		t.Fatal("unknown containment was released")
	}
	resources.quietErr = nil
	resources.removeErr = failure(api.CodeContainmentUnknown, "kernel rmdir refusal")
	err = releaseError(ctx, m, testRelease(lease, observation))
	requireCode(t, err, api.CodeContainmentUnknown)
	if store.records[0].Phase != "releasing" {
		t.Fatal("collection failure lost the durable releasing phase")
	}
	resources.removeErr = nil
	if err := releaseError(ctx, m, testRelease(lease, observation)); err != nil {
		t.Fatal(err)
	}
	if store.records[0].Phase != "released" {
		t.Fatal("successful kernel collection was not recorded")
	}
	removed, checked := len(resources.removed), len(resources.quiet)
	if err := releaseError(ctx, m, testRelease(lease, observation)); err != nil {
		t.Fatal(err)
	}
	if len(resources.removed) != removed || len(resources.quiet) != checked+1 {
		t.Fatal("release replay must recheck quiescence without deleting again")
	}
	_, err = m.allocate(ctx, testAllocation())
	requireCode(t, err, api.CodeConflict)
}

func TestActivationSaveFailure(t *testing.T) {
	m, store, _ := testManager()
	store.failSave = 2
	lease, err := m.allocate(context.Background(), testAllocation())
	requireCode(t, err, api.CodeIntegrity)
	if lease.ID != "" || store.records[0].Phase != "reserved" {
		t.Fatal("uncommitted activation returned success")
	}
	store.failSave = 0
	if _, err := m.allocate(context.Background(), testAllocation()); err != nil {
		t.Fatal(err)
	}
}

func TestPreparationNeedsGate(t *testing.T) {
	m, _, _ := testManager()
	lease, err := m.allocate(context.Background(), testAllocation())
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := m.prepare(context.Background(), api.HelperLaunchRequest{LeaseID: lease.ID,
		Cause:          testCause(api.InternalHelperPrepare, "life-a"),
		PreparedSpecID: "prepared-spec", SpecSHA256: testDigest("spec")})
	requireCode(t, err, api.CodeContainmentUnknown)
	if !reflect.DeepEqual(prepared, api.PreparedLaunch{}) {
		t.Fatal("missing bootstrap fabricated a prepared process")
	}
}

func TestHelperCausality(t *testing.T) {
	ctx := context.Background()
	for _, change := range []func(*api.HelperLeaseRequest){
		func(r *api.HelperLeaseRequest) { r.Cause = api.InternalIntent{} },
		func(r *api.HelperLeaseRequest) { r.Cause.Config = "other" },
		func(r *api.HelperLeaseRequest) { r.Cause.Target.LifeID = "other-life" },
		func(r *api.HelperLeaseRequest) { r.Cause.Kind = api.InternalMailDeliver },
		func(r *api.HelperLeaseRequest) { r.Cause.Actor.Kind = "lane" },
		func(r *api.HelperLeaseRequest) { r.Cause.CauseOperationID = "" },
		func(r *api.HelperLeaseRequest) { r.Cause.EffectID = "" },
	} {
		m, store, resources := testManager()
		request := testAllocation()
		change(&request)
		_, err := m.allocate(ctx, request)
		if err == nil || store.saveCount != 0 || len(resources.ensured) != 0 {
			t.Fatal("acceptance: invalid helper cause used")
		}
		requireCode(t, err, api.CodeInvalid)
	}
	m, _, _ := testManager()
	if _, err := m.allocate(ctx, testAllocation()); err != nil {
		t.Fatal(err)
	}
	changed := testAllocation()
	changed.Cause.CauseOperationID = "different-operation"
	_, err := m.allocate(ctx, changed)
	requireCode(t, err, api.CodeIdempotencyConflict)
}

func TestReleaseCausality(t *testing.T) {
	ctx := context.Background()
	m, store, resources := testManager()
	lease, err := m.allocate(ctx, testAllocation())
	if err != nil {
		t.Fatal(err)
	}
	request := testRelease(lease, testObservation(lease))
	invalid := request
	invalid.Cause.Target.Run++
	requireCode(t, releaseError(ctx, m, invalid), api.CodeInvalid)
	if len(resources.quiet) != 0 || len(resources.removed) != 0 {
		t.Fatal("invalid release cause reached collection")
	}
	if err := releaseError(ctx, m, request); err != nil {
		t.Fatal(err)
	}
	if store.records[0].Release == nil || !reflect.DeepEqual(*store.records[0].Release, request) {
		t.Fatal("release lost its causal receipt")
	}
	changed := request
	changed.Cause.EffectID = "other-effect"
	err = releaseError(ctx, m, changed)
	if err == nil {
		t.Fatal("acceptance: changed release replay")
	}
	requireCode(t, err, api.CodeIdempotencyConflict)
}

func TestStrictRequests(t *testing.T) {
	for _, body := range []string{
		`{"lease_id":"a","lease_id":"b"}`,
		`{"lease_id":null}`, `{} {}`, `{"argv":["sh"]}`, `{"path":"/root"}`,
		`{"lease_id":"\ud800"}`, string([]byte{0xff}),
	} {
		t.Run(strings.ReplaceAll(body[:min(len(body), 16)], "/", "_"), func(t *testing.T) {
			var request api.HelperLaunchRequest
			err := decodeStrict([]byte(body), &request)
			// encoding/json replaces lone surrogates. The ID validator must
			// still refuse the replacement, never treat it as an opaque ID.
			if err == nil {
				err = validatePreparation(request)
			}
			requireCode(t, err, api.CodeInvalid)
		})
	}
	var empty api.Empty
	if err := decodeStrict([]byte("{ }"), &empty); err != nil {
		t.Fatal(err)
	}
	request := testAllocation()
	encoded, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	var decoded api.HelperLeaseRequest
	if err := decodeStrict(encoded, &decoded); err != nil || !reflect.DeepEqual(request, decoded) {
		t.Fatal("valid typed allocation did not round trip")
	}
}

func TestBindingAndInputRefusals(t *testing.T) {
	b := testBinding()
	if err := b.validate(); err != nil {
		t.Fatal(err)
	}
	b.Lanes[0].UID = b.Service.UID
	requireCode(t, b.validate(), api.CodeIntegrity)
	b = testBinding()
	b.Release.Schema++
	requireCode(t, b.validate(), api.CodeVersion)
	request := testAllocation()
	request.LifeID = "../escape"
	requireCode(t, validateAllocation(request, "admin-case"), api.CodeInvalid)
	request = testAllocation()
	request.Backend = "unknown"
	requireCode(t, validateAllocation(request, "admin-case"), api.CodeInvalid)
	request = testAllocation()
	request.Budget.Processes = 0
	requireCode(t, validateAllocation(request, "admin-case"), api.CodeInvalid)
	requireCode(t, RunInternal(context.Background(), "admin-case", []string{"--", "sh"}), api.CodeForbidden)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	m, store, resources := testManager()
	_, err := m.allocate(ctx, testAllocation())
	requireCode(t, err, api.CodeCancelled)
	if store.saveCount != 0 || len(resources.ensured) != 0 {
		t.Fatal("cancelled operation created a lease")
	}
}

func TestBindingRevision(t *testing.T) {
	b := testBinding()
	if err := b.validate(); err != nil {
		t.Fatal(err)
	}
	b.Revision = "v2.0-draft.2"
	err := b.validate()
	if err == nil {
		t.Fatal("acceptance: mixed helper revision")
	}
	requireCode(t, err, api.CodeVersion)
}
