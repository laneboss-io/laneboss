package lifecycle

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

// This in-memory dependency model exercises the planner's actual selectors and
// durable fences. It is not a helper, Git, kernel, credential or driver E2E.
// No caller gives PlanLaunch a workspace, executable, plan or binding.
type launchFixture struct {
	*fixture
	store   *launchFixtureStore
	ports   *launchFixturePorts
	request api.StartRequest
	scope   api.Scope
}

type launchFixtureStore struct {
	*fixtureStore
	plans                  map[api.ID]api.LaunchPlanRecord
	effects                map[api.ID]api.EffectRecord
	bindings               map[api.ID]api.LaunchBindingRequest
	projections            map[api.ID]api.CredentialProjectionRecord
	workers                map[api.ID]api.WorkerLease
	dataStages             map[api.ID]api.LaunchDataStage
	turns                  map[api.ID]api.TurnSnapshot
	fences                 map[api.ID]api.Generation
	reservationCalls       int
	reservationRequests    []api.LaunchReservationRequest
	retainCalls            int
	intentReads            int
	reservationHook        func(*api.LaunchReservation)
	completeErr            error
	retainErr              error
	continuationFrames     map[api.ID][]byte
	continuationRequestIDs map[api.ID]api.ID
	mail                   map[api.ID]api.Mail
	sources                map[api.ID]api.RetainedSource
	mailHook               func(*api.DeliveryBatch)
	cleanups               map[api.ID]PlanCleanup
	failedWrites           []failedPlanWrite
	failPlanErr            error
}

func launchClone[T any](t *testing.T, value T) T {
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

func launchIDForTest() api.ID {
	id, err := newID()
	if err != nil {
		panic(err)
	}
	return id
}

func launchMissing() error {
	return &api.Error{Code: api.CodeNotFound, Message: "fixture retained selector absent"}
}
func launchConflict() error {
	_, file, line, _ := runtime.Caller(1)
	return &api.Error{Code: api.CodeConflict, Message: fmt.Sprintf("fixture current launch fence changed at %s:%d", filepath.Base(file), line)}
}

func newLaunchFixture(t *testing.T) *launchFixture {
	f := newFixture(t)
	store := &launchFixtureStore{fixtureStore: f.store, plans: map[api.ID]api.LaunchPlanRecord{},
		effects: map[api.ID]api.EffectRecord{}, bindings: map[api.ID]api.LaunchBindingRequest{},
		projections: map[api.ID]api.CredentialProjectionRecord{},
		workers:     map[api.ID]api.WorkerLease{}, turns: map[api.ID]api.TurnSnapshot{}, fences: map[api.ID]api.Generation{},
		dataStages: map[api.ID]api.LaunchDataStage{},
		mail:       map[api.ID]api.Mail{}, sources: map[api.ID]api.RetainedSource{}}
	ports := &launchFixturePorts{f: f, store: store, allocations: map[api.ID]api.HelperLease{},
		storage: map[api.ID]api.LaunchStorage{}, slots: map[api.LifeRef]api.CredentialSlot{},
		captures: map[api.ID]api.CaptureBinding{}, calls: map[string]int{}}
	project := f.blob("installed-project", "manifest", []byte("{\"files\":[{\"name\":\"main.txt\",\"text\":\"source bytes\\n\"}]}"))
	executable := api.Executable{ID: "installed-codex", SHA256: digestOf([]byte("installed adapter executable")), Version: "wrapper-1"}
	artifact := api.Executable{ID: "fixed-worker", SHA256: digestOf([]byte("installed fixed worker")), Version: "worker-1"}
	bootstrap := api.Executable{ID: "installed-bootstrap", SHA256: digestOf([]byte("installed bootstrap helper")), Version: "bootstrap-1"}
	runtimeBytes, err := json.Marshal(api.RuntimeManifest{Schema: "laneboss.runtime.v2", Generation: 1,
		Artifact: artifact, Bootstrap: bootstrap, Objects: []api.RuntimeObject{{ID: executable.ID, Role: "runner", RootID: "installed-runners",
			RelativePath: string(executable.ID), Mode: 0555, Content: api.BlobRef{ID: executable.ID, Class: "artifact", Bytes: int64(len("installed adapter executable")), SHA256: executable.SHA256}}}, Bindings: []api.InstalledBinding{}})
	if err != nil {
		t.Fatal(err)
	}
	runtime := f.blob("installed-runtime", "manifest", runtimeBytes)
	ports.enrollment = api.LaunchEnrollment{Schema: "laneboss.launch-enrollment.v2", Config: "example", Generation: 1,
		Projects: []api.ProjectEnrollment{{ID: "project-enrollment", Generation: 1, ProjectID: "project",
			Object: project, Base: strings.Repeat("a", 40), HistoryScope: "tree"}},
		Runtimes: []api.LaunchRuntime{{EnrollmentID: "runtime-enrollment", Generation: 1, Backend: "linux-bwrap-landlock",
			Driver: api.DriverCodex, Executable: executable, SessionExecutable: executable, Manifest: runtime}},
		Supervisor: &api.Executable{ID: "installed-capture", SHA256: digestOf([]byte("installed outside supervisor")), Version: "capture-1"}}
	request := fixtureStart(f)
	ports.delegated = api.GrantSet{ID: "parent-delegation", LifeID: f.parent.LifeID, Generation: 1,
		PolicyGeneration: store.policy.Generation, ExpiresAt: "2031-01-01T00:00:00Z",
		Data: []api.DataGrant{{ID: "parent-data", SourceObjectID: project.ID, SourceSHA256: project.SHA256,
			RelativePath: ".", Destination: "/work/main", Access: "rw", Delivery: "copy", HistoryScope: "tree", Delegate: true, ExpiresAt: "2031-01-01T00:00:00Z"}},
		Profiles: []api.ProfileGrant{{ID: request.ProfileGrantID, ProfileID: "enrolled-profile", Driver: request.Driver,
			Provider: "fixture-provider", Delegate: true, ExpiresAt: "2031-01-01T00:00:00Z"},
			{ID: "fallback-grant", ProfileID: "fallback-profile", Driver: request.Driver, Provider: "fixture-provider", Delegate: true, ExpiresAt: "2031-01-01T00:00:00Z"}}}
	request.Grants.Data = []api.DataGrantRequest{{ParentGrantID: "parent-data", RelativePath: ".", Access: "rw",
		Delivery: "copy", Destination: "/work/main", ExpiresAt: "2031-01-01T00:00:00Z"}}
	request.Grants.Profiles = []api.ProfileDelegation{{ParentGrantID: request.ProfileGrantID,
		ProfileID: "enrolled-profile", ExpiresAt: "2031-01-01T00:00:00Z"},
		{ParentGrantID: "fallback-grant", ProfileID: "fallback-profile", ExpiresAt: "2031-01-01T00:00:00Z"}}
	f.service.deps.Store, f.service.deps.Grants = store, ports
	admin := &launchFixtureAdmin{ports: ports}
	f.service.deps.Sources, f.service.deps.Capture = admin, admin
	f.service.deps.Worker, f.service.deps.Credentials = &launchFixtureWorker{ports: ports}, ports
	f.service.deps.CredentialIdentity = ports
	f.service.deps.Codex, f.service.deps.Templates, f.service.deps.Guidance = ports, ports, ports
	f.service.deps.Delivery = &launchFixtureDelivery{store: store}
	scope := f.scope("lane.start", request, f.parent)
	parent := store.lanes[f.parent.LifeID]
	parent.GrantSetID = ports.delegated.ID
	store.lanes[parent.LifeID] = parent
	starter := f.addTo(parent, "lane.created", fixtureLaunchEvent(parent, scope.LaunchID),
		"service", api.Actor{Kind: "human", ID: "fixture-root"})
	var seeded api.LaunchEvent
	if err := api.DecodeObject(starter.Payload, &seeded); err != nil {
		t.Fatalf("starter fixture has no closed launch event: %v", err)
	}
	return &launchFixture{fixture: f, store: store, ports: ports, request: request, scope: scope}
}

// Empty required arrays have a different wire meaning from null. Keep the
// seeded starter and later ready-lane events inside the real closed decoder.
func fixtureLaunchEvent(lane api.Lane, launchID api.ID) api.LaunchEvent {
	return api.LaunchEvent{Task: lane.Task, LaunchID: launchID, Lane: lane, GrantSetID: lane.GrantSetID,
		PolicyGeneration: lane.PolicyGeneration, TaskSHA256: lane.Task.SHA256,
		TaskSecretNames: []string{}, TaskSecretFileNames: []string{}, SecretGrantIDs: []api.ID{}, SecretSourceVersions: []string{},
		Trigger: api.Trigger{Kind: "task", MailIDs: []api.ID{}, CausingSeqs: []api.Sequence{}}}
}

func (store *launchFixtureStore) ReserveLaunch(_ context.Context, scope api.Scope, request api.LaunchReservationRequest) (api.LaunchReservation, error) {
	if err := api.ValidateLaunchReservationRequest(scope, request); err != nil {
		return api.LaunchReservation{}, err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	store.reservationCalls++
	store.reservationRequests = append(store.reservationRequests, request)
	for _, record := range store.plans {
		if record.Reservation.OperationID == request.OperationID {
			if record.Reservation.RequestedBy != scope.Actor || record.Reservation.Config != scope.Config {
				return api.LaunchReservation{}, launchConflict()
			}
			return record.Reservation, nil
		}
	}
	if request.ContinuationID != "" {
		return store.reserveContinuation(scope, request)
	}
	key := api.RequestKey{Method: scope.Request.Method, IdempotencyKey: scope.Request.IdempotencyKey, RequestSHA256: scope.Request.RequestSHA256}
	receipt, ok := store.receipts[fixtureReceiptKey(scope, key)]
	if !ok || receipt.Operation.ID != request.OperationID || receipt.Actor != scope.Actor || receipt.Key != key || receipt.Reply != nil {
		return api.LaunchReservation{}, launchConflict()
	}
	var original api.Request
	if api.DecodeObject(receipt.RawRequest, &original) != nil || !reflect.DeepEqual(original, scope.Request) {
		return api.LaunchReservation{}, launchConflict()
	}
	digest, err := api.RequestDigest(original)
	if err != nil || digest != key.RequestSHA256 {
		return api.LaunchReservation{}, launchConflict()
	}
	r := api.LaunchReservation{ID: launchIDForTest(), Config: scope.Config, Mode: strings.TrimPrefix(string(original.Method), "lane."),
		LaunchID: launchIDForTest(), SpecID: launchIDForTest(), GrantSetID: launchIDForTest(), Generation: 1,
		PolicyGeneration: store.policy.Generation, OperationID: request.OperationID, RequestID: original.RequestID,
		RequestSHA256: digest, RequestedBy: scope.Actor, StarterChain: []api.ID{}}
	r.Authority = api.LaunchAuthority{Kind: "starter", ID: scope.LaunchID}
	if scope.Actor.Kind == "human" {
		if original.Method == "lane.start" || original.Method == "lane.adopt" {
			for _, guard := range request.Guards {
				if guard.Ticket != nil {
					ticket, exists := store.tickets[guard.Ticket.TicketID]
					if !exists || ticket.Redeemed || ticket.PrincipalID != scope.Actor.ID ||
						ticket.GrantSetID != guard.Ticket.GrantSetID || ticket.Level != guard.Ticket.Level || ticket.Role != guard.Ticket.Role ||
						ticket.Config != scope.Config || ticket.EndpointGeneration != scope.EndpointGeneration {
						return api.LaunchReservation{}, launchConflict()
					}
					if grants, exists := store.grants[ticket.GrantSetID]; !exists || grants.ID != ticket.GrantSetID || grants.Revoked {
						return api.LaunchReservation{}, launchConflict()
					}
					r.Authority = api.LaunchAuthority{Kind: "ticket", ID: guard.Ticket.TicketID}
				}
			}
		} else {
			r.Authority = api.LaunchAuthority{Kind: "proof", ID: original.Proof.ID}
		}
	}
	turn := launchIDForTest()
	if r.Mode == "start" || r.Mode == "adopt" {
		if r.Mode == "start" {
			var value api.StartRequest
			if err := api.DecodeObject(original.Params, &value); err != nil {
				return api.LaunchReservation{}, err
			}
			r.Level, r.Role, r.Driver = value.Level, value.Role, value.Driver
		} else {
			var value api.AdoptRequest
			if err := api.DecodeObject(original.Params, &value); err != nil {
				return api.LaunchReservation{}, err
			}
			r.Level, r.Role, r.Driver = value.Level, value.Role, value.Driver
		}
		r.Target = api.LifeRef{LifeID: launchIDForTest(), Run: 1}
		r.RootLifeID = r.Target.LifeID
		if scope.Actor.Kind == "lane" {
			parent := store.lanes[scope.Actor.LifeID]
			r.ParentLifeID, r.RootLifeID = parent.LifeID, parent.RootLifeID
			r.StarterChain = append(append([]api.ID{}, parent.StarterChain...), parent.LifeID)
			for _, event := range store.events {
				if event.LifeID != parent.LifeID || event.Origin != "service" || event.Kind != "lane.created" && event.Kind != "lane.adopted" {
					continue
				}
				var created api.LaunchEvent
				if api.DecodeObject(event.Payload, &created) == nil && created.Lane.LifeID == parent.LifeID &&
					created.Lane.Level == parent.Level && created.Lane.Role == parent.Role {
					r.StarterEventSeq = event.Seq
				}
			}
			if r.StarterEventSeq == 0 {
				return api.LaunchReservation{}, launchConflict()
			}
		}
	} else {
		var target api.LifeRef
		var expected api.Generation
		if r.Mode == "resume" {
			var value api.ResumeRequest
			if err := api.DecodeObject(original.Params, &value); err != nil {
				return api.LaunchReservation{}, err
			}
			target, expected = value.Target, value.ExpectedGeneration
		} else if r.Mode == "turn" {
			var value api.TurnRequest
			if err := api.DecodeObject(original.Params, &value); err != nil {
				return api.LaunchReservation{}, err
			}
			target, expected = value.Target, value.ExpectedGeneration
		} else {
			return api.LaunchReservation{}, launchConflict()
		}
		lane := store.lanes[target.LifeID]
		if lane.Run != target.Run || lane.Generation != expected || lane.Cleaned {
			return api.LaunchReservation{}, launchConflict()
		}
		r.Target, r.BaseGeneration, r.Generation = api.LifeRef{LifeID: lane.LifeID, Run: lane.Run + 1}, expected, expected+1
		r.CancellationEpoch, r.PreviousLaunchID = lane.CancellationEpoch, lane.LaunchID
		r.Level, r.Role, r.Driver = lane.Level, lane.Role, lane.Session.Driver
		r.ParentLifeID, r.RootLifeID, r.StarterChain, r.StarterEventSeq = lane.ParentLifeID, lane.RootLifeID, lane.StarterChain, lane.StarterEventSeq
	}
	originalID := launchIDForTest()
	r.OriginalRequest = api.BlobRef{ID: originalID, Class: "launch_request", Bytes: int64(len(receipt.RawRequest)), SHA256: digestOf(receipt.RawRequest)}
	store.blobs[originalID] = append([]byte{}, receipt.RawRequest...)
	store.metadata[originalID] = api.ObjectMetadata{Ref: r.OriginalRequest, Origin: "service", SourceOperationID: r.OperationID,
		ACL: api.ObjectACL{Config: r.Config, LifeID: r.Target.LifeID, Audience: "owner", Generation: r.Generation,
			Owner: api.Actor{Kind: "service", ID: "launch-service"}}}
	if err := api.ValidateLaunchReservation(r); err != nil {
		return api.LaunchReservation{}, err
	}
	store.plans[r.ID] = api.LaunchPlanRecord{Reservation: r, Generation: 1, Phase: "reserved"}
	store.fences[r.Target.LifeID] = r.CancellationEpoch
	effectID := launchIDForTest()
	cause := api.InternalIntent{ID: launchIDForTest(), Kind: api.InternalLaunchPlan, Config: r.Config,
		Actor: api.Actor{Kind: "service", ID: "launch-service"}, RequestedBy: r.RequestedBy, CauseOperationID: r.OperationID,
		CauseRequestID: r.RequestID, EffectID: effectID, Target: r.Target, LogicalTurnID: turn, CancellationEpoch: r.CancellationEpoch}
	effect := api.Effect{ID: effectID, OperationID: r.OperationID, Context: &cause, PlanLaunch: &api.LaunchPlanEffect{ReservationID: r.ID}}
	store.effects[effectID] = api.EffectRecord{Effect: effect, Generation: 1, State: api.EffectPending}
	operation := api.Operation{ID: r.OperationID, Status: "pending", LifeID: r.Target.LifeID, Run: r.Target.Run}
	store.operations[operation.ID] = operation
	encoded, err := json.Marshal(operation)
	if err != nil {
		return api.LaunchReservation{}, err
	}
	receipt.Operation, receipt.Reply = operation, &api.RPCReply{Result: encoded}
	store.receipts[fixtureReceiptKey(scope, key)] = receipt
	store.closePending(fixtureReceiptKey(scope, key))
	if r.Authority.Kind == "ticket" {
		ticket := store.tickets[r.Authority.ID]
		ticket.Redeemed = true
		store.tickets[ticket.ID] = ticket
	}
	if store.reservationHook != nil {
		store.reservationHook(&r)
	}
	return r, nil
}

// Called under the same fixture store lock as the public reservation insert.
func (store *launchFixtureStore) reserveContinuation(scope api.Scope, request api.LaunchReservationRequest) (api.LaunchReservation, error) {
	intent, ok := store.continuations[request.ContinuationID]
	lane := store.lanes[intent.Target.LifeID]
	raw := store.continuationFrames[request.ContinuationID]
	var original api.ContinuationRequest
	if api.DecodeObject(raw, &original) == nil {
		if err := api.ValidateContinuationOperation(intent, original, store.operations[request.OperationID]); err != nil {
			return api.LaunchReservation{}, err
		}
	}
	if !ok || api.DecodeObject(raw, &original) != nil || original.IntentID != intent.ID || !reflect.DeepEqual(original.Swap, intent.Swap) ||
		intent.OperationID != request.OperationID || intent.Target.Run != lane.Run || intent.ExpectedGeneration != lane.Generation ||
		intent.CancellationEpoch != lane.CancellationEpoch || intent.LogicalTurnID != lane.LogicalTurnID ||
		intent.Status != "pending" && intent.Status != "claimed" || scope.Actor.Kind != "watchdog" || scope.PolicyGeneration != store.policy.Generation {
		return api.LaunchReservation{}, launchConflict()
	}
	r := api.LaunchReservation{ID: launchIDForTest(), Config: scope.Config, Mode: "continue",
		Target: api.LifeRef{LifeID: lane.LifeID, Run: lane.Run + 1}, LaunchID: launchIDForTest(), SpecID: launchIDForTest(),
		GrantSetID: launchIDForTest(), Generation: lane.Generation + 1, BaseGeneration: lane.Generation, CancellationEpoch: lane.CancellationEpoch,
		PolicyGeneration: store.policy.Generation, ParentLifeID: lane.ParentLifeID, RootLifeID: lane.RootLifeID,
		StarterChain: lane.StarterChain, StarterEventSeq: lane.StarterEventSeq, PreviousLaunchID: lane.LaunchID,
		OperationID: request.OperationID, RequestID: store.continuationRequestIDs[intent.ID], RequestSHA256: digestOf(raw), RequestedBy: scope.Actor}
	r.Level, r.Role, r.Driver = lane.Level, lane.Role, lane.Session.Driver
	r.Authority = api.LaunchAuthority{Kind: "starter", ID: lane.LaunchID}
	r.OriginalRequest = api.BlobRef{ID: launchIDForTest(), Class: "launch_request", SHA256: digestOf(raw), Bytes: int64(len(raw))}
	if err := api.ValidateLaunchReservation(r); err != nil {
		return api.LaunchReservation{}, err
	}
	store.blobs[r.OriginalRequest.ID] = append([]byte{}, raw...)
	store.metadata[r.OriginalRequest.ID] = api.ObjectMetadata{Ref: r.OriginalRequest, Origin: "service", SourceOperationID: r.OperationID,
		ACL: api.ObjectACL{Config: r.Config, LifeID: lane.LifeID, Audience: "owner", Generation: r.Generation, Owner: api.Actor{Kind: "service", ID: "launch-service"}}}
	store.plans[r.ID] = api.LaunchPlanRecord{Reservation: r, Generation: 1, Phase: "reserved"}
	store.fences[lane.LifeID] = lane.CancellationEpoch
	intent.Status, intent.Generation = "claimed", intent.Generation+1
	store.continuations[intent.ID] = intent
	store.operations[r.OperationID] = api.Operation{ID: r.OperationID, Status: "pending", LifeID: lane.LifeID, Run: r.Target.Run}
	effectID := launchIDForTest()
	cause := api.InternalIntent{ID: launchIDForTest(), Kind: api.InternalLaunchPlan, Config: r.Config,
		Actor: api.Actor{Kind: "service", ID: "launch-service"}, RequestedBy: scope.Actor, CauseOperationID: r.OperationID,
		CauseRequestID: r.RequestID, EffectID: effectID, Target: r.Target, LogicalTurnID: intent.LogicalTurnID, CancellationEpoch: lane.CancellationEpoch}
	store.effects[effectID] = api.EffectRecord{Effect: api.Effect{ID: effectID, OperationID: r.OperationID, Context: &cause,
		PlanLaunch: &api.LaunchPlanEffect{ReservationID: r.ID}}, Generation: 1, State: api.EffectPending}
	return r, nil
}

func (store *launchFixtureStore) LaunchPlan(_ context.Context, _ api.Scope, id api.ID) (api.LaunchPlanRecord, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	record, ok := store.plans[id]
	if !ok {
		return api.LaunchPlanRecord{}, launchMissing()
	}
	return record, nil
}

func (store *launchFixtureStore) Effect(_ context.Context, _ api.Scope, id api.ID) (api.EffectRecord, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	record, ok := store.effects[id]
	if !ok {
		record, ok = store.reviewEffects[id]
		if !ok {
			return api.EffectRecord{}, launchMissing()
		}
	}
	return record, nil
}

func (store *launchFixtureStore) ClaimEffect(_ context.Context, scope api.Scope, request api.EffectClaimRequest) (api.EffectLease, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	record, ok := store.effects[request.EffectID]
	deadline, err := time.Parse(time.RFC3339Nano, string(request.Deadline))
	if !ok || effectRecord(record) != nil || record.State != api.EffectPending && record.State != api.EffectClaimed ||
		record.Generation != request.ExpectedGeneration || scope.Actor.Kind != "service" ||
		request.ClaimantID != scope.Actor.ID || err != nil || !(fixtureClock{}).Now().Before(deadline) || record.Outcome != nil {
		return api.EffectLease{}, launchConflict()
	}
	if record.State == api.EffectClaimed && record.ClaimantID != scope.Actor.ID {
		return api.EffectLease{}, launchConflict()
	}
	record.Generation++
	record.State, record.ClaimID, record.ClaimantID, record.ClaimExpiresAt = api.EffectClaimed, launchIDForTest(), request.ClaimantID, request.Deadline
	if effectRecord(record) != nil {
		return api.EffectLease{}, launchConflict()
	}
	store.effects[request.EffectID] = record
	return api.EffectLease{Record: record, ClaimID: record.ClaimID, ExpiresAt: record.ClaimExpiresAt}, nil
}

func (store *launchFixtureStore) CompleteEffect(_ context.Context, scope api.Scope, outcome api.EffectOutcome) (api.Commit, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.completeErr != nil {
		return api.Commit{}, store.completeErr
	}
	record, ok := store.effects[outcome.EffectID]
	if !ok || record.Effect.Context == nil {
		return api.Commit{}, launchConflict()
	}
	epoch, present := store.fences[record.Effect.Context.Target.LifeID]
	if !ok || effectRecord(record) != nil || record.State != api.EffectClaimed || record.ClaimantID != scope.Actor.ID || record.ClaimID != outcome.ClaimID ||
		record.Generation != outcome.ExpectedGeneration || !present || epoch != record.Effect.Context.CancellationEpoch {
		return api.Commit{}, launchConflict()
	}
	if outcome.Status == "failed" && (outcome.Error == nil || outcome.HelperLease != nil || outcome.Output != nil) ||
		outcome.Status == "succeeded" && (outcome.Error != nil ||
			(record.Effect.HelperAllocate != nil && outcome.HelperLease == nil) || (record.Effect.Worker != nil && outcome.Output == nil)) ||
		outcome.Status != "failed" && outcome.Status != "succeeded" {
		return api.Commit{}, launchConflict()
	}
	record.State = api.EffectCompleted
	if outcome.Status == "failed" {
		record.State = api.EffectFailed
	}
	record.Outcome = &outcome
	record.Generation++
	if effectRecord(record) != nil {
		return api.Commit{}, launchConflict()
	}
	store.effects[outcome.EffectID] = record
	return api.Commit{Operation: store.operations[record.Effect.OperationID]}, nil
}

func (store *launchFixtureStore) checkIntent(scope api.Scope, cause api.InternalIntent, terminal ...bool) error {
	store.intentReads++
	record, ok := store.effects[cause.EffectID]
	if !ok || record.Effect.Context == nil {
		return launchConflict()
	}
	epoch, present := store.fences[cause.Target.LifeID]
	if !ok || effectRecord(record) != nil || record.State != api.EffectClaimed || record.ClaimantID != scope.Actor.ID || cause.Actor != scope.Actor ||
		cause.Config != scope.Config || record.Effect.OperationID != cause.CauseOperationID ||
		record.Effect.Context.Target != cause.Target || record.Effect.Context.CauseRequestID != cause.CauseRequestID ||
		record.Effect.Context.RequestedBy != cause.RequestedBy || !present || epoch != cause.CancellationEpoch {
		return launchConflict()
	}
	expires, err := time.Parse(time.RFC3339Nano, string(record.ClaimExpiresAt))
	if err != nil || !(fixtureClock{}).Now().Before(expires) {
		return launchConflict()
	}
	for _, plan := range store.plans {
		if plan.Reservation.OperationID == cause.CauseOperationID && plan.Reservation.Target == cause.Target &&
			plan.Phase != "opened" && plan.Reservation.PolicyGeneration != store.policy.Generation && !(len(terminal) == 1 && terminal[0]) {
			return launchConflict()
		}
	}
	return nil
}

func (store *launchFixtureStore) Transact(ctx context.Context, tx api.Transaction) (api.Commit, error) {
	if tx.Internal == nil {
		commit, err := store.fixtureStore.Transact(ctx, tx)
		if err != nil {
			return api.Commit{}, err
		}
		store.mu.Lock()
		for _, lane := range tx.Writes.Lanes {
			store.fences[lane.LifeID] = store.lanes[lane.LifeID].CancellationEpoch
		}
		store.mu.Unlock()
		return commit, nil
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.writeLaunch(ctx, tx, nil)
}

// The caller owns the one fixture writer lock, including failed-plan outbox
// insertion. Normal Transact cannot bypass FailPlan's cleanup validation.
func (store *launchFixtureStore) writeLaunch(ctx context.Context, tx api.Transaction, jobs []PlanCleanup) (api.Commit, error) {
	if err := store.checkFailedPlan(tx, jobs); err != nil {
		return api.Commit{}, err
	}
	bound, err := api.BindCurrentLaunchPolicy(ctx, lockedLaunchPolicy{store: store}, tx)
	if err != nil {
		return api.Commit{}, err
	}
	tx = bound
	if tx.Internal.Kind == api.InternalHelperPrepare {
		// The store owns sequence assignment and the identity commit. Derive
		// both from this exact staged event under the same transaction lock.
		for i := range tx.Writes.IdentityBindings {
			binding := &tx.Writes.IdentityBindings[i]
			encoded, err := json.Marshal(binding.Record)
			if err != nil {
				return api.Commit{}, err
			}
			canonical, err := api.CanonicalJSON(encoded)
			if err != nil {
				return api.Commit{}, err
			}
			found := false
			for j, event := range tx.Events {
				var record api.LaunchRecord
				if event.Kind == "identity.bound" && event.LifeID == binding.Record.Target.LifeID && event.Run == binding.Record.Target.Run &&
					api.DecodeObject(event.Payload, &record) == nil && reflect.DeepEqual(record, binding.Record) {
					binding.Identity = api.IdentityCommit{LaunchID: record.ID, EventID: event.ID, CommittedSeq: store.seq + api.Sequence(j) + 1, RecordSHA256: digestOf(canonical)}
					found = true
				}
			}
			if !found {
				return api.Commit{}, launchConflict()
			}
		}
	}
	var shapeErr error
	if len(jobs) != 0 {
		shapeErr = api.ValidateFailedPlanWrite(tx, jobs)
	} else {
		shapeErr = api.ValidateTransactionShape(tx)
	}
	if shapeErr != nil {
		return api.Commit{}, shapeErr
	}
	if err := store.preparePins(tx); err != nil {
		return api.Commit{}, err
	}
	if err := store.checkIntent(tx.Scope, *tx.Internal, len(jobs) != 0); err != nil {
		return api.Commit{}, err
	}
	for _, compare := range tx.Compare {
		var generation api.Generation
		switch compare.Kind {
		case api.CompareLaunchPlan:
			generation = store.plans[compare.ID].Generation
		case api.CompareGrants:
			generation = store.grants[compare.ID].Generation
		case api.CompareLane:
			generation = store.lanes[compare.ID].Generation
		default:
			return api.Commit{}, launchConflict()
		}
		if generation != compare.Generation {
			return api.Commit{}, launchConflict()
		}
	}
	for _, effect := range tx.Effects {
		if _, exists := store.effects[effect.ID]; exists {
			return api.Commit{}, launchConflict()
		}
	}
	for _, guard := range tx.Guards {
		if guard.Cancellation == nil {
			return api.Commit{}, launchConflict()
		}
		epoch, present := store.fences[guard.Cancellation.LifeID]
		if !present || epoch != guard.Cancellation.Epoch {
			return api.Commit{}, launchConflict()
		}
	}
	if tx.Internal.Kind == api.InternalHelperPrepare {
		for _, binding := range tx.Writes.IdentityBindings {
			if _, exists := store.bindings[binding.Record.ID]; exists {
				return api.Commit{}, launchConflict()
			}
			if _, exists := store.launches[binding.Record.ID]; exists {
				return api.Commit{}, launchConflict()
			}
		}
	}
	for _, record := range tx.Writes.LaunchPlans {
		if previous, exists := store.plans[record.Reservation.ID]; !exists || !reflect.DeepEqual(previous.Reservation, record.Reservation) {
			return api.Commit{}, launchConflict()
		}
	}
	for _, record := range tx.Writes.LaunchPlans {
		store.plans[record.Reservation.ID] = record
	}
	for _, grant := range tx.Writes.Grants {
		store.grants[grant.ID] = grant
	}
	for _, lease := range tx.Writes.WorkerLeases {
		store.workers[lease.ID] = lease
	}
	for _, effect := range tx.Effects {
		store.effects[effect.ID] = api.EffectRecord{Effect: effect, Generation: 1, State: api.EffectPending}
	}
	for _, event := range tx.Events {
		store.seq++
		event.Seq = store.seq
		store.events = append(store.events, event)
	}
	for _, lane := range tx.Writes.Lanes {
		store.lanes[lane.LifeID] = lane
	}
	for _, turn := range tx.Writes.Turns {
		store.turns[turn.LogicalTurnID] = turn
	}
	for _, binding := range tx.Writes.IdentityBindings {
		encoded, err := json.Marshal(binding.Record)
		if err != nil {
			return api.Commit{}, err
		}
		canonical, err := api.CanonicalJSON(encoded)
		if err != nil {
			return api.Commit{}, err
		}
		for _, event := range store.events {
			if event.Kind == "identity.bound" && event.LifeID == binding.Record.Target.LifeID && event.Run == binding.Record.Target.Run {
				binding.Identity = api.IdentityCommit{LaunchID: binding.Record.ID, EventID: event.ID, CommittedSeq: event.Seq, RecordSHA256: digestOf(canonical)}
			}
		}
		if binding.Identity.CommittedSeq == 0 {
			return api.Commit{}, launchConflict()
		}
		store.bindings[binding.Record.ID], store.launches[binding.Record.ID] = binding, binding.Record
	}
	store.transactions = append(store.transactions, tx)
	if len(jobs) != 0 {
		if store.cleanups == nil {
			store.cleanups = map[api.ID]PlanCleanup{}
		}
		for _, job := range jobs {
			store.cleanups[job.ID] = job
		}
		store.failedWrites = append(store.failedWrites, failedPlanWrite{Transaction: tx, Cleanup: append([]PlanCleanup{}, jobs...)})
	}
	return api.Commit{Operation: store.operations[tx.Internal.CauseOperationID], LastSeq: store.seq}, nil
}

func (store *launchFixtureStore) preparePins(tx api.Transaction) error {
	if tx.Internal.Kind != api.InternalHelperPrepare {
		return nil
	}
	for _, record := range tx.Writes.LaunchPlans {
		if record.Phase != "bound" || record.Plan == nil {
			continue
		}
		found := false
		for _, lane := range tx.Writes.Lanes {
			if lane.LifeID == record.Reservation.Target.LifeID && lane.Run == record.Reservation.Target.Run &&
				lane.Workspace == record.Plan.Data.Workspace && lane.LogicalTurnID == tx.Internal.LogicalTurnID &&
				validID(lane.LogicalTurnID) && lane.PolicyGeneration == record.Reservation.PolicyGeneration {
				found = true
			}
		}
		if !found {
			return launchConflict()
		}
	}
	return nil
}

func (store *launchFixtureStore) RetainObject(_ context.Context, scope api.Scope, request api.RetainObjectRequest) (api.BlobRef, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.retainErr != nil {
		return api.BlobRef{}, store.retainErr
	}
	if err := store.checkIntent(scope, request.Intent); err != nil {
		return api.BlobRef{}, err
	}
	object := request.Object
	owner := store.effects[request.Intent.EffectID].Effect.Context.Actor
	if object.Origin != "service" || object.SHA256 != digestOf(object.Bytes) || object.ACL.Config != scope.Config ||
		object.ACL.Owner != owner || object.ACL.LifeID != request.Intent.Target.LifeID || object.ACL.Audience != "owner" || object.ACL.Generation != 1 {
		return api.BlobRef{}, launchConflict()
	}
	if metadata, exists := store.metadata[object.ObjectKey]; exists {
		if metadata.SourceOperationID != request.Intent.CauseOperationID || metadata.Ref.SHA256 != object.SHA256 ||
			metadata.Ref.Class != object.Class || !reflect.DeepEqual(metadata.ACL, object.ACL) || !bytes.Equal(store.blobs[object.ObjectKey], object.Bytes) {
			return api.BlobRef{}, launchConflict()
		}
		return metadata.Ref, nil
	}
	ref := api.BlobRef{ID: object.ObjectKey, Class: object.Class, SHA256: object.SHA256, Bytes: int64(len(object.Bytes))}
	store.blobs[ref.ID] = append([]byte{}, object.Bytes...)
	store.metadata[ref.ID] = api.ObjectMetadata{Ref: ref, ACL: object.ACL, Origin: object.Origin, SourceOperationID: request.Intent.CauseOperationID}
	store.retainCalls++
	return ref, nil
}

func (store *launchFixtureStore) WorkerLease(_ context.Context, _ api.Scope, id api.ID) (api.WorkerLease, error) {
	lease, ok := store.workers[id]
	if !ok {
		lease, ok = store.reviewWorkers[id]
		if !ok {
			return api.WorkerLease{}, launchMissing()
		}
	}
	return lease, nil
}

func (store *launchFixtureStore) LaunchBinding(_ context.Context, id api.ID) (api.LaunchBindingRequest, error) {
	binding, ok := store.bindings[id]
	if !ok {
		return api.LaunchBindingRequest{}, launchMissing()
	}
	return binding, nil
}

func (store *launchFixtureStore) Turn(_ context.Context, _ api.Scope, target api.LifeRef, id api.ID) (api.TurnSnapshot, error) {
	turn, ok := store.turns[id]
	if !ok || turn.Target != target {
		return api.TurnSnapshot{}, launchMissing()
	}
	return turn, nil
}

func (store *launchFixtureStore) Source(_ context.Context, _ api.Scope, ref api.SourceRef) (api.RetainedSource, error) {
	source, ok := store.sources[ref.ID]
	if !ok {
		return api.RetainedSource{}, launchMissing()
	}
	if source.Source != ref {
		return api.RetainedSource{}, launchConflict()
	}
	return source, nil
}

func (store *launchFixtureStore) MailForTurn(_ context.Context, scope api.Scope, request api.DeliveryTurnRequest) (api.DeliveryBatch, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	current, ok := store.effects[request.Lease.Record.Effect.ID]
	if !ok || current.Effect.PlanLaunch == nil || current.State != api.EffectClaimed || current.Generation != request.Lease.Record.Generation ||
		current.ClaimID != request.Lease.ClaimID || current.ClaimantID != scope.Actor.ID {
		return api.DeliveryBatch{}, launchConflict()
	}
	record := store.plans[current.Effect.PlanLaunch.ReservationID]
	if record.Reservation.Target != request.Target || record.Reservation.Generation != request.ExpectedGeneration ||
		current.Effect.Context.LogicalTurnID != request.LogicalTurnID || store.fences[request.Target.LifeID] != request.CancellationEpoch {
		return api.DeliveryBatch{}, launchConflict()
	}
	batch := api.DeliveryBatch{Target: request.Target, LogicalTurnID: request.LogicalTurnID, Generation: 1, Mail: []api.Mail{}, Intent: *current.Effect.Context}
	batch.Intent.Kind = api.InternalMailDeliver
	for _, id := range request.MailIDs {
		mail, ok := store.mail[id]
		if !ok || mail.RecipientLifeID != request.Target.LifeID || mail.Status != "queued" && mail.Status != "delivering" ||
			mail.LogicalTurnID != "" && mail.LogicalTurnID != request.LogicalTurnID {
			return api.DeliveryBatch{}, launchConflict()
		}
		batch.Mail = append(batch.Mail, mail)
	}
	return batch, nil
}

type launchFixtureDelivery struct {
	api.MailDelivery
	store *launchFixtureStore
}

func (delivery *launchFixtureDelivery) BeginDelivery(ctx context.Context, scope api.Scope, request api.DeliveryTurnRequest) (api.DeliveryBatch, error) {
	batch, err := delivery.store.MailForTurn(ctx, scope, request)
	if err != nil {
		return api.DeliveryBatch{}, err
	}
	store := delivery.store
	store.mu.Lock()
	defer store.mu.Unlock()
	for i, mail := range batch.Mail {
		if store.mail[mail.ID].Generation != mail.Generation || !validID(mail.Sender.ID) {
			return api.DeliveryBatch{}, launchConflict()
		}
		if mail.Status == "queued" {
			mail.Generation++
		}
		mail.Status, mail.LogicalTurnID = "delivering", request.LogicalTurnID
		batch.Mail[i] = mail
	}
	for _, mail := range batch.Mail {
		store.mail[mail.ID] = mail
	}
	if store.mailHook != nil {
		store.mailHook(&batch)
	}
	return batch, nil
}

func (f *launchFixture) reserve(t *testing.T) (api.Operation, api.LaunchPlanRecord) {
	t.Helper()
	operation, err := f.service.LaneStart(context.Background(), f.scope, f.request)
	if err != nil {
		t.Fatal(err)
	}
	for _, record := range f.store.plans {
		if record.Reservation.OperationID == operation.ID {
			return operation, record
		}
	}
	t.Fatal("public launch returned without an issued reservation")
	return api.Operation{}, api.LaunchPlanRecord{}
}

func (f *launchFixture) claim(t *testing.T, record api.LaunchPlanRecord) (api.Scope, api.LaunchPlanRequest) {
	t.Helper()
	scope := api.Scope{Config: record.Reservation.Config, Actor: api.Actor{Kind: "service", ID: "launch-service"},
		Source: "outbox", PolicyGeneration: f.store.policy.Generation}
	for _, effect := range f.store.effects {
		if effect.Effect.PlanLaunch == nil || effect.Effect.PlanLaunch.ReservationID != record.Reservation.ID {
			continue
		}
		lease, err := f.store.ClaimEffect(context.Background(), scope, api.EffectClaimRequest{EffectID: effect.Effect.ID,
			ExpectedGeneration: effect.Generation, ClaimantID: scope.Actor.ID, Deadline: "2030-01-02T03:09:05Z"})
		if err != nil {
			t.Fatal(err)
		}
		return scope, api.LaunchPlanRequest{Lease: lease}
	}
	t.Fatal("reservation has no original planning effect")
	return api.Scope{}, api.LaunchPlanRequest{}
}
