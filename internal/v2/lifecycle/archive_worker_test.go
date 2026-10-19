package lifecycle

import (
	"bytes"
	"context"
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	archivejob "laneboss.io/laneboss/internal/v2/archive"
)

// This model keeps actual input/tar/read-back bytes, pending receipt channels
// and an owned workspace map. It does not simulate a passing native collector,
// authenticated installed service or OS worker acceptance result.
type terminalFixture struct {
	*fixture
	store *terminalStore
}

type terminalStore struct {
	*launchFixtureStore
	jobs         map[api.ID]ArchiveJob
	scopes       map[api.ID]api.Scope
	archiveCalls int
	runtime      api.BlobRef
	bootstrap    api.Executable
	producer     map[api.ID][]byte
	archiveReads map[api.ID][]api.BlobChunk
}

func newTerminalFixture(t *testing.T) *terminalFixture {
	f := newFixture(t)
	f.ended()
	lane := f.child
	lane.State = "abandoned"
	f.store.lanes[lane.LifeID] = lane
	base := &launchFixtureStore{fixtureStore: f.store, effects: map[api.ID]api.EffectRecord{}, workers: map[api.ID]api.WorkerLease{},
		fences: map[api.ID]api.Generation{lane.LifeID: lane.CancellationEpoch}, plans: map[api.ID]api.LaunchPlanRecord{}}
	return terminalFixtureFor(t, f, base)
}

func terminalFixtureFor(t *testing.T, f *fixture, base *launchFixtureStore) *terminalFixture {
	t.Helper()
	store := &terminalStore{launchFixtureStore: base, jobs: map[api.ID]ArchiveJob{}, scopes: map[api.ID]api.Scope{},
		producer: map[api.ID][]byte{}, archiveReads: map[api.ID][]api.BlobChunk{}}
	store.bootstrap = api.Executable{ID: "fixed-worker", Version: "fixture-1", SHA256: digestOf([]byte("enrolled worker bytes"))}
	raw, err := json.Marshal(api.RuntimeManifest{Schema: "laneboss.runtime.v2", Generation: 1, Artifact: store.bootstrap,
		Bootstrap: store.bootstrap, Objects: []api.RuntimeObject{}, Bindings: []api.InstalledBinding{}})
	if err != nil {
		t.Fatal(err)
	}
	store.runtime = f.blob("worker-runtime", "manifest", raw)
	f.service.deps.Store, f.service.deps.Archives = store, store
	return &terminalFixture{fixture: f, store: store}
}

// Caller holds the store mutex. Each retained object contains the bytes used
// by verification; IDs are fresh and hashes are derived from those bytes.
func (store *terminalStore) put(class string, raw []byte, operation api.ID, target api.LifeRef) api.BlobRef {
	ref := api.BlobRef{ID: launchIDForTest(), Class: class, Bytes: int64(len(raw)), SHA256: digestOf(raw)}
	store.blobs[ref.ID] = append([]byte{}, raw...)
	store.metadata[ref.ID] = api.ObjectMetadata{Ref: ref, Origin: "service", SourceOperationID: operation,
		ACL: api.ObjectACL{Config: "example", LifeID: target.LifeID, Audience: "tree", Generation: 1}}
	return ref
}

func (store *terminalStore) ReserveArchive(_ context.Context, scope api.Scope, intent ArchiveIntent) (ArchiveJob, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	key := api.RequestKey{Method: scope.Request.Method, IdempotencyKey: scope.Request.IdempotencyKey, RequestSHA256: scope.Request.RequestSHA256}
	domain := fixtureReceiptKey(scope, key)
	receipt, ok := store.receipts[domain]
	lane := store.lanes[intent.Request.Target.LifeID]
	if !ok || !receiptMatches(scope, key, receipt) || receipt.Operation.ID != intent.OperationID || receipt.Reply != nil ||
		store.pendingFrames[domain] != scope.Frame || lane.Generation != intent.Request.ExpectedGeneration || lane.CancellationEpoch != intent.CancellationEpoch || lane.Cleaned {
		return ArchiveJob{}, launchConflict()
	}
	if job, ok := store.jobs[intent.OperationID]; ok {
		return job, nil
	}
	store.archiveCalls++
	job := ArchiveJob{ID: launchIDForTest(), Intent: intent}
	job.Lease = api.WorkerLease{ID: launchIDForTest(), Kind: "archive", OperationID: intent.OperationID, EffectID: launchIDForTest(), Target: intent.Request.Target,
		RuntimeManifest: store.runtime,
		GrantSetID:      launchIDForTest(), Generation: 1, ExpiresAt: "2030-01-02T03:09:05Z"}
	job.Plan = api.WorkerPlan{Schema: "laneboss.worker-plan.v2", Kind: "archive", Executable: store.bootstrap,
		Input: job.Lease.Input, GrantSetID: job.Lease.GrantSetID, Budget: lane.BudgetRemaining,
		Argv: []string{"laneboss", "internal", "worker", "--binding", "/runtime/laneboss-worker.json", "--lease", string(job.Lease.ID)}}
	task := store.put("artifact", store.blobs[lane.Task.ID], intent.OperationID, intent.Request.Target)
	snapshotBytes, err := json.Marshal(api.ObjectManifest{Schema: "laneboss.objects.v2", Entries: []api.ObjectEntry{
		{Path: "task", Kind: "file", Mode: 0600, Content: &task}}})
	if err != nil {
		return ArchiveJob{}, err
	}
	snapshot := store.put("manifest", snapshotBytes, intent.OperationID, intent.Request.Target)
	zero := uint64(0)
	freeze, err := json.Marshal(ArchiveFreeze{Target: intent.Request.Target, LaunchID: lane.LaunchID, CancellationEpoch: lane.CancellationEpoch,
		Snapshot: snapshot, Writers: &zero, WritableExports: &zero, ObservedAt: "2030-01-02T03:04:05Z"})
	if err != nil {
		return ArchiveJob{}, err
	}
	job.Freeze = store.put("manifest", freeze, intent.OperationID, intent.Request.Target)
	input, err := json.Marshal(archivejob.Input{Schema: "laneboss.archive-input.v2", JobID: job.ID, Intent: intent, Freeze: job.Freeze,
		ReceiptID: launchIDForTest(), StoreID: "fixture-archive-store", Budget: job.Plan.Budget})
	if err != nil {
		return ArchiveJob{}, err
	}
	job.Lease.Input = store.put("archive_input", input, intent.OperationID, intent.Request.Target)
	job.Plan.Input = job.Lease.Input
	store.grants[job.Lease.GrantSetID] = api.GrantSet{ID: job.Lease.GrantSetID, LifeID: lane.LifeID, Generation: 1, PolicyGeneration: scope.PolicyGeneration,
		SHA256: digestOf(input), ExpiresAt: job.Lease.ExpiresAt, Data: []api.DataGrant{}, Resources: []api.ResourceGrant{},
		Secrets: []api.SecretGrant{}, Profiles: []api.ProfileGrant{}, Channels: []api.ChannelGrant{}, Network: []api.NetworkGrant{}}
	cause := api.InternalIntent{ID: launchIDForTest(), Kind: api.InternalLifecycleEffect, Config: scope.Config,
		Actor: api.Actor{Kind: "service", ID: "lifecycle"}, RequestedBy: scope.Actor, CauseOperationID: intent.OperationID,
		CauseRequestID: scope.Request.RequestID, EffectID: job.Lease.EffectID, Target: intent.Request.Target, CancellationEpoch: intent.CancellationEpoch}
	store.effects[job.Lease.EffectID] = api.EffectRecord{Effect: api.Effect{ID: job.Lease.EffectID, OperationID: intent.OperationID, Context: &cause, Worker: &job.Plan}, Generation: 1, State: api.EffectPending}
	store.workers[job.Lease.ID] = job.Lease
	store.jobs[intent.OperationID], store.scopes[intent.OperationID] = job, scope
	return job, nil
}

func (store *terminalStore) ArchiveJob(_ context.Context, _ api.Scope, operation api.ID) (ArchiveJob, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	job, ok := store.jobs[operation]
	if !ok {
		return ArchiveJob{}, launchMissing()
	}
	return job, nil
}

func (store *terminalStore) WorkerLease(_ context.Context, _ api.Scope, id api.ID) (api.WorkerLease, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	lease, ok := store.workers[id]
	if !ok {
		return api.WorkerLease{}, launchMissing()
	}
	return lease, nil
}

func (store *terminalStore) Blob(ctx context.Context, scope api.Scope, request api.BlobReadRequest) (api.BlobChunk, error) {
	chunk, err := store.launchFixtureStore.Blob(ctx, scope, request)
	if err != nil {
		return chunk, err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if _, found := store.producer[request.ObjectID]; found {
		recorded := chunk
		recorded.Data = append([]byte{}, chunk.Data...)
		store.archiveReads[request.ObjectID] = append(store.archiveReads[request.ObjectID], recorded)
	}
	return chunk, nil
}

// Inspect the actual ranges returned by Store.Blob, separately from the bytes
// held by the producer. A rejected archive may stop at the first changed range;
// a successful archive must read every byte and EOF of every retained part.
func (store *terminalStore) archiveReadWitness(corrupt bool) bool {
	store.mu.Lock()
	defer store.mu.Unlock()
	storedChanged, readChanged := false, false
	if len(store.producer) == 0 {
		return false
	}
	for id, produced := range store.producer {
		stored := store.blobs[id]
		if len(stored) != len(produced) {
			return false
		}
		storedChanged = storedChanged || !bytes.Equal(stored, produced)
		var count int64
		eof := false
		for _, chunk := range store.archiveReads[id] {
			end := chunk.Offset + int64(len(chunk.Data))
			if chunk.ObjectID != id || chunk.Offset != count || end > int64(len(stored)) ||
				chunk.SHA256 != digestOf(chunk.Data) || !bytes.Equal(chunk.Data, stored[chunk.Offset:end]) {
				return false
			}
			count = end
			readChanged = readChanged || !bytes.Equal(chunk.Data, produced[chunk.Offset:end])
			eof = eof || len(chunk.Data) == 0 && end == int64(len(stored))
		}
		if !corrupt && (count != int64(len(stored)) || !eof) {
			return false
		}
	}
	return corrupt && storedChanged && readChanged || !corrupt && !storedChanged
}

func (store *terminalStore) Transact(ctx context.Context, tx api.Transaction) (api.Commit, error) {
	commit, err := store.launchFixtureStore.Transact(ctx, tx)
	if err != nil {
		return api.Commit{}, err
	}
	if tx.Internal == nil && !commit.Replayed {
		store.mu.Lock()
		for _, lease := range tx.Writes.WorkerLeases {
			store.workers[lease.ID] = lease
		}
		for _, effect := range tx.Effects {
			store.effects[effect.ID] = api.EffectRecord{Effect: effect, Generation: 1, State: api.EffectPending}
		}
		store.mu.Unlock()
	}
	return commit, nil
}

func (f *terminalFixture) finishArchive(t *testing.T, operation api.ID, mode string) api.ArchiveReceipt {
	t.Helper()
	store := f.store
	store.mu.Lock()
	job, ok := store.jobs[operation]
	scope := store.scopes[operation]
	store.mu.Unlock()
	if !ok {
		t.Fatal("archive never retained its worker reservation")
	}
	executor := api.Scope{Config: scope.Config, Actor: api.Actor{Kind: "service", ID: "lifecycle"}, PolicyGeneration: scope.PolicyGeneration}
	claim, err := store.ClaimEffect(context.Background(), executor, api.EffectClaimRequest{EffectID: job.Lease.EffectID,
		ExpectedGeneration: 1, ClaimantID: executor.Actor.ID, Deadline: job.Lease.ExpiresAt})
	if err != nil {
		t.Fatal(err)
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	lane := store.lanes[job.Intent.Request.Target.LifeID]
	if lane.CancellationEpoch != job.Intent.CancellationEpoch || lane.Generation != job.Intent.Request.ExpectedGeneration {
		t.Fatal("fixture worker crossed its original life fence")
	}
	var input archivejob.Input
	if err := api.DecodeObject(store.blobs[job.Lease.Input.ID], &input); err != nil {
		t.Fatal(err)
	}
	if input.Intent != job.Intent || input.Freeze != job.Freeze || input.JobID != job.ID {
		t.Fatal("fixture producer did not receive its exact retained archive input")
	}
	var freeze ArchiveFreeze
	if err := api.DecodeObject(store.blobs[input.Freeze.ID], &freeze); err != nil {
		t.Fatal(err)
	}
	tree, err := archivejob.Manifest(store.blobs[freeze.Snapshot.ID])
	if err != nil {
		t.Fatal(err)
	}
	var buffer bytes.Buffer
	if err := archivejob.Write(context.Background(), &buffer, tree, func(_ context.Context, request api.BlobReadRequest) (api.BlobChunk, error) {
		data, found := store.blobs[request.ObjectID]
		if !found || request.Offset < 0 || request.Offset > int64(len(data)) {
			return api.BlobChunk{}, launchMissing()
		}
		part := data[request.Offset:min(int64(len(data)), request.Offset+int64(request.Limit))]
		return api.BlobChunk{ObjectID: request.ObjectID, Offset: request.Offset, Data: append([]byte{}, part...), SHA256: digestOf(part)}, nil
	}, job.Plan.Budget.DiskBytes); err != nil {
		t.Fatal(err)
	}
	part := store.put("artifact", buffer.Bytes(), operation, job.Intent.Request.Target)
	store.producer[part.ID] = append([]byte{}, buffer.Bytes()...)
	receipt := api.ArchiveReceipt{ID: input.ReceiptID, LifeID: lane.LifeID, Manifest: freeze.Snapshot, StoreID: input.StoreID,
		ArchiveSHA256: digestOf(buffer.Bytes()), ReadBackSHA256: digestOf(store.blobs[part.ID]), VerifiedAt: "2030-01-02T03:04:05Z"}
	completion := ArchiveCompletion{Receipt: receipt, Archive: api.ObjectAssembly{SHA256: receipt.ArchiveSHA256, Bytes: int64(buffer.Len()), Parts: []api.BlobRef{part}}}
	if mode == "bytes" {
		changed := append([]byte{}, store.blobs[part.ID]...)
		changed[0] ^= 1
		store.blobs[part.ID] = changed
		// Leave the producer buffer, immutable references and receipt intact.
		// Only an independent read of the persisted copy observes this change.
	}
	if mode == "output" {
		completion.Receipt.StoreID = "foreign-store"
	}
	raw, err := json.Marshal(completion)
	if err != nil {
		t.Fatal(err)
	}
	output := store.put("worker_result", raw, operation, job.Intent.Request.Target)
	lease := store.workers[job.Lease.ID]
	lease.ConsumedBy = launchIDForTest()
	store.workers[lease.ID] = lease
	process := api.ProcessHandle{ID: launchIDForTest(), Target: job.Intent.Request.Target, ContainmentID: launchIDForTest(), Generation: string(launchIDForTest())}
	principal := api.LaunchRecord{Kind: "worker", ID: lease.ConsumedBy, Config: scope.Config, Target: lease.Target, HostUID: 60001,
		Actor: api.Actor{Kind: "worker", ID: launchIDForTest()}, GrantSetID: lease.GrantSetID, ContainmentID: process.ContainmentID, ProcessGeneration: process.Generation}
	if mode == "principal" {
		principal.Kind = "agent"
	}
	store.launches[principal.ID] = principal
	zero, exit := uint64(0), 0
	if mode == "exit" {
		exit = 9
	}
	observation := api.ProcessObservation{Handle: process, State: "exited", ExitCode: &exit, Survivors: &zero, PromptStatus: "completed", ObservedAt: "2030-01-02T03:04:05Z"}
	if mode != "pending" {
		store.mu.Unlock()
		_, err := store.CompleteEffect(context.Background(), executor, api.EffectOutcome{EffectID: job.Lease.EffectID,
			ClaimID: claim.ClaimID, ExpectedGeneration: claim.Record.Generation, Status: "succeeded", Output: &output, Observation: &observation})
		store.mu.Lock()
		if err != nil {
			t.Fatal(err)
		}
	}
	if mode != "event" {
		event, err := f.service.event(scope, lane, "archive.verified", receipt, api.Actor{Kind: "service", ID: "lifecycle"})
		if err != nil {
			t.Fatal(err)
		}
		store.seq++
		event.OperationID, event.Seq = operation, store.seq
		store.events = append(store.events, event)
	}
	key := api.RequestKey{Method: scope.Request.Method, IdempotencyKey: scope.Request.IdempotencyKey, RequestSHA256: scope.Request.RequestSHA256}
	domain := fixtureReceiptKey(scope, key)
	retained := store.receipts[domain]
	reply, err := json.Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	retained.Reply = &api.RPCReply{Result: reply}
	retained.Operation.Status, retained.Operation.LifeID, retained.Operation.Run = "succeeded", lane.LifeID, lane.Run
	store.receipts[domain], store.operations[operation] = retained, retained.Operation
	if mode == "fence" {
		lane.Generation++
		store.lanes[lane.LifeID] = lane
	}
	store.closePending(domain)
	return receipt
}

func TestArchiveWorkerCompletion(t *testing.T) {
	for _, mode := range []string{"valid", "bytes", "output", "principal", "exit", "pending", "event", "fence"} {
		t.Run(mode, func(t *testing.T) {
			f := newTerminalFixture(t)
			request := api.ArchiveRequest{Target: f.target, ExpectedGeneration: f.child.Generation}
			scope := f.fixture.scope("lane.archive", request, f.parent)
			f.store.receiptAwaited = make(chan struct{}, 1)
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			type reply struct {
				receipt api.ArchiveReceipt
				err     error
			}
			done := make(chan reply, 1)
			go func() { value, err := f.service.LaneArchive(ctx, scope, request); done <- reply{value, err} }()
			select {
			case <-f.store.receiptAwaited:
			case got := <-done:
				t.Fatalf("archive never awaited its original worker: %v", got.err)
			case <-ctx.Done():
				t.Fatal("archive never reached its protected completion wait")
			}
			gateCtx, release := context.WithTimeout(ctx, 100*time.Millisecond)
			unlock, err := f.service.lockLife(gateCtx, f.target.LifeID)
			release()
			if err != nil {
				t.Fatal("archive held the life gate during its worker wait")
			}
			unlock()
			key := api.RequestKey{Method: scope.Request.Method, IdempotencyKey: scope.Request.IdempotencyKey, RequestSHA256: scope.Request.RequestSHA256}
			original, err := f.store.LookupReceipt(ctx, scope, key)
			if err != nil || original.Reply != nil {
				t.Fatalf("archive reported intent as verified completion: %v", err)
			}
			want := f.finishArchive(t, original.Operation.ID, mode)
			select {
			case got := <-done:
				if mode == "valid" {
					if got.err != nil || got.receipt != want || f.store.archiveCalls != 1 || !f.store.archiveReadWitness(false) {
						t.Fatalf("archive lost its measured worker receipt: %v", got.err)
					}
					actual, err := f.service.LaneArchive(ctx, scope, request)
					if err != nil || actual != want || f.store.archiveCalls != 1 {
						t.Fatalf("archive retry replaced its retained worker: %v", err)
					}
				} else {
					code := api.CodeIntegrity
					if mode == "fence" {
						code = api.CodeConflict
					}
					if typed, ok := got.err.(*api.Error); !ok || typed.Code != code || mode == "bytes" && !f.store.archiveReadWitness(true) {
						t.Fatalf("unmeasured archive completion was accepted: %s: %v", mode, got.err)
					}
				}
			case <-ctx.Done():
				t.Fatal("archive did not finish after its actual receipt")
			}
		})
	}
}

func TestArchiveReservationPins(t *testing.T) {
	for _, mode := range []string{"freeze", "runtime", "effect", "grants", "input"} {
		t.Run(mode, func(t *testing.T) {
			f := newTerminalFixture(t)
			request := api.ArchiveRequest{Target: f.target, ExpectedGeneration: f.child.Generation}
			scope := f.fixture.scope("lane.archive", request, f.parent)
			receipt, err := f.service.pendingMutation(context.Background(), scope)
			if err != nil {
				t.Fatal(err)
			}
			end := f.store.events[len(f.store.events)-1]
			intent := ArchiveIntent{Request: request, OperationID: receipt.Operation.ID, EndEventID: end.ID, EndSeq: end.Seq}
			job, err := f.store.ReserveArchive(context.Background(), scope, intent)
			if err != nil {
				t.Fatal(err)
			}
			switch mode {
			case "freeze":
				var freeze ArchiveFreeze
				if err := api.DecodeObject(f.store.blobs[job.Freeze.ID], &freeze); err != nil {
					t.Fatal(err)
				}
				one := uint64(1)
				freeze.WritableExports = &one
				raw, err := json.Marshal(freeze)
				if err != nil {
					t.Fatal(err)
				}
				job.Freeze = f.store.put("manifest", raw, intent.OperationID, f.target)
				var input archivejob.Input
				if err := api.DecodeObject(f.store.blobs[job.Lease.Input.ID], &input); err != nil {
					t.Fatal(err)
				}
				input.Freeze = job.Freeze
				raw, err = json.Marshal(input)
				if err != nil {
					t.Fatal(err)
				}
				job.Lease.Input = f.store.put("archive_input", raw, intent.OperationID, f.target)
				job.Plan.Input = job.Lease.Input
				f.store.workers[job.Lease.ID] = job.Lease
				effect := f.store.effects[job.Lease.EffectID]
				effect.Effect.Worker = &job.Plan
				f.store.effects[effect.Effect.ID] = effect
				grants := f.store.grants[job.Lease.GrantSetID]
				grants.SHA256 = digestOf(raw)
				f.store.grants[grants.ID] = grants
				f.store.jobs[intent.OperationID] = job
			case "runtime":
				job.Plan.Executable.SHA256 = digestOf([]byte("different worker executable"))
				f.store.jobs[intent.OperationID] = job
				effect := f.store.effects[job.Lease.EffectID]
				effect.Effect.Worker = &job.Plan
				f.store.effects[effect.Effect.ID] = effect
			case "effect":
				effect := f.store.effects[job.Lease.EffectID]
				effect.Effect.Context.CauseOperationID = "foreign-operation"
				f.store.effects[effect.Effect.ID] = effect
			case "grants":
				grants := f.store.grants[job.Lease.GrantSetID]
				grants.Secrets = []api.SecretGrant{{ID: "unrelated-secret"}}
				f.store.grants[grants.ID] = grants
			case "input":
				f.store.blobs[job.Lease.Input.ID][0] ^= 1
			}
			err = f.service.archiveJob(context.Background(), scope, f.store, f.child, intent, job)
			if typed, ok := err.(*api.Error); !ok || typed.Code != api.CodeIntegrity ||
				mode == "freeze" && typed.Message != "archive has no measured frozen input snapshot" {
				t.Fatalf("archive reservation ignored its protected worker pins: %s: %v", mode, err)
			}
		})
	}
}

type collectorFixture struct {
	objects     map[api.ID][]byte
	owned       map[api.ID]bool
	dirty       map[api.ID]bool
	results     map[api.ID]api.CleanEvent
	observation api.ProcessObservation
	calls       int
	mutate      func(*api.CleanEvent)
}

func (collector *collectorFixture) CollectOwned(_ context.Context, _ api.Scope, lease api.EffectLease, request OwnedCleanRequest) (api.CleanEvent, error) {
	collector.calls++
	if result, ok := collector.results[lease.Record.Effect.ID]; ok {
		return result, nil
	}
	_, exists := collector.objects[request.WorkspaceID]
	if !exists || !collector.owned[request.WorkspaceID] || collector.dirty[request.WorkspaceID] {
		return api.CleanEvent{}, problem(api.CodeConflict, "fixture workspace is missing, unowned or dirty", "Preserve it for review.")
	}
	result := api.CleanEvent{ArchiveReceipt: request.Archive, RemovedObjectIDs: []api.ID{request.WorkspaceID},
		RetainedObjectIDs: append([]api.ID{}, request.RetainedObjectIDs...), Quiescence: collector.observation}
	delete(collector.objects, request.WorkspaceID)
	if collector.mutate != nil {
		collector.mutate(&result)
	}
	collector.results[lease.Record.Effect.ID] = result
	return result, nil
}

func TestCleanCollectorDone(t *testing.T) {
	for _, mode := range []string{"valid", "dirty", "unowned", "removed", "retained", "observation", "epoch", "claim"} {
		t.Run(mode, func(t *testing.T) {
			f := newTerminalFixture(t)
			archive := fixtureArchive(f.fixture)
			f.fixture.add("archive.verified", archive, f.target.Run, "service", f.parent)
			request := api.CleanRequest{Target: f.target, ExpectedGeneration: f.child.Generation, ArchiveReceiptID: archive.ID}
			scope := f.fixture.scope("lane.clean", request, f.parent)
			operation, err := f.service.LaneClean(context.Background(), scope, request)
			if err != nil {
				t.Fatal(err)
			}
			var effect api.EffectRecord
			for _, candidate := range f.store.effects {
				if candidate.Effect.OperationID == operation.ID {
					effect = candidate
				}
			}
			if effect.Effect.Context == nil || effect.Effect.Clean == nil {
				t.Fatal("clean operation has no original collector effect")
			}
			internal := api.Scope{Config: "example", Actor: effect.Effect.Context.Actor, Source: "outbox", PolicyGeneration: 1}
			lease, err := f.store.ClaimEffect(context.Background(), internal, api.EffectClaimRequest{EffectID: effect.Effect.ID,
				ExpectedGeneration: effect.Generation, ClaimantID: internal.Actor.ID, Deadline: "2030-01-02T03:09:05Z"})
			if err != nil {
				t.Fatal(err)
			}
			collector := &collectorFixture{objects: map[api.ID][]byte{f.child.Workspace.ID: append([]byte{}, f.store.blobs[f.child.Task.ID]...)},
				owned: map[api.ID]bool{f.child.Workspace.ID: true}, dirty: map[api.ID]bool{}, results: map[api.ID]api.CleanEvent{}, observation: f.launcher.observation}
			switch mode {
			case "dirty":
				collector.dirty[f.child.Workspace.ID] = true
			case "unowned":
				collector.owned[f.child.Workspace.ID] = false
			case "removed":
				collector.mutate = func(result *api.CleanEvent) { result.RemovedObjectIDs = []api.ID{} }
			case "retained":
				collector.mutate = func(result *api.CleanEvent) { result.RetainedObjectIDs = []api.ID{} }
			case "observation":
				one := uint64(1)
				collector.observation.Survivors = &one
			case "epoch":
				lane := f.store.lanes[f.child.LifeID]
				lane.CancellationEpoch++
				f.store.lanes[lane.LifeID] = lane
				f.store.fences[lane.LifeID] = lane.CancellationEpoch
			case "claim":
				lease.ClaimID = "foreign-claim"
			}
			f.service.deps.Collector = collector
			before := len(f.store.transactions)
			taskBefore := append([]byte{}, f.store.blobs[f.child.Task.ID]...)
			result, err := f.service.CollectClean(context.Background(), internal, lease)
			actual := f.store.lanes[f.child.LifeID]
			if mode == "valid" {
				_, exists := collector.objects[f.child.Workspace.ID]
				if err != nil || exists || !actual.Cleaned || actual.Generation != f.child.Generation+1 || collector.calls != 1 ||
					len(f.store.transactions) != before+1 || !bytes.Equal(f.store.blobs[f.child.Task.ID], taskBefore) {
					t.Fatalf("collector did not publish actual owned removal: %v", err)
				}
				last := f.store.events[len(f.store.events)-1]
				if last.Kind != "lane.cleaned" || last.OperationID != operation.ID || last.Actor != internal.Actor || last.RequestedBy != f.parent {
					t.Fatal("collector lost the original causal request")
				}
				replayed, err := f.service.CollectClean(context.Background(), internal, lease)
				if err != nil || !reflect.DeepEqual(replayed, result) || collector.calls != 1 || len(f.store.transactions) != before+1 {
					t.Fatalf("collector retry repeated native removal: %v", err)
				}
			} else {
				want := api.CodeIntegrity
				if mode == "dirty" || mode == "unowned" || mode == "epoch" || mode == "claim" {
					want = api.CodeConflict
				}
				// A later writer fence can still refuse after native removal.
				// These entry gates must decide before the collector is called.
				crossedGate := (mode == "epoch" || mode == "claim") && collector.calls != 0
				if typed, ok := err.(*api.Error); !ok || typed.Code != want || actual.Cleaned || len(f.store.transactions) != before || crossedGate {
					t.Fatalf("collector published an unverified removal: %s: %v", mode, err)
				}
				if mode == "dirty" || mode == "unowned" || mode == "epoch" || mode == "claim" {
					if _, exists := collector.objects[f.child.Workspace.ID]; !exists {
						t.Fatal("collector removed work after a stopped ownership or fence gate")
					}
				}
			}
		})
	}
}
