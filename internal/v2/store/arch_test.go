//go:build linux

package store

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	archivejob "laneboss.io/laneboss/internal/v2/archive"
)

// Protocol/native observations are explicit component fixtures. The SQLite
// bytes, append/claim/completion transactions and reopen are the real store.
type archPeer struct{ facts api.PeerFacts }

func (p *archPeer) Facts(ctx context.Context) (api.PeerFacts, error) {
	if err := ctx.Err(); err != nil {
		return api.PeerFacts{}, err
	}
	return p.facts, nil
}
func (*archPeer) Alive(ctx context.Context) error { return ctx.Err() }
func (*archPeer) Close() error                    { return nil }

type archFrame struct{ raw []byte }

func (f *archFrame) Bytes() []byte { return append([]byte(nil), f.raw...) }
func (*archFrame) Verify(ctx context.Context, c api.ConnectionContext) error {
	if c == nil || c.Peer() == nil {
		return errors.New("missing fixture native peer")
	}
	return c.Peer().Alive(ctx)
}

type archNative struct {
	intent  archivejob.Intent
	freeze  archivejob.Freeze
	checks  int
	fail    error
	objects []api.ObjectWrite
	calls   int
}

func (n *archNative) FreezeArchive(ctx context.Context, intent archivejob.Intent, lane api.Lane) (archivejob.Snapshot, error) {
	if err := ctx.Err(); err != nil {
		return archivejob.Snapshot{}, err
	}
	if intent != n.intent || lane.LifeID != intent.Request.Target.LifeID || lane.Run != intent.Request.Target.Run {
		return archivejob.Snapshot{}, errors.New("fixture native archive selected another job")
	}
	n.calls++
	return archivejob.Snapshot{Freeze: n.freeze, Objects: n.objects}, n.fail
}
func (n *archNative) CheckArchiveFreeze(ctx context.Context, intent archivejob.Intent, f archivejob.Freeze) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if intent != n.intent {
		return errors.New("fixture native archive selected another intent")
	}
	n.checks++
	if n.fail != nil {
		return n.fail
	}
	if !sameValue(n.freeze, f) {
		return errors.New("fixture freeze changed")
	}
	return nil
}

type archFixture struct {
	s                *Service
	deps             Dependencies
	record           archiveRecord
	executor, worker api.Scope
	native           *archNative
	tree             api.ObjectManifest
	tar              []byte
	owner            context.Context
	retire           func()
}

func archJSON(t *testing.T, value any) []byte {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
func archStamp() api.Timestamp { return api.Timestamp(time.Now().UTC().Format(timeFormat)) }
func archSave(t *testing.T, s *Service, r archiveRecord) {
	t.Helper()
	fixtureProjection(t, s, "archive_job", r.Job.Intent.OperationID, 2, r)
}

func newArch(t *testing.T) *archFixture {
	t.Helper()
	s, deps := testStore(t)
	return buildArch(t, s, deps, false)
}

func newFreshArch(t *testing.T) *archFixture {
	t.Helper()
	s, deps := testStore(t)
	return buildArch(t, s, deps, true)
}

func buildArch(t *testing.T, s *Service, deps Dependencies, fresh bool, owners ...api.Scope) *archFixture {
	t.Helper()
	ctx := context.Background()
	executor := api.Scope{Config: deps.Config, Actor: api.Actor{Kind: "service", ID: testID(t)}, PolicyGeneration: 1}
	life, launch, grant := testID(t), testID(t), testID(t)
	target := api.LifeRef{LifeID: life, Run: 1}
	policy := api.EffectivePolicy{Generation: 1, SHA256: testDigest([]byte("component archive policy")), Context: api.RoleContext{Level: 6, Role: "supervisor"}, Rules: []api.Rule{}, Skip: []api.SkipEntry{}, Sources: []api.SourceRef{}, ProfileExclusions: []api.ID{}}
	fixtureProjection(t, s, "policy", api.ID(deps.Config), 1, policy)
	budget := api.Budget{WallMS: 60000, CPUSeconds: 10, MemoryBytes: 64 << 20, Processes: 4, DiskBytes: 4 << 20, Currency: "USD"}
	lane := api.Lane{LifeID: life, LaunchID: launch, RootLifeID: life, StarterChain: []api.ID{}, Name: "archive-component", Level: 3, Role: "executor", State: "verifying", Generation: 4, Run: 1, CancellationEpoch: 2, GrantSetID: grant, PolicyGeneration: 1, BudgetRemaining: budget, Workspace: api.Workspace{ID: testID(t), Branch: "lane/" + string(life)}}
	fixtureProjection(t, s, "lane", life, lane.Generation, lane)
	grants := api.GrantSet{ID: grant, LifeID: life, Generation: 1, PolicyGeneration: 1, SHA256: testDigest([]byte("source grants")), ExpiresAt: api.Timestamp(time.Now().Add(time.Minute).UTC().Format(timeFormat)), Data: []api.DataGrant{}, Resources: []api.ResourceGrant{}, Secrets: []api.SecretGrant{}, Profiles: []api.ProfileGrant{}, Network: []api.NetworkGrant{}, Channels: []api.ChannelGrant{}}
	fixtureProjection(t, s, "grants", grant, 1, grants)
	request := testRequest(t, "lane.archive", api.ArchiveRequest{Target: target, ExpectedGeneration: lane.Generation})
	human := api.Scope{Config: deps.Config, Actor: api.Actor{Kind: "human", ID: testID(t)}, Request: request, EndpointGeneration: 1, PolicyGeneration: 1, Connection: &scopeConnection{id: testID(t), binding: api.InstalledBinding{Config: deps.Config, Class: api.EndpointHuman, EndpointGeneration: 1}, peer: &scopePeer{}}, Frame: &archFrame{raw: archJSON(t, request)}}
	if len(owners) == 1 {
		human = owners[0]
		human.Request = request
		human.Frame = &archFrame{raw: archJSON(t, request)}
	}
	owner, retire := s.TrackMutation(ctx)
	t.Cleanup(retire)
	receipt, won, err := s.ReserveMutation(owner, api.RequestReservation{Scope: human, RawRequest: archJSON(t, request), Deadline: api.Timestamp(time.Now().Add(time.Minute).UTC().Format(timeFormat))})
	if err != nil || !won {
		t.Fatal("archive component reservation", err)
	}
	zero, exit := uint64(0), 0
	end := api.RunEndEvent{LaunchID: launch, Reason: "exit", BudgetRemaining: budget, Observation: api.ProcessObservation{Handle: api.ProcessHandle{ID: launch, Target: target, ContainmentID: testID(t), Generation: "component:agent"}, State: "exited", ExitCode: &exit, Survivors: &zero, PromptStatus: "completed", ObservedAt: archStamp()}}
	event := api.Event{Schema: api.SchemaVersion, ID: testID(t), Config: deps.Config, Kind: "lane.ended", Actor: executor.Actor, RequestedBy: human.Actor, OperationID: receipt.Operation.ID, RequestID: request.RequestID, LifeID: life, Run: 1, Origin: "service", StarterChain: []api.ID{}, Payload: archJSON(t, end)}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	seq, err := appendPrivateEvent(ctx, tx, event, archStamp())
	if err != nil {
		tx.Rollback()
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	fixtureProjection(t, s, "launch_observation", launch, 1, struct {
		Observation api.ProcessObservation
		Generation  api.Generation
	}{end.Observation, 1})
	r := archiveRecord{Scope: api.Scope{Config: deps.Config, Actor: human.Actor, PolicyGeneration: 1}, Request: request, Lane: lane, Phase: "sealed", Parts: []api.BlobRef{}, WorkerLaunchID: testID(t), WorkerActor: api.Actor{Kind: "worker", ID: testID(t)}}
	r.Job = archivejob.Job{ID: testID(t), Intent: archivejob.Intent{Request: api.ArchiveRequest{Target: target, ExpectedGeneration: lane.Generation}, OperationID: receipt.Operation.ID, CancellationEpoch: lane.CancellationEpoch, EndEventID: event.ID, EndSeq: seq}}
	r.Grants = grants
	r.Grants.ID = testID(t)
	r.Job.Lease = api.WorkerLease{ID: testID(t), Kind: "archive", Target: target, OperationID: receipt.Operation.ID, EffectID: testID(t), GrantSetID: r.Grants.ID, Generation: 1, ExpiresAt: grants.ExpiresAt}
	tx, err = s.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	content := []byte("actual current workspace bytes\n")
	ref, err := s.archiveBytes(ctx, tx, r, "artifact", content)
	if err != nil {
		tx.Rollback()
		t.Fatal(err)
	}
	tree := api.ObjectManifest{Schema: "laneboss.objects.v2", Entries: []api.ObjectEntry{{Path: "current.txt", Kind: "file", Mode: 0600, Content: &ref}}}
	bodies := map[api.ID][]byte{ref.ID: content}
	if len(owners) == 1 {
		head, pack := restoreGitSource(t, content)
		packRef, err := s.archiveBytes(ctx, tx, r, "artifact", pack)
		if err != nil {
			t.Fatal(err)
		}
		bodies[packRef.ID] = pack
		tree = api.ObjectManifest{Schema: "laneboss.objects.v2", Git: &api.ArchiveGit{Head: head, Branch: "lane/restore"}, Entries: []api.ObjectEntry{
			{Path: "workspace", Kind: "directory", Mode: 0700}, {Path: "workspace/current.txt", Kind: "file", Mode: 0600, Content: &ref},
			{Path: "git", Kind: "directory", Mode: 0700}, {Path: "git/pack", Kind: "file", Mode: 0400, Content: &packRef},
		}}
	}
	snapshot, err := s.archiveBytes(ctx, tx, r, "manifest", archJSON(t, tree))
	if err != nil {
		tx.Rollback()
		t.Fatal(err)
	}
	frozen := archivejob.Freeze{Target: target, LaunchID: launch, CancellationEpoch: lane.CancellationEpoch, Snapshot: snapshot, Writers: &zero, WritableExports: &zero, ObservedAt: archStamp()}
	r.Job.Freeze, err = s.archiveBytes(ctx, tx, r, "manifest", archJSON(t, frozen))
	if err != nil {
		tx.Rollback()
		t.Fatal(err)
	}
	r.Job.Lease.RuntimeManifest, err = s.archiveBytes(ctx, tx, r, "manifest", []byte("component enrolled runtime bytes"))
	if err != nil {
		tx.Rollback()
		t.Fatal(err)
	}
	r.Input = archivejob.Input{Schema: "laneboss.archive-input.v2", JobID: r.Job.ID, Intent: r.Job.Intent, Freeze: r.Job.Freeze, ReceiptID: testID(t), StoreID: s.storeID, Budget: budget}
	input, inputErr := canonicalValue(r.Input)
	if inputErr != nil {
		tx.Rollback()
		t.Fatal(inputErr)
	}
	r.Job.Lease.Input, err = s.archiveBytes(ctx, tx, r, "archive_input", input)
	if err != nil {
		tx.Rollback()
		t.Fatal(err)
	}
	r.Job.Plan = api.WorkerPlan{Schema: "laneboss.worker-plan.v2", Kind: "archive", Executable: api.Executable{ID: testID(t), SHA256: testDigest([]byte("runtime")), Version: "0.7.0"}, Input: r.Job.Lease.Input, GrantSetID: r.Grants.ID, Budget: budget, Argv: []string{"laneboss", "internal", "worker", "--binding", "/runtime/laneboss-worker.json", "--lease", string(r.Job.Lease.ID)}}
	if fresh {
		// Native source bytes are staged only to assemble the component fixture.
		// Roll them back: sealArchive must retain every object for the first time.
		objects := []api.ObjectWrite{}
		for _, source := range []api.BlobRef{ref, snapshot, r.Job.Lease.RuntimeManifest} {
			meta, data, err := objectRow(ctx, tx, source.ID)
			if err != nil {
				tx.Rollback()
				t.Fatal(err)
			}
			objects = append(objects, api.ObjectWrite{ObjectKey: source.ID, Class: source.Class, Bytes: data, SHA256: source.SHA256, Origin: meta.Origin, ACL: meta.ACL})
		}
		if err := tx.Rollback(); err != nil {
			t.Fatal(err)
		}
		r.Job.Freeze, r.Job.Lease.Input, r.Job.Plan.Input, r.Input.Freeze = api.BlobRef{}, api.BlobRef{}, api.BlobRef{}, api.BlobRef{}
		r.Phase = "freezing"
		fixtureProjection(t, s, "archive_job", r.Job.Intent.OperationID, 1, r)
		native := &archNative{intent: r.Job.Intent, freeze: frozen, objects: objects}
		s.deps.ArchiveNative = native
		deps.ArchiveNative = native
		return &archFixture{s: s, deps: deps, record: r, executor: executor, native: native, tree: tree, owner: owner, retire: retire}
	}
	cause := api.InternalIntent{ID: testID(t), Kind: api.InternalLifecycleEffect, Config: deps.Config, Actor: executor.Actor, RequestedBy: human.Actor, CauseOperationID: receipt.Operation.ID, CauseRequestID: request.RequestID, EffectID: r.Job.Lease.EffectID, Target: target, CancellationEpoch: lane.CancellationEpoch}
	if err := insertLaunchEffect(ctx, tx, api.Effect{ID: cause.EffectID, OperationID: cause.CauseOperationID, Context: &cause, Worker: &r.Job.Plan}); err != nil {
		tx.Rollback()
		t.Fatal(err)
	}
	if err := put(ctx, tx, "grants", r.Grants.ID, 1, r.Grants); err != nil {
		tx.Rollback()
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	r.Claim, err = s.ClaimEffect(ctx, executor, api.EffectClaimRequest{EffectID: cause.EffectID, ExpectedGeneration: 1, ClaimantID: executor.Actor.ID, Deadline: grants.ExpiresAt})
	if err != nil {
		t.Fatal(err)
	}
	r.Allocation = api.HelperLease{ID: testID(t), UID: uint32(os.Geteuid()) + 1, GID: uint32(os.Getegid()) + 1, ContainmentID: testID(t), EndpointGeneration: 1}
	endpoint := api.InstalledBinding{Config: deps.Config, Class: api.EndpointWorker, LaunchID: r.WorkerLaunchID, WorkerLeaseID: r.Job.Lease.ID, Target: &target, EndpointGeneration: 1, InstallationGeneration: 1}
	r.Endpoint = &endpoint
	r.Process = api.ProcessHandle{ID: r.WorkerLaunchID, Target: target, ContainmentID: r.Allocation.ContainmentID, Generation: "component:worker"}
	record := api.LaunchRecord{Kind: "worker", ID: r.WorkerLaunchID, Config: deps.Config, Target: target, RootLifeID: life, StarterChain: []api.ID{}, Actor: r.WorkerActor, UIDLeaseID: r.Allocation.ID, HostUID: r.Allocation.UID, ProcessGeneration: r.Process.Generation, ContainmentID: r.Process.ContainmentID, GrantSetID: r.Grants.ID, GrantsSHA256: r.Grants.SHA256, PolicyGeneration: 1, EndpointGeneration: 1}
	tx, err = s.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	bound, err := s.archiveEvent(r, "identity.bound", record)
	if err != nil {
		tx.Rollback()
		t.Fatal(err)
	}
	boundSeq, err := appendPrivateEvent(ctx, tx, bound, archStamp())
	if err != nil {
		tx.Rollback()
		t.Fatal(err)
	}
	identity := api.IdentityCommit{LaunchID: record.ID, EventID: bound.ID, CommittedSeq: boundSeq, RecordSHA256: testDigest(archJSON(t, record))}
	for _, row := range []struct {
		kind  string
		id    api.ID
		value any
	}{{"launch", record.ID, record}, {"launch_binding", record.ID, api.LaunchBindingRequest{Record: record, Identity: identity}}, {"endpoint", record.ID, api.EndpointProjection{Binding: endpoint, Generation: 1}}} {
		if err := put(ctx, tx, row.kind, row.id, 1, row.value); err != nil {
			tx.Rollback()
			t.Fatal(err)
		}
	}
	workerLease := r.Job.Lease
	workerLease.ConsumedBy = record.ID
	if err := put(ctx, tx, "worker_lease", workerLease.ID, 1, workerLease); err != nil {
		tx.Rollback()
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	archSave(t, s, r)
	peer := &archPeer{facts: api.PeerFacts{HostUID: r.Allocation.UID, HostGID: r.Allocation.GID, HostPID: os.Getpid(), ProcessGeneration: "component:connector", ContainmentID: r.Allocation.ContainmentID}}
	worker := api.Scope{Config: deps.Config, Actor: record.Actor, LaunchID: record.ID, EndpointGeneration: 1, PolicyGeneration: 1, Connection: &scopeConnection{id: testID(t), binding: endpoint, peer: peer}, Frame: &archFrame{}}
	native := &archNative{freeze: frozen, intent: r.Job.Intent}
	s.deps.ArchiveNative = native
	deps.ArchiveNative = native
	var tar bytes.Buffer
	if err := archivejob.Write(ctx, &tar, tree, func(_ context.Context, q api.BlobReadRequest) (api.BlobChunk, error) {
		body := bodies[q.ObjectID]
		data := body[q.Offset:min(int64(len(body)), q.Offset+int64(q.Limit))]
		return api.BlobChunk{ObjectID: q.ObjectID, Offset: q.Offset, Data: data, SHA256: testDigest(data)}, nil
	}, budget.DiskBytes); err != nil {
		t.Fatal(err)
	}
	return &archFixture{s: s, deps: deps, record: r, executor: executor, worker: worker, native: native, tree: tree, tar: tar.Bytes(), owner: owner, retire: retire}
}

func (f *archFixture) append(t *testing.T, data []byte) api.BlobRef {
	t.Helper()
	ref, err := f.s.ArchivePart(context.Background(), f.worker, f.record.Job.Lease.ID, 0, data)
	if err != nil {
		t.Fatal("real archive part append", err)
	}
	return ref
}
func (f *archFixture) result(t *testing.T, ref api.BlobRef, data []byte) api.WorkerResultReceipt {
	t.Helper()
	receipt := api.ArchiveReceipt{ID: f.record.Input.ReceiptID, LifeID: f.record.Lane.LifeID, Manifest: f.native.freeze.Snapshot, ArchiveSHA256: testDigest(data), ReadBackSHA256: testDigest(data), VerifiedAt: archStamp(), StoreID: f.s.storeID}
	result := archivejob.Completion{Receipt: receipt, Archive: api.ObjectAssembly{SHA256: receipt.ArchiveSHA256, Bytes: int64(len(data)), Parts: []api.BlobRef{ref}}}
	raw, err := canonicalValue(result)
	if err != nil {
		t.Fatal(err)
	}
	ack, err := f.s.WorkerResult(context.Background(), f.worker, api.WorkerResultSubmission{LeaseID: f.record.Job.Lease.ID, ExpectedGeneration: 1, InputSHA256: f.record.Job.Lease.Input.SHA256, Result: raw})
	if err != nil {
		t.Fatal("real archive result retention", err)
	}
	return ack
}

func TestArchOwner(t *testing.T) {
	f := newArch(t)
	scope := f.record.Scope
	scope.Request = f.record.Request
	won, err := f.s.ownsMutation(f.owner, scope, requestKey(scope.Request), f.record.Job.Intent.OperationID)
	if err != nil || !won {
		t.Fatal("actual archive insertion winner lost ownership", err)
	}
	stolen, err := f.s.ownsMutation(context.Background(), scope, requestKey(scope.Request), f.record.Job.Intent.OperationID)
	if err != nil {
		t.Fatal(err)
	}
	if stolen {
		t.Fatal("copied archive request acquired dispatcher ownership")
	}
	f.retire()
	won, err = f.s.ownsMutation(f.owner, scope, requestKey(scope.Request), f.record.Job.Intent.OperationID)
	if err != nil || won {
		t.Fatal("retired archive invocation retained ownership", err)
	}
}

func TestArchPartRetry(t *testing.T) {
	f := newArch(t)
	ref := f.append(t, f.tar)
	again, err := f.s.ArchivePart(context.Background(), f.worker, f.record.Job.Lease.ID, 0, append([]byte(nil), f.tar...))
	if err != nil || again != ref {
		t.Fatal("archive part retry changed its persisted identity", err)
	}
	changed := append([]byte(nil), f.tar...)
	changed[0] ^= 1
	if _, err := f.s.ArchivePart(context.Background(), f.worker, f.record.Job.Lease.ID, 0, changed); err == nil {
		t.Fatal("changed archive part retry was acknowledged")
	} else {
		expectCode(t, err, api.CodeIdempotencyConflict)
	}
	if _, err := f.s.ArchivePart(context.Background(), f.worker, f.record.Job.Lease.ID, 2, f.tar); err == nil {
		t.Fatal("archive part gap was acknowledged")
	} else {
		expectCode(t, err, api.CodeConflict)
	}
}

func TestArchByteGate(t *testing.T) {
	f := newArch(t)
	invalid := append(append([]byte(nil), f.tar...), make([]byte, 512)...)
	ref := f.append(t, invalid)
	var r archiveRecord
	if err := storedProjection(context.Background(), f.s.db, "archive_job", f.record.Job.Intent.OperationID, &r); err != nil {
		t.Fatal(err)
	}
	receipt := api.ArchiveReceipt{ID: r.Input.ReceiptID, LifeID: r.Lane.LifeID, Manifest: f.native.freeze.Snapshot, ArchiveSHA256: testDigest(invalid), ReadBackSHA256: testDigest(invalid), VerifiedAt: archStamp(), StoreID: f.s.storeID}
	raw, err := canonicalValue(archivejob.Completion{Receipt: receipt, Archive: api.ObjectAssembly{SHA256: receipt.ArchiveSHA256, Bytes: int64(len(invalid)), Parts: []api.BlobRef{ref}}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.s.verifyArchiveBytes(context.Background(), f.s.db, r, raw); err == nil {
		t.Fatal("noncanonical persisted archive passed the byte gate")
	}
	var count int
	if err := f.s.db.QueryRow("SELECT count(*) FROM events WHERE json_extract(data,'$.kind')='archive.verified'").Scan(&count); err != nil || count != 0 {
		t.Fatal("failed byte verification published success", err)
	}
}

func TestArchAtomicReply(t *testing.T) {
	f := newArch(t)
	ref := f.append(t, f.tar)
	f.result(t, ref, f.tar)
	observation := api.ProcessObservation{Handle: f.record.Process, State: "exited", PromptStatus: "completed", ObservedAt: archStamp()}
	zero, code := uint64(0), 0
	observation.Survivors, observation.ExitCode = &zero, &code
	first, err := f.s.CompleteArchive(context.Background(), f.executor, f.record.Claim, observation)
	if err != nil || first.Operation.Status != "succeeded" {
		t.Fatal("archive atomic completion failed", err)
	}
	if f.native.checks != 1 {
		t.Fatal("archive completion omitted the actual freeze recheck")
	}
	if err := f.s.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := New(f.deps)
	if err != nil {
		t.Fatal("archive durable reopen", err)
	}
	t.Cleanup(func() {
		if err := reopened.Close(); err != nil {
			t.Error(err)
		}
	})
	second, err := reopened.CompleteArchive(context.Background(), f.executor, f.record.Claim, observation)
	if err != nil || !second.Replayed || !sameValue(second.Operation, first.Operation) {
		t.Fatal("archive lost-reply retry changed its original completion", err)
	}
	var count int
	if err := reopened.db.QueryRow("SELECT count(*) FROM events WHERE json_extract(data,'$.kind')='archive.verified'").Scan(&count); err != nil || count != 1 {
		t.Fatal("archive retry duplicated its verification event", err)
	}
}

func TestArchExitGate(t *testing.T) {
	f := newArch(t)
	ref := f.append(t, f.tar)
	f.result(t, ref, f.tar)
	code := 0
	observation := api.ProcessObservation{Handle: f.record.Process, State: "exited", ExitCode: &code, PromptStatus: "completed", ObservedAt: archStamp()}
	if _, err := f.s.CompleteArchive(context.Background(), f.executor, f.record.Claim, observation); err == nil {
		t.Fatal("unknown worker survivors produced an archive receipt")
	} else {
		expectCode(t, err, api.CodeContainmentUnknown)
	}
	key := requestKey(f.record.Request)
	scope := f.record.Scope
	receipt, err := f.s.lookupReceipt(context.Background(), f.s.db, scope, key)
	if err != nil || receipt.Reply != nil {
		t.Fatal("unknown worker exit sealed the pending public reply", err)
	}
}

func TestArchCancelGate(t *testing.T) {
	f := newArch(t)
	lane := f.record.Lane
	lane.CancellationEpoch++
	fixtureProjection(t, f.s, "lane", lane.LifeID, lane.Generation, lane)
	if _, err := f.s.ArchivePart(context.Background(), f.worker, f.record.Job.Lease.ID, 0, f.tar); err == nil {
		t.Fatal("cancelled archive worker appended a persisted part")
	} else {
		expectCode(t, err, api.CodeConflict)
	}
}

func TestArchFreeze(t *testing.T) {
	f := newArch(t)
	meta, raw, err := objectRow(context.Background(), f.s.db, f.native.freeze.Snapshot.ID)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := archivejob.Snapshot{Freeze: f.native.freeze, Objects: []api.ObjectWrite{{ObjectKey: meta.Ref.ID, Class: meta.Ref.Class, Bytes: raw, SHA256: meta.Ref.SHA256, Origin: meta.Origin, ACL: meta.ACL}}}
	if err := validateArchiveFreeze(f.record, snapshot, time.Now()); err != nil {
		t.Fatal("measured freeze control failed", err)
	}
	count := uint64(1)
	snapshot.Freeze.Writers = &count
	if err := validateArchiveFreeze(f.record, snapshot, time.Now()); err == nil {
		t.Fatal("nonzero storage writers passed the archive freeze")
	}
	snapshot.Freeze.Writers = nil
	if err := validateArchiveFreeze(f.record, snapshot, time.Now()); err == nil {
		t.Fatal("unknown storage writers passed the archive freeze")
	}
}

func TestArchReserveOwner(t *testing.T) {
	f := newArch(t)
	scope := f.record.Scope
	scope.Request = f.record.Request
	scope.EndpointGeneration = 1
	scope.Connection = &scopeConnection{id: testID(t), binding: api.InstalledBinding{Config: scope.Config, Class: api.EndpointHuman, EndpointGeneration: 1}, peer: &scopePeer{}}
	scope.Frame = &archFrame{raw: archJSON(t, scope.Request)}
	job, err := f.s.ReserveArchive(f.owner, scope, f.record.Job.Intent)
	if err != nil || !sameValue(job, f.record.Job) {
		t.Fatal("archive exact reservation retry lost its durable job", err)
	}
	if _, err := f.s.ReserveArchive(context.Background(), scope, f.record.Job.Intent); err == nil {
		t.Fatal("losing dispatcher reserved an archive worker")
	} else {
		expectCode(t, err, api.CodeForbidden)
	}
}

func TestArchWorkerScope(t *testing.T) {
	f := newArch(t)
	scope := f.worker
	scope.Actor.ID = testID(t)
	if _, err := f.s.ArchivePart(context.Background(), scope, f.record.Job.Lease.ID, 0, f.tar); err == nil {
		t.Fatal("foreign worker scope appended an archive part")
	} else {
		expectCode(t, err, api.CodeUnauthenticated)
	}
}
