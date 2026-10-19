package migration

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

type migrationTestConnection struct {
	api.ConnectionContext
	binding api.InstalledBinding
}

type migrationReadView struct {
	value  api.ReadSnapshot
	closed bool
}

func (view *migrationReadView) Snapshot() api.ReadSnapshot { return view.value }
func (view *migrationReadView) Close() error {
	if view.closed {
		return integrityErr("fixture read view closed twice")
	}
	view.closed = true
	return nil
}

func (state *memStore) BeginRead(_ context.Context, scope api.Scope) (api.ReadView, error) {
	return &migrationReadView{value: api.ReadSnapshot{
		ID: DeterministicID("snapshot-", scope.Config, fmt.Sprint(len(state.events))), Config: scope.Config,
		LastSeq: api.Sequence(len(state.events)), AsOf: api.Timestamp(time.Now().UTC().Format(time.RFC3339Nano)),
	}}, nil
}

func (connection migrationTestConnection) Binding() api.InstalledBinding { return connection.binding }

func boundApplyScope(scope api.Scope) api.Scope {
	scope.EndpointGeneration = 1
	scope.Connection = migrationTestConnection{binding: api.InstalledBinding{
		Config: scope.Config, Class: api.EndpointHuman, InstallationGeneration: 1, EndpointGeneration: 1}}
	return scope
}

// This fixture represents the service coordinator's persisted measurements. It
// does not implement or claim OS freeze, backup or effect-claim acceptance.
func primeMigrationCompletion(t *testing.T, service *Service, state *memStore, humanScope api.Scope, plan api.MigrationPlan) (api.Scope, api.EffectLease) {
	t.Helper()
	var record api.EffectRecord
	for _, candidate := range state.effects {
		if candidate.Effect.Migration != nil && candidate.Effect.Migration.PlanID == plan.ID {
			record = candidate
			break
		}
	}
	if record.Effect.Context == nil {
		t.Fatal("apply did not persist its migration effect context")
	}
	record.Generation++
	record.State, record.ClaimID = "claimed", DeterministicID("claim-", string(record.Effect.ID))
	record.ClaimantID = record.Effect.Context.Actor.ID
	record.ClaimExpiresAt = api.Timestamp(time.Now().UTC().Add(time.Minute).Format(time.RFC3339Nano))
	state.effects[record.Effect.ID] = record
	deployment := state.deployments[plan.ID]
	freeze := api.FreezeReceipt{ID: DeterministicID("freeze-", string(plan.ID)), Config: humanScope.Config,
		OperationID: record.Effect.OperationID, InstallationGeneration: deployment.InstallationGeneration,
		DispatchEpoch: 1, FrozenAt: api.Timestamp(time.Now().UTC().Format(time.RFC3339Nano))}
	var configRef api.BlobRef
	for _, entry := range service.plans[plan.ID].bundle.Manifest.Inventory.Entries {
		if entry.Path == "config/config.toml" && entry.Content != nil {
			configRef = *entry.Content
		}
	}
	if configRef.ID == "" {
		t.Fatal("fixture has no frozen configuration")
	}
	releaseBytes, err := json.Marshal(map[string]string{"source_version": plan.SourceVersion, "fixture": "old-release"})
	if err != nil {
		t.Fatal(err)
	}
	releaseRef := state.putBlob("fixture-release", releaseBytes, "manifest")
	recoveryBytes, err := json.Marshal([]api.BlobRef{plan.SourceManifest, configRef, releaseRef})
	if err != nil {
		t.Fatal(err)
	}
	recoveryRef := state.putBlob("fixture-recovery", recoveryBytes, "manifest")
	backup := api.FrozenBackup{ID: DeterministicID("backup-", string(plan.ID)), StateManifest: plan.SourceManifest,
		ConfigManifest: configRef, ReleaseManifest: releaseRef, RecoveryEvidence: recoveryRef,
		Quiescence: api.QuiescenceReceipt{ID: "fixture-quiescence", Freeze: freeze, Observations: []api.ProcessObservation{},
			PendingEffectIDs: []api.ID{}, ObservedAt: freeze.FrozenAt}, VerifiedAt: freeze.FrozenAt}
	state.backups[backup.ID] = backup
	deployment.Generation++
	deployment.Phase, deployment.Freeze, deployment.Backup = "migrating", &freeze, &backup
	state.deployments[plan.ID] = deployment
	return api.Scope{Config: humanScope.Config, Actor: record.Effect.Context.Actor}, api.EffectLease{
		Record: record, ClaimID: record.ClaimID, ExpiresAt: record.ClaimExpiresAt}
}

func finishMigration(t *testing.T, service *Service, state *memStore, scope api.Scope, plan api.MigrationPlan) api.Operation {
	t.Helper()
	serviceScope, lease := primeMigrationCompletion(t, service, state, scope, plan)
	operation, err := service.CompleteMigration(context.Background(), serviceScope, lease)
	if err != nil {
		t.Fatalf("CompleteMigration failed: %v", err)
	}
	return operation
}

func migrationApplyFixture(t *testing.T) (*Service, *memStore, *memHuman, api.Scope, api.MigrationPlan, api.MigrationApplyRequest) {
	t.Helper()
	state, human := newMemStore(), newMemHuman()
	service, err := New(Dependencies{Store: state, Human: human, Worker: &memWorker{}})
	if err != nil {
		t.Fatal(err)
	}
	request, _ := buildFixtureInStore(t, state, "0.7.0", "demo")
	scope := api.Scope{Config: "demo", Actor: api.Actor{Kind: "human", ID: "human-1"}}
	plan, err := service.MigrationPlan(context.Background(), scope, request)
	if err != nil {
		t.Fatal(err)
	}
	apply := api.MigrationApplyRequest{PlanID: plan.ID}
	digest, err := RequestDigest(scope.Config, "migration.apply", apply)
	if err != nil {
		t.Fatal(err)
	}
	params, err := json.Marshal(apply)
	if err != nil {
		t.Fatal(err)
	}
	scope.Request = api.Request{Protocol: api.Protocol, Schema: api.SchemaVersion, Config: scope.Config,
		Method: "migration.apply", Params: params, RequestID: DeterministicID("request-", string(plan.ID)),
		IdempotencyKey: DeterministicID("idempotency-", string(plan.ID)), RequestSHA256: digest,
		Proof: &api.ProofRef{ID: "fixture-proof", RequestSHA256: digest, ExpiresAt: "2099-01-01T00:00:00Z"}}
	return service, state, human, boundApplyScope(scope), plan, apply
}

func TestMigrationWriteCatalog(t *testing.T) {
	service, state, _, scope, plan, request := migrationApplyFixture(t)
	if _, err := service.MigrationApply(context.Background(), scope, request); err != nil {
		t.Fatal(err)
	}
	public := state.transactions[0]
	if err := api.ValidateTransactionShape(public); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*api.Transaction){
		"missing-reply":           func(tx *api.Transaction) { tx.Reply = nil },
		"history-on-public-apply": func(tx *api.Transaction) { tx.Events = []api.Event{{Kind: "record.appended"}} },
		"canonical-decision":      func(tx *api.Transaction) { tx.Writes.Decisions = []api.DecisionProjection{{RecordID: "unapproved"}} },
		"state-changing-read":     func(tx *api.Transaction) { tx.Scope.Request.Method = "migration.plan" },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := public
			change(&candidate)
			if err := api.ValidateTransactionShape(candidate); err == nil {
				t.Fatal("migration transaction escaped its public write/reply matrix")
			}
		})
	}
	serviceScope, lease := primeMigrationCompletion(t, service, state, scope, plan)
	completion, err := buildImportTransaction(serviceScope, plan, service.plans[plan.ID].bundle, *lease.Record.Effect.Context, state.deployments[plan.ID])
	if err != nil {
		t.Fatal(err)
	}
	if err := api.ValidateTransactionShape(completion); err != nil {
		t.Fatalf("internal migration completion violates draft.4: %v", err)
	}
	if completion.Reply != nil || len(completion.Guards) != 0 || completion.Internal.Kind != api.InternalMigrationApply || len(completion.Writes.Decisions) != 0 || len(completion.Writes.Mail) != 0 {
		t.Fatal("migration completion consumed authority again or created active legacy projections")
	}
	for _, event := range completion.Events {
		if event.Actor != lease.Record.Effect.Context.Actor || event.RequestedBy != scope.Actor {
			t.Fatal("migration completion lost its actual service actor or original requester")
		}
	}
	wrongKind := *completion.Internal
	wrongKind.Kind = api.InternalEffectComplete
	completion.Internal = &wrongKind
	if err := api.ValidateTransactionShape(completion); err == nil {
		t.Fatal("generic effect completion accepted migration history writes")
	}
}

type migrationReceiptStore struct {
	*memStore
	lookup api.MutationReceipt
	await  api.MutationReceipt
}

func (store migrationReceiptStore) LookupReceipt(context.Context, api.Scope, api.RequestKey) (api.MutationReceipt, error) {
	return store.lookup, nil
}

func (store migrationReceiptStore) AwaitReceipt(context.Context, api.Scope, api.RequestKey) (api.MutationReceipt, error) {
	return store.await, nil
}

func TestMigrationReceiptBinding(t *testing.T) {
	_, state, human, scope, _, request := migrationApplyFixture(t)
	operation := api.Operation{ID: "retained-operation", Status: "pending", FirstSeq: 7, LastSeq: 8}
	raw, err := json.Marshal(operation)
	if err != nil {
		t.Fatal(err)
	}
	base := api.MutationReceipt{Config: scope.Config, Actor: scope.Actor, Operation: operation,
		Key:   api.RequestKey{Method: scope.Request.Method, IdempotencyKey: scope.Request.IdempotencyKey, RequestSHA256: scope.Request.RequestSHA256},
		Reply: &api.RPCReply{Result: raw}}
	for _, phase := range []string{"lookup", "await"} {
		for name, change := range map[string]func(*api.MutationReceipt){
			"config":    func(receipt *api.MutationReceipt) { receipt.Config = "other" },
			"kind":      func(receipt *api.MutationReceipt) { receipt.Actor.Kind = "lane" },
			"principal": func(receipt *api.MutationReceipt) { receipt.Actor.ID = "other" },
			"life":      func(receipt *api.MutationReceipt) { receipt.Actor.LifeID = "other" },
			"method":    func(receipt *api.MutationReceipt) { receipt.Key.Method = "upgrade.apply" },
			"key":       func(receipt *api.MutationReceipt) { receipt.Key.IdempotencyKey = "other" },
			"digest":    func(receipt *api.MutationReceipt) { receipt.Key.RequestSHA256 = api.Digest(strings.Repeat("0", 64)) },
		} {
			t.Run(phase+"/"+name, func(t *testing.T) {
				foreign := base
				change(&foreign)
				backend := migrationReceiptStore{memStore: state, lookup: foreign}
				if phase == "await" {
					backend.lookup, backend.await = base, foreign
					backend.lookup.Reply = nil
				}
				service, err := New(Dependencies{Store: backend, Human: human, Worker: &memWorker{}})
				if err != nil {
					t.Fatal(err)
				}
				_, err = service.MigrationApply(context.Background(), scope, request)
				var typed *api.Error
				if !asAPIError(err, &typed) || typed.Code != api.CodeIntegrity || len(state.transactions) != 0 || human.checks != 0 {
					t.Fatalf("foreign receipt escaped before proof/preflight: %v", err)
				}
			})
		}
	}
	backend := migrationReceiptStore{memStore: state, lookup: base}
	service, err := New(Dependencies{Store: backend, Human: human, Worker: &memWorker{}})
	if err != nil {
		t.Fatal(err)
	}
	replayed, err := service.MigrationApply(context.Background(), scope, request)
	if err != nil || !reflect.DeepEqual(replayed, operation) {
		t.Fatalf("matching receipt did not replay exact bytes before plan lookup: %+v, %v", replayed, err)
	}
}

func TestMigrationCompletionPrerequisites(t *testing.T) {
	for _, name := range []string{"missing-backup", "wrong-phase", "live-process", "unknown-process", "foreign-claim", "expired-claim"} {
		t.Run(name, func(t *testing.T) {
			service, state, _, scope, plan, request := migrationApplyFixture(t)
			if _, err := service.MigrationApply(context.Background(), scope, request); err != nil {
				t.Fatal(err)
			}
			serviceScope, lease := primeMigrationCompletion(t, service, state, scope, plan)
			deployment := state.deployments[plan.ID]
			want := api.CodeConflict
			switch name {
			case "missing-backup":
				deployment.Backup = nil
			case "wrong-phase":
				deployment.Phase = "planned"
			case "live-process", "unknown-process":
				backup := *deployment.Backup
				observation := api.ProcessObservation{State: "exited"}
				if name == "live-process" {
					count := uint64(1)
					observation.Survivors = &count
				}
				backup.Quiescence.Observations = []api.ProcessObservation{observation}
				deployment.Backup = &backup
				state.backups[backup.ID] = backup
				want = api.CodeContainmentUnknown
			case "foreign-claim":
				lease.ClaimID = "foreign"
				want = api.CodeForbidden
			case "expired-claim":
				lease.ExpiresAt = "2000-01-01T00:00:00Z"
				want = api.CodeForbidden
			}
			state.deployments[plan.ID] = deployment
			_, err := service.CompleteMigration(context.Background(), serviceScope, lease)
			var typed *api.Error
			if !asAPIError(err, &typed) || typed.Code != want || len(state.records) != 0 || len(state.events) != 0 {
				t.Fatalf("completion accepted %s or failed at the wrong gate: %v", name, err)
			}
		})
	}
}

type migrationBlobStore struct {
	*memStore
	change func(api.BlobReadRequest, api.BlobChunk) api.BlobChunk
}

func (store migrationBlobStore) Blob(ctx context.Context, scope api.Scope, request api.BlobReadRequest) (api.BlobChunk, error) {
	chunk, err := store.memStore.Blob(ctx, scope, request)
	if err != nil {
		return chunk, err
	}
	return store.change(request, chunk), nil
}

func TestMigrationBlobReadIntegrity(t *testing.T) {
	state := newMemStore()
	data := []byte("source bytes with a tail")
	ref := state.putBlob("blob-source", data, "archive")
	actual, err := readBlobFull(context.Background(), state, api.Scope{}, ref)
	if err != nil || !bytes.Equal(actual, data) {
		t.Fatalf("valid full source blob did not round trip: %v", err)
	}
	prefix := ref
	prefix.Bytes, prefix.SHA256 = 6, DigestBytes(data[:6])
	if _, err := readBlobFull(context.Background(), state, api.Scope{}, prefix); err == nil || !strings.Contains(err.Error(), "prefix") {
		t.Fatalf("a matching prefix digest hid trailing source bytes: %v", err)
	}
	for name, change := range map[string]func(api.BlobReadRequest, api.BlobChunk) api.BlobChunk{
		"foreign-object": func(_ api.BlobReadRequest, chunk api.BlobChunk) api.BlobChunk {
			chunk.ObjectID = "foreign-object"
			return chunk
		},
		"end-hash": func(request api.BlobReadRequest, chunk api.BlobChunk) api.BlobChunk {
			if request.Offset == ref.Bytes {
				chunk.SHA256 = DigestBytes([]byte("not empty"))
			}
			return chunk
		},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := readBlobFull(context.Background(), migrationBlobStore{memStore: state, change: change}, api.Scope{}, ref)
			var typed *api.Error
			if !asAPIError(err, &typed) || typed.Code != api.CodeIntegrity {
				t.Fatalf("invalid source blob receipt escaped its integrity gate: %v", err)
			}
		})
	}
}

type migrationNoReplyStore struct{ *memStore }

func (store migrationNoReplyStore) Transact(ctx context.Context, transaction api.Transaction) (api.Commit, error) {
	commit, err := store.memStore.Transact(ctx, transaction)
	commit.Reply = nil
	return commit, err
}

func TestMigrationRequiresDurableReply(t *testing.T) {
	service, state, _, scope, _, request := migrationApplyFixture(t)
	service.deps.Store = migrationNoReplyStore{state}
	operation, err := service.MigrationApply(context.Background(), scope, request)
	var typed *api.Error
	if !asAPIError(err, &typed) || typed.Code != api.CodeIntegrity || operation.ID != "" || len(state.transactions) != 1 {
		t.Fatalf("migration fabricated a successful result without a durable reply: %+v, %v", operation, err)
	}
}
