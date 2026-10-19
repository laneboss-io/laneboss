package templates_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client"
	"laneboss.io/laneboss/internal/v2/templates"
)

type fixtureClock struct{ now time.Time }

func (clock fixtureClock) Now() time.Time { return clock.now }

type fixtureFrame struct{ raw []byte }

func (frame fixtureFrame) Bytes() []byte { return bytes.Clone(frame.raw) }
func (fixtureFrame) Verify(context.Context, api.ConnectionContext) error {
	return errors.New("a component fixture cannot verify a real transport frame")
}

type fixturePublisher struct{ api.OrgPublisher }

type fixtureHuman struct {
	api.HumanVerifier
	store   *memoryStore
	calls   int
	failure error
}

func (human *fixtureHuman) CheckProof(_ context.Context, _ api.Scope, _ api.ProofRef, _ api.HumanChallengeRequest) (api.VerifiedHumanProof, error) {
	human.calls++
	if human.failure != nil {
		return api.VerifiedHumanProof{}, human.failure
	}
	return human.store.proof, nil
}

func (s *memoryStore) LookupReceipt(_ context.Context, scope api.Scope, key api.RequestKey) (api.MutationReceipt, error) {
	s.receiptCalls++
	trustedService := s.lifecycleService != nil && scope.Actor == *s.lifecycleService && scope.Actor.Kind == "service"
	foreignActor := s.reservation.Actor.Kind != scope.Actor.Kind || s.reservation.Actor.ID != scope.Actor.ID || s.reservation.Actor.LifeID != scope.Actor.LifeID
	if s.reservation.Config != scope.Config || foreignActor && !trustedService ||
		s.reservation.Key.Method != key.Method || s.reservation.Key.IdempotencyKey != key.IdempotencyKey {
		return api.MutationReceipt{}, &api.Error{Code: api.CodeNotFound, Message: "fixture receipt domain differs", Instead: "Use the original configuration, principal, life, method and key."}
	}
	if s.reservation.Key != key {
		return api.MutationReceipt{}, &api.Error{Code: api.CodeIdempotencyConflict, Message: "fixture receipt key differs", Instead: "Reuse the exact fixture request."}
	}
	receipt := s.reservation
	if s.changeReceipt != nil {
		s.changeReceipt(&receipt)
	}
	return receipt, nil
}

func mutationKey(t *testing.T) api.ID {
	t.Helper()
	key, err := client.NewRequestID()
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func (s *memoryStore) AuthorizationTarget(_ context.Context, _ api.Scope, _ api.Request) (api.HumanChallengeRequest, error) {
	return s.target, s.targetError
}

func reframe(t *testing.T, store *memoryStore, scope *api.Scope) {
	t.Helper()
	raw, err := json.Marshal(scope.Request)
	if err != nil {
		t.Fatal(err)
	}
	scope.Frame = fixtureFrame{raw: raw}
	store.reservation.RawRequest = bytes.Clone(raw)
}

func bootstrapComponent(t *testing.T) (*templates.Service, *memoryStore, *fixtureHuman, api.Scope, api.BootstrapRequest) {
	t.Helper()
	_, store, policy, scope, _ := component(t)
	scope.Actor = api.Actor{Kind: "human", ID: "human-one"}
	scope.EndpointGeneration = 2
	manifest := api.ObjectManifest{Schema: "laneboss.objects.v2", Entries: []api.ObjectEntry{}}
	for _, file := range store.snapshot.Sources {
		content := file.Content
		manifest.Entries = append(manifest.Entries, api.ObjectEntry{Path: file.Source.Path, Kind: "file", Mode: file.Mode, Content: &content})
	}
	data, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	ref := api.BlobRef{ID: "bootstrap-input", Class: "manifest", Bytes: int64(len(data)), SHA256: digest(data)}
	store.put(ref, data)
	request := api.BootstrapRequest{OrgName: "new-org", SourceManifest: ref}
	params, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	scope.Request, err = client.PrepareRequest(api.Request{Config: scope.Config, Method: "org.bootstrap", Params: params,
		IdempotencyKey: mutationKey(t)})
	if err != nil {
		t.Fatal(err)
	}
	scope.Request.Proof = &api.ProofRef{ID: "proof-one", RequestSHA256: scope.Request.RequestSHA256, ExpiresAt: "2030-01-01T00:10:00Z"}
	store.target = api.HumanChallengeRequest{Method: "org.bootstrap", TargetID: "new-org",
		RequestSHA256: scope.Request.RequestSHA256, BaseGeneration: 0}
	store.proof = api.VerifiedHumanProof{Ref: *scope.Request.Proof, Config: scope.Config, PrincipalID: scope.Actor.ID,
		CredentialID: "credential-one", NonceID: "nonce-one", Target: store.target,
		EndpointClass: api.EndpointHuman, EndpointGeneration: scope.EndpointGeneration}
	store.reservation = api.MutationReceipt{Config: scope.Config, Actor: scope.Actor,
		Key:       api.RequestKey{Method: scope.Request.Method, IdempotencyKey: scope.Request.IdempotencyKey, RequestSHA256: scope.Request.RequestSHA256},
		Operation: api.Operation{ID: "reserved-operation", Status: "pending"}}
	reframe(t, store, &scope)
	store.orgError = &api.Error{Code: api.CodeInvalid, Message: "bootstrap must not read a snapshot", Instead: "Use the authorization target and absent-org CAS."}
	store.allowBootstrap = true
	human := &fixtureHuman{store: store}
	service, err := templates.New(templates.Dependencies{Store: store, Policy: policy, Publisher: &fixturePublisher{}, Human: human,
		Clock:             fixtureClock{now: time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)},
		BootstrapRenderer: store.snapshot.Renderer, BootstrapOwnership: store.snapshot.OwnershipManifest})
	if err != nil {
		t.Fatal(err)
	}
	return service, store, human, scope, request
}

func TestBootstrapAtomicIntent(t *testing.T) {
	service, store, human, scope, request := bootstrapComponent(t)
	operation, err := service.OrgBootstrap(context.Background(), scope, request)
	if len(store.transactions) != 1 {
		t.Fatalf("bootstrap did not submit its atomic intent: %v", err)
	}
	// Inspect the submitted intent even when the shared shape validator refuses
	// it. A missing-guard control must reach this assertion, not a setup error.
	tx := store.transactions[0]
	if len(tx.Compare) != 1 || tx.Compare[0].Kind != api.CompareOrg || tx.Compare[0].ID != store.target.TargetID || tx.Compare[0].Generation != 0 {
		t.Fatal("bootstrap omitted its absent-org comparison")
	}
	if len(tx.Guards) != 1 || tx.Guards[0].Proof == nil || *tx.Guards[0].Proof != (api.ProofUse{Proof: store.proof.Ref, Target: store.target}) {
		t.Fatal("bootstrap proof use was not atomic with the effect")
	}
	if len(tx.Effects) != 1 || tx.Effects[0].Bootstrap == nil || tx.Effects[0].Context == nil {
		t.Fatal("bootstrap omitted its durable typed publication effect")
	}
	if err != nil {
		t.Fatal(err)
	}
	if operation.ID != store.reservation.Operation.ID || operation.Status != "pending" ||
		operation.FirstSeq == 0 || operation.FirstSeq != store.sequence || operation.LastSeq != store.sequence || human.calls != 1 {
		t.Fatal("bootstrap did not return its actual pending reservation and commit")
	}
	effect := tx.Effects[0]
	if effect.Bootstrap.Renderer != store.snapshot.Renderer || effect.Bootstrap.OwnershipManifest != store.snapshot.OwnershipManifest ||
		effect.Bootstrap.SourceManifest != request.SourceManifest || effect.Context.Kind != api.InternalOrgBootstrap ||
		effect.Context.RequestedBy != scope.Actor || effect.Context.CauseOperationID != operation.ID || effect.Context.EffectID != effect.ID {
		t.Fatal("bootstrap effect lost its protected pins or actual requester")
	}
	if len(tx.Events) != 0 || len(tx.Writes.OrgSnapshots) != 0 || !bytes.Equal(tx.RawRequest, scope.Frame.Bytes()) {
		t.Fatal("queued bootstrap claimed publication or lost exact request bytes")
	}
	// Replaying the retained reply performs no proof preflight or second effect.
	store.orgError = errors.New("replay must precede org preflight")
	store.proof.ConsumedBy = operation.ID
	human.failure = errors.New("a replay must not check its consumed proof again")
	again, err := service.OrgBootstrap(context.Background(), scope, request)
	if err != nil || !reflect.DeepEqual(again, operation) || len(store.transactions) != 1 || human.calls != 1 {
		t.Fatal("bootstrap replay repeated proof use or publication intent")
	}
}

func TestBootstrapProofGuards(t *testing.T) {
	for _, row := range []struct {
		name   string
		change func(*memoryStore, *api.Scope)
	}{
		{"expired", func(s *memoryStore, scope *api.Scope) {
			scope.Request.Proof.ExpiresAt = "2029-12-31T23:59:59Z"
			s.proof.Ref = *scope.Request.Proof
		}},
		{"consumed", func(s *memoryStore, _ *api.Scope) { s.proof.ConsumedBy = "earlier-operation" }},
		{"principal", func(s *memoryStore, _ *api.Scope) { s.proof.PrincipalID = "another-human" }},
		{"endpoint", func(s *memoryStore, _ *api.Scope) { s.proof.EndpointGeneration++ }},
		{"lane-proof", func(s *memoryStore, _ *api.Scope) { s.proof.EndpointClass = api.EndpointLane }},
		{"target", func(s *memoryStore, _ *api.Scope) { s.proof.Target.TargetID = "another-org" }},
	} {
		t.Run(row.name, func(t *testing.T) {
			service, store, _, scope, request := bootstrapComponent(t)
			row.change(store, &scope)
			reframe(t, store, &scope)
			operation, err := service.OrgBootstrap(context.Background(), scope, request)
			if err == nil || operation.ID != "" || store.writes != 0 {
				t.Fatal("invalid human proof reached the bootstrap transaction")
			}
			errorCode(t, err, api.CodeForbidden)
		})
	}
}

func TestBootstrapExistingOrg(t *testing.T) {
	valid, _, _, validScope, validRequest := bootstrapComponent(t)
	if result, err := valid.OrgBootstrap(context.Background(), validScope, validRequest); err != nil || result.ID == "" || result.Status != "pending" {
		t.Fatal("valid absent-org bootstrap was refused", err)
	}
	service, store, _, scope, request := bootstrapComponent(t)
	store.target.BaseGeneration = store.snapshot.Ref.Generation
	store.proof.Target = store.target
	operation, err := service.OrgBootstrap(context.Background(), scope, request)
	if err == nil || operation.ID != "" || store.writes != 0 {
		t.Fatal("bootstrap replaced an existing org or returned success")
	}
	errorCode(t, err, api.CodeConflict)
}

func TestBootstrapTargetError(t *testing.T) {
	valid, _, _, validScope, validRequest := bootstrapComponent(t)
	if result, err := valid.OrgBootstrap(context.Background(), validScope, validRequest); err != nil || result.ID == "" {
		t.Fatal("valid bootstrap failed", err)
	}
	service, store, _, scope, request := bootstrapComponent(t)
	sentinel := &api.Error{Code: api.CodeUnavailable, Owner: "lb-v2-service", Message: "target unavailable"}
	store.targetError = sentinel
	result, err := service.OrgBootstrap(context.Background(), scope, request)
	if !errors.Is(err, sentinel) || result.ID != "" || store.writes != 0 || len(store.orgRequests) != 0 {
		t.Fatal("bootstrap lost its authorization-target error", err)
	}
}

func TestBootstrapFrameBinding(t *testing.T) {
	service, store, _, scope, request := bootstrapComponent(t)
	changed := scope.Request
	other := request
	other.OrgName = "different-org"
	params, err := json.Marshal(other)
	if err != nil {
		t.Fatal(err)
	}
	changed.Params = params
	raw, err := json.Marshal(changed)
	if err != nil {
		t.Fatal(err)
	}
	scope.Frame, store.reservation.RawRequest = fixtureFrame{raw: raw}, raw
	operation, err := service.OrgBootstrap(context.Background(), scope, request)
	if err == nil || operation.ID != "" || store.writes != 0 {
		t.Fatal("bootstrap accepted a frame with different exact intent")
	}
	errorCode(t, err, api.CodeIntegrity)
}

func TestBootstrapCommitFailure(t *testing.T) {
	t.Run("transaction", func(t *testing.T) {
		service, store, _, scope, request := bootstrapComponent(t)
		failure := &api.Error{Code: api.CodeConflict, Message: "fixture absence CAS changed", Instead: "Use D6 on the new baseline."}
		store.transactionError = failure
		operation, err := service.OrgBootstrap(context.Background(), scope, request)
		if !errors.Is(err, failure) || operation.ID != "" || len(store.transactions) != 1 {
			t.Fatal("bootstrap transaction failure was swallowed")
		}
	})
	for _, name := range []string{"nil-reply", "empty-reply"} {
		t.Run(name, func(t *testing.T) {
			service, store, _, scope, request := bootstrapComponent(t)
			store.changeCommit = func(commit *api.Commit) {
				commit.Reply = nil
				if name == "empty-reply" {
					commit.Reply = &api.RPCReply{}
				}
			}
			operation, err := service.OrgBootstrap(context.Background(), scope, request)
			if err == nil || operation.ID != "" {
				t.Fatal("missing durable bootstrap reply returned success")
			}
			errorCode(t, err, api.CodeIntegrity)
		})
	}
}
