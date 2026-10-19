package secrets

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client"
	"laneboss.io/laneboss/internal/v2/secrets/native"
	"laneboss.io/laneboss/internal/v2/secrets/testdir"
	"laneboss.io/laneboss/internal/v2/secrets/wire"
)

// This is a transaction/identity unit fixture, not authenticated-service
// evidence. Issued proofs are explicit test facts; unexpected proofs refuse.
// The backend is the real native implementation with fresh random canaries.
type mutationState struct {
	api.StateStore
	stages            testdir.StageLedger
	mu                sync.Mutex
	receipts          map[string]api.MutationReceipt
	issued            map[api.ID]api.VerifiedHumanProof
	used              map[api.ID]api.ID
	events            []api.Event
	checked, attempts int
	fail              error
	directory         string
}

func fixtureDomain(scope api.Scope) string {
	return scope.Config + "/" + string(scope.Actor.ID) + "/" + string(scope.Request.Method) + "/" + string(scope.Request.IdempotencyKey)
}

func copyReceipt(r api.MutationReceipt) api.MutationReceipt {
	r.RawRequest = append([]byte(nil), r.RawRequest...)
	if r.Reply != nil {
		r.Reply = &api.RPCReply{Result: append(json.RawMessage(nil), r.Reply.Result...), Error: r.Reply.Error}
	}
	return r
}

func (m *mutationState) LookupReceipt(_ context.Context, scope api.Scope, key api.RequestKey) (api.MutationReceipt, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.receipts[fixtureDomain(scope)]
	if !ok {
		return r, wire.Error(api.CodeNotFound, "fixture receipt is absent")
	}
	if r.Config != scope.Config || r.Actor != scope.Actor || r.Key != key {
		return api.MutationReceipt{}, wire.Error(api.CodeIdempotencyConflict, "fixture retry intent changed")
	}
	return copyReceipt(r), nil
}

func (m *mutationState) ReserveRequest(ctx context.Context, request api.RequestReservation) (api.MutationReceipt, error) {
	if err := wire.Context(ctx); err != nil {
		return api.MutationReceipt{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	scope := request.Scope
	if !bytes.Equal(request.RawRequest, scope.Frame.Bytes()) {
		return api.MutationReceipt{}, wire.Error(api.CodeIntegrity, "fixture reservation changed frame")
	}
	if r, ok := m.receipts[fixtureDomain(scope)]; ok {
		if !receiptMatches(scope, r) {
			return api.MutationReceipt{}, wire.Error(api.CodeIdempotencyConflict, "fixture retry intent changed")
		}
		return copyReceipt(r), nil
	}
	id, err := client.NewRequestID()
	if err != nil {
		return api.MutationReceipt{}, err
	}
	r := api.MutationReceipt{Config: scope.Config, Actor: scope.Actor, Key: requestKey(scope),
		Operation: api.Operation{ID: id, Status: "pending"}, RawRequest: append([]byte(nil), request.RawRequest...)}
	m.receipts[fixtureDomain(scope)] = r
	return copyReceipt(r), nil
}

func (*mutationState) AuthorizationTarget(_ context.Context, scope api.Scope, request api.Request) (api.HumanChallengeRequest, error) {
	var input struct {
		Name string `json:"name"`
	}
	if err := json.Unmarshal(request.Params, &input); err != nil || !wire.Name(input.Name) {
		return api.HumanChallengeRequest{}, wire.Error(api.CodeInvalid, "fixture mutation has no name")
	}
	return api.HumanChallengeRequest{Method: request.Method, TargetID: api.ID(input.Name), RequestSHA256: request.RequestSHA256}, nil
}

type mutationReadView struct {
	api.ReadView
	snapshot api.ReadSnapshot
	events   []api.Event
	closed   bool
}

func (v *mutationReadView) Snapshot() api.ReadSnapshot { return v.snapshot }
func (v *mutationReadView) Close() error               { v.closed = true; return nil }
func (m *mutationState) BeginRead(ctx context.Context, scope api.Scope) (api.ReadView, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if scope.Config != "service-case" || scope.Actor.Kind != "service" {
		return nil, wire.Error(api.CodeForbidden, "fixture history scope differs")
	}
	return &mutationReadView{snapshot: api.ReadSnapshot{Config: scope.Config, ID: "mutation-history", LastSeq: api.Sequence(len(m.events))}, events: append([]api.Event{}, m.events...)}, nil
}

func (m *mutationState) Events(_ context.Context, scope api.Scope, _ api.EventTailRequest) (api.EventPage, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if scope.Config != "service-case" || scope.Actor.Kind != "service" {
		return api.EventPage{}, wire.Error(api.CodeForbidden, "fixture secret history scope differs")
	}
	if v, ok := scope.ReadView.(*mutationReadView); ok {
		if v.closed {
			return api.EventPage{}, wire.Error(api.CodeConflict, "fixture history snapshot closed")
		}
		return api.EventPage{Events: append([]api.Event{}, v.events...), Complete: true}, nil
	}
	return api.EventPage{Events: append([]api.Event{}, m.events...), Complete: true}, nil
}

func (m *mutationState) CommitSecretStage(ctx context.Context, input api.Transaction, allocated api.SecretStage) (api.Commit, error) {
	return m.stages.CommitSecretStage(ctx, input, allocated)
}

func (m *mutationState) Transact(ctx context.Context, tx api.Transaction) (api.Commit, error) {
	if tx.Scope.Request.Method == "secret.stage" {
		return m.stages.Transact(ctx, tx)
	}
	if err := wire.Context(ctx); err != nil {
		return api.Commit{}, err
	}
	if err := api.ValidateTransactionShape(tx); err != nil {
		return api.Commit{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.attempts++
	r, ok := m.receipts[fixtureDomain(tx.Scope)]
	if !ok || !receiptMatches(tx.Scope, r) {
		return api.Commit{}, wire.Error(api.CodeIntegrity, "fixture transaction has no exact reservation")
	}
	if r.Reply != nil {
		return api.Commit{Reply: copyReceipt(r).Reply, Operation: r.Operation, Replayed: true}, nil
	}
	if tx.Reply == nil || tx.Reply.Error != nil || len(tx.Guards) != 1 || tx.Guards[0].Proof == nil ||
		len(tx.Events) != 1 || len(tx.Effects) != 0 || !reflect.ValueOf(tx.Writes).IsZero() ||
		!bytes.Equal(tx.RawRequest, tx.Scope.Frame.Bytes()) {
		return api.Commit{}, wire.Error(api.CodeIntegrity, "fixture transaction omitted atomic proof event or reply")
	}
	use := tx.Guards[0].Proof
	target, err := m.AuthorizationTarget(ctx, tx.Scope, tx.Scope.Request)
	if err != nil {
		return api.Commit{}, err
	}
	verified, exists := m.issued[use.Proof.ID]
	if !exists || verified.Ref != use.Proof || verified.Target != target || use.Target != target || m.used[use.Proof.ID] != "" {
		return api.Commit{}, wire.Error(api.CodeForbidden, "fixture proof is unknown mismatched or consumed")
	}
	event := tx.Events[0]
	expectedKind := map[api.Method]api.EventKind{"secret.import": "secret.imported", "secret.rotate": "secret.rotated", "secret.revoke": "secret.revoked"}[tx.Scope.Request.Method]
	if event.Config != tx.Scope.Config || event.Kind != expectedKind || event.OperationID != r.Operation.ID || event.RequestID != tx.Scope.Request.RequestID {
		return api.Commit{}, wire.Error(api.CodeIntegrity, "fixture event causality differs")
	}
	// Observe protected bytes before the commit; committing first fails this
	// independent check, rather than being accepted by a success-only mock.
	var info api.SecretInfo
	if event.Kind == "secret.revoked" {
		var payload api.SecretEvent
		if err := json.Unmarshal(event.Payload, &payload); err != nil || len(payload.Names) != 1 || len(payload.Versions) != 1 {
			return api.Commit{}, wire.Error(api.CodeIntegrity, "fixture revoke payload differs")
		}
		for _, prior := range m.events {
			if prior.Kind != "secret.imported" && prior.Kind != "secret.rotated" {
				continue
			}
			var p api.SecretEvent
			if err := json.Unmarshal(prior.Payload, &p); err != nil {
				return api.Commit{}, err
			}
			if p.Names[0] == payload.Names[0] && p.Versions[0] == payload.Versions[0] {
				info.SourceHandle = prior.ID
			}
		}
	} else {
		if err := json.Unmarshal(tx.Reply.Result, &info); err != nil {
			return api.Commit{}, err
		}
		if info.SourceHandle != event.ID {
			return api.Commit{}, wire.Error(api.CodeIntegrity, "fixture event lost protected source correlation")
		}
	}
	data, err := os.ReadFile(filepath.Join(m.directory, string(info.SourceHandle)+".json"))
	if err != nil {
		return api.Commit{}, wire.Error(api.CodeIntegrity, "fixture event preceded protected backend write")
	}
	var record struct {
		Info api.SecretInfo `json:"info"`
	}
	if err := json.Unmarshal(data, &record); err != nil || record.Info.Revoked != (event.Kind == "secret.revoked") {
		return api.Commit{}, wire.Error(api.CodeIntegrity, "fixture event preceded protected backend state")
	}
	if m.fail != nil {
		return api.Commit{}, m.fail
	}
	event.Seq = api.Sequence(len(m.events) + 1)
	r.Operation.Status, r.Operation.FirstSeq, r.Operation.LastSeq = "succeeded", event.Seq, event.Seq
	r.FirstSeq, r.LastSeq = event.Seq, event.Seq
	r.Reply = &api.RPCReply{Result: append(json.RawMessage(nil), tx.Reply.Result...)}
	// These three changes are under the same fixture transaction lock.
	m.used[use.Proof.ID] = r.Operation.ID
	m.events = append(m.events, event)
	m.receipts[fixtureDomain(tx.Scope)] = r
	return api.Commit{Reply: copyReceipt(r).Reply, Operation: r.Operation, FirstSeq: r.FirstSeq, LastSeq: r.LastSeq}, nil
}

type mutationHuman struct {
	api.HumanVerifier
	state *mutationState
	clock api.Clock
}

func (h *mutationHuman) CheckProof(_ context.Context, scope api.Scope, proof api.ProofRef, target api.HumanChallengeRequest) (api.VerifiedHumanProof, error) {
	h.state.mu.Lock()
	defer h.state.mu.Unlock()
	h.state.checked++
	verified, ok := h.state.issued[proof.ID]
	if !ok || verified.Ref != proof || verified.Target != target || verified.PrincipalID != scope.Actor.ID ||
		h.state.used[proof.ID] != "" || !future(proof.ExpiresAt, h.clock.Now()) {
		return api.VerifiedHumanProof{}, wire.Error(api.CodeForbidden, "fixture proof is unknown mismatched or consumed")
	}
	return verified, nil
}

type measuredBackend struct {
	*native.Service
	mu                      sync.Mutex
	stores, revokes, scopes int
	failStore               error
}
type measuredView struct {
	api.SecretBackend
	owner *measuredBackend
}

func (v measuredView) Store(ctx context.Context, info api.SecretInfo, material api.SecretMaterial) (api.SecretInfo, error) {
	v.owner.mu.Lock()
	v.owner.stores++
	err := v.owner.failStore
	v.owner.mu.Unlock()
	if err != nil {
		return api.SecretInfo{}, err
	}
	return v.SecretBackend.Store(ctx, info, material)
}
func (v measuredView) Revoke(ctx context.Context, info api.SecretInfo) error {
	v.owner.mu.Lock()
	v.owner.revokes++
	v.owner.mu.Unlock()
	return v.SecretBackend.Revoke(ctx, info)
}
func (b *measuredBackend) WithMutation(ctx context.Context, operation api.ID, fn func(api.SecretBackend, []api.SecretInfo) error) error {
	b.mu.Lock()
	b.scopes++
	b.mu.Unlock()
	return b.Service.WithMutation(ctx, operation, func(protected api.SecretBackend, infos []api.SecretInfo) error {
		return fn(measuredView{SecretBackend: protected, owner: b}, infos)
	})
}

func syntheticBytes(t *testing.T, n int) []byte {
	t.Helper()
	data := make([]byte, n)
	if _, err := rand.Read(data); err != nil {
		t.Fatal("synthetic random bytes unavailable")
	}
	return data
}

func mutationFixture(t *testing.T) (*Service, *measuredBackend, *mutationState, *clockFixture, []byte) {
	t.Helper()
	clock := &clockFixture{now: time.Date(2001, 2, 3, 4, 5, 6, 0, time.UTC)}
	directory := filepath.Join(testdir.New(t), "records")
	key := syntheticBytes(t, 32)
	backend := openMutationBackend(t, directory, clock, key)
	state := &mutationState{directory: directory, receipts: map[string]api.MutationReceipt{},
		issued: map[api.ID]api.VerifiedHumanProof{}, used: map[api.ID]api.ID{}, events: []api.Event{}}
	return newMutationService(t, backend, state, clock), backend, state, clock, key
}

func openMutationBackend(t *testing.T, directory string, clock api.Clock, key []byte) *measuredBackend {
	t.Helper()
	n, err := native.New(native.Dependencies{Directory: directory, Config: "service-case", KeyHandle: "key-a", Clock: clock})
	if err != nil {
		t.Fatal("cannot open mutation backend")
	}
	t.Cleanup(func() {
		if err := n.Close(); err != nil {
			t.Error("cannot close mutation backend")
		}
	})
	if err := n.Unlock(context.Background(), "key-a", bytes.NewReader(key)); err != nil {
		t.Fatal("cannot unlock mutation backend")
	}
	return &measuredBackend{Service: n}
}

func newMutationService(t *testing.T, backend api.SecretBackend, state *mutationState, clock api.Clock) *Service {
	t.Helper()
	s, err := New(Dependencies{ProjectionIdentity: deniedProjection{}, Backend: backend, Store: state, Human: &mutationHuman{state: state, clock: clock}, Clock: clock, Config: "service-case"})
	if err != nil {
		t.Fatal("cannot initialize mutating secret service")
	}
	return s
}

func mutationScope(t *testing.T, clock *clockFixture, connection api.ConnectionContext, method api.Method, input any, state *mutationState) api.Scope {
	t.Helper()
	scope := scopeFixture(method)
	if connection != nil {
		scope.Connection = connection
	}
	c := scope.Connection.(*connectionFixture)
	c.authority.IdleExpiresAt = api.Timestamp(clock.now.Add(4 * time.Minute).Format(time.RFC3339Nano))
	c.authority.ExpiresAt = api.Timestamp(clock.now.Add(29 * time.Minute).Format(time.RFC3339Nano))
	scope.Actor.ID, scope.EndpointGeneration = c.authority.PrincipalID, c.binding.EndpointGeneration
	scope = withInput(scope, input)
	if state != nil {
		id, err := client.NewRequestID()
		if err != nil {
			t.Fatal("cannot issue synthetic proof ID")
		}
		proof := api.ProofRef{ID: id, RequestSHA256: scope.Request.RequestSHA256, ExpiresAt: api.Timestamp(clock.now.Add(5 * time.Minute).Format(time.RFC3339Nano))}
		target, err := state.AuthorizationTarget(context.Background(), scope, scope.Request)
		if err != nil {
			t.Fatal("cannot construct synthetic authorization target")
		}
		state.mu.Lock()
		state.issued[id] = api.VerifiedHumanProof{Ref: proof, Config: scope.Config, PrincipalID: scope.Actor.ID,
			CredentialID: c.authority.CredentialID, NonceID: api.ID("nonce-" + string(id)), Target: target,
			EndpointClass: api.EndpointHuman, EndpointGeneration: scope.EndpointGeneration, ConnectionID: c.ID()}
		state.mu.Unlock()
		scope.Request.Proof = &proof
		scope = framedScope(scope)
	}
	return scope
}

func stageValue(t *testing.T, s *Service, clock *clockFixture, connection api.ConnectionContext, name, version string, value []byte, tamper bool) (api.SecretStage, api.ConnectionContext) {
	t.Helper()
	keyScope := mutationScope(t, clock, connection, "secret.key", api.Empty{}, nil)
	key, err := s.SecretKey(context.Background(), keyScope, api.Empty{})
	if err != nil {
		t.Fatal("cannot issue mutation upload key")
	}
	sealed, err := SealStage("service-case", key, name, version, api.SecretMaterial{Bytes: value}, clock)
	if err != nil {
		t.Fatal("cannot seal mutation input")
	}
	if tamper {
		sealed.Ciphertext[0] ^= 1
	}
	scope := mutationScope(t, clock, keyScope.Connection, "secret.stage", sealed, nil)
	stage, err := s.SecretStage(context.Background(), scope, sealed)
	if err != nil || stage.Name != name || stage.Version != version || stage.ID == "" {
		t.Fatal("cannot retain encrypted mutation stage")
	}
	if bytes.Contains(s.stages[stage.ID].request.Ciphertext, value) {
		t.Fatal("stage retained plaintext material")
	}
	return stage, keyScope.Connection
}

func fetchMutation(t *testing.T, backend api.SecretBackend, clock api.Clock, info api.SecretInfo) []byte {
	t.Helper()
	got, err := backend.Fetch(context.Background(), api.SecretGrant{ID: "grant-a", Name: info.Name, Version: info.Version, SourceHandle: info.SourceHandle,
		ExpiresAt: api.Timestamp(clock.Now().Add(time.Minute).Format(time.RFC3339Nano))})
	if err != nil {
		t.Fatal("cannot fetch committed synthetic source")
	}
	return got.Bytes
}
