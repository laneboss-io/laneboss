package messaging

import (
	"context"
	"reflect"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

type testHuman struct {
	api.HumanVerifier
	store *memoryStore
}

func (h *testHuman) CheckProof(_ context.Context, scope api.Scope, proof api.ProofRef, target api.HumanChallengeRequest) (api.VerifiedHumanProof, error) {
	row, ok := h.store.proofs[proof.ID]
	if !ok || row.Ref != proof || row.Config != scope.Config || row.PrincipalID != scope.Actor.ID || row.Target != target || row.ConsumedBy != "" {
		return api.VerifiedHumanProof{}, problem(api.CodeUnauthenticated, "fixture proof does not authorize the resolved target")
	}
	return row, nil
}

func (f *fixture) confirmProof(t *testing.T, scope api.Scope) {
	t.Helper()
	target, err := f.store.AuthorizationTarget(context.Background(), scope, scope.Request)
	if err != nil {
		t.Fatal(err)
	}
	f.store.proofs[scope.Request.Proof.ID] = api.VerifiedHumanProof{
		Ref: *scope.Request.Proof, Config: scope.Config, PrincipalID: scope.Actor.ID, Target: target,
		CredentialID: randomID(t), NonceID: randomID(t), EndpointClass: api.EndpointHuman, EndpointGeneration: scope.EndpointGeneration,
		VerifiedAt: api.Timestamp(f.clock.now.Format(time.RFC3339Nano)),
	}
}

func (f *fixture) enroll(t *testing.T, id api.ID) {
	t.Helper()
	f.store.channels[id] = api.EnrolledChannel{ID: id, Config: "fixture", Generation: 1,
		Source:       api.SourceRef{ID: randomID(t), Path: "channels/fixture.toml", SHA256: hashBytes([]byte(id)), Generation: 1},
		ExpiresAt:    api.Timestamp(f.clock.now.Add(time.Hour).Format(time.RFC3339Nano)),
		Destinations: []api.ChannelDestination{{ID: randomID(t), Transport: "fixture", EndpointID: randomID(t), CredentialHandle: randomID(t), DeliverySemantics: "read-back"}}}
}

func (f *fixture) typedBlob(t *testing.T, data []byte, class string) api.BlobRef {
	t.Helper()
	ref := f.blob(t, data)
	ref.Class = class
	metadata := f.store.metadata[ref.ID]
	metadata.Ref = ref
	f.store.metadata[ref.ID] = metadata
	return ref
}

func (m *memoryStore) Effect(_ context.Context, _ api.Scope, id api.ID) (api.EffectRecord, error) {
	row, ok := m.effectRows[id]
	if !ok {
		return api.EffectRecord{}, problem(api.CodeNotFound, "fixture effect not found")
	}
	return row, nil
}

func (m *memoryStore) WorkerLease(_ context.Context, _ api.Scope, id api.ID) (api.WorkerLease, error) {
	row, ok := m.workerLeases[id]
	if !ok {
		return api.WorkerLease{}, problem(api.CodeNotFound, "fixture worker lease not found")
	}
	return row, nil
}

func (m *memoryStore) Turn(_ context.Context, _ api.Scope, target api.LifeRef, id api.ID) (api.TurnSnapshot, error) {
	row, ok := m.turns[id]
	if !ok || row.Target != target {
		return api.TurnSnapshot{}, problem(api.CodeNotFound, "fixture turn not found")
	}
	return row, nil
}

func (m *memoryStore) MailForTurn(ctx context.Context, scope api.Scope, request api.DeliveryTurnRequest) (api.DeliveryBatch, error) {
	if err := internalScope(ctx, scope); err != nil {
		return api.DeliveryBatch{}, err
	}
	effect, ok := m.effectRows[request.Lease.Record.Effect.ID]
	if !ok || !reflect.DeepEqual(effect, request.Lease.Record) || effect.ClaimID != request.Lease.ClaimID || effect.ClaimantID != scope.Actor.ID || effect.Effect.Context == nil || effect.Effect.Deliver == nil || effect.Effect.Deliver.RecipientLifeID != request.Target.LifeID {
		return api.DeliveryBatch{}, problem(api.CodeForbidden, "fixture batch is not bound to its effect claimant and recipient")
	}
	turn, err := m.Turn(ctx, scope, request.Target, request.LogicalTurnID)
	if err != nil || !reflect.DeepEqual(turn.MailIDs, request.MailIDs) {
		return api.DeliveryBatch{}, problem(api.CodeConflict, "fixture batch is not the retained turn")
	}
	intent := *effect.Effect.Context
	if intent.Actor != scope.Actor || intent.Target != request.Target || intent.LogicalTurnID != request.LogicalTurnID || intent.CancellationEpoch != request.CancellationEpoch {
		return api.DeliveryBatch{}, problem(api.CodeForbidden, "fixture request differs from the bound lifecycle delivery intent")
	}
	batch := api.DeliveryBatch{Intent: intent, Target: request.Target, LogicalTurnID: request.LogicalTurnID, Generation: m.lanes[request.Target.LifeID].Generation, Mail: []api.Mail{}}
	for _, id := range request.MailIDs {
		mail, ok := m.mail[id]
		if !ok || mail.RecipientLifeID != request.Target.LifeID {
			return api.DeliveryBatch{}, problem(api.CodeNotFound, "fixture batch mail does not address the leased recipient")
		}
		batch.Mail = append(batch.Mail, mail)
	}
	return batch, nil
}

func (f *fixture) delivery(t *testing.T, messages ...api.Mail) (api.Scope, api.DeliveryTurnRequest) {
	t.Helper()
	if len(messages) == 0 {
		t.Fatal("delivery fixture requires actual queued mail")
	}
	scope := api.Scope{Config: "fixture", Source: "worker", Actor: api.Actor{Kind: "service", ID: randomID(t)}}
	var effect api.EffectRecord
	for _, row := range f.store.effectRows {
		if row.Effect.Deliver != nil && row.Effect.Deliver.ID == messages[0].ID {
			effect = row
			break
		}
	}
	if effect.Effect.ID == "" {
		t.Fatal("delivery fixture has no causal outbox effect")
	}
	life := f.store.lanes[messages[0].RecipientLifeID]
	ids := make([]api.ID, len(messages))
	for i, mail := range messages {
		ids[i] = mail.ID
	}
	request := api.DeliveryTurnRequest{Target: api.LifeRef{LifeID: life.LifeID, Run: life.Run}, LogicalTurnID: randomID(t), MailIDs: ids, ExpectedGeneration: life.Generation, CancellationEpoch: life.CancellationEpoch}
	// Model the separate prepared lifecycle effect, already bound to its actual
	// internal executor and turn. An enqueue's unbound context is not a lease
	// that authorizes a worker to relabel its actor, epoch or recipient run.
	intent := *effect.Effect.Context
	intent.ID, intent.EffectID, intent.CauseOperationID = randomID(t), randomID(t), randomID(t)
	intent.Actor, intent.Target, intent.LogicalTurnID, intent.CancellationEpoch = scope.Actor, request.Target, request.LogicalTurnID, request.CancellationEpoch
	parent := f.store.lanes[life.ParentLifeID]
	turnRequest := api.TurnRequest{Target: request.Target, ExpectedGeneration: life.Generation, MailIDs: ids}
	requester := f.scope(t, parent.LifeID, "lane.turn", turnRequest)
	intent.RequestedBy, intent.CauseRequestID = requester.Actor, requester.Request.RequestID
	first := messages[0]
	effect = api.EffectRecord{Effect: api.Effect{ID: intent.EffectID, OperationID: intent.CauseOperationID, Context: &intent, Deliver: &first},
		Generation: 1, ClaimID: randomID(t), ClaimantID: scope.Actor.ID, State: "claimed", ClaimExpiresAt: api.Timestamp(f.clock.now.Add(time.Minute).Format(time.RFC3339Nano))}
	f.store.effectRows[effect.Effect.ID] = effect
	request.Lease = api.EffectLease{Record: effect, ClaimID: effect.ClaimID, ExpiresAt: effect.ClaimExpiresAt}
	f.store.turns[request.LogicalTurnID] = api.TurnSnapshot{Target: request.Target, LogicalTurnID: request.LogicalTurnID, Task: life.Task, PolicyGeneration: life.PolicyGeneration, Generation: 1, MailIDs: ids, Status: "prepared"}
	life.LogicalTurnID = request.LogicalTurnID
	f.store.lanes[life.LifeID] = life
	return scope, request
}
