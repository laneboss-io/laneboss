package messaging

import (
	"context"
	"encoding/json"
	"reflect"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

var _ api.MailDelivery = (*Service)(nil)

// BeginDelivery is a trusted service call. MailForTurn resolves the leased
// batch without borrowing either the requester or any carried sender's ACL.
func (s *Service) BeginDelivery(ctx context.Context, scope api.Scope, request api.DeliveryTurnRequest) (api.DeliveryBatch, error) {
	if err := internalScope(ctx, scope); err != nil {
		return api.DeliveryBatch{}, err
	}
	if !validID(request.LogicalTurnID) || request.MailIDs == nil || len(request.MailIDs) > 200 || request.ExpectedGeneration == 0 {
		return api.DeliveryBatch{}, problem(api.CodeInvalid, "delivery needs a bounded logical-turn batch")
	}
	effect, err := s.deps.Store.Effect(ctx, scope, request.Lease.Record.Effect.ID)
	if err != nil {
		return api.DeliveryBatch{}, err
	}
	if !reflect.DeepEqual(effect, request.Lease.Record) || effect.ClaimID == "" || effect.ClaimID != request.Lease.ClaimID || effect.ClaimantID != scope.Actor.ID || !future(request.Lease.ExpiresAt, s.deps.Clock.Now()) || effect.ClaimExpiresAt != request.Lease.ExpiresAt || effect.State != api.EffectClaimed {
		return api.DeliveryBatch{}, problem(api.CodeConflict, "delivery effect claim is absent, stale or belongs to another executor")
	}
	if effect.Effect.PlanLaunch != nil {
		coordinator, ok := s.deps.Store.(interface {
			BeginLaunchDelivery(context.Context, api.Scope, api.DeliveryTurnRequest) (api.DeliveryBatch, error)
		})
		if !ok {
			return api.DeliveryBatch{}, api.NotImplemented("lb-v2-service", "atomic reserved-turn mail selection")
		}
		preview, err := s.deps.Store.MailForTurn(ctx, scope, request)
		if err != nil {
			return api.DeliveryBatch{}, err
		}
		for _, mail := range preview.Mail {
			if _, err := s.content(ctx, scope, mail.Content); err != nil {
				return api.DeliveryBatch{}, err
			}
			for _, ref := range mail.Artifacts {
				if err := s.artifact(ctx, scope, ref); err != nil {
					return api.DeliveryBatch{}, err
				}
			}
		}
		return coordinator.BeginLaunchDelivery(ctx, scope, request)
	}
	batch, err := s.deps.Store.MailForTurn(ctx, scope, request)
	if err != nil {
		return api.DeliveryBatch{}, err
	}
	if err := validDeliveryIntent(scope, batch.Intent, effect, false); err != nil {
		return api.DeliveryBatch{}, err
	}
	if batch.Generation != request.ExpectedGeneration {
		return api.DeliveryBatch{}, problem(api.CodeConflict, "delivery batch targets a changed life generation")
	}
	if batch.Target != request.Target || batch.LogicalTurnID != request.LogicalTurnID || batch.Intent.Target != request.Target || batch.Intent.LogicalTurnID != request.LogicalTurnID || batch.Intent.CancellationEpoch != request.CancellationEpoch || len(batch.Mail) != len(request.MailIDs) {
		return api.DeliveryBatch{}, problem(api.CodeIntegrity, "leased mail batch differs from the actual turn")
	}
	to, err := s.lane(ctx, scope, request.Target)
	if err != nil {
		return api.DeliveryBatch{}, err
	}
	if to.Generation != request.ExpectedGeneration || to.CancellationEpoch != request.CancellationEpoch {
		return api.DeliveryBatch{}, problem(api.CodeConflict, "delivery targets a changed life or cancellation epoch")
	}
	if err := eligible(to); err != nil {
		return api.DeliveryBatch{}, err
	}
	grants, err := s.currentGrants(ctx, scope, to)
	if err != nil {
		return api.DeliveryBatch{}, err
	}
	turn, err := s.deps.Store.Turn(ctx, scope, request.Target, request.LogicalTurnID)
	if err != nil {
		return api.DeliveryBatch{}, err
	}
	if turn.Target != request.Target || turn.LogicalTurnID != request.LogicalTurnID || turn.Generation == 0 || turn.PolicyGeneration != to.PolicyGeneration || !reflect.DeepEqual(turn.MailIDs, request.MailIDs) || turn.Task != to.Task || turn.Status != "preparing" && turn.Status != "prepared" {
		return api.DeliveryBatch{}, problem(api.CodeConflict, "delivery has no matching current prepared turn")
	}
	compares := []api.Compare{{Kind: api.CompareLane, ID: to.LifeID, Generation: to.Generation}, {Kind: api.CompareGrants, ID: grants.ID, Generation: grants.Generation}}
	requesterCompares, err := s.turnRequester(ctx, scope, to, batch.Intent.RequestedBy)
	if err != nil {
		return api.DeliveryBatch{}, err
	}
	compares = append(compares, requesterCompares...)
	seen := make(map[api.ID]bool)
	var previous api.Sequence
	for i := range batch.Mail {
		mail := &batch.Mail[i]
		if err := validStoredMail(*mail); err != nil {
			return api.DeliveryBatch{}, err
		}
		if mail.ID != request.MailIDs[i] || seen[mail.ID] || mail.Generation >= maxExact || mail.RecipientLifeID != to.LifeID || mail.ChannelGrantID != "" || mail.QueuedSeq <= previous || mail.Status != "queued" && mail.Status != "returned" {
			return api.DeliveryBatch{}, problem(api.CodeConflict, "delivery must carry eligible recipient mail in queue order")
		}
		seen[mail.ID], previous = true, mail.QueuedSeq
		senderCompares, err := s.deliverySender(ctx, scope, to, mail.Sender)
		if err != nil {
			return api.DeliveryBatch{}, err
		}
		compares = append(compares, senderCompares...)
		if _, err := s.content(ctx, scope, mail.Content); err != nil {
			return api.DeliveryBatch{}, err
		}
		for _, ref := range mail.Artifacts {
			if err := s.artifact(ctx, scope, ref); err != nil {
				return api.DeliveryBatch{}, err
			}
		}
		compares = append(compares, api.Compare{Kind: api.CompareMail, ID: mail.ID, Generation: mail.Generation})
		mail.Generation++
		mail.Status, mail.LogicalTurnID = "delivering", request.LogicalTurnID
	}
	commit, err := s.deps.Store.Transact(ctx, api.Transaction{Scope: scope, Internal: &batch.Intent, Compare: compares,
		Guards: []api.TransactionGuard{{Cancellation: &api.CancellationCheck{LifeID: to.LifeID, Epoch: request.CancellationEpoch}}},
		Writes: api.StateWrites{Mail: batch.Mail}})
	if err != nil {
		return api.DeliveryBatch{}, err
	}
	if err := successfulInternal(commit); err != nil {
		return api.DeliveryBatch{}, err
	}
	return batch, nil
}

func (s *Service) RecordDelivery(ctx context.Context, scope api.Scope, request api.DeliveryReceiptRequest) (api.Operation, error) {
	if err := internalScope(ctx, scope); err != nil {
		return api.Operation{}, err
	}
	if request.MailID != request.Receipt.MailID || request.ExpectedGeneration == 0 || request.CaptureIDs == nil || len(request.CaptureIDs) > 200 {
		return api.Operation{}, problem(api.CodeInvalid, "delivery receipt has invalid mail generation or capture references")
	}
	effect, err := s.deps.Store.Effect(ctx, scope, request.Intent.EffectID)
	if err != nil {
		return api.Operation{}, err
	}
	if effect.Effect.Deliver != nil && effect.Effect.Context != nil && effect.Effect.Context.Target.Run == 0 {
		lease, ok := api.EffectLeaseFromContext(ctx)
		if !ok || !reflect.DeepEqual(lease.Record, effect) || lease.ClaimID != effect.ClaimID || lease.ExpiresAt != effect.ClaimExpiresAt || effect.ClaimantID != scope.Actor.ID || effect.State != api.EffectClaimed || effect.Outcome != nil || !future(effect.ClaimExpiresAt, s.deps.Clock.Now()) {
			return api.Operation{}, problem(api.CodeConflict, "queued mail receipt requires its actual current claim")
		}
	}
	if err := validDeliveryIntent(scope, request.Intent, effect, true); err != nil {
		return api.Operation{}, err
	}
	if request.Intent.Target != request.Receipt.Target || request.Intent.LogicalTurnID != request.Receipt.LogicalTurnID {
		return api.Operation{}, problem(api.CodeConflict, "receipt differs from its retained delivery intent")
	}
	mail, err := s.findMail(ctx, scope, request.Receipt.Target.LifeID, request.MailID)
	if err != nil {
		return api.Operation{}, err
	}
	if mail.Generation != request.ExpectedGeneration || mail.Generation >= maxExact || mail.Status != "delivering" {
		return api.Operation{}, problem(api.CodeConflict, "delivery receipt has a stale mail generation or phase")
	}
	if err := s.ValidateReceipt(ctx, scope, request.Receipt); err != nil {
		return api.Operation{}, err
	}
	if err := s.receiptCaptures(ctx, scope, request); err != nil {
		return api.Operation{}, err
	}
	to, err := s.lane(ctx, scope, request.Receipt.Target)
	if err != nil {
		return api.Operation{}, err
	}
	if to.CancellationEpoch != request.Intent.CancellationEpoch || to.LogicalTurnID != request.Receipt.LogicalTurnID {
		return api.Operation{}, problem(api.CodeConflict, "delivery was cancelled before its receipt")
	}
	mail.Generation++
	mail.Status = request.Receipt.Status
	raw, err := json.Marshal(request.Receipt)
	if err != nil {
		return api.Operation{}, problem(api.CodeIntegrity, "cannot encode the observed mail receipt")
	}
	now := api.Timestamp(s.deps.Clock.Now().UTC().Format(time.RFC3339Nano))
	intent := request.Intent
	intent.ID = api.ID("receipt-" + string(hashBytes(raw)))
	event := api.Event{Schema: api.SchemaVersion, ID: intent.ID, Config: scope.Config, Kind: api.EventKind("mail." + mail.Status),
		Actor: intent.Actor, RequestedBy: intent.RequestedBy, RequestID: intent.CauseRequestID,
		LifeID: to.LifeID, Run: request.Receipt.Target.Run, ParentLifeID: to.ParentLifeID, RootLifeID: to.RootLifeID,
		StarterChain: append([]api.ID{}, to.StarterChain...), StarterEventSeq: to.StarterEventSeq,
		LogicalTurnID: mail.LogicalTurnID, RequestedAt: now, ObservedAt: request.Receipt.ObservedAt, Origin: "service", Payload: raw}
	commit, err := s.deps.Store.Transact(ctx, api.Transaction{Scope: scope, Internal: &intent,
		Compare: []api.Compare{{Kind: api.CompareMail, ID: mail.ID, Generation: request.ExpectedGeneration}, {Kind: api.CompareLane, ID: to.LifeID, Generation: to.Generation}},
		Guards:  []api.TransactionGuard{{Cancellation: &api.CancellationCheck{LifeID: to.LifeID, Epoch: request.Intent.CancellationEpoch}}},
		Events:  []api.Event{event}, Writes: api.StateWrites{Mail: []api.Mail{mail}}})
	if err != nil {
		return api.Operation{}, err
	}
	if err := successfulInternal(commit); err != nil {
		return api.Operation{}, err
	}
	return commit.Operation, nil
}

func internalScope(ctx context.Context, scope api.Scope) error {
	if err := ctx.Err(); err != nil {
		return cancelled(err)
	}
	if scope.Request.Method != "" || scope.Config == "" || !validID(scope.Actor.ID) || scope.Actor.Kind != "service" && scope.Actor.Kind != "scheduler" || scope.Actor.LifeID != "" || scope.Actor.Level != 0 || scope.Actor.Role != "" || scope.Source != "worker" && scope.Source != "scheduler" {
		return problem(api.CodeForbidden, "delivery requires a bound internal service executor")
	}
	return nil
}

func validDeliveryIntent(scope api.Scope, intent api.InternalIntent, effect api.EffectRecord, continuation bool) error {
	parent := effect.Effect.Context
	if continuation && parent != nil && effect.Effect.Deliver != nil && parent.Target.Run == 0 && parent.LogicalTurnID == "" {
		if parent.Kind != api.InternalMailDeliver || parent.Config != scope.Config || parent.Target.LifeID != intent.Target.LifeID ||
			effect.Effect.Deliver.RecipientLifeID != intent.Target.LifeID || intent.Target.Run == 0 || !validID(intent.LogicalTurnID) ||
			intent.Kind != api.InternalMailDeliver || intent.Config != parent.Config || intent.Actor != scope.Actor || intent.RequestedBy != parent.RequestedBy ||
			intent.EffectID != effect.Effect.ID || intent.CauseOperationID != effect.Effect.OperationID || intent.CauseOperationID != parent.CauseOperationID || intent.CauseRequestID != parent.CauseRequestID || !validID(intent.ID) {
			return problem(api.CodeForbidden, "queued receipt differs from its original delivery cause")
		}
		return nil
	}
	targetMatches := parent != nil && parent.Target == intent.Target
	if continuation && parent != nil {
		targetMatches = parent.Target.LifeID == intent.Target.LifeID && parent.Target.Run > 0 && intent.Target.Run >= parent.Target.Run && intent.Target.Run <= maxExact
	}
	if parent == nil || parent.Kind != api.InternalMailDeliver || parent.Config != scope.Config || parent.Actor != scope.Actor || parent.EffectID != effect.Effect.ID || parent.CauseOperationID != effect.Effect.OperationID || !targetMatches || parent.LogicalTurnID != intent.LogicalTurnID || parent.CancellationEpoch != intent.CancellationEpoch || !validID(intent.ID) || intent.Kind != api.InternalMailDeliver || intent.Config != scope.Config || intent.Actor != scope.Actor || intent.EffectID != effect.Effect.ID || intent.CauseOperationID != effect.Effect.OperationID || !validID(intent.CauseOperationID) || !validID(intent.CauseRequestID) || intent.CauseRequestID != parent.CauseRequestID || intent.RequestedBy != parent.RequestedBy || !validID(intent.Target.LifeID) || !validID(intent.LogicalTurnID) {
		return problem(api.CodeForbidden, "delivery intent differs from the immutable effect's actual causality")
	}
	return nil
}

func successfulInternal(commit api.Commit) error {
	if commit.Operation.Error != nil {
		return commit.Operation.Error
	}
	if !validID(commit.Operation.ID) || commit.Operation.Status != "succeeded" {
		return problem(api.CodeIntegrity, "internal mail state was not durably completed")
	}
	return nil
}

func (s *Service) turnRequester(ctx context.Context, scope api.Scope, target api.Lane, requester api.Actor) ([]api.Compare, error) {
	if requester.Kind != "lane" {
		if validActor(requester) && requester.Kind == "human" {
			return nil, nil
		}
		if validID(requester.ID) && (requester.Kind == "service" || requester.Kind == "scheduler" || requester.Kind == "worker" || requester.Kind == "watchdog") && requester.LifeID == "" && requester.Level == 0 && requester.Role == "" {
			return nil, nil
		}
		return nil, problem(api.CodeForbidden, "delivery has no authentic turn requester")
	}
	from, err := s.relatedLife(ctx, scope, requester.LifeID)
	if err != nil {
		return nil, err
	}
	if requester.Level != from.Level || requester.Role != from.Role || from.LifeID != target.LifeID && (from.Level <= target.Level || relation(from, relationFacts(target)) != nil) {
		return nil, problem(api.CodeForbidden, "mail turn requester must be self or an authentic ancestor")
	}
	grants, err := s.relationGrants(ctx, scope, from)
	if err != nil {
		return nil, err
	}
	return []api.Compare{{Kind: api.CompareLane, ID: from.LifeID, Generation: from.Generation}, {Kind: api.CompareGrants, ID: grants.ID, Generation: grants.Generation}}, nil
}
