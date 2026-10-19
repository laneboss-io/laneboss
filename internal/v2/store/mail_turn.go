package store

import (
	"context"
	"slices"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client/wire"
)

// MailForTurn is a private, live-claim read. The reservation owns the next run
// before its lane projection exists; a public parent never borrows Mail's ACL.
func (s *Service) MailForTurn(ctx context.Context, scope api.Scope, request api.DeliveryTurnRequest) (api.DeliveryBatch, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	batch, _, _, err := s.mailForTurn(ctx, scope, request)
	return batch, err
}

func (s *Service) mailForTurn(ctx context.Context, scope api.Scope, request api.DeliveryTurnRequest) (batch api.DeliveryBatch, turn api.TurnSnapshot, plan api.LaunchPlanRecord, err error) {
	if err = s.available(); err != nil {
		return
	}
	if err = s.scope(ctx, s.db, scope); err != nil {
		return
	}
	if !internalScope(scope) || scope.Actor.Kind != "service" || scope.Request.Method != "" || scope.ReadView != nil || request.MailIDs == nil || len(request.MailIDs) > 200 {
		err = fault(api.CodeForbidden, "prepared mail requires the bound private planning executor")
		return
	}
	var current api.EffectRecord
	current, err = effectRow(ctx, s.db, request.Lease.Record.Effect.ID)
	if err != nil {
		return
	}
	if !sameValue(current, request.Lease.Record) || current.State != api.EffectClaimed || current.Outcome != nil || current.ClaimID != request.Lease.ClaimID || current.ClaimantID != scope.Actor.ID || current.ClaimExpiresAt != request.Lease.ExpiresAt || !future(current.ClaimExpiresAt, s.deps.Clock.Now()) || current.Effect.PlanLaunch == nil || current.Effect.Context == nil {
		err = fault(api.CodeConflict, "prepared mail has a stale or foreign planning claim")
		return
	}
	if err = storedProjection(ctx, s.db, "launch_plan", current.Effect.PlanLaunch.ReservationID, &plan); err != nil {
		return
	}
	r, cause := plan.Reservation, current.Effect.Context
	if plan.Inputs == nil || plan.Phase == "reserved" || plan.Phase == "failed" {
		err = fault(api.CodePrerequisite, "prepared mail requires the original sourced launch reservation")
		return
	}
	if r.Target != request.Target || r.Generation != request.ExpectedGeneration || r.CancellationEpoch != request.CancellationEpoch || cause.LogicalTurnID != request.LogicalTurnID || cause.Target != r.Target || cause.CauseOperationID != r.OperationID || cause.CauseRequestID != r.RequestID || cause.RequestedBy != r.RequestedBy || !wire.ValidID(string(request.LogicalTurnID)) {
		err = fault(api.CodeConflict, "prepared mail differs from its reserved target, generation or turn")
		return
	}
	if err = s.checkLaunchBytes(ctx, s.db, plan); err != nil {
		return
	}
	if err = s.currentLaunch(ctx, s.db, plan); err != nil {
		return
	}
	var raw []byte
	raw, err = s.privateLaunchObject(ctx, s.db, r.OriginalRequest, r.OperationID, r.Target.LifeID)
	if err != nil {
		return
	}
	var frame api.Request
	frame, err = wire.DecodeRequest(raw)
	if err != nil {
		return
	}
	var task api.BlobRef
	selected := []api.ID{}
	if r.Mode == "start" {
		var start api.StartRequest
		if err = wire.Decode(frame.Params, &start); err != nil {
			return
		}
		task = start.Task
	} else if r.Mode == "turn" {
		var input api.TurnRequest
		if err = wire.Decode(frame.Params, &input); err != nil {
			return
		}
		selected = input.MailIDs
		var previous api.Lane
		if err = storedProjection(ctx, s.db, "lane", r.Target.LifeID, &previous); err != nil {
			return
		}
		task = previous.Task
	} else {
		err = fault(api.CodeForbidden, "mail selection requires an original start or requested turn")
		return
	}
	if !slices.Equal(selected, request.MailIDs) {
		err = fault(api.CodeForbidden, "mail selection differs from the exact original requested batch")
		return
	}
	to := api.Lane{LifeID: r.Target.LifeID, Run: r.Target.Run, Generation: r.Generation, Level: r.Level, Role: r.Role,
		ParentLifeID: r.ParentLifeID, RootLifeID: r.RootLifeID, StarterChain: r.StarterChain, GrantSetID: r.GrantSetID}
	if r.RequestedBy.Kind == "lane" {
		var requester api.Lane
		if err = storedProjection(ctx, s.db, "lane", r.RequestedBy.LifeID, &requester); err != nil {
			return
		}
		if requester.Level != r.RequestedBy.Level || requester.Role != r.RequestedBy.Role || !laneControls(requester, to) {
			err = fault(api.CodeForbidden, "reserved mail turn requester lost its authentic control relation")
			return
		}
		if err = s.mailGrantChain(ctx, s.db, requester); err != nil {
			return
		}
	}
	if err = s.mailGrantChain(ctx, s.db, to); err != nil {
		return
	}
	batch = api.DeliveryBatch{Target: r.Target, LogicalTurnID: request.LogicalTurnID, Generation: r.Generation, Mail: []api.Mail{}}
	batch.Intent = *cause
	batch.Intent.ID, batch.Intent.Kind, batch.Intent.Actor = api.ID("mail-turn-"+hash([]byte(r.ID))), api.InternalMailDeliver, scope.Actor
	trigger := api.Trigger{Kind: "idle", MailIDs: append([]api.ID{}, selected...), CausingSeqs: []api.Sequence{}}
	if r.Mode == "start" {
		trigger.Kind = "start"
	} else if len(selected) > 0 {
		trigger.Kind = "mail"
	}
	seen := map[api.ID]bool{}
	var seq api.Sequence
	for _, id := range selected {
		if !wire.ValidID(string(id)) || seen[id] {
			err = wire.Invalid("prepared mail has duplicate or invalid references")
			return
		}
		seen[id] = true
		var mail api.Mail
		if err = storedProjection(ctx, s.db, "mail", id, &mail); err != nil {
			return
		}
		if mail.RecipientLifeID != to.LifeID || mail.ChannelGrantID != "" || mail.QueuedSeq <= seq || mail.Generation == 0 || mail.Status != "queued" && mail.Status != "returned" && !(mail.Status == "delivering" && mail.LogicalTurnID == request.LogicalTurnID) {
			err = fault(api.CodeConflict, "prepared mail is foreign, reordered or already selected by another turn")
			return
		}
		if mail.Sender.Kind == "lane" {
			var from api.Lane
			if err = storedProjection(ctx, s.db, "lane", mail.Sender.LifeID, &from); err != nil {
				return
			}
			if from.Cleaned || from.State == "merged" || from.State == "abandoned" || mail.Sender.Level != from.Level || mail.Sender.Role != from.Role || !mailRelated(from, to) {
				err = fault(api.CodeForbidden, "carried mail sender no longer has its authentic D7 relation")
				return
			}
			if err = s.mailGrantChain(ctx, s.db, from); err != nil {
				return
			}
		} else if mail.Sender.Kind != "human" {
			err = fault(api.CodeIntegrity, "queued mail has an invalid sender")
			return
		}
		for _, ref := range append([]api.BlobRef{mail.Content}, mail.Artifacts...) {
			var meta api.ObjectMetadata
			meta, _, err = objectRow(ctx, s.db, ref.ID)
			if err != nil {
				return
			}
			if meta.Ref != ref {
				err = fault(api.CodeIntegrity, "prepared mail bytes differ from their immutable reference")
				return
			}
		}
		batch.Mail = append(batch.Mail, mail)
		seq = mail.QueuedSeq
		trigger.CausingSeqs = append(trigger.CausingSeqs, seq)
	}
	turn = api.TurnSnapshot{Target: r.Target, LogicalTurnID: request.LogicalTurnID, Generation: 1, Task: task, MailIDs: append([]api.ID{}, selected...),
		PolicyGeneration: r.PolicyGeneration, Status: "prepared", Trigger: trigger}
	receipt, readErr := s.reservationReceipt(ctx, s.db, plan)
	if readErr != nil {
		err = readErr
		return
	}
	turn.CreatedAt = receipt.RecordedAt
	return
}

// BeginLaunchDelivery owns the atomic selection. Retries reauthorize the live
// claim and every carried sender, then return the same selection without a
// second mail generation advance or a second logical turn.
func (s *Service) BeginLaunchDelivery(ctx context.Context, scope api.Scope, request api.DeliveryTurnRequest) (batch api.DeliveryBatch, resultErr error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	batch, turn, plan, err := s.mailForTurn(ctx, scope, request)
	if err != nil {
		return batch, err
	}
	var kept api.DeliveryBatch
	err = storedProjection(ctx, s.db, "mail_turn_selection", plan.Reservation.ID, &kept)
	if err == nil {
		if kept.Target != batch.Target || kept.LogicalTurnID != batch.LogicalTurnID || kept.Generation != batch.Generation || len(kept.Mail) != len(batch.Mail) {
			return api.DeliveryBatch{}, fault(api.CodeIntegrity, "retained mail selection changed its reserved turn")
		}
		for i, mail := range batch.Mail {
			if !sameValue(mail, kept.Mail[i]) {
				return api.DeliveryBatch{}, fault(api.CodeConflict, "mail changed after its original turn selection")
			}
		}
		kept.Intent.Actor = scope.Actor
		return kept, nil
	}
	if !absent(err) {
		return api.DeliveryBatch{}, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return api.DeliveryBatch{}, err
	}
	defer finish(tx, &resultErr)
	for i := range batch.Mail {
		mail := &batch.Mail[i]
		if mail.Status == "delivering" || mail.Generation >= 1<<53-1 {
			return api.DeliveryBatch{}, fault(api.CodeConflict, "mail already has a logical turn without this selection")
		}
		mail.Generation++
		mail.Status, mail.LogicalTurnID = "delivering", batch.LogicalTurnID
		if err := putGenerated(ctx, tx, "mail", mail.ID, mail.Generation, *mail); err != nil {
			return api.DeliveryBatch{}, err
		}
	}
	var existing api.TurnSnapshot
	err = storedProjection(ctx, tx, "turn", turn.LogicalTurnID, &existing)
	if err == nil {
		if existing.Target != turn.Target || existing.Task != turn.Task || !slices.Equal(existing.MailIDs, turn.MailIDs) || !sameValue(existing.Trigger, turn.Trigger) {
			return api.DeliveryBatch{}, fault(api.CodeConflict, "prepared mail differs from the retained turn")
		}
	} else if absent(err) {
		if err := putGenerated(ctx, tx, "turn", turn.LogicalTurnID, turn.Generation, turn); err != nil {
			return api.DeliveryBatch{}, err
		}
	} else {
		return api.DeliveryBatch{}, err
	}
	if err := put(ctx, tx, "mail_turn_selection", plan.Reservation.ID, 1, batch); err != nil {
		return api.DeliveryBatch{}, err
	}
	if err := tx.Commit(); err != nil {
		return api.DeliveryBatch{}, err
	}
	s.notifyChanged()
	return batch, nil
}
