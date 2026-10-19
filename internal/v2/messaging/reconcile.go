package messaging

import (
	"context"
	"reflect"

	"laneboss.io/laneboss/internal/v2/api"
)

func deliveryWaiting(message string) *api.Error {
	err := problem(api.CodeUnavailable, message)
	err.Retryable = true
	return err
}

// ReconcileDelivery consumes the queue effect only after the selected logical
// turn has real outside end, prompt and primary capture evidence. It schedules
// no synthetic public turn and never acknowledges a provider-limit exit.
func (s *Service) ReconcileDelivery(ctx context.Context, scope api.Scope, lease api.EffectLease) (api.ProcessObservation, error) {
	if err := internalScope(ctx, scope); err != nil {
		return api.ProcessObservation{}, err
	}
	record, err := s.deps.Store.Effect(ctx, scope, lease.Record.Effect.ID)
	if err != nil {
		return api.ProcessObservation{}, err
	}
	if !reflect.DeepEqual(record, lease.Record) || record.State != api.EffectClaimed || record.Outcome != nil || record.ClaimID != lease.ClaimID || record.ClaimantID != scope.Actor.ID || record.ClaimExpiresAt != lease.ExpiresAt || !future(lease.ExpiresAt, s.deps.Clock.Now()) || record.Effect.Deliver == nil || record.Effect.Context == nil {
		return api.ProcessObservation{}, problem(api.CodeConflict, "mail reconciliation lost its actual queue effect claim")
	}
	original := record.Effect.Deliver
	mail, err := s.findMail(ctx, scope, original.RecipientLifeID, original.ID)
	if err != nil {
		return api.ProcessObservation{}, err
	}
	if mail.ID != original.ID || mail.Sender != original.Sender || mail.RecipientLifeID != original.RecipientLifeID || mail.Content != original.Content || !reflect.DeepEqual(mail.Artifacts, original.Artifacts) || mail.ChannelGrantID != "" {
		return api.ProcessObservation{}, problem(api.CodeIntegrity, "mail reconciliation differs from its immutable queue effect")
	}
	if mail.LogicalTurnID == "" || mail.Status == "queued" {
		return api.ProcessObservation{}, deliveryWaiting("mail awaits an authenticated requested or scheduled turn")
	}
	if mail.Status == "delivered" || mail.Status == "returned" {
		return s.reconcileRetainedDelivery(ctx, scope, record, mail)
	}
	lane, err := s.lane(ctx, scope, api.LifeRef{LifeID: mail.RecipientLifeID})
	if err != nil {
		return api.ProcessObservation{}, err
	}
	if lane.LogicalTurnID != mail.LogicalTurnID {
		return api.ProcessObservation{}, problem(api.CodeConflict, "mail completion belongs to another logical turn")
	}
	var end *api.RunEndEvent
	captures := []api.ID{}
	query := api.EventTailRequest{LifeID: lane.LifeID, Run: lane.Run}
	seen := map[string]bool{}
	for {
		page, err := s.deps.Store.Events(ctx, scope, query)
		if err != nil {
			return api.ProcessObservation{}, err
		}
		for _, event := range page.Events {
			if event.Config != scope.Config || event.Origin != "service" || event.LifeID != lane.LifeID || event.Run != lane.Run || event.LogicalTurnID != mail.LogicalTurnID {
				continue
			}
			switch event.Kind {
			case "capture.appended":
				var capture api.CaptureRecord
				if err := decodeBody(event.Payload, &capture); err != nil {
					return api.ProcessObservation{}, err
				}
				if capture.Primary && capture.Coverage == "complete" {
					captures = append(captures, capture.ID)
				}
			case "lane.ended":
				if end != nil {
					return api.ProcessObservation{}, problem(api.CodeIntegrity, "mail run has more than one committed end")
				}
				value, err := decodeRunEnd(event.Payload)
				if err != nil {
					return api.ProcessObservation{}, err
				}
				end = &value
			}
		}
		if page.Complete {
			break
		}
		if page.Cursor == "" || seen[page.Cursor] {
			return api.ProcessObservation{}, problem(api.CodeIntegrity, "mail completion history did not advance")
		}
		seen[page.Cursor], query.Cursor = true, page.Cursor
	}
	if end == nil {
		return api.ProcessObservation{}, deliveryWaiting("mail awaits its actual committed logical-turn end")
	}
	if end.ProfileContinuation || end.Reason == "limit" {
		return api.ProcessObservation{}, deliveryWaiting("mail remains pending across provider-limit continuation")
	}
	observation := end.Observation
	if err := validExitEvidence(*end); err != nil {
		return api.ProcessObservation{}, err
	}
	status := "returned"
	if end.Reason == "exit" && observation.ExitCode != nil && *observation.ExitCode == 0 && observation.Signal == nil && observation.PromptStatus == "completed" {
		status = "delivered"
	}
	receipt := api.MailReceipt{MailID: mail.ID, Target: api.LifeRef{LifeID: lane.LifeID, Run: lane.Run}, LogicalTurnID: mail.LogicalTurnID,
		Status: status, PromptStatus: observation.PromptStatus, Cause: end.Reason, ObservedAt: observation.ObservedAt}
	if mail.Status != "delivering" {
		return api.ProcessObservation{}, problem(api.CodeConflict, "mail is no longer in its selected delivery")
	}
	intent := *record.Effect.Context
	intent.Actor, intent.Target, intent.LogicalTurnID, intent.CancellationEpoch = scope.Actor, receipt.Target, mail.LogicalTurnID, lane.CancellationEpoch
	ctx = api.WithEffectLease(ctx, lease)
	if _, err := s.RecordDelivery(ctx, scope, api.DeliveryReceiptRequest{Intent: intent, MailID: mail.ID, ExpectedGeneration: mail.Generation, Receipt: receipt, CaptureIDs: captures}); err != nil {
		return api.ProcessObservation{}, err
	}
	return observation, nil
}

func (s *Service) reconcileRetainedDelivery(ctx context.Context, scope api.Scope, record api.EffectRecord, mail api.Mail) (api.ProcessObservation, error) {
	query := api.EventTailRequest{LifeID: mail.RecipientLifeID}
	seen := map[string]bool{}
	var receipt *api.MailReceipt
	ends := map[api.RunNumber]api.RunEndEvent{}
	for {
		page, err := s.deps.Store.Events(ctx, scope, query)
		if err != nil {
			return api.ProcessObservation{}, err
		}
		for _, event := range page.Events {
			if event.Origin != "service" || event.Config != scope.Config || event.LifeID != mail.RecipientLifeID || event.LogicalTurnID != mail.LogicalTurnID {
				continue
			}
			if event.Kind == "lane.ended" {
				end, err := decodeRunEnd(event.Payload)
				if err != nil {
					return api.ProcessObservation{}, err
				}
				if _, exists := ends[event.Run]; exists {
					return api.ProcessObservation{}, problem(api.CodeIntegrity, "retained mail has duplicate authentic run ends")
				}
				ends[event.Run] = end
			}
			if event.Kind == api.EventKind("mail."+mail.Status) && event.OperationID == record.Effect.OperationID && event.RequestID == record.Effect.Context.CauseRequestID && event.RequestedBy == record.Effect.Context.RequestedBy && event.Actor.Kind == "service" {
				var value api.MailReceipt
				if err := decodeBody(event.Payload, &value); err != nil {
					return api.ProcessObservation{}, err
				}
				if value.MailID == mail.ID {
					if receipt != nil {
						return api.ProcessObservation{}, problem(api.CodeIntegrity, "mail has duplicate logical completion receipts")
					}
					receipt = &value
				}
			}
		}
		if page.Complete {
			break
		}
		if page.Cursor == "" || seen[page.Cursor] {
			return api.ProcessObservation{}, problem(api.CodeIntegrity, "retained mail history did not advance")
		}
		seen[page.Cursor], query.Cursor = true, page.Cursor
	}
	if receipt == nil {
		return api.ProcessObservation{}, problem(api.CodeIntegrity, "completed mail lost its authentic queue-effect receipt")
	}
	if err := s.ValidateReceipt(ctx, scope, *receipt); err != nil {
		return api.ProcessObservation{}, err
	}
	end, exists := ends[receipt.Target.Run]
	if !exists || end.Observation.Handle.Target != receipt.Target || end.Observation.ObservedAt != receipt.ObservedAt {
		return api.ProcessObservation{}, problem(api.CodeIntegrity, "retained receipt lost its actual completing run")
	}
	return end.Observation, nil
}
