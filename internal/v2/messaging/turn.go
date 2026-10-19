package messaging

import (
	"context"

	"laneboss.io/laneboss/internal/v2/api"
)

func (s *Service) deliverySender(ctx context.Context, scope api.Scope, to api.Lane, sender api.Actor) ([]api.Compare, error) {
	if !validActor(sender) {
		return nil, problem(api.CodeIntegrity, "carried mail has invalid sender provenance")
	}
	if sender.Kind == "human" {
		// Only the authenticated mail.send transaction can create human mail.
		// The persisted Mail is the store's trusted projection, not an input
		// supplied by the requester of this later turn. No sender proof is
		// reused or converted into the turn actor's authority here.
		return nil, nil
	}
	from, err := s.relatedLife(ctx, scope, sender.LifeID)
	if err != nil {
		return nil, err
	}
	if sender.LifeID != from.LifeID || sender.Level != from.Level || sender.Role != from.Role {
		return nil, problem(api.CodeForbidden, "the carried sender no longer matches its authentic life")
	}
	grants, err := s.relationGrants(ctx, scope, from)
	if err != nil {
		return nil, err
	}
	if err := relation(from, relationFacts(to)); err != nil {
		return nil, err
	}
	return []api.Compare{{Kind: api.CompareLane, ID: from.LifeID, Generation: from.Generation}, {Kind: api.CompareGrants, ID: grants.ID, Generation: grants.Generation}}, nil
}

// ValidateReceipt verifies a claimed logical-turn outcome against actual
// service-origin turn/end observations. It makes no state change. In
// particular, profile continuation cannot deliver or return the mail.
func (s *Service) ValidateReceipt(ctx context.Context, scope api.Scope, receipt api.MailReceipt) error {
	if scope.Actor.Kind != "service" || !validID(scope.Actor.ID) || scope.Actor.LifeID != "" || scope.Actor.Level != 0 || scope.Actor.Role != "" || scope.Config == "" || scope.Source != "worker" {
		return problem(api.CodeForbidden, "mail receipts require a trusted outside lifecycle observer")
	}
	if err := validReceiptInput(receipt); err != nil {
		return err
	}
	mail, err := s.findMail(ctx, scope, receipt.Target.LifeID, receipt.MailID)
	if err != nil {
		return err
	}
	if mail.RecipientLifeID != receipt.Target.LifeID || mail.LogicalTurnID != receipt.LogicalTurnID {
		return problem(api.CodeConflict, "mail is not bound to the observed recipient and logical turn")
	}
	// A quota continuation changes runs, while the initiating mail turn and
	// its binding remain in the earlier run. Read the life, then select the
	// exact logical turn and final run before considering completion.
	request := api.EventTailRequest{LifeID: receipt.Target.LifeID}
	seen := make(map[string]bool)
	eventIDs := make(map[api.ID]bool)
	var previousSeq api.Sequence
	var turnSeq api.Sequence
	var end *api.RunEndEvent
	for {
		if err := ctx.Err(); err != nil {
			return cancelled(err)
		}
		page, err := s.deps.Store.Events(ctx, scope, request)
		if err != nil {
			return err
		}
		for _, event := range page.Events {
			if event.Origin != "service" || event.Config != scope.Config || event.LifeID != receipt.Target.LifeID || event.Run > receipt.Target.Run || event.LogicalTurnID != receipt.LogicalTurnID {
				continue
			}
			if event.Schema != api.SchemaVersion || !validID(event.ID) || event.Seq == 0 || event.Seq > maxExact {
				return problem(api.CodeIntegrity, "mail completion references an invalid service event")
			}
			if eventIDs[event.ID] || event.Seq <= previousSeq {
				return problem(api.CodeIntegrity, "mail completion observations are duplicated or out of order")
			}
			eventIDs[event.ID], previousSeq = true, event.Seq
			switch event.Kind {
			case "lane.turn":
				var turn api.TurnEvent
				if err := decodeBody(event.Payload, &turn); err != nil {
					return problem(api.CodeIntegrity, "stored mail turn has an invalid payload")
				}
				for _, id := range turn.MailIDs {
					if id == mail.ID {
						if event.Seq <= mail.QueuedSeq {
							return problem(api.CodeIntegrity, "mail turn precedes its authentic queue event")
						}
						if !validTurnCause(turn.Trigger, mail) {
							return problem(api.CodeIntegrity, "mail turn lost its original causal mail or queue sequence")
						}
						turnSeq = event.Seq
					}
				}
			case "lane.ended":
				observed, err := decodeRunEnd(event.Payload)
				if err != nil {
					return err
				}
				if event.Run == receipt.Target.Run && turnSeq != 0 && event.Seq > turnSeq {
					if end != nil {
						return problem(api.CodeIntegrity, "mail completion has more than one authentic end for the selected run")
					}
					if err := validExitEvidence(observed); err != nil {
						return err
					}
					copy := observed
					end = &copy
				}
			}
		}
		if page.Complete {
			break
		}
		if page.Cursor == "" || len(page.Cursor) > maxCursor || seen[page.Cursor] {
			return problem(api.CodeIntegrity, "run observation pagination is incomplete or cyclic")
		}
		seen[page.Cursor], request.Cursor = true, page.Cursor
	}
	if end == nil {
		return problem(api.CodeConflict, "mail has no authentic logical-turn completion")
	}
	if end.ProfileContinuation || end.Reason == "limit" {
		return problem(api.CodeConflict, "a profile-limit run cannot acknowledge or return logical-turn mail")
	}
	observation := end.Observation
	if observation.Handle.Target != receipt.Target || observation.State != "exited" || observation.Survivors == nil || *observation.Survivors != 0 || observation.PromptStatus != receipt.PromptStatus || observation.ObservedAt != receipt.ObservedAt || end.Reason != receipt.Cause {
		return problem(api.CodeConflict, "mail receipt differs from the actual outside process observation")
	}
	completed := end.Reason == "exit" && observation.ExitCode != nil && *observation.ExitCode == 0 && observation.Signal == nil && observation.PromptStatus == "completed"
	if receipt.Status == "delivered" && !completed || receipt.Status == "returned" && completed {
		return problem(api.CodeConflict, "mail status does not match actual completed delivery")
	}
	return nil
}
