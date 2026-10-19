package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client/wire"
)

// Under the sole writer, compute the exact event position that this atomic
// transaction will append. The unchanged authored input remains the replay
// digest; this private copy is validated and later compared to the real append.
func (s *Service) prepareIdentityBindings(ctx context.Context, input api.Transaction) (api.Transaction, error) {
	if len(input.Writes.IdentityBindings) == 0 {
		return input, nil
	}
	var head api.Sequence
	if err := s.db.QueryRowContext(ctx, "SELECT coalesce(max(seq),0) FROM events").Scan(&head); err != nil {
		return input, err
	}
	input.Writes.IdentityBindings = append([]api.LaunchBindingRequest{}, input.Writes.IdentityBindings...)
	for i, binding := range input.Writes.IdentityBindings {
		if binding.Record.Actor.Kind != "lane" {
			continue
		}
		var actual api.IdentityCommit
		matches := 0
		for index, event := range input.Events {
			if event.Kind != "identity.bound" {
				continue
			}
			var record api.LaunchRecord
			if err := wire.Decode(event.Payload, &record); err != nil {
				return input, err
			}
			if !sameValue(record, binding.Record) {
				continue
			}
			canonical, err := canonicalValue(record)
			if err != nil {
				return input, err
			}
			actual = api.IdentityCommit{LaunchID: record.ID, EventID: event.ID, CommittedSeq: head + api.Sequence(index) + 1, RecordSHA256: api.Digest(hash(canonical))}
			matches++
		}
		if matches != 1 || binding.Identity != (api.IdentityCommit{}) && binding.Identity != actual {
			return input, fault(api.CodeForbidden, "prepared binding differs from its exact atomic identity event")
		}
		binding.Identity = actual
		input.Writes.IdentityBindings[i] = binding
	}
	return input, nil
}

// Authority facts are derived after journal append, within the same commit.
// Neither a module-supplied sequence nor an uncommitted prepared tuple is a
// receipt that identity or guidance may use.
func (s *Service) stampAuthority(ctx context.Context, tx *sql.Tx, input api.Transaction, operation api.ID) error {
	if input.Writes.Policy != nil && input.Writes.Policy.AllowCaptureRefusal {
		if err := s.approvedCapturePolicy(ctx, tx, *input.Writes.Policy); err != nil {
			return err
		}
	}
	if err := s.stampRevocations(ctx, tx, input, operation); err != nil {
		return err
	}
	if err := s.stampDelegationLeases(ctx, tx, input, operation); err != nil {
		return err
	}
	if input.Internal != nil && input.Internal.Kind == api.InternalAdminEnroll {
		if err := s.stampEnrollment(ctx, tx, input, operation); err != nil {
			return err
		}
	}
	for _, binding := range input.Writes.IdentityBindings {
		if input.Internal == nil || !boundInternalActor(input) {
			return fault(api.CodeForbidden, "identity binding requires its internal emitter")
		}
		record, prepared := binding.Record, binding.Prepared
		if record.Config != s.deps.Config || record.Revoked || record.ID == prepared.ID || prepared.ID == "" || prepared.GateID == "" ||
			!wire.ValidDigest(string(prepared.SpecSHA256)) || prepared.Target != record.Target || prepared.ContainmentID != record.ContainmentID ||
			prepared.ProcessGeneration != record.ProcessGeneration || prepared.EndpointGeneration != record.EndpointGeneration {
			return fault(api.CodeForbidden, "prepared gate differs from launch identity")
		}
		event, err := authorityEvent(ctx, tx, operation, "identity.bound", record.ID)
		if err != nil {
			return err
		}
		var committed api.LaunchRecord
		if err := wire.Decode(event.Payload, &committed); err != nil {
			return err
		}
		if !sameValue(record, committed) {
			return fault(api.CodeForbidden, "identity write differs from committed launch event")
		}
		data, err := json.Marshal(committed)
		if err != nil {
			return err
		}
		canonical, err := api.CanonicalJSON(data)
		if err != nil {
			return err
		}
		actual := api.IdentityCommit{LaunchID: record.ID, EventID: event.ID, CommittedSeq: event.Seq, RecordSHA256: api.Digest(hash(canonical))}
		if binding.Identity != (api.IdentityCommit{}) && binding.Identity != actual {
			return fault(api.CodeForbidden, "caller supplied an uncommitted identity receipt")
		}
		binding.Identity = actual
		if record.Actor.Kind == "lane" {
			if binding.Recovery == nil {
				return fault(api.CodeIntegrity, "agent identity requires the complete retained recovery binding")
			}
			var plan api.LaunchPlanRecord
			if err := storedProjection(ctx, tx, "launch_plan", binding.Recovery.PlanID, &plan); err != nil {
				return err
			}
			if plan.Plan == nil || plan.Phase != "bound" {
				return fault(api.CodeForbidden, "identity binding requires its atomic bound launch plan")
			}
			if err := api.ValidateLaunchBindingPlan(binding, *plan.Plan); err != nil {
				return err
			}
			if err := s.checkLaunchBytes(ctx, tx, plan); err != nil {
				return err
			}
		}
		if err := putGenerated(ctx, tx, "launch_binding", record.ID, 1, binding); err != nil {
			return err
		}
	}
	for _, decision := range input.Writes.Decisions {
		event, err := authorityEvent(ctx, tx, operation, "decision.changed", decision.RecordID)
		if err != nil {
			return err
		}
		var record api.Record
		if err := projection(ctx, tx, "record", decision.RecordID, &record); err != nil {
			return err
		}
		if record.Collection != "decisions" || record.Origin != "service" || record.LifeID != "" || decision.Candidate.ID != record.ID ||
			decision.Candidate.Source.ID != record.ID || decision.Candidate.Source.SHA256 != record.Content.SHA256 ||
			decision.Candidate.Source.Generation == 0 || decision.Candidate.Source.Generation > record.Generation ||
			(decision.Status != "active" && decision.Status != "superseded") {
			return fault(api.CodeForbidden, "decision authority differs from canonical record")
		}
		var prior api.DecisionProjection
		err = storedProjection(ctx, tx, "decision", decision.RecordID, &prior)
		if err == nil {
			if !sameValue(decision.Candidate, prior.Candidate) || prior.Status == "superseded" && decision.Status != "superseded" {
				return fault(api.CodeForbidden, "decision edit changed original candidate authority")
			}
		} else {
			var typed *api.Error
			if !errors.As(err, &typed) || typed.Code != api.CodeNotFound {
				return err
			}
			if decision.Candidate.Authority.SourceSeq != 0 {
				return fault(api.CodeForbidden, "decision source sequence is assigned by the store")
			}
			switch decision.Candidate.Authority.Kind {
			case "human":
				if input.Scope.Actor.Kind != "human" || input.Scope.Request.Proof == nil || decision.Candidate.Authority.ReceiptID != input.Scope.Request.Proof.ID {
					return fault(api.CodeForbidden, "decision lacks its consumed human proof")
				}
				var used api.ProofUseReceipt
				if err := storedProjection(ctx, tx, "proof_use", decision.Candidate.Authority.ReceiptID, &used); err != nil {
					return err
				}
				if used.OperationID != operation {
					return fault(api.CodeForbidden, "decision proof belongs to another operation")
				}
			case "d6":
				var receiptData []byte
				if err := tx.QueryRowContext(ctx, "SELECT data FROM projections WHERE kind='application' AND json_extract(data,'$.id')=?", string(decision.Candidate.Authority.ReceiptID)).Scan(&receiptData); err != nil {
					return fault(api.CodeForbidden, "decision lacks an approved publication receipt")
				}
				var receipt api.ChangeReceipt
				if err := wire.Decode(receiptData, &receipt); err != nil {
					return err
				}
				if input.Internal == nil || input.Internal.Kind != api.InternalOrgPublish || receipt.NewGeneration != decision.Candidate.Authority.OrgGeneration {
					return fault(api.CodeForbidden, "decision publication generation differs")
				}
			default:
				return fault(api.CodeForbidden, "decision authority is not human or approved publication")
			}
		}
		decision.Candidate.Authority.SourceSeq = event.Seq
		if err := put(ctx, tx, "decision", record.ID, record.Generation, decision); err != nil {
			return err
		}
	}
	return nil
}

func authorityEvent(ctx context.Context, db queryer, operation api.ID, kind api.EventKind, object api.ID) (api.Event, error) {
	var event api.Event
	var data []byte
	selector := "$.payload.id"
	if kind == "org.change.applied" {
		selector = "$.payload.receipt.id"
	}
	err := db.QueryRowContext(ctx, "SELECT data FROM events WHERE json_extract(data,'$.operation_id')=? AND json_extract(data,'$.kind')=? AND json_extract(data,?)=? ORDER BY seq DESC LIMIT 1", string(operation), string(kind), selector, string(object)).Scan(&data)
	if errors.Is(err, sql.ErrNoRows) {
		return event, fault(api.CodeForbidden, "typed authority write lacks its matching committed event")
	}
	if err != nil {
		return event, err
	}
	if err := wire.Decode(data, &event); err != nil {
		return event, err
	}
	return event, nil
}
