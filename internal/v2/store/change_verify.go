package store

import (
	"context"
	"encoding/json"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client/wire"
)

// Caller holds the store read lock. Read all rows before joined queries so the
// single SQLite connection is never recursively awaited behind an open cursor.
func (s *Service) verifyOrgApplies(ctx context.Context) error {
	rows, err := s.db.QueryContext(ctx, "SELECT id,data FROM projections WHERE kind='org_apply'")
	if err != nil {
		return err
	}
	jobs := []orgApply{}
	for rows.Next() {
		var id api.ID
		var raw []byte
		var job orgApply
		if err := rows.Scan(&id, &raw); err != nil {
			rows.Close()
			return err
		}
		if decodeStored(raw, &job) != nil || id != job.Deferred.OperationID || job.Effect.ID != job.Deferred.EffectID || job.Effect.ApplyChange == nil {
			rows.Close()
			return fault(api.CodeIntegrity, "publication staging lost its original operation/effect binding")
		}
		jobs = append(jobs, job)
	}
	readErr, closeErr := rows.Err(), rows.Close()
	if readErr != nil {
		return readErr
	}
	if closeErr != nil {
		return closeErr
	}
	var effects int
	if err := s.db.QueryRowContext(ctx, "SELECT count(*) FROM effects WHERE json_extract(data,'$.ApplyChange') IS NOT NULL").Scan(&effects); err != nil {
		return err
	}
	if effects != len(jobs) {
		return fault(api.CodeIntegrity, "publication effect and original staging inventories differ")
	}
	for _, job := range jobs {
		if err := s.verifyOrgPolicy(ctx, job); err != nil {
			return err
		}
		scope := api.Scope{Config: s.deps.Config, Actor: job.Change.Requester}
		receipt, err := s.lookupReceipt(ctx, s.db, scope, job.Deferred.Key)
		if err != nil {
			return err
		}
		if err := s.validateOrgReceipt(ctx, s.db, receipt); err != nil {
			return err
		}
		var eventData []byte
		if err := s.db.QueryRowContext(ctx, "SELECT data FROM events WHERE json_extract(data,'$.kind')='org.change.proposed' AND json_extract(data,'$.payload.change.id')=? ORDER BY seq LIMIT 1", string(job.Change.ID)).Scan(&eventData); err != nil {
			return fault(api.CodeIntegrity, "publication lost its original proposed source event")
		}
		var event api.Event
		var proposed api.ChangeEvent
		if wire.Decode(eventData, &event) != nil || wire.Decode(event.Payload, &proposed) != nil || !sameValue(proposed.Change, job.Change) || event.Config != s.deps.Config || event.Origin != "service" || event.Actor.Kind != "service" || event.RequestedBy != job.Change.Requester {
			return fault(api.CodeIntegrity, "publication source staging differs from its original proposal event")
		}
		record, err := effectRow(ctx, s.db, job.Deferred.EffectID)
		if err != nil {
			return err
		}
		if !job.Completed {
			var gate orgApply
			if err := storedProjection(ctx, s.db, "org_apply_gate", job.Change.OrgID, &gate); err != nil {
				return err
			}
			if !sameValue(gate, job) {
				return fault(api.CodeIntegrity, "pending publication lost its exclusive org generation gate")
			}
			continue
		}
		if record.Outcome == nil || receipt.Reply == nil {
			return fault(api.CodeIntegrity, "completed publication lost its measured outcome or final reply")
		}
		pending := receipt
		pending.Reply, pending.Operation.Status, pending.Operation.Error = nil, "pending", nil
		claim := record
		claim.Outcome, claim.State, claim.Generation = nil, api.EffectClaimed, record.Outcome.ExpectedGeneration
		lease := api.EffectLease{Record: claim, ClaimID: claim.ClaimID, ExpiresAt: claim.ClaimExpiresAt}
		if err := api.ValidateDeferredCompletion(pending, lease, *record.Outcome); err != nil {
			return err
		}
		if !sameValue(record.Outcome.Reply.Reply, *receipt.Reply) {
			return fault(api.CodeIntegrity, "publication final reply differs from its immutable measured outcome")
		}
	}
	var gate orgApply
	if err := storedProjection(ctx, s.db, "org_apply_gate", api.ID(s.deps.Config), &gate); absent(err) {
		return nil
	} else if err != nil {
		return err
	}
	if gate.Policy != nil {
		var current api.EffectivePolicy
		if err := storedProjection(ctx, s.db, "policy", api.ID(s.deps.Config), &current); err != nil {
			return err
		}
		want := gate.Policy.Before
		if gate.Completed {
			record, err := effectRow(ctx, s.db, gate.Deferred.EffectID)
			if err != nil {
				return err
			}
			if record.Outcome != nil && record.Outcome.Status == "succeeded" {
				want = gate.Policy.After
			}
		}
		if !sameValue(current, want) {
			return fault(api.CodeIntegrity, "current policy differs from its measured org publication phase")
		}
	}
	if gate.Completed {
		record, err := effectRow(ctx, s.db, gate.Deferred.EffectID)
		if err != nil {
			return err
		}
		if record.Outcome != nil && record.Outcome.Status == "succeeded" {
			return s.verifyCurrentOrgPublication(gate, *record.Outcome.Publication)
		}
	}
	return nil
}

func (s *Service) verifyOrgPolicy(ctx context.Context, job orgApply) error {
	if job.Policy == nil {
		for _, file := range job.Snapshot.Sources {
			if file.Kind == "policy" {
				return fault(api.CodeIntegrity, "publication lost its retained policy compiler inputs")
			}
		}
		return nil
	}
	if err := s.checkOrgPolicyStamp(ctx, s.db, job, api.CodeIntegrity); err != nil {
		return err
	}
	snapshot, err := nextOrgSnapshot(job, api.ChangeReceipt{})
	if err != nil {
		return err
	}
	compiled, err := s.compileOrgPolicy(ctx, s.db, job.Policy.Before, job.Snapshot, snapshot)
	if err != nil {
		return err
	}
	if !sameValue(compiled, job.Policy.After) {
		return fault(api.CodeIntegrity, "retained policy differs from its exact source compilation")
	}
	raw, err := json.Marshal(job.Policy.Before)
	if err != nil {
		return err
	}
	var count int
	if err := s.db.QueryRowContext(ctx, "SELECT count(*) FROM projection_history WHERE kind='policy' AND id=? AND data=? AND sha256=?", s.deps.Config, raw, hash(raw)).Scan(&count); err != nil {
		return err
	}
	if count == 0 {
		return fault(api.CodeIntegrity, "publication lost its original approved policy history")
	}
	return nil
}
