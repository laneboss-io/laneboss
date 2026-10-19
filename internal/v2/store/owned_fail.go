package store

import (
	"context"

	"laneboss.io/laneboss/internal/v2/api"
)

type ownedFailureRecord struct {
	Outcome  api.EffectOutcome
	Evidence api.BlobRef
	Commit   api.Commit
}

// This is a new private port beside the unchanged native handoff methods.
// Failure records never authorize deletion, clean a lane or verify an archive.
func (s *Service) FailOwnedEffect(ctx context.Context, scope api.Scope, lease api.EffectLease, failure *api.Error, observation *api.ProcessObservation) (commit api.Commit, resultErr error) {
	workspace, err := s.readCleanupFailure(ctx, scope, lease)
	if err != nil {
		return commit, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.dataScope(ctx, s.db, scope); err != nil {
		return commit, err
	}
	if failure == nil || failure.Code == "" || failure.Code == api.CodeConflict || failure.Code == api.CodeForbidden {
		return commit, fault(api.CodeInvalid, "owned failure requires a measured non-fence reason")
	}
	current, err := effectRow(ctx, s.db, lease.Record.Effect.ID)
	if err != nil {
		return commit, err
	}
	if current.Effect.Clean == nil && (current.Effect.Worker == nil || current.Effect.Worker.Kind != "archive") {
		return commit, fault(api.CodeForbidden, "failure port belongs to archive and cleanup effects")
	}
	if current.ClaimID != lease.ClaimID || current.ClaimantID != scope.Actor.ID {
		return commit, fault(api.CodeConflict, "owned failure belongs to another current claim")
	}
	var archived archiveRecord
	if current.Effect.Worker != nil {
		if err := storedProjection(ctx, s.db, "archive_job", current.Effect.OperationID, &archived); err != nil {
			return commit, err
		}
		if err := s.checkOwnedQuiescence(archived, observation); err != nil {
			return commit, err
		}
	} else {
		if observation != nil {
			return commit, fault(api.CodeInvalid, "cleanup failure cannot invent a worker observation")
		}
		var collection collectionRecord
		err := storedProjection(ctx, s.db, "collection", current.Effect.ID, &collection)
		if err != nil && !absent(err) {
			return commit, err
		}
		if collection.RemovalClaim != nil && (!workspace.present || workspace.intent != collection.Intent.ID || workspace.remover != collection.RemovalClaim.ClaimID || collection.RemovalJournal != nil && collection.RemovalJournal.Action == "remove_clean") {
			return commit, &api.Error{Code: api.CodeConflict, Owner: "lb-v2-grants", Message: "cleanup failure remains pending for its original protected collection journals",
				Instead: "Reconcile the same cleanup effect and intent with the retained removing claim; preserve its workspace journal and object dispositions."}
		}
	}
	outcome := api.EffectOutcome{EffectID: current.Effect.ID, ClaimID: lease.ClaimID, ExpectedGeneration: lease.Record.Generation, Status: "failed", Error: failure, Observation: observation}
	if current.Outcome != nil {
		if !sameValue(*current.Outcome, outcome) {
			return commit, fault(api.CodeConflict, "owned effect already has another outcome")
		}
		var saved ownedFailureRecord
		if err := storedProjection(ctx, s.db, "owned_failure", current.Effect.ID, &saved); err != nil {
			return commit, err
		}
		commit = saved.Commit
		commit.Replayed = true
		return commit, nil
	}
	if !sameValue(current, lease.Record) {
		return commit, fault(api.CodeConflict, "owned failure lost its original generation")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return commit, err
	}
	defer finish(tx, &resultErr)
	raw, err := canonicalValue(outcome)
	if err != nil {
		return commit, err
	}
	r := archiveRecord{Scope: api.Scope{Actor: current.Effect.Context.RequestedBy}, Lane: api.Lane{LifeID: current.Effect.Context.Target.LifeID}}
	r.Job.Intent.OperationID = current.Effect.OperationID
	ref, err := s.archiveBytes(ctx, tx, r, "manifest", raw)
	if err != nil {
		return commit, err
	}
	commit, err = s.finishOwnedEffect(ctx, tx, scope, lease, outcome, 0, &api.RPCReply{Error: failure})
	if err != nil {
		return commit, err
	}
	if err := put(ctx, tx, "owned_failure", current.Effect.ID, 1, ownedFailureRecord{Outcome: outcome, Evidence: ref, Commit: commit}); err != nil {
		return commit, err
	}
	if current.Effect.Worker != nil {
		archived.Phase, archived.Failure, archived.Commit = "failed", failure, &commit
		if err := s.saveArchive(ctx, tx, archived); err != nil {
			return commit, err
		}
	}
	if err := tx.Commit(); err != nil {
		return commit, err
	}
	s.notifyChanged()
	return commit, nil
}

func (s *Service) CleanupNativeReady() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed || s.deps.CleanupNative == nil {
		return false
	}
	if port, ok := s.deps.CleanupNative.(interface{ CleanupNativeReady() bool }); ok {
		return port.CleanupNativeReady()
	}
	return true
}
