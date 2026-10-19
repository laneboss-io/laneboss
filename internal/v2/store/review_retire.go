package store

import (
	"context"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	archivejob "laneboss.io/laneboss/internal/v2/archive"
	"laneboss.io/laneboss/internal/v2/client/wire"
)

// Current effect authority is required, but worker expiry and a moved life
// fence cannot prevent observation/collection of the already-owned allocation.
func (s *Service) reviewRetirementClaim(ctx context.Context, scope api.Scope, lease api.EffectLease) (reviewRecord, error) {
	var r reviewRecord
	if err := s.dataScope(ctx, s.db, scope); err != nil {
		return r, err
	}
	current, err := effectRow(ctx, s.db, lease.Record.Effect.ID)
	if err != nil {
		return r, err
	}
	if current.Outcome != nil || !sameValue(current, lease.Record) || current.ClaimID != lease.ClaimID || current.ClaimantID != scope.Actor.ID || !future(lease.ExpiresAt, s.deps.Clock.Now()) {
		return r, fault(api.CodeConflict, "review recovery lost its actual current effect claim")
	}
	if err := storedProjection(ctx, s.db, "review_job", current.Effect.OperationID, &r); err != nil {
		return r, err
	}
	if current.Effect.Worker == nil || current.Effect.ID != r.Job.Lease.EffectID || !sameValue(*current.Effect.Worker, r.Job.Plan) {
		return r, fault(api.CodeForbidden, "review recovery selected another original worker")
	}
	return r, nil
}

func (s *Service) ReviewRecovery(ctx context.Context, scope api.Scope, lease api.EffectLease) (archivejob.Recovery, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	r, err := s.reviewRetirementClaim(ctx, scope, lease)
	return archivejob.Recovery{Job: r.Job, Allocation: r.Allocation, Process: r.Process, Handoff: r.Handoff != nil, Allocating: r.Allocating, Retirement: r.Retirement}, err
}

// Durable original allocation intent precedes the first helper grant. A lost
// helper reply must reconcile/retire this intent before failure can be sealed.
func (s *Service) BeginReviewAllocation(ctx context.Context, scope api.Scope, lease api.EffectLease) (resultErr error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, err := s.reviewClaim(ctx, s.db, scope, lease)
	if err != nil {
		return err
	}
	if r.Retirement != nil {
		return fault(api.CodePrerequisite, "retired archive must resolve its original completion without another allocation")
	}
	if r.Allocating {
		return nil
	}
	r.Allocating, r.Claim = true, lease
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer finish(tx, &resultErr)
	if err := s.saveReview(ctx, tx, r); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Service) RecordReviewAllocation(ctx context.Context, scope api.Scope, lease api.EffectLease, allocation api.HelperLease) (resultErr error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, err := s.reviewRetirementClaim(ctx, scope, lease)
	if err != nil {
		return err
	}
	if r.Retirement != nil || !r.Allocating || !wire.ValidID(string(allocation.ID)) || allocation.UID == 0 || allocation.GID == 0 || !wire.ValidID(string(allocation.ContainmentID)) || allocation.EndpointGeneration == 0 || r.Allocation.ID != "" && r.Allocation != allocation {
		return fault(api.CodeConflict, "review allocation differs from its durable original intent")
	}
	r.Allocation = allocation
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer finish(tx, &resultErr)
	if err := s.saveReview(ctx, tx, r); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Service) RecordReviewRetirement(ctx context.Context, scope api.Scope, lease api.EffectLease, proof archivejob.Retirement) (resultErr error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, err := s.reviewRetirementClaim(ctx, scope, lease)
	if err != nil {
		return err
	}
	when, timeErr := time.Parse(time.RFC3339Nano, string(proof.ObservedAt))
	if timeErr != nil || when.IsZero() || when.After(s.deps.Clock.Now()) {
		return fault(api.CodeIntegrity, "review retirement timestamp mismatch: require a valid nonfuture measurement")
	}
	if proof.JobID != r.Job.ID || proof.OperationID != r.Job.Intent.OperationID || proof.EffectID != r.Job.Lease.EffectID || proof.Target != r.Job.Intent.Request.Target {
		return fault(api.CodeIntegrity, "review retirement selector mismatch: require the original job, operation, effect and target")
	}
	if r.Retirement != nil {
		if !sameValue(*r.Retirement, proof) {
			return fault(api.CodeConflict, "review retirement evidence is immutable")
		}
		return nil
	}
	if proof.Absent {
		if proof.Allocation != (api.HelperLease{}) || proof.Release != nil || proof.Abort != nil || proof.Boot != nil || r.Allocation.ID != "" || r.Handoff != nil || r.Process.ID != "" {
			return fault(api.CodeContainmentUnknown, "review absence binding mismatch: absence cannot replace an existing allocation, handoff or process")
		}
	} else {
		kinds := 0
		for _, present := range []bool{proof.Release != nil, proof.Abort != nil, proof.Boot != nil} {
			if present {
				kinds++
			}
		}
		if !wire.ValidID(string(proof.Allocation.ID)) || proof.Allocation.UID == 0 || proof.Allocation.GID == 0 || !wire.ValidID(string(proof.Allocation.ContainmentID)) || r.Allocation.ID != "" && r.Allocation != proof.Allocation || kinds != 1 {
			return fault(api.CodeContainmentUnknown, "review retirement binding mismatch: require the exact allocation and one release or abort")
		}
		if proof.Boot != nil {
			q := proof.Boot
			if err := archivejob.ValidateBootRetirement(proof.Allocation, proof.Target, *q, proof.ObservedAt); err != nil {
				return err
			}
			if q.Process.ID != r.WorkerLaunchID || r.Process.ID != "" && q.Process != r.Process {
				return fault(api.CodeContainmentUnknown, "review boot retirement changed its original process")
			}
			if r.Process.ID != "" {
				binding, err := s.launchBinding(ctx, s.db, r.WorkerLaunchID)
				if err != nil || binding.Record.UIDLeaseID != proof.Allocation.ID || binding.Record.HostUID != proof.Allocation.UID || binding.Record.ContainmentID != proof.Allocation.ContainmentID || binding.Record.ProcessGeneration != q.Process.Generation {
					return fault(api.CodeContainmentUnknown, "review boot retirement changed its installed allocation")
				}
			}
		} else if proof.Release != nil {
			q := proof.Release
			observed, err := time.Parse(time.RFC3339Nano, string(q.Quiescence.ObservedAt))
			if err != nil || observed.IsZero() || observed.After(when) || q.ObservedAt != q.Quiescence.ObservedAt {
				return fault(api.CodeContainmentUnknown, "review release timestamp mismatch: receipt and quiescence must agree and precede retirement")
			}
			if q.OperationID != proof.OperationID || q.EffectID != proof.EffectID || q.Quiescence.Handle.ID != r.WorkerLaunchID || q.Quiescence.Handle.Target != proof.Target {
				return fault(api.CodeContainmentUnknown, "review release selector mismatch: require the original operation, effect, launch and target")
			}
			for _, count := range []*uint64{q.Quiescence.Survivors, q.LiveConnections, q.QueuedJobs, q.WritableExports} {
				if count == nil || *count != 0 {
					return fault(api.CodeContainmentUnknown, "review release counter mismatch: survivors, connections, jobs and exports must be known zero")
				}
			}
			if (q.Quiescence.ExitCode == nil) == (q.Quiescence.Signal == nil) || q.Quiescence.Signal != nil && (*q.Quiescence.Signal <= 0 || *q.Quiescence.Signal > 64) {
				return fault(api.CodeContainmentUnknown, "review release terminal selector mismatch: require exactly one exit code or signal 1 through 64")
			}
			binding, bindErr := s.launchBinding(ctx, s.db, r.WorkerLaunchID)
			if api.ValidateReleaseReceipt(*q) != nil || bindErr != nil || binding.Record.UIDLeaseID != proof.Allocation.ID || binding.Record.HostUID != proof.Allocation.UID || binding.Record.ContainmentID != proof.Allocation.ContainmentID || binding.Record.ProcessGeneration != q.Quiescence.Handle.Generation || q.LeaseID != proof.Allocation.ID || q.ContainmentID != proof.Allocation.ContainmentID || q.Quiescence.Handle.Generation == "" || r.Process.ID != "" && r.Process != q.Quiescence.Handle {
				return fault(api.CodeContainmentUnknown, "review release binding mismatch: require the installed allocation, backend and exited process generation")
			}
			r.Process = q.Quiescence.Handle
		} else {
			q := proof.Abort
			at, err := time.Parse(time.RFC3339Nano, string(q.ObservedAt))
			if err != nil || at.IsZero() || at.After(when) || q.ObservedAt != q.Quiescence.ObservedAt {
				return fault(api.CodeContainmentUnknown, "review abort timestamp mismatch: receipt and quiescence must agree and precede retirement")
			}
			if !wire.ValidID(string(q.ID)) || q.Quiescence.Handle.Target != proof.Target {
				return fault(api.CodeContainmentUnknown, "review abort selector mismatch: require a receipt ID and the original target")
			}
			if q.Quiescence.Survivors == nil || *q.Quiescence.Survivors != 0 {
				return fault(api.CodeContainmentUnknown, "review abort counter mismatch: survivors must be known zero")
			}
			if q.LeaseID != proof.Allocation.ID || q.AgentExecuted || r.Process.ID != "" || q.Quiescence.Handle.ContainmentID != proof.Allocation.ContainmentID || q.Quiescence.State != "not_started" {
				return fault(api.CodeContainmentUnknown, "review abort binding mismatch: require the original unopened allocation and not_started state")
			}
		}
		r.Allocation = proof.Allocation
	}
	r.Retirement = &proof
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer finish(tx, &resultErr)
	if err := s.saveReview(ctx, tx, r); err != nil {
		return err
	}
	return tx.Commit()
}
