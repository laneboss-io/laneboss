package admin

import (
	"context"
	"reflect"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	archivejob "laneboss.io/laneboss/internal/v2/archive"
)

type reviewRecoveryStore interface {
	ReviewRecovery(context.Context, api.Scope, api.EffectLease) (archivejob.Recovery, error)
}

func validReviewRetirement(job archivejob.Job, claim api.EffectLease, config string, now time.Time) error {
	effect := claim.Record.Effect
	expiry, err := time.Parse(time.RFC3339Nano, string(claim.ExpiresAt))
	if err != nil || !expiry.After(now) || !validID(claim.ClaimID) || claim.ClaimID != claim.Record.ClaimID || claim.ExpiresAt != claim.Record.ClaimExpiresAt ||
		!api.EffectLeaseClaimed(claim) || claim.Record.Outcome != nil || claim.Record.Generation == 0 || !validID(claim.Record.ClaimantID) ||
		!validID(job.ID) || !validID(job.Lease.ID) || (job.Lease.Kind != "export" && job.Lease.Kind != "test") || job.Lease.Target != job.Intent.Request.Target ||
		!validID(job.Intent.OperationID) || !validID(job.Intent.EndEventID) || job.Intent.EndSeq == 0 ||
		job.Lease.OperationID != job.Intent.OperationID || job.Lease.EffectID != effect.ID || effect.OperationID != job.Intent.OperationID ||
		effect.Context == nil || effect.Context.Config != config || effect.Context.Target != job.Lease.Target || effect.Context.CancellationEpoch != job.Intent.CancellationEpoch ||
		effect.Worker == nil || !reflect.DeepEqual(*effect.Worker, job.Plan) || job.Plan.Kind != job.Lease.Kind || job.Plan.Input != job.Lease.Input || job.Plan.GrantSetID != job.Lease.GrantSetID {
		return failure(api.CodeForbidden, "review retirement differs from its original job and live effect claim")
	}
	return nil
}

func (s *Service) reviewRetirementAuthority(ctx context.Context, job archivejob.Job, claim api.EffectLease) (archiveRetireQuery, error) {
	q := archiveRetireQuery{Job: job, Claim: claim}
	if err := validReviewRetirement(job, claim, s.deps.Config, time.Now()); err != nil {
		return q, err
	}
	store, ok := s.deps.Store.(reviewRecoveryStore)
	if !ok {
		return q, api.NotImplemented(owner, "retained archive recovery authority")
	}
	scope := api.Scope{Config: s.deps.Config, Actor: api.Actor{Kind: "service", ID: claim.Record.ClaimantID}, Source: "service"}
	current, err := s.deps.Store.Effect(ctx, scope, job.Lease.EffectID)
	if err != nil {
		return q, err
	}
	if !reflect.DeepEqual(current, claim.Record) {
		return q, failure(api.CodeConflict, "review retirement requires the actual current effect claim")
	}
	state, err := store.ReviewRecovery(ctx, scope, claim)
	if err != nil {
		return q, err
	}
	if !reflect.DeepEqual(state.Job, job) {
		return q, failure(api.CodeForbidden, "review retirement changed its retained recovery job")
	}
	q.Allocation, q.Process, q.Handoff = state.Allocation, state.Process, state.Handoff
	return q, nil
}

func (s *Service) RetireReviewWorker(ctx context.Context, job archivejob.Job, claim api.EffectLease) (archivejob.Retirement, error) {
	q, err := s.reviewRetirementAuthority(ctx, job, claim)
	if err != nil {
		return archivejob.Retirement{}, err
	}
	var result archivejob.Retirement
	if err := s.call(ctx, "review_retire", q, &result); err != nil {
		return result, err
	}
	if err := validateRetirementProof(job, result, time.Now()); err != nil {
		return archivejob.Retirement{}, err
	}
	var process api.ProcessHandle
	if result.Release != nil {
		process = result.Release.Quiescence.Handle
	} else if result.Boot != nil {
		process = result.Boot.Process
	}
	if q.Allocation.ID != "" && result.Allocation != q.Allocation || q.Process.ID != "" && process != q.Process {
		return archivejob.Retirement{}, failure(api.CodeIntegrity, "review retirement reply changed its retained allocation or process")
	}
	if !result.Absent {
		if err := s.finishRevocation(result.Allocation.ContainmentID, true, nil); err != nil {
			return archivejob.Retirement{}, err
		}
	}
	return result, nil
}
