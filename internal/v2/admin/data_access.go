package admin

import (
	"context"
	"errors"
	"reflect"

	"laneboss.io/laneboss/internal/v2/api"
)

// An unopened job has no helper token to revoke. Preserve the authorization
// refusal while still propagating cleanup failures for an actual retained job.
func deniedDataLaunch(found bool, revoke func() error) error {
	if found {
		if err := revoke(); err != nil {
			return err
		}
	}
	return failure(api.CodeForbidden, "revoked launch cannot retain a data token")
}

// Invalidation is independent of the parent planning claim. Once its launch
// revocation is committed, even an expired/completed planner cannot keep a
// helper-held token usable by preventing a fresh authority lookup.
func (s *Service) dataRevocation(ctx context.Context, r dataReg) error {
	if s.deps.Store == nil {
		return api.NotImplemented("lb-v2-service", "data launch revocation read")
	}
	for _, id := range []api.ID{r.Reservation.LaunchID, r.LaunchID} {
		record, err := s.deps.Store.Launch(ctx, id)
		if err != nil {
			var typed *api.Error
			if errors.As(err, &typed) && typed.Code == api.CodeNotFound {
				continue
			}
			return err
		}
		if record.ID != id || record.Config != s.deps.Config || record.Target != r.Reservation.Target {
			return failure(api.CodeIntegrity, "data revocation read returned a foreign launch")
		}
		if record.Revoked {
			if err := s.RevokeDataStorage(ctx, id); err != nil {
				return err
			}
			return failure(api.CodeForbidden, "revoked launch cannot retain a data token")
		}
	}
	return nil
}

func (s *Service) priorData(ctx context.Context, q api.StorageProjectionRequest) (dataReg, bool, error) {
	var r dataReg
	if err := s.call(ctx, "data_query", q, &r); err != nil {
		var typed *api.Error
		if errors.As(err, &typed) && typed.Code == api.CodeNotFound {
			return r, false, nil
		}
		return r, false, err
	}
	wireSelector := q
	wireSelector.Claim = api.LaunchClaim{}
	if r.Request != wireSelector {
		return r, false, failure(api.CodeIntegrity, "helper data query substituted its original selector")
	}
	if err := validateDataReg(r, s.deps.Config); err != nil {
		return r, false, err
	}
	return r, true, s.dataRevocation(ctx, r)
}

func (s *Service) retainedData(ctx context.Context, q api.StorageProjectionRequest) (dataReg, api.Scope, api.LaunchDataStage, error) {
	r, found, err := s.priorData(ctx, q)
	if err != nil {
		return r, api.Scope{}, api.LaunchDataStage{}, err
	}
	if !found {
		return r, api.Scope{}, api.LaunchDataStage{}, failure(api.CodeNotFound, "data result has no retained helper job")
	}
	scope := api.Scope{Config: s.deps.Config, Actor: r.ParentActor, Source: "service", PolicyGeneration: r.Reservation.PolicyGeneration}
	if q.Claim != (api.LaunchClaim{}) {
		// A supplied selector is checked unchanged even for retained reads.
		// Internal historical queries without one remain read-only.
		authority, err := s.launchAuthority(ctx, q.ReservationID, r.Reservation.GrantSetID, nil, q.Claim)
		if err != nil {
			return r, scope, api.LaunchDataStage{}, err
		}
		if authority.Claim.Effect.ID != r.ParentEffect {
			return r, scope, api.LaunchDataStage{}, failure(api.CodeForbidden, "retained data selector names another planning effect")
		}
		scope = authority.Scope
	}
	stage, err := s.deps.Store.LaunchDataStage(ctx, scope, api.LaunchDataRequest{ReservationID: q.ReservationID, GrantSetID: r.Reservation.GrantSetID, LeaseID: q.AgentLeaseID, Claim: q.Claim})
	if err != nil {
		return r, scope, stage, err
	}
	if err := api.ValidateLaunchDataStage(stage, api.LaunchDataRequest{ReservationID: q.ReservationID, GrantSetID: r.Reservation.GrantSetID, LeaseID: q.AgentLeaseID}); err != nil {
		return r, scope, stage, err
	}
	if stage.ID != q.StageID || stage.WorkerLaunchID != r.LaunchID || stage.Worker.ID != q.WorkerLeaseID || stage.ParentEffectID != r.ParentEffect || !reflect.DeepEqual(stage.Reservation, r.Reservation) || !reflect.DeepEqual(stage.Inputs, r.Inputs) || !reflect.DeepEqual(stage.Grants, r.Grants) || !reflect.DeepEqual(stage.Plan, r.Plan) || stage.Worker != r.Worker {
		return r, scope, stage, failure(api.CodeIntegrity, "data result differs from the actual retained launch-time stage")
	}
	worker, err := s.deps.Store.WorkerLease(ctx, scope, r.Worker.ID)
	if err != nil {
		return r, scope, stage, err
	}
	want := r.Worker
	want.Generation = worker.Generation
	if worker.Generation < r.Worker.Generation || worker.Generation > r.Worker.Generation+1 || worker != want {
		return r, scope, stage, failure(api.CodeForbidden, "data result worker lease changed")
	}
	for _, original := range []api.GrantSet{r.Grants, r.Inputs.Grants} {
		current, err := s.deps.Store.Grants(ctx, original.ID)
		if err != nil {
			return r, scope, stage, err
		}
		if !reflect.DeepEqual(current, original) {
			if current.Revoked {
				if e := s.RevokeDataStorage(ctx, r.LaunchID); e != nil {
					return r, scope, stage, e
				}
			}
			return r, scope, stage, failure(api.CodeForbidden, "data result grant set was revoked or changed")
		}
	}
	return r, scope, stage, nil
}

func (m *leaseManager) dataByLease(id api.ID) (leaseRecord, int, bool, error) {
	records, err := m.records()
	if err != nil {
		return leaseRecord{}, 0, false, err
	}
	for _, parent := range records {
		for i, job := range parent.DataJobs {
			if job.Lease.ID == id {
				return parent, i, true, nil
			}
		}
	}
	return leaseRecord{}, 0, false, nil
}

// The helper holds its operation lock throughout this read-only query. Resolve
// both the native child and its ticket's parent from one validated journal
// generation. This read-only view is never handed to a mutable record lookup.
// Each query checks storage generation; every helper save invalidates the view.
func (m *leaseManager) containmentRecord(ctx context.Context, id api.ID, opened bool) (leaseRecord, leaseRecord, error) {
	defer helperStage(ctx, "containment_record")()
	records, err := m.containmentRecords(ctx)
	if err != nil {
		return leaseRecord{}, leaseRecord{}, err
	}
	for _, parent := range records {
		for _, worker := range parent.Usages {
			if worker.Lease.ID != id {
				continue
			}
			if parent.BootID != m.bootID || parent.Revoked || worker.Revoked || worker.Collected || worker.Spec == nil || opened && (worker.Gate == nil || worker.Gate.State != "opened" || worker.Gate.Permit == nil) {
				return leaseRecord{}, leaseRecord{}, failure(api.CodeContainmentUnknown, "usage containment lost its original native worker")
			}
			return usageChild(parent, worker), parent, nil
		}
	}
	for _, channel := range records {
		for _, w := range channel.Judges {
			if w.Lease.ID != id {
				continue
			}
			if channel.BootID != m.bootID || channel.Revoked || w.Revoked || w.Collected || w.Spec == nil || opened && (w.Gate == nil || w.Gate.State != "opened" || w.Gate.Permit == nil) {
				return leaseRecord{}, leaseRecord{}, failure(api.CodeContainmentUnknown, "judge containment lost its original native worker")
			}
			return judgeChild(channel, w), channel, nil
		}
		for _, w := range channel.Channels {
			if w.Lease.ID != id {
				continue
			}
			if channel.BootID != m.bootID || channel.Revoked || w.Revoked || w.Collected || w.Spec == nil || opened && (w.Gate == nil || w.Gate.State != "opened" || w.Gate.Permit == nil) {
				return leaseRecord{}, leaseRecord{}, failure(api.CodeContainmentUnknown, "channel containment lost its original native worker")
			}
			return channelChild(channel, w), channel, nil
		}
	}
	for _, archive := range records {
		if archive.Archive == nil || archive.Archive.Worker == nil || archive.Archive.Worker.Lease.ID != id {
			for _, review := range archive.Reviews {
				if review.Worker != nil && review.Worker.Lease.ID == id {
					archive.Archive = review
					break
				}
			}
		}
		if archive.Archive == nil || archive.Archive.Worker == nil || archive.Archive.Worker.Lease.ID != id {
			continue
		}
		w := archive.Archive.Worker
		// A stopped lane's measured credential fence permits its archive; all
		// other parent revocations and every worker revocation still refuse.
		stopFenced := archive.Phase == "released" && archive.Receipt != nil && archive.Credentials != nil && archive.Credentials.Stop != nil
		if archive.BootID != m.bootID || archive.Revoked && !stopFenced || w.Revoked || w.Collecting || w.Collected || w.Spec == nil || opened && (w.Gate == nil || w.Gate.State != "opened" || w.Gate.Permit == nil) {
			return leaseRecord{}, leaseRecord{}, failure(api.CodeContainmentUnknown, "archive containment lost its original opened worker")
		}
		return archiveChild(archive, *w), archive, nil
	}
	for _, parent := range records {
		for _, job := range parent.DataJobs {
			if job.Lease.ID != id {
				continue
			}
			if parent.BootID != m.bootID || parent.Phase != "active" || parent.Revoked || opened && job.State != "opened" {
				return leaseRecord{}, leaseRecord{}, failure(api.CodeContainmentUnknown, "worker containment has no current parent allocation")
			}
			if err := m.checkData(ctx, parent, job); err != nil {
				return leaseRecord{}, leaseRecord{}, err
			}
			return dataChild(parent, job), parent, nil
		}
	}
	for _, parent := range records {
		if parent.Lease.ID == id {
			return parent, parent, nil
		}
	}
	return leaseRecord{}, leaseRecord{}, failure(api.CodeNotFound, "unknown helper lease")
}

func (s *Service) dataSelector(ctx context.Context, id api.ID) (api.StorageProjectionRequest, error) {
	var q api.StorageProjectionRequest
	if !validID(id) {
		return q, failure(api.CodeInvalid, "invalid retained data native selector")
	}
	err := s.call(ctx, "data_selector", struct {
		ID api.ID `json:"id"`
	}{id}, &q)
	return q, err
}
