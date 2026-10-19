// Review uses the common immutable job DTO and fixed-worker algorithms, with
// its own protected native journal. It never reserves an archival operation.
package admin

import (
	"context"
	"reflect"
	"slices"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	archivejob "laneboss.io/laneboss/internal/v2/archive"
)

func (s *Service) FreezeReview(ctx context.Context, intent archivejob.Intent, lane api.Lane) (archivejob.Snapshot, error) {
	var header archiveHeader
	if err := s.call(ctx, "review_freeze", archiveQuery{Intent: intent, Lane: lane}, &header); err != nil {
		return archivejob.Snapshot{}, err
	}
	if len(header.Objects) == 0 || len(header.Objects) > 4096 {
		return archivejob.Snapshot{}, failure(api.CodeIntegrity, "native review lost its complete object inventory")
	}
	result := archivejob.Snapshot{Freeze: header.Freeze}
	for index, ref := range header.Objects {
		if !validID(ref.ID) || !validDigest(ref.SHA256) || ref.Bytes < 0 || ref.Bytes > api.MaxObjectBytes {
			return archivejob.Snapshot{}, failure(api.CodeIntegrity, "native review object exceeds its bounded pin")
		}
		body := make([]byte, 0, int(ref.Bytes))
		for int64(len(body)) < ref.Bytes {
			var chunk api.BlobChunk
			q := archiveQuery{Intent: intent, Freeze: header.Freeze, Index: index, Offset: int64(len(body)), Limit: int(min(int64(api.MaxChunkBytes), ref.Bytes-int64(len(body))))}
			if err := s.call(ctx, "review_bytes", q, &chunk); err != nil {
				return archivejob.Snapshot{}, err
			}
			if chunk.ObjectID != ref.ID || chunk.Offset != q.Offset || len(chunk.Data) == 0 || len(chunk.Data) > q.Limit || digestBytes(chunk.Data) != chunk.SHA256 {
				return archivejob.Snapshot{}, failure(api.CodeIntegrity, "native review range changed")
			}
			body = append(body, chunk.Data...)
		}
		if digestBytes(body) != ref.SHA256 {
			return archivejob.Snapshot{}, failure(api.CodeIntegrity, "native review bytes differ from their measured pin")
		}
		result.Objects = append(result.Objects, api.ObjectWrite{ObjectKey: ref.ID, Class: ref.Class, Bytes: body, SHA256: ref.SHA256, Origin: "service", ACL: api.ObjectACL{Config: s.deps.Config, LifeID: intent.Request.Target.LifeID}})
	}
	return result, s.CheckReviewFreeze(ctx, intent, header.Freeze)
}

// The store holds its own authority fence while invoking this read. Do not
// recursively call that writer from a native readback.
func (s *Service) CheckReviewFreeze(ctx context.Context, intent archivejob.Intent, freeze archivejob.Freeze) error {
	var result archiveHeader
	return s.call(ctx, "review_check", archiveQuery{Intent: intent, Freeze: freeze}, &result)
}

type reviewAuthorityStore interface {
	ReviewJob(context.Context, api.Scope, api.ID) (archivejob.Job, error)
	ReviewWorkerID(context.Context, api.Scope, api.EffectLease) (api.ID, error)
}

func validReviewReg(r archiveReg, config string) error {
	j, c := r.Job, r.Claim
	e := c.Record.Effect
	deadline, err := time.Parse(time.RFC3339Nano, string(c.ExpiresAt))
	if !validID(j.ID) || !validID(r.LaunchID) || (j.Lease.Kind != "export" && j.Lease.Kind != "test") || j.Lease.Target != j.Intent.Request.Target ||
		j.Lease.OperationID != j.Intent.OperationID || j.Lease.EffectID != e.ID || e.OperationID != j.Intent.OperationID ||
		e.Context == nil || e.Context.Config != config || e.Context.Target != j.Lease.Target || e.Context.CancellationEpoch != j.Intent.CancellationEpoch ||
		e.Context.Actor.Kind != "service" || !validID(c.Record.ClaimantID) ||
		e.Worker == nil || !reflect.DeepEqual(*e.Worker, j.Plan) || j.Plan.Kind != j.Lease.Kind || j.Plan.Input != j.Lease.Input ||
		j.Plan.GrantSetID != j.Lease.GrantSetID || j.Plan.Schema != "laneboss.worker-plan.v2" ||
		!api.EffectLeaseClaimed(c) || c.Record.Outcome != nil || c.ClaimID != c.Record.ClaimID || c.ExpiresAt != c.Record.ClaimExpiresAt ||
		err != nil || !deadline.After(time.Now()) ||
		!slices.Equal(j.Plan.Argv, []string{"laneboss", "internal", "worker", "--binding", "/runtime/laneboss-worker.json", "--lease", string(j.Lease.ID)}) {
		return failure(api.CodeForbidden, "review worker differs from its original live claim and fixed plan")
	}
	workerExpiry, err := time.Parse(time.RFC3339Nano, string(j.Lease.ExpiresAt))
	if err != nil || !workerExpiry.After(time.Now()) || deadline.After(workerExpiry) {
		return failure(api.CodeForbidden, "review worker claim exceeds its original lease")
	}
	return nil
}

func (s *Service) reviewAuthority(ctx context.Context, job archivejob.Job, claim api.EffectLease) (archiveReg, api.Scope, error) {
	r := archiveReg{Job: job, Claim: claim}
	scope := api.Scope{Config: s.deps.Config, Actor: api.Actor{Kind: "service", ID: claim.Record.ClaimantID}, Source: "service"}
	store, ok := s.deps.Store.(reviewAuthorityStore)
	if !ok {
		return r, scope, api.NotImplemented("lb-v2-service", "retained archive claim resolver")
	}
	if job.Lease.Kind != "export" && job.Lease.Kind != "test" {
		return r, scope, failure(api.CodeForbidden, "review requires its original export verifier")
	}
	current, err := s.deps.Store.Effect(ctx, scope, job.Lease.EffectID)
	if err != nil {
		return r, scope, err
	}
	if !reflect.DeepEqual(current, claim.Record) {
		return r, scope, failure(api.CodeConflict, "review worker claim was replaced")
	}
	actual, err := store.ReviewJob(ctx, scope, job.Intent.OperationID)
	if err != nil {
		return r, scope, err
	}
	if !reflect.DeepEqual(actual, job) {
		return r, scope, failure(api.CodeForbidden, "review retry changed its original job")
	}
	r.LaunchID, err = store.ReviewWorkerID(ctx, scope, claim) // The writer rechecks policy, grants, life and cancellation.
	if err != nil {
		return r, scope, err
	}
	return r, scope, validReviewReg(r, s.deps.Config)
}

func (s *Service) ReviewWorkerLease(ctx context.Context, job archivejob.Job, claim api.EffectLease) (api.HelperLease, error) {
	r, _, err := s.reviewAuthority(ctx, job, claim)
	if err != nil {
		return api.HelperLease{}, err
	}
	var result api.HelperLease
	if err := s.call(ctx, "review_lease", r, &result); err != nil {
		return result, err
	}
	return result, validateLease(result, s.binding)
}

func (s *Service) RegisterReviewWorker(ctx context.Context, job archivejob.Job, claim api.EffectLease, handoff api.PreparedSpecHandoff, endpoint api.InstalledBinding) (api.PreparedSpecReceipt, error) {
	r, scope, err := s.reviewAuthority(ctx, job, claim)
	if err != nil {
		return api.PreparedSpecReceipt{}, err
	}
	original, err := s.readLaunchObject(ctx, scope, handoff.Original, job.Intent.OperationID, job.Lease.Target.LifeID, false)
	if err != nil {
		return api.PreparedSpecReceipt{}, err
	}
	input, err := s.readLaunchObject(ctx, scope, job.Lease.Input, job.Intent.OperationID, job.Lease.Target.LifeID, false)
	if err != nil {
		return api.PreparedSpecReceipt{}, err
	}
	grants, err := s.deps.Store.Grants(ctx, job.Lease.GrantSetID)
	if err != nil {
		return api.PreparedSpecReceipt{}, err
	}
	if !reflect.DeepEqual(grants, handoff.Spec.Grants) {
		return api.PreparedSpecReceipt{}, failure(api.CodeForbidden, "review handoff grants changed")
	}
	var result api.PreparedSpecReceipt
	err = s.call(ctx, "review_register", archiveSeal{Reg: r, Spec: specRegistration{Handoff: handoff, Original: original}, Endpoint: endpoint, Input: input}, &result)
	return result, err
}

func (s *Service) PrepareReviewWorker(ctx context.Context, job archivejob.Job, claim api.EffectLease) (api.PreparedLaunch, error) {
	r, _, err := s.reviewAuthority(ctx, job, claim)
	if err != nil {
		return api.PreparedLaunch{}, err
	}
	var result api.PreparedLaunch
	if err := s.call(ctx, "review_prepare", r, &result); err != nil {
		return result, err
	}
	return result, s.bindReviewContainment(ctx, r)
}

func (s *Service) OpenReviewWorker(ctx context.Context, job archivejob.Job, claim api.EffectLease, request api.HelperOpenRequest) (api.ProcessHandle, error) {
	r, _, err := s.reviewAuthority(ctx, job, claim)
	if err != nil {
		return api.ProcessHandle{}, err
	}
	binding, err := s.deps.Store.LaunchBinding(ctx, r.LaunchID)
	if err != nil {
		return api.ProcessHandle{}, err
	}
	if err := validateOpenCommit(request, binding, s.deps.Config); err != nil {
		return api.ProcessHandle{}, err
	}
	var result api.ProcessHandle
	err = s.call(ctx, "review_open", archiveOpen{Reg: r, Request: request, Record: binding.Record, Identity: binding.Identity}, &result)
	return result, err
}

func (s *Service) ObserveReviewWorker(ctx context.Context, job archivejob.Job, claim api.EffectLease) (api.ProcessObservation, error) {
	r, _, err := s.reviewAuthority(ctx, job, claim)
	if err != nil {
		return api.ProcessObservation{}, err
	}
	var result api.ProcessObservation
	err = s.call(ctx, "review_observe", r, &result)
	return result, err
}

// ReconcileReviewWorker reads the original gate and its actually consumed
// permit after a lost open reply. It neither reissues a permit nor opens a gate.
func (s *Service) ReconcileReviewWorker(ctx context.Context, job archivejob.Job, claim api.EffectLease) (api.LaunchReconciliation, error) {
	r, _, err := s.reviewAuthority(ctx, job, claim)
	if err != nil {
		return api.LaunchReconciliation{}, err
	}
	var result api.LaunchReconciliation
	err = s.call(ctx, "review_reconcile", r, &result)
	return result, err
}
