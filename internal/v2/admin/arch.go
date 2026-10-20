package admin

import (
	"context"
	"reflect"
	"slices"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	archivejob "laneboss.io/laneboss/internal/v2/archive"
)

// Native records belong to the existing protected helper journal. They never
// publish an archive or complete a service effect.
type archiveJournal struct {
	SourceOperationID api.ID `json:",omitempty"`
	Intent            archivejob.Intent
	LaunchID          api.ID
	Phase             string
	Tree              api.ObjectManifest
	GitRoot           *storageIdentity `json:",omitempty"`
	Objects           []archiveSource  `json:",omitempty"`
	Inventory         []storageInode
	Freeze            archivejob.Freeze         `json:",omitempty,omitzero"`
	Worker            *archiveWorker            `json:",omitempty"`
	Retirement        *archiveRetirementJournal `json:",omitempty"`
}

type archiveSource struct {
	Ref        api.BlobRef
	Root, Name string
}

type archiveWorker struct {
	Revoked     bool
	Collecting  bool
	Collected   bool
	Reg         archiveReg
	Lease       api.HelperLease
	State       string
	Created     api.Timestamp
	Spec        *specRegistration       `json:",omitempty"`
	Endpoint    *api.InstalledBinding   `json:",omitempty"`
	Input       []byte                  `json:",omitempty"`
	Gate        *dataGate               `json:",omitempty"`
	Observation *api.ProcessObservation `json:",omitempty"`
}

type archiveReg struct {
	Job      archivejob.Job
	Claim    api.EffectLease
	LaunchID api.ID
}

type archiveQuery struct {
	Intent archivejob.Intent
	Epoch  *archivejob.EpochFence `json:",omitempty"`
	Lane   api.Lane               `json:",omitempty,omitzero"`
	Freeze archivejob.Freeze      `json:",omitempty,omitzero"`
	Index  int
	Offset int64
	Limit  int
}

type archiveHeader struct {
	Freeze  archivejob.Freeze
	Objects []api.BlobRef
}

type archiveSeal struct {
	Reg      archiveReg
	Spec     specRegistration
	Endpoint api.InstalledBinding
	Input    []byte
}

type archiveOpen struct {
	Reg      archiveReg
	Request  api.HelperOpenRequest
	Record   api.LaunchRecord
	Identity api.IdentityCommit
}

var _ archivejob.Native = (*Service)(nil)

func (s *Service) FreezeArchive(ctx context.Context, intent archivejob.Intent, lane api.Lane) (archivejob.Snapshot, error) {
	var header archiveHeader
	query, err := s.archiveFreezeQuery(ctx, intent, lane)
	if err != nil {
		return archivejob.Snapshot{}, err
	}
	if err := s.call(ctx, "archive_freeze", query, &header); err != nil {
		return archivejob.Snapshot{}, err
	}
	return s.archiveSnapshot(ctx, intent, header)
}

func (s *Service) archiveFreezeQuery(ctx context.Context, intent archivejob.Intent, lane api.Lane) (archiveQuery, error) {
	query := archiveQuery{Intent: intent, Lane: lane}
	if err := contextError(ctx); err != nil {
		return query, err
	}
	if lane.State == "abandoned" || lane.State == "merged" {
		writer, ok := s.deps.Store.(interface {
			ReadArchiveEpochFence(context.Context, archivejob.Intent) (*archivejob.EpochFence, error)
		})
		if !ok {
			return query, api.NotImplemented("lb-v2-service", "committed archive epoch handoff")
		}
		var err error
		query.Epoch, err = writer.ReadArchiveEpochFence(ctx, intent)
		if err != nil {
			return query, err
		}
		if query.Epoch != nil && (query.Epoch.Intent != intent || query.Epoch.LaunchID != lane.LaunchID) {
			return query, failure(api.CodeForbidden, "archive epoch handoff selected another retained launch")
		}
	}
	return query, nil
}

func (s *Service) archiveSnapshot(ctx context.Context, intent archivejob.Intent, header archiveHeader) (archivejob.Snapshot, error) {
	if len(header.Objects) == 0 || len(header.Objects) > 4096 {
		return archivejob.Snapshot{}, failure(api.CodeIntegrity, "native archive lost its complete object inventory")
	}
	result := archivejob.Snapshot{Freeze: header.Freeze}
	for index, ref := range header.Objects {
		if !validID(ref.ID) || !validDigest(ref.SHA256) || ref.Bytes < 0 || ref.Bytes > api.MaxObjectBytes {
			return archivejob.Snapshot{}, failure(api.CodeIntegrity, "native archive object exceeds its bounded pin")
		}
		body := make([]byte, 0, int(ref.Bytes))
		for int64(len(body)) < ref.Bytes {
			var chunk api.BlobChunk
			q := archiveQuery{Intent: intent, Freeze: header.Freeze, Index: index, Offset: int64(len(body)), Limit: int(min(int64(api.MaxChunkBytes), ref.Bytes-int64(len(body))))}
			if err := s.call(ctx, "archive_bytes", q, &chunk); err != nil {
				return archivejob.Snapshot{}, err
			}
			if chunk.ObjectID != ref.ID || chunk.Offset != q.Offset || len(chunk.Data) == 0 || len(chunk.Data) > q.Limit || digestBytes(chunk.Data) != chunk.SHA256 {
				return archivejob.Snapshot{}, failure(api.CodeIntegrity, "native archive range changed")
			}
			body = append(body, chunk.Data...)
		}
		if digestBytes(body) != ref.SHA256 {
			return archivejob.Snapshot{}, failure(api.CodeIntegrity, "native archive bytes differ from their measured pin")
		}
		result.Objects = append(result.Objects, api.ObjectWrite{ObjectKey: ref.ID, Class: ref.Class, Bytes: body, SHA256: ref.SHA256, Origin: "service", ACL: api.ObjectACL{Config: s.deps.Config, LifeID: intent.Request.Target.LifeID}})
	}
	return result, s.CheckArchiveFreeze(ctx, intent, header.Freeze)
}

// The store holds its own authority fence while invoking this read. Do not
// recursively call that writer from a native readback.
func (s *Service) CheckArchiveFreeze(ctx context.Context, intent archivejob.Intent, freeze archivejob.Freeze) error {
	var result archiveHeader
	return s.call(ctx, "archive_check", archiveQuery{Intent: intent, Freeze: freeze}, &result)
}

type archiveAuthorityStore interface {
	ArchiveJob(context.Context, api.Scope, api.ID) (archivejob.Job, error)
	ArchiveWorkerID(context.Context, api.Scope, api.EffectLease) (api.ID, error)
}

func validArchiveReg(r archiveReg, config string) error {
	if r.Job.Lease.Kind == "export" || r.Job.Lease.Kind == "test" {
		return validReviewReg(r, config)
	}
	j, c := r.Job, r.Claim
	e := c.Record.Effect
	deadline, err := time.Parse(time.RFC3339Nano, string(c.ExpiresAt))
	if !validID(j.ID) || !validID(r.LaunchID) || j.Lease.Kind != "archive" || j.Lease.Target != j.Intent.Request.Target ||
		j.Lease.OperationID != j.Intent.OperationID || j.Lease.EffectID != e.ID || e.OperationID != j.Intent.OperationID ||
		e.Context == nil || e.Context.Config != config || e.Context.Target != j.Lease.Target || e.Context.CancellationEpoch != j.Intent.CancellationEpoch ||
		e.Context.Actor.Kind != "service" || !validID(c.Record.ClaimantID) ||
		e.Worker == nil || !reflect.DeepEqual(*e.Worker, j.Plan) || j.Plan.Kind != "archive" || j.Plan.Input != j.Lease.Input ||
		j.Plan.GrantSetID != j.Lease.GrantSetID || j.Plan.Schema != "laneboss.worker-plan.v2" ||
		!api.EffectLeaseClaimed(c) || c.Record.Outcome != nil || c.ClaimID != c.Record.ClaimID || c.ExpiresAt != c.Record.ClaimExpiresAt ||
		err != nil || !deadline.After(time.Now()) ||
		!slices.Equal(j.Plan.Argv, []string{"laneboss", "internal", "worker", "--binding", "/runtime/laneboss-worker.json", "--lease", string(j.Lease.ID)}) {
		return failure(api.CodeForbidden, "archive worker differs from its original live claim and fixed plan")
	}
	workerExpiry, err := time.Parse(time.RFC3339Nano, string(j.Lease.ExpiresAt))
	if err != nil || !workerExpiry.After(time.Now()) || deadline.After(workerExpiry) {
		return failure(api.CodeForbidden, "archive worker claim exceeds its original lease")
	}
	return nil
}

func (s *Service) archiveAuthority(ctx context.Context, job archivejob.Job, claim api.EffectLease) (archiveReg, api.Scope, error) {
	r := archiveReg{Job: job, Claim: claim}
	scope := api.Scope{Config: s.deps.Config, Actor: api.Actor{Kind: "service", ID: claim.Record.ClaimantID}, Source: "service"}
	store, ok := s.deps.Store.(archiveAuthorityStore)
	if !ok {
		return r, scope, api.NotImplemented("lb-v2-service", "retained archive claim resolver")
	}
	current, err := s.deps.Store.Effect(ctx, scope, job.Lease.EffectID)
	if err != nil {
		return r, scope, err
	}
	if !reflect.DeepEqual(current, claim.Record) {
		return r, scope, failure(api.CodeConflict, "archive worker claim was replaced")
	}
	actual, err := store.ArchiveJob(ctx, scope, job.Intent.OperationID)
	if err != nil {
		return r, scope, err
	}
	if !reflect.DeepEqual(actual, job) {
		return r, scope, failure(api.CodeForbidden, "archive retry changed its original job")
	}
	r.LaunchID, err = store.ArchiveWorkerID(ctx, scope, claim) // The writer rechecks policy, grants, life and cancellation.
	if err != nil {
		return r, scope, err
	}
	return r, scope, validArchiveReg(r, s.deps.Config)
}

func (s *Service) ArchiveWorkerLease(ctx context.Context, job archivejob.Job, claim api.EffectLease) (api.HelperLease, error) {
	r, _, err := s.archiveAuthority(ctx, job, claim)
	if err != nil {
		return api.HelperLease{}, err
	}
	var result api.HelperLease
	if err := s.call(ctx, "archive_lease", r, &result); err != nil {
		return result, err
	}
	return result, validateLease(result, s.binding)
}

func (s *Service) RegisterArchiveWorker(ctx context.Context, job archivejob.Job, claim api.EffectLease, handoff api.PreparedSpecHandoff, endpoint api.InstalledBinding) (api.PreparedSpecReceipt, error) {
	r, scope, err := s.archiveAuthority(ctx, job, claim)
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
		return api.PreparedSpecReceipt{}, failure(api.CodeForbidden, "archive handoff grants changed")
	}
	var result api.PreparedSpecReceipt
	err = s.call(ctx, "archive_register", archiveSeal{Reg: r, Spec: specRegistration{Handoff: handoff, Original: original}, Endpoint: endpoint, Input: input}, &result)
	return result, err
}

func (s *Service) PrepareArchiveWorker(ctx context.Context, job archivejob.Job, claim api.EffectLease) (api.PreparedLaunch, error) {
	r, _, err := s.archiveAuthority(ctx, job, claim)
	if err != nil {
		return api.PreparedLaunch{}, err
	}
	var result api.PreparedLaunch
	if err := s.call(ctx, "archive_prepare", r, &result); err != nil {
		return result, err
	}
	return result, s.bindArchiveContainment(ctx, r)
}

func (s *Service) OpenArchiveWorker(ctx context.Context, job archivejob.Job, claim api.EffectLease, request api.HelperOpenRequest) (api.ProcessHandle, error) {
	r, _, err := s.archiveAuthority(ctx, job, claim)
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
	err = s.call(ctx, "archive_open", archiveOpen{Reg: r, Request: request, Record: binding.Record, Identity: binding.Identity}, &result)
	return result, err
}

func (s *Service) ObserveArchiveWorker(ctx context.Context, job archivejob.Job, claim api.EffectLease) (api.ProcessObservation, error) {
	r, _, err := s.archiveAuthority(ctx, job, claim)
	if err != nil {
		return api.ProcessObservation{}, err
	}
	var result api.ProcessObservation
	err = s.call(ctx, "archive_observe", r, &result)
	return result, err
}

// ReconcileArchiveWorker reads the original gate and its actually consumed
// permit after a lost open reply. It neither reissues a permit nor opens a gate.
func (s *Service) ReconcileArchiveWorker(ctx context.Context, job archivejob.Job, claim api.EffectLease) (api.LaunchReconciliation, error) {
	r, _, err := s.archiveAuthority(ctx, job, claim)
	if err != nil {
		return api.LaunchReconciliation{}, err
	}
	var result api.LaunchReconciliation
	err = s.call(ctx, "archive_reconcile", r, &result)
	return result, err
}
