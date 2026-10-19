package admin

import (
	"context"
	"encoding/json"
	"reflect"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	archivejob "laneboss.io/laneboss/internal/v2/archive"
)

type archiveRetireQuery struct {
	Job        archivejob.Job
	Claim      api.EffectLease
	Allocation api.HelperLease
	Process    api.ProcessHandle
	Handoff    bool
}

type archiveRetirementJournal struct {
	Job          archivejob.Job
	Claim        api.EffectLease
	AuthorizedAt api.Timestamp
	Opened       bool
	Observation  *api.ProcessObservation    `json:",omitempty"`
	Boot         *archivejob.BootRetirement `json:",omitempty"`
	Proof        *archivejob.Retirement     `json:",omitempty"`
}

type archiveRecoveryStore interface {
	ArchiveRecovery(context.Context, api.Scope, api.EffectLease) (archivejob.Recovery, error)
}

var _ archivejob.RetirementHelper = (*Service)(nil)

// Recovery accepts expired worker capabilities, never an expired current effect
// claim. It carries no allocation/open authority or replacement launch selector.
func validArchiveRetirement(job archivejob.Job, claim api.EffectLease, config string, now time.Time) error {
	if job.Lease.Kind == "export" || job.Lease.Kind == "test" {
		return validReviewRetirement(job, claim, config, now)
	}
	effect := claim.Record.Effect
	expiry, err := time.Parse(time.RFC3339Nano, string(claim.ExpiresAt))
	if err != nil || !expiry.After(now) || !validID(claim.ClaimID) || claim.ClaimID != claim.Record.ClaimID || claim.ExpiresAt != claim.Record.ClaimExpiresAt ||
		!api.EffectLeaseClaimed(claim) || claim.Record.Outcome != nil || claim.Record.Generation == 0 || !validID(claim.Record.ClaimantID) ||
		!validID(job.ID) || !validID(job.Lease.ID) || job.Lease.Kind != "archive" || job.Lease.Target != job.Intent.Request.Target ||
		!validID(job.Intent.OperationID) || !validID(job.Intent.EndEventID) || job.Intent.EndSeq == 0 ||
		job.Lease.OperationID != job.Intent.OperationID || job.Lease.EffectID != effect.ID || effect.OperationID != job.Intent.OperationID ||
		effect.Context == nil || effect.Context.Config != config || effect.Context.Target != job.Lease.Target || effect.Context.CancellationEpoch != job.Intent.CancellationEpoch ||
		effect.Worker == nil || !reflect.DeepEqual(*effect.Worker, job.Plan) || job.Plan.Kind != "archive" || job.Plan.Input != job.Lease.Input || job.Plan.GrantSetID != job.Lease.GrantSetID {
		return failure(api.CodeForbidden, "archive retirement differs from its original job and live effect claim")
	}
	return nil
}

func (s *Service) archiveRetirementAuthority(ctx context.Context, job archivejob.Job, claim api.EffectLease) (archiveRetireQuery, error) {
	q := archiveRetireQuery{Job: job, Claim: claim}
	if err := validArchiveRetirement(job, claim, s.deps.Config, time.Now()); err != nil {
		return q, err
	}
	store, ok := s.deps.Store.(archiveRecoveryStore)
	if !ok {
		return q, api.NotImplemented(owner, "retained archive recovery authority")
	}
	scope := api.Scope{Config: s.deps.Config, Actor: api.Actor{Kind: "service", ID: claim.Record.ClaimantID}, Source: "service"}
	current, err := s.deps.Store.Effect(ctx, scope, job.Lease.EffectID)
	if err != nil {
		return q, err
	}
	if !reflect.DeepEqual(current, claim.Record) {
		return q, failure(api.CodeConflict, "archive retirement requires the actual current effect claim")
	}
	state, err := store.ArchiveRecovery(ctx, scope, claim)
	if err != nil {
		return q, err
	}
	if !reflect.DeepEqual(state.Job, job) {
		return q, failure(api.CodeForbidden, "archive retirement changed its retained recovery job")
	}
	q.Allocation, q.Process, q.Handoff = state.Allocation, state.Process, state.Handoff
	return q, nil
}

func (s *Service) RetireArchiveWorker(ctx context.Context, job archivejob.Job, claim api.EffectLease) (archivejob.Retirement, error) {
	q, err := s.archiveRetirementAuthority(ctx, job, claim)
	if err != nil {
		return archivejob.Retirement{}, err
	}
	var result archivejob.Retirement
	if err := s.call(ctx, "archive_retire", q, &result); err != nil {
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
		return archivejob.Retirement{}, failure(api.CodeIntegrity, "archive retirement reply changed its retained allocation or process")
	}
	if !result.Absent {
		if err := s.finishRevocation(result.Allocation.ContainmentID, true, nil); err != nil {
			return archivejob.Retirement{}, err
		}
	}
	return result, nil
}

func validateRetirementProof(job archivejob.Job, proof archivejob.Retirement, now time.Time) error {
	when, err := time.Parse(time.RFC3339Nano, string(proof.ObservedAt))
	if err != nil || when.IsZero() || when.After(now) || proof.JobID != job.ID || proof.OperationID != job.Intent.OperationID || proof.EffectID != job.Lease.EffectID || proof.Target != job.Lease.Target {
		return failure(api.CodeIntegrity, "archive retirement changed its original selector or measurement time")
	}
	if proof.Absent {
		if proof.Allocation != (api.HelperLease{}) || proof.Release != nil || proof.Abort != nil || proof.Boot != nil {
			return failure(api.CodeIntegrity, "archive absence has competing native allocation evidence")
		}
		return nil
	}
	kinds := 0
	for _, present := range []bool{proof.Release != nil, proof.Abort != nil, proof.Boot != nil} {
		if present {
			kinds++
		}
	}
	if !validID(proof.Allocation.ID) || !validID(proof.Allocation.ContainmentID) || proof.Allocation.UID == 0 || proof.Allocation.GID == 0 || kinds != 1 {
		return failure(api.CodeContainmentUnknown, "archive retirement lost its measured allocation")
	}
	if proof.Boot != nil {
		return archivejob.ValidateBootRetirement(proof.Allocation, proof.Target, *proof.Boot, proof.ObservedAt)
	}
	var observation api.ProcessObservation
	if proof.Release != nil {
		r := proof.Release
		if api.ValidateReleaseReceipt(*r) != nil || r.LeaseID != proof.Allocation.ID || r.ContainmentID != proof.Allocation.ContainmentID || r.OperationID != proof.OperationID || r.EffectID != proof.EffectID || r.ObservedAt != r.Quiescence.ObservedAt || !validID(r.Quiescence.Handle.ID) || r.Quiescence.Handle.Generation == "" || (r.Quiescence.ExitCode == nil) == (r.Quiescence.Signal == nil) || r.Quiescence.Signal != nil && (*r.Quiescence.Signal <= 0 || *r.Quiescence.Signal > 64) {
			return failure(api.CodeContainmentUnknown, "archive retirement release has no measured terminal lifetime")
		}
		observation = r.Quiescence
	} else {
		r := proof.Abort
		if !validID(r.ID) || r.LeaseID != proof.Allocation.ID || r.AgentExecuted || r.ObservedAt != r.Quiescence.ObservedAt || r.Quiescence.State != "not_started" || r.Quiescence.ExitCode != nil || r.Quiescence.Signal != nil {
			return failure(api.CodeContainmentUnknown, "archive retirement abort has no measured unopened lifetime")
		}
		observation = r.Quiescence
	}
	at, err := time.Parse(time.RFC3339Nano, string(observation.ObservedAt))
	if err != nil || at.IsZero() || at.After(when) || observation.Handle.Target != proof.Target || observation.Handle.ContainmentID != proof.Allocation.ContainmentID || observation.Survivors == nil || *observation.Survivors != 0 {
		return failure(api.CodeContainmentUnknown, "archive retirement has unknown or surviving native state")
	}
	return nil
}

func retirementAllowsCollection(j *archiveJournal) bool {
	if j.Retirement != nil && j.Retirement.Boot != nil && j.Worker != nil {
		b := j.Retirement.Boot
		return archivejob.ValidateBootRetirement(j.Worker.Lease, j.Retirement.Job.Lease.Target, *b, b.ObservedAt) == nil
	}
	if j.Retirement == nil || j.Retirement.Observation == nil || j.Worker == nil || j.Worker.State != "exited" {
		return false
	}
	o := j.Retirement.Observation
	return o.Survivors != nil && *o.Survivors == 0 && (o.State == "not_started" || o.State == "exited")
}

// freezeObject reports whether a job's freeze object is the canonical encoding of this record's freeze:
// store/archive.go retains canonical JSON of the same Freeze as the job's "manifest" object, so the job's
// ref is never the tree snapshot inside it (box 91: retirement compared it with Freeze.Snapshot and
// refused every archive as "a foreign native job").
func freezeObject(f archivejob.Freeze, ref api.BlobRef) bool {
	encoded, err := json.Marshal(f)
	if err != nil {
		return false
	}
	canonical, err := api.CanonicalJSON(encoded)
	if err != nil {
		return false
	}
	return ref.Class == "manifest" && ref.Bytes == int64(len(canonical)) && ref.SHA256 == digestBytes(canonical)
}

func validateArchiveRetirement(p leaseRecord) error {
	j := p.Archive
	if j.Retirement == nil {
		return nil
	}
	r := j.Retirement
	at, err := time.Parse(time.RFC3339Nano, string(r.AuthorizedAt))
	if err != nil || at.IsZero() || r.Job.Intent != j.Intent || !freezeObject(j.Freeze, r.Job.Freeze) || validArchiveRetirement(r.Job, r.Claim, p.Request.Config, at) != nil {
		return failure(api.CodeIntegrity, "retirement journal lost its original authorized job")
	}
	w := j.Worker
	if w != nil && (!w.Revoked || !reflect.DeepEqual(w.Reg.Job, r.Job)) {
		return failure(api.CodeIntegrity, "retirement journal changed its original native worker")
	}
	if r.Boot != nil {
		b := r.Boot
		observed, err := time.Parse(time.RFC3339Nano, string(b.ObservedAt))
		if w == nil || err != nil || observed.Before(at) || b.PreviousBootID != p.BootID || archivejob.ValidateBootRetirement(w.Lease, r.Job.Lease.Target, *b, b.ObservedAt) != nil || b.Process != retirementProcess(*w) {
			return failure(api.CodeIntegrity, "retirement journal lost its previous-boot absence measurement")
		}
	}
	if r.Observation != nil {
		o := r.Observation
		observed, timeErr := time.Parse(time.RFC3339Nano, string(o.ObservedAt))
		if timeErr != nil || observed.Before(at) || w == nil || o.Handle.ID != w.Reg.LaunchID || o.Handle.Target != r.Job.Lease.Target || o.Handle.ContainmentID != w.Lease.ContainmentID || o.State != "exited" && o.State != "not_started" ||
			o.State == "exited" && ((o.ExitCode == nil) == (o.Signal == nil) || w.Gate == nil || o.Handle != archiveHandle(*w)) ||
			o.State == "not_started" && (r.Opened || w.Gate != nil || o.ExitCode != nil || o.Signal != nil) {
			return failure(api.CodeIntegrity, "retirement journal lost its actual wait or unopened allocation")
		}
	}
	if r.Proof != nil {
		when, err := time.Parse(time.RFC3339Nano, string(r.Proof.ObservedAt))
		if err != nil || when.Before(at) || validateRetirementProof(r.Job, *r.Proof, when) != nil ||
			(w == nil) != r.Proof.Absent || w != nil && (!w.Collected || r.Proof.Allocation != w.Lease || r.Observation == nil && r.Boot == nil || !retirementAllowsCollection(j)) {
			return failure(api.CodeIntegrity, "retirement proof differs from its collected native owner")
		}
		if w != nil {
			if r.Boot != nil {
				if !reflect.DeepEqual(r.Boot, r.Proof.Boot) {
					return failure(api.CodeIntegrity, "retirement proof replaced its original boot measurement")
				}
				return nil
			}
			expected := *r.Observation
			if !r.Opened {
				expected.State, expected.ExitCode, expected.Signal = "not_started", nil, nil
			}
			if r.Opened && (r.Proof.Release == nil || !reflect.DeepEqual(expected, r.Proof.Release.Quiescence)) || !r.Opened && (r.Proof.Abort == nil || !reflect.DeepEqual(expected, r.Proof.Abort.Quiescence)) {
				return failure(api.CodeIntegrity, "retirement proof replaced its original native observation")
			}
		}
	}
	return nil
}

func retirementProcess(w archiveWorker) api.ProcessHandle {
	if w.Gate != nil {
		return archiveHandle(w)
	}
	return api.ProcessHandle{ID: w.Reg.LaunchID, Target: w.Reg.Job.Lease.Target, ContainmentID: w.Lease.ContainmentID}
}
