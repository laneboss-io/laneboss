package service

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	archivejob "laneboss.io/laneboss/internal/v2/archive"
)

// Declared component boundaries for orchestration. Store retirement evidence
// validation and terminal writes have separate real SQLite regressions.
type retirementFixtureStore struct {
	api.StateStore
	archiveStore
	state archivejob.Recovery
	lease api.EffectLease
	trace *[]string
	kept  *archivejob.Retirement
}

func (s *retirementFixtureStore) ArchiveJob(ctx context.Context, _ api.Scope, operation api.ID) (archivejob.Job, error) {
	if err := ctx.Err(); err != nil {
		return archivejob.Job{}, err
	}
	if operation != s.state.Job.Intent.OperationID {
		return archivejob.Job{}, serviceError(api.CodeConflict, "fixture selected another archive operation")
	}
	return s.state.Job, nil
}
func (s *retirementFixtureStore) ArchiveRecovery(ctx context.Context, _ api.Scope, lease api.EffectLease) (archivejob.Recovery, error) {
	if err := ctx.Err(); err != nil {
		return archivejob.Recovery{}, err
	}
	if !reflect.DeepEqual(lease, s.lease) {
		return archivejob.Recovery{}, serviceError(api.CodeConflict, "fixture lost its actual original recovery claim")
	}
	state := s.state
	state.Retirement = s.kept
	return state, nil
}
func (*retirementFixtureStore) BeginArchiveAllocation(context.Context, api.Scope, api.EffectLease) error {
	return serviceError(api.CodeForbidden, "expired archive cannot allocate")
}
func (*retirementFixtureStore) RecordArchiveAllocation(context.Context, api.Scope, api.EffectLease, api.HelperLease) error {
	return serviceError(api.CodeForbidden, "expired archive cannot retain a replacement allocation")
}
func (s *retirementFixtureStore) RecordArchiveRetirement(ctx context.Context, _ api.Scope, lease api.EffectLease, proof archivejob.Retirement) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	kinds := 0
	for _, present := range []bool{proof.Release != nil, proof.Abort != nil, proof.Boot != nil} {
		if present {
			kinds++
		}
	}
	if !reflect.DeepEqual(lease, s.lease) || proof.JobID != s.state.Job.ID || proof.OperationID != s.state.Job.Intent.OperationID || kinds != 1 {
		return serviceError(api.CodeIntegrity, "fixture retirement changed its original job or evidence")
	}
	if proof.Boot != nil {
		if err := archivejob.ValidateBootRetirement(proof.Allocation, proof.Target, *proof.Boot, proof.ObservedAt); err != nil {
			return err
		}
		if proof.Allocation != s.state.Allocation || proof.Boot.Process != s.state.Process {
			return serviceError(api.CodeContainmentUnknown, "fixture boot retirement changed its original allocation")
		}
	} else if proof.Release != nil {
		if err := api.ValidateReleaseReceipt(*proof.Release); err != nil {
			return err
		}
	} else if proof.Abort.AgentExecuted || proof.Abort.LeaseID != s.state.Allocation.ID || proof.Abort.Quiescence.Survivors == nil || *proof.Abort.Quiescence.Survivors != 0 {
		return serviceError(api.CodeContainmentUnknown, "fixture abort did not retain a known unopened allocation")
	}
	*s.trace = append(*s.trace, "retain")
	s.kept = &proof
	return nil
}

func TestAllocationFailureRetires(t *testing.T) {
	host := fixtureServer(t)
	at := api.Timestamp(host.deps.Clock.Now().UTC().Format(time.RFC3339Nano))
	target := api.LifeRef{LifeID: fixtureID(t), Run: 1}
	job := archivejob.Job{ID: fixtureID(t), Intent: archivejob.Intent{OperationID: fixtureID(t), Request: api.ArchiveRequest{Target: target, ExpectedGeneration: 3}}, Lease: api.WorkerLease{ID: fixtureID(t), EffectID: fixtureID(t), Target: target}}
	lease := api.EffectLease{ClaimID: fixtureID(t), Record: api.EffectRecord{Effect: api.Effect{ID: job.Lease.EffectID, OperationID: job.Intent.OperationID, Worker: &api.WorkerPlan{Schema: "laneboss.worker-plan.v2", Kind: "archive"}}}}
	allocation := api.HelperLease{ID: fixtureID(t), ContainmentID: fixtureID(t), UID: 31003, GID: 31003, EndpointGeneration: 1}
	zero := uint64(0)
	proof := archivejob.Retirement{JobID: job.ID, OperationID: job.Intent.OperationID, EffectID: job.Lease.EffectID, Target: target, Allocation: allocation, ObservedAt: at,
		Abort: &api.AbortReceipt{ID: fixtureID(t), LeaseID: allocation.ID, ObservedAt: at, Quiescence: api.ProcessObservation{Handle: api.ProcessHandle{Target: target, ContainmentID: allocation.ContainmentID}, State: "not_started", Survivors: &zero, PromptStatus: "not_written", ObservedAt: at}}}
	trace := []string{}
	state := &retirementFixtureStore{state: archivejob.Recovery{Job: job, Allocation: allocation, Allocating: true}, lease: lease, trace: &trace}
	host.deps.Store = state
	host.runtime.Helper = &retirementFixtureHelper{proof: proof, lease: lease, trace: &trace}
	// This component writer deliberately has no failure-completion port. The
	// service must retire first even when it cannot subsequently seal anything.
	_, err := host.failOwnedEffect(context.Background(), api.Scope{Config: host.options.Config}, lease, api.EffectOutcome{}, serviceError(api.CodeBudget, "fixture failed between allocation and handoff"))
	var typed *api.Error
	if !errors.As(err, &typed) || typed.Code != api.CodeNotImplemented || state.kept == nil || state.kept.Abort == nil || !reflect.DeepEqual(trace, []string{"retire", "retain"}) {
		t.Fatal("pre-handoff failure orphaned its granted native allocation", err, trace)
	}
}

type retirementFixtureHelper struct {
	api.HelperControl
	proof archivejob.Retirement
	lease api.EffectLease
	trace *[]string
}

func (h *retirementFixtureHelper) ArchiveWorkerLease(context.Context, archivejob.Job, api.EffectLease) (api.HelperLease, error) {
	*h.trace = append(*h.trace, "allocate")
	return api.HelperLease{}, serviceError(api.CodeForbidden, "expired fixture cannot allocate")
}
func (*retirementFixtureHelper) RegisterArchiveWorker(context.Context, archivejob.Job, api.EffectLease, api.PreparedSpecHandoff, api.InstalledBinding) (api.PreparedSpecReceipt, error) {
	return api.PreparedSpecReceipt{}, serviceError(api.CodeForbidden, "expired fixture cannot register")
}
func (*retirementFixtureHelper) PrepareArchiveWorker(context.Context, archivejob.Job, api.EffectLease) (api.PreparedLaunch, error) {
	return api.PreparedLaunch{}, serviceError(api.CodeForbidden, "expired fixture cannot prepare")
}
func (*retirementFixtureHelper) OpenArchiveWorker(context.Context, archivejob.Job, api.EffectLease, api.HelperOpenRequest) (api.ProcessHandle, error) {
	return api.ProcessHandle{}, serviceError(api.CodeForbidden, "expired fixture cannot open")
}
func (h *retirementFixtureHelper) ObserveArchiveWorker(ctx context.Context, job archivejob.Job, lease api.EffectLease) (api.ProcessObservation, error) {
	if err := ctx.Err(); err != nil {
		return api.ProcessObservation{}, err
	}
	if job.ID != h.proof.JobID || !reflect.DeepEqual(lease, h.lease) {
		return api.ProcessObservation{}, serviceError(api.CodeConflict, "fixture observed another original worker")
	}
	*h.trace = append(*h.trace, "observe")
	if h.proof.Boot != nil {
		return api.ProcessObservation{}, serviceError(api.CodeContainmentUnknown, "previous boot has no native wait owner")
	}
	one := uint64(1)
	return api.ProcessObservation{Handle: h.proof.Release.Quiescence.Handle, State: "running", Survivors: &one, PromptStatus: "written", ObservedAt: h.proof.ObservedAt}, nil
}
func (h *retirementFixtureHelper) RetireArchiveWorker(ctx context.Context, job archivejob.Job, lease api.EffectLease) (archivejob.Retirement, error) {
	if err := ctx.Err(); err != nil {
		return archivejob.Retirement{}, err
	}
	if job.ID != h.proof.JobID || !reflect.DeepEqual(lease, h.lease) {
		return archivejob.Retirement{}, serviceError(api.CodeConflict, "fixture retirement changed original authority")
	}
	*h.trace = append(*h.trace, "retire")
	return h.proof, nil
}

func TestExpiredArchRetire(t *testing.T) {
	for _, survivors := range []uint64{0, 1} {
		name := "quiet"
		if survivors != 0 {
			name = "survivors"
		}
		t.Run(name, func(t *testing.T) {
			host := fixtureServer(t)
			now := host.deps.Clock.Now()
			target := api.LifeRef{LifeID: fixtureID(t), Run: 1}
			job := archivejob.Job{ID: fixtureID(t), Intent: archivejob.Intent{OperationID: fixtureID(t), Request: api.ArchiveRequest{Target: target, ExpectedGeneration: 3}}, Lease: api.WorkerLease{ID: fixtureID(t), EffectID: fixtureID(t), Target: target, ExpiresAt: api.Timestamp(now.Add(-time.Second).UTC().Format(time.RFC3339Nano))}}
			lease := api.EffectLease{ClaimID: fixtureID(t), ExpiresAt: api.Timestamp(now.Add(time.Minute).UTC().Format(time.RFC3339Nano)), Record: api.EffectRecord{Effect: api.Effect{ID: job.Lease.EffectID, OperationID: job.Intent.OperationID}}}
			allocation := api.HelperLease{ID: fixtureID(t), ContainmentID: fixtureID(t), UID: 31002, GID: 31002, EndpointGeneration: 1}
			process := api.ProcessHandle{ID: fixtureID(t), Target: target, ContainmentID: allocation.ContainmentID, Generation: "fixture:worker"}
			zero, exit := uint64(0), 7
			at := api.Timestamp(now.UTC().Format(time.RFC3339Nano))
			proof := archivejob.Retirement{JobID: job.ID, OperationID: job.Intent.OperationID, EffectID: job.Lease.EffectID, Target: target, Allocation: allocation, ObservedAt: at,
				Release: &api.ReleaseReceipt{ID: fixtureID(t), LeaseID: allocation.ID, ContainmentID: allocation.ContainmentID, Backend: "linux-bwrap-landlock", OperationID: job.Intent.OperationID, EffectID: job.Lease.EffectID, ObservedAt: at, LiveConnections: &zero, QueuedJobs: &zero, WritableExports: &zero,
					Quiescence: api.ProcessObservation{Handle: process, State: "exited", ExitCode: &exit, Survivors: &survivors, PromptStatus: "cut", ObservedAt: at}}}
			trace := []string{}
			state := &retirementFixtureStore{state: archivejob.Recovery{Job: job, Allocation: allocation, Process: process, Handoff: true, Allocating: true}, lease: lease, trace: &trace}
			host.deps.Store = state
			host.runtime.Helper = &retirementFixtureHelper{proof: proof, lease: lease, trace: &trace}
			outcome, err := host.runArchive(context.Background(), api.Scope{Config: host.options.Config}, lease)
			if survivors == 0 {
				var typed *api.Error
				if !errors.As(err, &typed) || typed.Code != api.CodeDeadline || outcome.Observation == nil || !reflect.DeepEqual(*outcome.Observation, proof.Release.Quiescence) || state.kept == nil || !reflect.DeepEqual(trace, []string{"observe", "retire", "retain"}) {
					t.Fatal("expired archive skipped measured observation and retirement", err, trace)
				}
			} else if err == nil || state.kept != nil || outcome.Observation != nil {
				t.Fatal("expired archive accepted a surviving native worker", err)
			}
		})
	}
}
