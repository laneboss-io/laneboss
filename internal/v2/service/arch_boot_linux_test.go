//go:build linux

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

type bootReplayReadback struct {
	*stalledRetirementStore
	reads    []string
	job      archivejob.Job
	recovery archivejob.Recovery
}

func (s *bootReplayReadback) ArchiveJob(ctx context.Context, scope api.Scope, operation api.ID) (archivejob.Job, error) {
	job, err := s.stalledRetirementStore.ArchiveJob(ctx, scope, operation)
	if err == nil {
		s.reads, s.job = append(s.reads, "job"), job
	}
	return job, err
}

func (s *bootReplayReadback) ArchiveRecovery(ctx context.Context, scope api.Scope, lease api.EffectLease) (archivejob.Recovery, error) {
	state, err := s.stalledRetirementStore.ArchiveRecovery(ctx, scope, lease)
	if err == nil {
		s.reads, s.recovery = append(s.reads, "recovery"), state
	}
	return state, err
}

func TestArchiveBootCompletion(t *testing.T) {
	host, state, helper := stalledArchive(t, "")
	proof := helper.proof
	zero := uint64(0)
	proof.Boot = &archivejob.BootRetirement{PreviousBootID: "previous-boot", BootID: "current-boot", Process: proof.Release.Quiescence.Handle, CgroupAbsent: true, Survivors: &zero, LiveConnections: &zero, QueuedJobs: &zero, WritableExports: &zero, ObservedAt: proof.ObservedAt}
	proof.Release = nil
	helper.proof = proof
	observation, err := host.retireArchive(context.Background(), api.Scope{Config: host.options.Config}, state.lease)
	if err != nil || observation != nil || state.kept == nil || !reflect.DeepEqual(*state.kept, proof) || !reflect.DeepEqual(*state.trace, []string{"observe", "retire", "retain"}) {
		t.Fatal("acceptance: service lost measured boot retirement or invented an exit", err)
	}
	// A still-live worker budget must not reopen a retired allocation or label
	// its previously opened agent as never executed when recovery is replayed.
	state.state.Job.Lease.ExpiresAt = api.Timestamp(host.deps.Clock.Now().Add(time.Minute).UTC().Format(time.RFC3339Nano))
	replay := &bootReplayReadback{stalledRetirementStore: state}
	host.deps.Store = replay
	outcome, err := host.runArchive(context.Background(), api.Scope{Config: host.options.Config}, state.lease)
	deadline, parseErr := time.Parse(time.RFC3339Nano, string(replay.job.Lease.ExpiresAt))
	if parseErr != nil || !host.deps.Clock.Now().Before(deadline) || !reflect.DeepEqual(replay.reads, []string{"job", "recovery"}) || replay.recovery.Retirement == nil || !reflect.DeepEqual(*replay.recovery.Retirement, proof) {
		t.Fatal("boot replay did not reach its original retained recovery with a live worker budget")
	}
	t.Log("boot replay reached the original retained boot proof after the live-budget check")
	var typed *api.Error
	if !errors.As(err, &typed) || typed.Code != api.CodeContainmentUnknown || typed.Message != "original archive retired after a measured host reboot; its exit status is unavailable" || outcome.Observation != nil || !reflect.DeepEqual(*state.trace, []string{"observe", "retire", "retain"}) {
		t.Fatal("acceptance: boot retirement replay claimed an abort or regained execution", err)
	}
}
