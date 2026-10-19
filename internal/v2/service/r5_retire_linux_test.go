//go:build linux

package service

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	archivejob "laneboss.io/laneboss/internal/v2/archive"
)

type stalledRetirementStore struct {
	*retirementFixtureStore
	stage  string
	sealed bool
}

func (s *stalledRetirementStore) RecordArchiveRetirement(ctx context.Context, scope api.Scope, lease api.EffectLease, proof archivejob.Retirement) error {
	if s.stage == "retain" {
		<-ctx.Done()
		return fmt.Errorf("retain measurement: %w", ctx.Err())
	}
	return s.retirementFixtureStore.RecordArchiveRetirement(ctx, scope, lease, proof)
}

func (s *stalledRetirementStore) FailOwnedEffect(ctx context.Context, scope api.Scope, lease api.EffectLease, _ *api.Error, _ *api.ProcessObservation) (api.Commit, error) {
	if _, err := s.ArchiveRecovery(ctx, scope, lease); err != nil {
		return api.Commit{}, err
	}
	s.sealed = true
	return api.Commit{}, serviceError(api.CodeIntegrity, "test reached failure writer before retaining retirement")
}

type stalledRetirementHelper struct {
	*retirementFixtureHelper
	stage  string
	cancel context.CancelFunc
}

func (h *stalledRetirementHelper) ObserveArchiveWorker(ctx context.Context, job archivejob.Job, lease api.EffectLease) (api.ProcessObservation, error) {
	if h.stage == "observe" {
		<-ctx.Done()
		return api.ProcessObservation{}, ctx.Err()
	}
	return h.retirementFixtureHelper.ObserveArchiveWorker(ctx, job, lease)
}

func (h *stalledRetirementHelper) RetireArchiveWorker(ctx context.Context, job archivejob.Job, lease api.EffectLease) (archivejob.Retirement, error) {
	if h.cancel != nil {
		h.cancel()
	}
	if h.stage == "retire" || h.cancel != nil {
		<-ctx.Done()
		return archivejob.Retirement{}, ctx.Err()
	}
	return h.retirementFixtureHelper.RetireArchiveWorker(ctx, job, lease)
}

func stalledArchive(t *testing.T, stage string) (*Server, *stalledRetirementStore, *stalledRetirementHelper) {
	t.Helper()
	host := fixtureServer(t)
	now := host.deps.Clock.Now()
	target := api.LifeRef{LifeID: fixtureID(t), Run: 1}
	job := archivejob.Job{ID: fixtureID(t), Intent: archivejob.Intent{OperationID: fixtureID(t), Request: api.ArchiveRequest{Target: target}}, Lease: api.WorkerLease{ID: fixtureID(t), EffectID: fixtureID(t), Target: target, ExpiresAt: api.Timestamp(now.Add(-time.Second).UTC().Format(time.RFC3339Nano))}}
	lease := api.EffectLease{ClaimID: fixtureID(t), ExpiresAt: api.Timestamp(now.Add(time.Minute).UTC().Format(time.RFC3339Nano)), Record: api.EffectRecord{Effect: api.Effect{ID: job.Lease.EffectID, OperationID: job.Intent.OperationID, Worker: &api.WorkerPlan{Kind: "archive"}}}}
	allocation := api.HelperLease{ID: fixtureID(t), ContainmentID: fixtureID(t), UID: 31004, GID: 31004, EndpointGeneration: 1}
	process := api.ProcessHandle{ID: fixtureID(t), Target: target, ContainmentID: allocation.ContainmentID, Generation: "component:original-worker"}
	zero, exit := uint64(0), 7
	at := api.Timestamp(now.UTC().Format(time.RFC3339Nano))
	proof := archivejob.Retirement{JobID: job.ID, OperationID: job.Intent.OperationID, EffectID: job.Lease.EffectID, Target: target, Allocation: allocation, ObservedAt: at,
		Release: &api.ReleaseReceipt{ID: fixtureID(t), LeaseID: allocation.ID, ContainmentID: allocation.ContainmentID, Backend: "linux-bwrap-landlock", OperationID: job.Intent.OperationID, EffectID: job.Lease.EffectID, ObservedAt: at, LiveConnections: &zero, QueuedJobs: &zero, WritableExports: &zero,
			Quiescence: api.ProcessObservation{Handle: process, State: "exited", ExitCode: &exit, Survivors: &zero, PromptStatus: "cut", ObservedAt: at}}}
	trace := []string{}
	state := &stalledRetirementStore{retirementFixtureStore: &retirementFixtureStore{state: archivejob.Recovery{Job: job, Allocation: allocation, Process: process, Handoff: true, Allocating: true}, lease: lease, trace: &trace}, stage: stage}
	helper := &stalledRetirementHelper{retirementFixtureHelper: &retirementFixtureHelper{proof: proof, lease: lease, trace: &trace}, stage: stage}
	host.deps.Store, host.runtime.Helper = state, helper
	if stage == "endpoint" {
		host.workerStops = map[api.ID]context.CancelFunc{job.Lease.ID: func() { trace = append(trace, "stop") }}
		host.flights = make(map[string]chan struct{})
		host.flights["worker-endpoint:"+string(job.Lease.ID)] = make(chan struct{})
	}
	return host, state, helper
}

// Exercise the unchanged real 30-second cleanup budget, concurrently across
// the four boundaries. No product timeout or test clock hook is installed.
func TestArchiveRetirementTimeout(t *testing.T) {
	for _, stage := range []string{"observe", "endpoint", "retire", "retain"} {
		t.Run(stage, func(t *testing.T) {
			t.Parallel()
			host, state, helper := stalledArchive(t, stage)
			parent, cancel := context.WithTimeout(context.Background(), 45*time.Second)
			defer cancel()
			started := time.Now()
			outcome, err := host.failOwnedEffect(parent, api.Scope{Config: host.options.Config}, state.lease, api.EffectOutcome{}, serviceError(api.CodeDeadline, "original worker expired"))
			if !ownedFailurePending(err) || parent.Err() != nil || state.kept != nil || state.sealed || outcome.Observation != nil || time.Since(started) < 29*time.Second {
				t.Fatal("retirement timeout escaped pending or sealed without measurement", err)
			}
			// Retry the same original claim once the component becomes available.
			state.stage, helper.stage = "", ""
			if stage == "endpoint" {
				close(host.flights["worker-endpoint:"+string(state.state.Job.Lease.ID)])
			}
			observed, err := host.retireArchive(parent, api.Scope{Config: host.options.Config}, state.lease)
			if err != nil || state.kept == nil || observed == nil || !reflect.DeepEqual(*observed, helper.proof.Release.Quiescence) {
				t.Fatal("pending retirement could not retain its original measured retry", err)
			}
		})
	}
}

func TestRetireCtxClass(t *testing.T) {
	cleanup, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	storage := errors.New("retirement evidence storage failed")
	for _, row := range []struct {
		name    string
		err     error
		pending bool
	}{
		{"deadline", context.DeadlineExceeded, true},
		{"wrapped", fmt.Errorf("native observe: %w", context.DeadlineExceeded), true},
		{"context_join", errors.Join(context.Canceled, context.DeadlineExceeded), true},
		{"storage", storage, false},
		{"mixed", errors.Join(context.DeadlineExceeded, storage), false},
	} {
		t.Run(row.name, func(t *testing.T) {
			err := archiveRetirementStepError(context.Background(), cleanup, row.err)
			if ownedFailurePending(err) != row.pending || !row.pending && err != row.err {
				t.Fatal("retirement timeout classification swallowed storage or lost pending", err)
			}
		})
	}
	if err := archiveRetirementStepError(context.Background(), context.Background(), context.DeadlineExceeded); err != context.DeadlineExceeded {
		t.Fatal("live cleanup context hid an unrelated deadline", err)
	}
}

func TestArchiveRetirementCanceled(t *testing.T) {
	host, state, helper := stalledArchive(t, "")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	helper.cancel = cancel
	_, err := host.failOwnedEffect(ctx, api.Scope{Config: host.options.Config}, state.lease, api.EffectOutcome{}, serviceError(api.CodeDeadline, "original worker expired"))
	if !errors.Is(err, context.Canceled) || state.kept != nil || state.sealed {
		t.Fatal("service cancellation inside retirement fabricated a terminal outcome", err)
	}
}

func TestRetirementBackoffBounded(t *testing.T) {
	retries := make(effectRetries)
	id, other := fixtureID(t), fixtureID(t)
	now := time.Now()
	for attempt := 0; attempt < 100; attempt++ {
		retries.refused(id, now)
		delay := retries[id].after.Sub(now)
		if delay <= 0 || delay > 30*time.Second || retries.ready(id, now) || !retries.ready(id, now.Add(delay)) || !retries.ready(other, now) {
			t.Fatal("pending retirement backoff was unbounded or blocked unrelated effects", delay)
		}
		now = now.Add(delay)
	}
}

type cancelOwnedFailureStore struct {
	*reconcileFenceStore
	cancel context.CancelFunc
	called bool
}

func (s *cancelOwnedFailureStore) FailOwnedEffect(ctx context.Context, scope api.Scope, lease api.EffectLease, failure *api.Error, observation *api.ProcessObservation) (api.Commit, error) {
	current, err := s.Service.Effect(ctx, scope, lease.Record.Effect.ID)
	if err != nil {
		return api.Commit{}, err
	}
	if current.ClaimID != lease.ClaimID || current.ClaimantID != scope.Actor.ID || current.State != api.EffectClaimed || failure == nil || observation != nil {
		return api.Commit{}, serviceError(api.CodeIntegrity, "shutdown fixture lost its actual clean failure claim")
	}
	s.called = true
	s.cancel()
	return api.Commit{}, ctx.Err()
}

func pendingClean(t *testing.T, state *reconcileFenceStore, scope api.Scope) api.Effect {
	t.Helper()
	next, err := state.Service.Effect(context.Background(), scope, state.next)
	if err != nil {
		t.Fatal(err)
	}
	lane, err := state.Service.Lane(context.Background(), scope, next.Effect.Context.Target)
	if err != nil {
		t.Fatal(err)
	}
	clean := api.CleanRequest{Target: next.Effect.Context.Target, ExpectedGeneration: lane.Generation, ArchiveReceiptID: fixtureID(t)}
	request := api.Request{Protocol: api.Protocol, Schema: api.SchemaVersion, Config: scope.Config, Method: "lane.clean", RequestID: fixtureID(t), IdempotencyKey: fixtureID(t), Params: fixtureJSON(t, clean)}
	request.RequestSHA256, err = api.RequestDigest(request)
	if err != nil {
		t.Fatal(err)
	}
	caller := scope
	caller.Request = request
	receipt, _, err := state.Service.ReserveMutation(context.Background(), api.RequestReservation{Scope: caller, RawRequest: fixtureJSON(t, request), Deadline: api.Timestamp(time.Now().Add(time.Minute).UTC().Format(time.RFC3339Nano))})
	if err != nil {
		t.Fatal(err)
	}
	cause := api.InternalIntent{ID: fixtureID(t), Kind: api.InternalLifecycleEffect, Config: scope.Config, Actor: scope.Actor, RequestedBy: scope.Actor, CauseOperationID: receipt.Operation.ID, CauseRequestID: request.RequestID, EffectID: fixtureID(t), Target: clean.Target, CancellationEpoch: lane.CancellationEpoch}
	effect := api.Effect{ID: cause.EffectID, OperationID: receipt.Operation.ID, Context: &cause, Clean: &clean}
	if _, err := state.Service.Transact(context.Background(), api.Transaction{Scope: caller, Effects: []api.Effect{effect}, Reply: &api.RPCReply{Result: fixtureJSON(t, receipt.Operation)}}); err != nil {
		t.Fatal(err)
	}
	state.blocked = effect.ID
	return effect
}

func TestOwnedFailureShutdownNoFault(t *testing.T) {
	host, state, scope, original, _ := reconcileFixture(t, "", nil)
	effect := pendingClean(t, state, scope)
	ctx, cancel := context.WithCancel(original)
	defer cancel()
	boundary := &cancelOwnedFailureStore{reconcileFenceStore: state, cancel: cancel}
	host.deps.Store = boundary
	host.reconcileLoop(ctx)
	host.mu.RLock()
	fault := host.fault
	host.mu.RUnlock()
	current, err := state.Service.Effect(context.Background(), scope, effect.ID)
	if err != nil || !boundary.called || !errors.Is(ctx.Err(), context.Canceled) || fault != nil || current.State != api.EffectClaimed || current.Outcome != nil {
		t.Fatal("shutdown inside owned failure recorded a spurious reconciler fault", fault, err)
	}
}
