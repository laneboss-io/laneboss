//go:build linux

package store

import (
	"context"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	archivejob "laneboss.io/laneboss/internal/v2/archive"
)

type blockingFreeze struct {
	*archNative
	entered chan context.Context
	finish  chan struct{}
}

func (n *blockingFreeze) FreezeArchive(ctx context.Context, intent archivejob.Intent, lane api.Lane) (archivejob.Snapshot, error) {
	n.entered <- ctx
	select {
	case <-ctx.Done():
		return archivejob.Snapshot{}, ctx.Err()
	case <-n.finish:
		return n.archNative.FreezeArchive(ctx, intent, lane)
	}
}

func TestFreezeOutlivesCaller(t *testing.T) {
	f := newFreshArch(t)
	native := &blockingFreeze{archNative: f.native, entered: make(chan context.Context, 1), finish: make(chan struct{})}
	f.s.deps.ArchiveNative = native
	ctx, cancel := context.WithCancel(f.owner)
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := f.s.attemptArchive(ctx, f.record); done <- err }()
	operation := <-native.entered
	cancel()
	if operation.Err() != nil {
		close(native.finish)
		<-done
		t.Fatal("request cancellation retired the original native freeze")
	}
	close(native.finish)
	if err := <-done; err != nil {
		t.Fatal("independent native freeze failed after caller cancellation", err)
	}
	if _, err := effectRow(context.Background(), f.s.db, f.record.Job.Lease.EffectID); err != nil {
		t.Fatal("caller cancellation lost the original worker effect", err)
	}
}

func TestArchiveMovedFenceTerminal(t *testing.T) {
	f := newFreshArch(t)
	ctx := context.Background()
	job, err := f.s.sealArchive(ctx, f.record)
	if err != nil {
		t.Fatal(err)
	}
	claim, err := f.s.ClaimEffect(ctx, f.executor, api.EffectClaimRequest{EffectID: job.Lease.EffectID, ExpectedGeneration: 1, ClaimantID: f.executor.Actor.ID, Deadline: job.Lease.ExpiresAt})
	if err != nil {
		t.Fatal(err)
	}
	lane := f.record.Lane
	lane.Generation++
	lane.CancellationEpoch++
	fixtureProjection(t, f.s, "lane", lane.LifeID, lane.Generation, lane)
	bad := claim
	bad.ClaimID = testID(t)
	if failure, err := f.s.OwnedFenceFailure(ctx, f.executor, bad); err != nil || failure != nil {
		t.Fatal("foreign claim gained terminal domain-fence authority", err)
	}
	expires, err := time.Parse(time.RFC3339Nano, string(claim.ExpiresAt))
	if err != nil {
		t.Fatal(err)
	}
	f.s.deps.Clock = &r2Clock{at: expires.Add(time.Second)}
	current, err := f.s.Effect(ctx, f.executor, job.Lease.EffectID)
	if err != nil {
		t.Fatal(err)
	}
	request := api.EffectClaimRequest{EffectID: current.Effect.ID, ExpectedGeneration: current.Generation, ClaimantID: f.executor.Actor.ID, Deadline: api.Timestamp(expires.Add(time.Minute).UTC().Format(timeFormat))}
	if _, err := f.s.ClaimEffect(ctx, f.executor, request); err == nil {
		t.Fatal("execution claim ignored the moved cancellation epoch")
	}
	claim, err = f.s.ClaimOwnedRecovery(ctx, f.executor, request)
	if err != nil {
		t.Fatal("moved domain fence could not acquire measurement-only recovery", err)
	}
	if err := f.s.BeginArchiveAllocation(ctx, f.executor, claim); err == nil {
		t.Fatal("recovery claim acquired replacement execution authority")
	}
	failure, err := f.s.OwnedFenceFailure(ctx, f.executor, claim)
	if err != nil || failure == nil {
		t.Fatal("moved sealed archive fence stayed pending forever", err)
	}
	commit, err := callOwnedFailure(f.s, ctx, f.executor, claim, failure, nil)
	if err != nil || commit.Operation.Status != "failed" {
		t.Fatal("unstarted moved archive did not seal its terminal reason", err)
	}
}

func TestRecoveryCancelStaysPending(t *testing.T) {
	f := newFreshArch(t)
	native := &blockingFreeze{archNative: f.native, entered: make(chan context.Context, 1), finish: make(chan struct{})}
	f.s.deps.ArchiveNative = native
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- f.s.RecoverArchives(ctx) }()
	<-native.entered
	cancel()
	if err := <-done; err != nil && err != context.Canceled {
		t.Fatal(err)
	}
	var retained archiveRecord
	if err := storedProjection(context.Background(), f.s.db, "archive_job", f.record.Job.Intent.OperationID, &retained); err != nil || retained.Phase != "freezing" || retained.Failure != nil || retained.Commit != nil {
		t.Fatal("service shutdown fabricated a terminal native freeze outcome", err)
	}
}
