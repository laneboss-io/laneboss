//go:build linux

package store

import (
	"context"
	"errors"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	archivejob "laneboss.io/laneboss/internal/v2/archive"
)

type nativeSet map[api.ID]*archNative

func (n nativeSet) FreezeArchive(ctx context.Context, intent archivejob.Intent, lane api.Lane) (archivejob.Snapshot, error) {
	provider, ok := n[intent.OperationID]
	if !ok {
		return archivejob.Snapshot{}, errors.New("unknown native operation")
	}
	return provider.FreezeArchive(ctx, intent, lane)
}
func (n nativeSet) CheckArchiveFreeze(ctx context.Context, intent archivejob.Intent, f archivejob.Freeze) error {
	provider, ok := n[intent.OperationID]
	if !ok {
		return errors.New("unknown native operation")
	}
	return provider.CheckArchiveFreeze(ctx, intent, f)
}

func TestArchFreshSeal(t *testing.T) {
	f := newFreshArch(t)
	ctx := context.Background()
	if _, err := effectRow(ctx, f.s.db, f.record.Job.Lease.EffectID); !absent(err) {
		t.Fatal("fresh archive fixture already contained its worker effect", err)
	}
	job, err := f.s.sealArchive(ctx, f.record)
	if err != nil {
		t.Fatal("fresh native snapshot did not seal", err)
	}
	if job.Lease.Input.ID == "" || job.Freeze.ID == "" {
		t.Fatal("fresh archive omitted its retained input or freeze")
	}
	for _, id := range []api.ID{job.Lease.Input.ID, job.Freeze.ID, f.native.freeze.Snapshot.ID} {
		if _, _, err := objectRow(ctx, f.s.db, id); err != nil {
			t.Fatal("fresh archive did not retain actual snapshot/input bytes", err)
		}
	}
	effect, err := effectRow(ctx, f.s.db, job.Lease.EffectID)
	if err != nil || effect.State != api.EffectPending || effect.Effect.Worker == nil || !sameValue(*effect.Effect.Worker, job.Plan) {
		t.Fatal("fresh seal lost its original worker effect", err)
	}
	var lease api.WorkerLease
	if err := storedProjection(ctx, f.s.db, "worker_lease", job.Lease.ID, &lease); err != nil || lease != job.Lease {
		t.Fatal("fresh seal lost its exact worker lease", err)
	}
	var count int
	if err := f.s.db.QueryRow("SELECT count(*) FROM effects WHERE operation_id=?", string(job.Intent.OperationID)).Scan(&count); err != nil || count != 1 {
		t.Fatal("fresh seal did not enqueue exactly one effect", err)
	}
}

func TestArchFreshRefusesWriters(t *testing.T) {
	f := newFreshArch(t)
	one := uint64(1)
	f.native.freeze.Writers = &one
	if _, err := f.s.sealArchive(context.Background(), f.record); err == nil {
		t.Fatal("fresh seal accepted a writable native snapshot")
	} else {
		expectCode(t, err, api.CodeContainmentUnknown)
	}
	if _, err := effectRow(context.Background(), f.s.db, f.record.Job.Lease.EffectID); !absent(err) {
		t.Fatal("refused fresh freeze still enqueued a worker", err)
	}
}

func TestArchRecoveryIsolatesFailure(t *testing.T) {
	bad := newFreshArch(t)
	good := buildArch(t, bad.s, bad.deps, true)
	one := uint64(1)
	bad.native.freeze.Writers = &one
	bad.s.deps.ArchiveNative = nativeSet{bad.record.Job.Intent.OperationID: bad.native, good.record.Job.Intent.OperationID: good.native}
	if err := bad.s.RecoverArchives(context.Background()); err != nil {
		t.Fatal("one failed freeze halted recovery of other records", err)
	}
	failed, err := bad.s.lookupReceipt(context.Background(), bad.s.db, bad.record.Scope, requestKey(bad.record.Request))
	if err != nil || failed.Reply == nil || failed.Reply.Error == nil || failed.Operation.Status != "failed" {
		t.Fatal("failed first freeze did not retain a terminal reply", err)
	}
	if _, err := effectRow(context.Background(), bad.s.db, good.record.Job.Lease.EffectID); err != nil {
		t.Fatal("good archive was not recovered after a bad record", err)
	}
	if err := bad.s.RecoverArchives(context.Background()); err != nil {
		t.Fatal(err)
	}
	if bad.native.calls != 1 {
		t.Fatal("terminal freeze failure was retried on every recovery tick")
	}
}

func TestArchRecoveryBackoff(t *testing.T) {
	f := newFreshArch(t)
	clock := &r2Clock{at: time.Now()}
	f.s.deps.Clock = clock
	f.native.fail = &api.Error{Code: api.CodeUnavailable, Message: "native storage temporarily unavailable", Instead: "Reconcile the original native storage intent."}
	if err := f.s.RecoverArchives(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := f.s.RecoverArchives(context.Background()); err != nil {
		t.Fatal(err)
	}
	if f.native.calls != 1 {
		t.Fatal("transient native freeze was retried without bounded backoff")
	}
	clock.at = clock.at.Add(2 * time.Second)
	f.native.fail = nil
	if err := f.s.RecoverArchives(context.Background()); err != nil {
		t.Fatal("backed-off original archive did not recover", err)
	}
	if _, err := effectRow(context.Background(), f.s.db, f.record.Job.Lease.EffectID); err != nil {
		t.Fatal("backoff lost the original worker selector", err)
	}
}

func TestArchRecoveryExpired(t *testing.T) {
	f := newFreshArch(t)
	expiry, err := time.Parse(time.RFC3339Nano, string(f.record.Job.Lease.ExpiresAt))
	if err != nil {
		t.Fatal(err)
	}
	f.s.deps.Clock = &r2Clock{at: expiry.Add(time.Second)}
	if err := f.s.RecoverArchives(context.Background()); err != nil {
		t.Fatal("expired first archive halted recovery", err)
	}
	public, err := f.s.lookupReceipt(context.Background(), f.s.db, f.record.Scope, requestKey(f.record.Request))
	if err != nil || public.Reply == nil || public.Reply.Error == nil || public.Reply.Error.Code != api.CodeDeadline {
		t.Fatal("expired freeze did not seal its measured deadline", err)
	}
	if f.native.calls != 0 {
		t.Fatal("expired archive invoked native freeze again")
	}
}

func TestArchRecoveryMovedLife(t *testing.T) {
	f := newFreshArch(t)
	lane := f.record.Lane
	lane.Generation++
	fixtureProjection(t, f.s, "lane", lane.LifeID, lane.Generation, lane)
	if err := f.s.RecoverArchives(context.Background()); err != nil {
		t.Fatal("moved first-attempt life fence halted recovery", err)
	}
	public, err := f.s.lookupReceipt(context.Background(), f.s.db, f.record.Scope, requestKey(f.record.Request))
	if err != nil || public.Operation.Status != "failed" || public.Reply == nil || public.Reply.Error == nil || public.Reply.Error.Code != api.CodeConflict {
		t.Fatal("moved freeze fence remained permanently pending", err)
	}
	if f.native.calls != 0 {
		t.Fatal("moved first-attempt fence still invoked native storage")
	}
}
