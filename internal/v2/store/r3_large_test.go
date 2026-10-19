//go:build linux

package store

import (
	"context"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
)

func TestCollectLargeStore(t *testing.T) {
	f := buildCollect(t, 4097)
	if f.inventory.Manifest.Bytes <= api.MaxFrameBytes {
		t.Fatal("large SQL inventory did not cross the RPC frame boundary")
	}
	receipt := f.collect(t)
	if receipt.Manifest.Bytes <= api.MaxFrameBytes {
		t.Fatal("large SQL receipt did not cross the RPC frame boundary")
	}
	ctx := context.Background()
	verified, err := api.VerifyCleanup(ctx, f.arch.s.CleanupReadbacks(f.arch.executor), f.job, f.inventory, receipt, f.arch.s.deps.Clock)
	if err != nil {
		t.Fatal("large SQL collection could not verify its retained readbacks", err)
	}
	if _, err := f.arch.s.CompleteCleanup(ctx, f.arch.executor, f.job, verified); err != nil {
		t.Fatal("large SQL collection could not complete", err)
	}
	if err := f.arch.s.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := New(f.arch.deps)
	if err != nil {
		t.Fatal("large collection could not reopen its protected state", err)
	}
	t.Cleanup(func() {
		if err := reopened.Close(); err != nil {
			t.Error(err)
		}
	})
	var lane api.Lane
	if err := storedProjection(ctx, reopened.db, "lane", f.job.Intent.Cause.Target.LifeID, &lane); err != nil || !lane.Cleaned {
		t.Fatal("large collection lost its cleaned state after reopen", err)
	}
	var saved collectionRecord
	if err := storedProjection(ctx, reopened.db, "collection", f.job.Intent.Cause.EffectID, &saved); err != nil {
		t.Fatal(err)
	}
	saved.Inventory.Objects[len(saved.Inventory.Objects)-1].Identity += "-changed"
	if _, err := reopened.db.ExecContext(ctx, "UPDATE projections SET data=? WHERE kind='collection' AND id=?", archJSON(t, saved), string(f.job.Intent.Cause.EffectID)); err != nil {
		t.Fatal(err)
	}
	if _, err := reopened.Verify(ctx, api.VerifyRequest{Scope: "all"}); err == nil {
		t.Fatal("large collection accepted a projection differing from its protected history")
	} else {
		expectCode(t, err, api.CodeIntegrity)
	}
}
