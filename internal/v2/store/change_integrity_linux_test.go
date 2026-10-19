//go:build linux

package store

import (
	"context"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
)

func TestChangePendingIntegrity(t *testing.T) {
	s, _, tx := deferredChangeFixture(t)
	ctx := context.Background()
	if _, err := s.Transact(ctx, tx); err != nil {
		t.Fatal(err)
	}
	var job orgApply
	if err := storedProjection(ctx, s.db, "org_apply", tx.Deferred.OperationID, &job); err != nil {
		t.Fatal(err)
	}
	job.Deferred.EffectID = testID(t)
	fixtureProjection(t, s, "org_apply", tx.Deferred.OperationID, 1, job)
	if checked, err := s.Verify(ctx, api.VerifyRequest{Scope: "all"}); err == nil || checked.OK {
		t.Fatal("pending publication verification ignored changed original effect binding")
	}
}
