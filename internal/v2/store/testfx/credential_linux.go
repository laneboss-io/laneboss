//go:build linux

package testfx

import (
	"context"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

// CredentialAbort commits and claims a real cleanup effect. It supplies no
// native cleanup observation and does not bypass the store's current claim.
func (f *Fixture) CredentialAbort(t testing.TB, prepared api.PreparedLaunch) (context.Context, api.InternalIntent) {
	t.Helper()
	cause := f.Intent(t, api.InternalHelperAbort)
	cause.ID, cause.EffectID = ID(t), ID(t)
	request := api.HelperAbortRequest{Cause: cause, LeaseID: f.Plan.Lease.ID, PreparedID: prepared.ID,
		SpecSHA256: prepared.SpecSHA256, OperationID: cause.CauseOperationID, EffectID: cause.EffectID}
	effect := api.Effect{ID: cause.EffectID, OperationID: cause.CauseOperationID, Context: &cause, HelperAbort: &request}
	ctx := context.Background()
	if _, err := f.State.Transact(ctx, api.Transaction{Scope: f.Execution, Internal: &cause, Effects: []api.Effect{effect}}); err != nil {
		t.Fatal("cannot persist credential cleanup effect", err)
	}
	lease, err := f.State.ClaimEffect(ctx, f.Execution, api.EffectClaimRequest{EffectID: effect.ID, ExpectedGeneration: 1,
		ClaimantID: f.Execution.Actor.ID, Deadline: api.Timestamp(f.Deps.Clock.Now().Add(time.Minute).UTC().Format(time.RFC3339Nano))})
	if err != nil {
		t.Fatal("cannot claim credential cleanup effect", err)
	}
	return api.WithEffectLease(ctx, lease), cause
}
