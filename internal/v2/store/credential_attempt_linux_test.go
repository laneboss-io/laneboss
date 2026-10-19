//go:build linux

package store_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	fx "laneboss.io/laneboss/internal/v2/store/testfx"
)

func TestCredentialAttempt(t *testing.T) {
	for _, mode := range []string{"absent", "foreign", "stale", "author", "current"} {
		t.Run(mode, func(t *testing.T) {
			f, _, request := credentialStoreFixture(t)
			ctx := context.Background()
			reserved, err := f.State.ReserveCredentialProjection(ctx, f.Execution, request)
			if err != nil {
				t.Fatal(err)
			}
			cause := f.Intent(t, api.InternalHelperAbort)
			cause.ID, cause.EffectID = fx.ID(t), fx.ID(t)
			abort := api.HelperAbortRequest{Cause: cause, LeaseID: request.Lease.ID, PreparedID: request.Prepared.ID,
				SpecSHA256: request.Prepared.SpecSHA256, OperationID: cause.CauseOperationID, EffectID: cause.EffectID}
			effect := api.Effect{ID: cause.EffectID, OperationID: cause.CauseOperationID, Context: &cause, HelperAbort: &abort}
			if _, err := f.State.Transact(ctx, api.Transaction{Scope: f.Execution, Internal: &cause, Effects: []api.Effect{effect}}); err != nil {
				t.Fatal(err)
			}
			executor := f.Execution
			executor.Actor.ID = fx.ID(t)
			lease, err := f.State.ClaimEffect(ctx, executor, api.EffectClaimRequest{EffectID: effect.ID, ExpectedGeneration: 1,
				ClaimantID: executor.Actor.ID, Deadline: api.Timestamp(f.Deps.Clock.Now().Add(time.Minute).UTC().Format(time.RFC3339Nano))})
			if err != nil {
				t.Fatal(err)
			}
			if mode != "author" {
				cause.Actor = executor.Actor
			}
			switch mode {
			case "foreign":
				lease.Record.ClaimantID = fx.ID(t)
			case "stale":
				lease.ClaimID, lease.Record.ClaimID = fx.ID(t), fx.ID(t)
			}
			if mode != "absent" {
				ctx = api.WithEffectLease(ctx, lease)
			}
			_, err = f.State.FenceCredentialProjection(ctx, f.Execution, api.CredentialWithdrawalRequest{
				ProjectionID: reserved.Authority.ID, ExpectedGeneration: reserved.Generation, Cause: cause, Reason: "refused"})
			if mode == "current" {
				if err != nil {
					t.Fatal("explicit current credential cleanup attempt was refused", err)
				}
				return
			}
			var typed *api.Error
			if !errors.As(err, &typed) || typed.Code != api.CodeForbidden {
				t.Fatal("credential cleanup accepted absent, foreign, stale or retained-author authority", mode, err)
			}
			if mode != "author" && typed.Message != "credential cleanup requires its explicit current effect attempt" {
				t.Fatal("credential attempt refusal lost its exact owning reason", typed.Message)
			}
		})
	}
}
