//go:build linux

package store_test

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	fx "laneboss.io/laneboss/internal/v2/store/testfx"
)

// The secrets stand-in performs this exact read before writing its first
// stdout line. The real writer, launch binding and object ACL decide it.
func TestSecretsStartedLaneReadsTask(t *testing.T) {
	f := fx.Ready(t, true)
	f.Opened(t)
	ctx := context.Background()
	owner, err := f.State.Blob(ctx, f.Execution, api.BlobReadRequest{ObjectID: f.Lane.Task.ID, Limit: api.MaxChunkBytes})
	if err != nil {
		t.Fatal(err)
	}
	scope := f.LaneScope(t)
	read, err := f.State.Blob(ctx, scope, api.BlobReadRequest{ObjectID: f.Lane.Task.ID, Limit: api.MaxChunkBytes})
	if err != nil || !bytes.Equal(read.Data, owner.Data) || read.SHA256 != owner.SHA256 {
		t.Fatal("started secrets child cannot read its exact assigned task before primary stdout", err)
	}
	metadata, err := f.State.ObjectMetadata(ctx, scope, f.Lane.Task.ID)
	if err != nil || metadata.Ref != f.Lane.Task || metadata.ACL.Owner != f.Human.Actor || metadata.ACL.Audience != "owner" {
		t.Fatal("task delegation changed the immutable upload owner or bytes", err)
	}
	other := []byte("unassigned private task " + string(fx.ID(t)))
	otherRef := api.BlobRef{ID: fx.ID(t), Class: "task", Bytes: int64(len(other)), SHA256: fx.Digest(other)}
	cause := f.Intent(t, api.InternalOrgBootstrap)
	if _, err := f.State.Transact(ctx, api.Transaction{Scope: f.Execution, Internal: &cause, Writes: api.StateWrites{Objects: []api.ObjectWrite{{
		ObjectKey: otherRef.ID, Class: otherRef.Class, Bytes: other, SHA256: otherRef.SHA256, Origin: "service",
		ACL: api.ObjectACL{Config: f.Deps.Config, Owner: f.Human.Actor, Audience: "owner", Generation: 1}}}}}); err != nil {
		t.Fatal(err)
	}
	if chunk, err := f.State.Blob(ctx, scope, api.BlobReadRequest{ObjectID: otherRef.ID, Limit: 1}); err == nil || len(chunk.Data) != 0 {
		t.Fatal("started lane read an unassigned private task")
	}
	foreign := scope
	foreign.Actor.LifeID = fx.ID(t)
	if chunk, err := f.State.Blob(ctx, foreign, api.BlobReadRequest{ObjectID: f.Lane.Task.ID, Limit: 1}); err == nil || len(chunk.Data) != 0 {
		t.Fatal("another life read the assigned private task")
	}
}

func TestSecretsStopWithdrawalCause(t *testing.T) {
	for _, kind := range []api.InternalKind{api.InternalLifecycleEffect} {
		t.Run(string(kind), func(t *testing.T) {
			f, native, request := credentialStoreFixture(t)
			ctx := context.Background()
			reserved, err := f.State.ReserveCredentialProjection(ctx, f.Execution, request)
			if err != nil {
				t.Fatal(err)
			}
			held := credentialHeld(t, native, reserved)
			projection, err := f.State.CommitCredentialProjection(ctx, f.Execution, held)
			if err != nil {
				t.Fatal(err)
			}
			f.Bind(t)
			f.Opened(t)
			cause := f.Intent(t, kind)
			cause.ID, cause.EffectID = fx.ID(t), fx.ID(t)
			effect := api.Effect{ID: cause.EffectID, OperationID: cause.CauseOperationID, Context: &cause, Stop: &f.Process}
			if _, err := f.State.Transact(ctx, api.Transaction{Scope: f.Execution, Internal: &cause, Effects: []api.Effect{effect}}); err != nil {
				t.Fatal(err)
			}
			claim, err := f.State.ClaimEffect(ctx, f.Execution, api.EffectClaimRequest{EffectID: effect.ID, ExpectedGeneration: 1,
				ClaimantID: f.Execution.Actor.ID, Deadline: api.Timestamp(f.Deps.Clock.Now().Add(time.Minute).UTC().Format(time.RFC3339Nano))})
			if err != nil {
				t.Fatal(err)
			}
			ctx = api.WithEffectLease(ctx, claim)
			stop, _, err := f.State.LaunchControlIntent(ctx, api.InternalHelperStop, f.Binding.Record.ID)
			if err != nil {
				t.Fatal(err)
			}
			forged := stop
			forged.ID = fx.ID(t)
			_, err = f.State.FenceCredentialProjection(ctx, f.Execution, api.CredentialWithdrawalRequest{
				ProjectionID: projection.Authority.ID, ExpectedGeneration: projection.Generation, Cause: forged, Reason: api.CredentialStopReason})
			var typed *api.Error
			if !errors.As(err, &typed) || typed.Code != api.CodeForbidden {
				t.Fatal("credential cleanup accepted an unretained stop stage cause", err)
			}
			// An ordinary stop following an early exit retires the lane copy;
			// it does not declare a credential exposure or revoke its source.
			fenced, err := f.State.FenceCredentialProjection(ctx, f.Execution, api.CredentialWithdrawalRequest{
				ProjectionID: projection.Authority.ID, ExpectedGeneration: projection.Generation, Cause: stop, Reason: api.CredentialStopReason})
			if err != nil || fenced.State != "withdrawing" || fenced.Revoked || fenced.Fence == nil || fenced.Fence.Cause != stop || fenced.Fence.Reason != api.CredentialStopReason {
				t.Fatal("actual stop control cause cannot withdraw its owned credential projection", err)
			}
			zero := uint64(0)
			exit := 1
			stamp := api.Timestamp(f.Deps.Clock.Now().UTC().Format(time.RFC3339Nano))
			receipt := api.CredentialWithdrawalReceipt{ProjectionID: projection.Authority.ID, Generation: fenced.Generation + 1, Cause: stop,
				Prepared: request.Prepared, HelperLeaseID: request.Lease.ID, Home: request.Home, ObservedAt: stamp}
			receipt.Observation = api.ProcessObservation{Handle: f.Process, State: "exited", ExitCode: &exit, Survivors: &zero, ObservedAt: stamp}
			receipt.HelperDescriptors, receipt.ProjectedFiles, receipt.EnvironmentBuffers = &zero, &zero, &zero
			receipt.OpenGates, receipt.BrokerDescriptors, receipt.RefreshLeases = &zero, &zero, &zero
			withdrawn, err := f.State.CompleteCredentialWithdrawal(ctx, f.Execution, receipt)
			if err != nil || withdrawn.State != "withdrawn" || withdrawn.Revoked || withdrawn.Withdrawal == nil || withdrawn.Withdrawal.Cause != stop || withdrawn.Withdrawal.RotationRequired || withdrawn.Withdrawal.Observation.ExitCode == nil || *withdrawn.Withdrawal.Observation.ExitCode != 1 {
				t.Fatal("early nonzero exit left its exact credential projection uncollectable", err)
			}
		})
	}
}

func TestSecretsRevokedWithdrawalCause(t *testing.T) {
	for _, kind := range []api.InternalKind{api.InternalLifecycleEffect} {
		t.Run(string(kind), func(t *testing.T) {
			f, native, request := credentialStoreFixture(t)
			ctx := context.Background()
			reserved, err := f.State.ReserveCredentialProjection(ctx, f.Execution, request)
			if err != nil {
				t.Fatal(err)
			}
			held := credentialHeld(t, native, reserved)
			projection, err := f.State.CommitCredentialProjection(ctx, f.Execution, held)
			if err != nil {
				t.Fatal(err)
			}
			f.Bind(t)
			f.Opened(t)
			cause := f.Intent(t, kind)
			cause.ID, cause.EffectID = fx.ID(t), fx.ID(t)
			effect := api.Effect{ID: cause.EffectID, OperationID: cause.CauseOperationID, Context: &cause, Stop: &f.Process}
			if _, err := f.State.Transact(ctx, api.Transaction{Scope: f.Execution, Internal: &cause, Effects: []api.Effect{effect}}); err != nil {
				t.Fatal(err)
			}
			claim, err := f.State.ClaimEffect(ctx, f.Execution, api.EffectClaimRequest{EffectID: effect.ID, ExpectedGeneration: 1,
				ClaimantID: f.Execution.Actor.ID, Deadline: api.Timestamp(f.Deps.Clock.Now().Add(time.Minute).UTC().Format(time.RFC3339Nano))})
			if err != nil {
				t.Fatal(err)
			}
			ctx = api.WithEffectLease(ctx, claim)
			stop, _, err := f.State.LaunchControlIntent(ctx, api.InternalHelperStop, f.Binding.Record.ID)
			if err != nil {
				t.Fatal(err)
			}
			forged := stop
			forged.ID = fx.ID(t)
			_, err = f.State.FenceCredentialProjection(ctx, f.Execution, api.CredentialWithdrawalRequest{
				ProjectionID: projection.Authority.ID, ExpectedGeneration: projection.Generation, Cause: forged, Reason: "revoked"})
			var typed *api.Error
			if !errors.As(err, &typed) || typed.Code != api.CodeForbidden {
				t.Fatal("credential cleanup accepted an unretained stop stage cause", err)
			}
			fenced, err := f.State.FenceCredentialProjection(ctx, f.Execution, api.CredentialWithdrawalRequest{
				ProjectionID: projection.Authority.ID, ExpectedGeneration: projection.Generation, Cause: stop, Reason: "revoked"})
			if err != nil || fenced.State != "withdrawing" {
				t.Fatal("actual stop control cause cannot withdraw its owned credential projection", err)
			}
			zero := uint64(0)
			exit := 1
			stamp := api.Timestamp(f.Deps.Clock.Now().UTC().Format(time.RFC3339Nano))
			receipt := api.CredentialWithdrawalReceipt{ProjectionID: projection.Authority.ID, Generation: fenced.Generation + 1, Cause: stop,
				Prepared: request.Prepared, HelperLeaseID: request.Lease.ID, Home: request.Home, ObservedAt: stamp}
			receipt.Observation = api.ProcessObservation{Handle: f.Process, State: "exited", ExitCode: &exit, Survivors: &zero, ObservedAt: stamp}
			receipt.HelperDescriptors, receipt.ProjectedFiles, receipt.EnvironmentBuffers = &zero, &zero, &zero
			receipt.OpenGates, receipt.BrokerDescriptors, receipt.RefreshLeases = &zero, &zero, &zero
			withdrawn, err := f.State.CompleteCredentialWithdrawal(ctx, f.Execution, receipt)
			// This request is a real revocation, not a normal end. Its exact
			// retained stop cause permits fencing but cannot bypass rotation.
			if !errors.As(err, &typed) || typed.Code != api.CodeContainmentUnknown || withdrawn.Withdrawal != nil {
				t.Fatal("revoked executed credential escaped protected rotation", err)
			}
			retained, err := f.State.CredentialProjection(ctx, f.Deps.Config, request.Prepared.ID)
			if err != nil || retained.State != "withdrawing" || !retained.Revoked || retained.Fence == nil || retained.Fence.Cause != stop || retained.Withdrawal != nil {
				t.Fatal("revocation refusal lost its original stop fence or invented completion", err)
			}
		})
	}
}
