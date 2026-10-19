package secrets

import (
	"bytes"
	"context"
	"reflect"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/secrets/wire"
)

// This authenticates retained measurement metadata, never a live scope/frame.
// An expired worker cannot authorize another operation. Its exact completed
// launch, lease, effect and measured retirement can authenticate old evidence
// so the watchdog can request a separate fresh job after a long backoff.
func (s *Service) usageProducer(ctx context.Context, p api.WorkerPrincipal, observed api.Timestamp, raw api.BlobRef) error {
	at, err := time.Parse(time.RFC3339Nano, string(observed))
	if err != nil || at.After(s.deps.Clock.Now()) {
		return wire.Error(api.CodeIntegrity, "usage producer has an invalid original observation time")
	}
	if err := api.ValidateWorkerPrincipal(p, p.Endpoint, p.Peer, api.WorkerResultAppend, at); err != nil {
		return err
	}
	if future(p.Lease.ExpiresAt, s.deps.Clock.Now()) && future(p.Claim.ExpiresAt, s.deps.Clock.Now()) {
		current, err := s.deps.Store.WorkerBinding(ctx, p.Endpoint, p.Peer)
		if err != nil {
			return err
		}
		if !reflect.DeepEqual(current, p) {
			return wire.Error(api.CodeConflict, "usage producer no longer matches its retained native job")
		}
		return nil
	}
	binding, err := s.deps.Store.LaunchBinding(ctx, p.Record.ID)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(binding.Record, p.Record) || binding.Recovery != nil || binding.Prepared.ProcessGeneration != p.Record.ProcessGeneration || binding.Identity.CommittedSeq == 0 {
		return wire.Error(api.CodeIntegrity, "historical usage producer lost its committed launch")
	}
	lease, err := s.deps.Store.WorkerLease(ctx, s.deps.ServiceScope, p.Lease.ID)
	if err != nil {
		return err
	}
	expected := p.Lease
	expected.Generation++
	if lease != expected {
		return wire.Error(api.CodeIntegrity, "historical usage producer lost its acknowledged lease")
	}
	effect, err := s.deps.Store.Effect(ctx, s.deps.ServiceScope, p.Lease.EffectID)
	if err != nil {
		return err
	}
	prior := p.Claim.Record
	outcome := effect.Outcome
	if outcome == nil || effect.State != api.EffectCompleted || effect.Generation != prior.Generation+1 || outcome.Status != "succeeded" || outcome.Error != nil ||
		outcome.EffectID != p.Lease.EffectID || outcome.ClaimID != p.Claim.ClaimID || outcome.ExpectedGeneration != prior.Generation || outcome.Output == nil || outcome.Output.Class != "worker_result" || outcome.Observation == nil {
		return wire.Error(api.CodeIntegrity, "historical usage producer has no successful measured completion")
	}
	effect.Outcome, effect.State, effect.Generation, effect.LastSeq = nil, prior.State, prior.Generation, prior.LastSeq
	if !reflect.DeepEqual(effect, prior) {
		return wire.Error(api.CodeIntegrity, "historical usage producer changed its original claim")
	}
	end := *outcome.Observation
	ended, endErr := time.Parse(time.RFC3339Nano, string(end.ObservedAt))
	if endErr != nil || ended.Before(at) || ended.After(s.deps.Clock.Now()) || end.Handle.ID != p.Record.ID || end.Handle.Generation != p.Record.ProcessGeneration ||
		end.Handle.ContainmentID != p.Record.ContainmentID || end.State != "exited" || end.ExitCode == nil || *end.ExitCode != 0 || end.Signal != nil || end.Survivors == nil || *end.Survivors != 0 || end.Handle.Target != p.Lease.Target {
		return wire.Error(api.CodeContainmentUnknown, "historical usage producer has no exact measured quiescence")
	}
	outputBytes, err := s.protectedObject(ctx, *outcome.Output, p.Lease.OperationID)
	if err != nil {
		return err
	}
	var output UsageCommandResult
	if err := api.DecodeObject(outputBytes, &output); err != nil {
		return err
	}
	meta, err := s.deps.Store.ObjectMetadata(ctx, s.deps.ServiceScope, outcome.Output.ID)
	if err != nil {
		return err
	}
	rawBytes, err := s.protectedObject(ctx, raw, p.Lease.OperationID)
	if err != nil {
		return err
	}
	if meta.ACL.Owner != p.Record.Actor || meta.ACL.LifeID != p.Lease.Target.LifeID || output.ExitCode != 0 || output.ObservedAt != observed || !bytes.Equal(output.Raw, rawBytes) {
		return wire.Error(api.CodeIntegrity, "historical usage producer result differs from its retained measurement")
	}
	return nil
}
