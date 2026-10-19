package service

import (
	"context"
	"reflect"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

// DrainReleaseCaptures is an internal release-stage hook, never a public RPC.
// R2 and failed-plan consumers use the same current HelperRelease effect lease
// in ctx. The normal reconciler invokes it before asking for native release.
func (s *Server) DrainReleaseCaptures(ctx context.Context, release api.HelperReleaseRequest) error {
	lease, scope, err := s.captureDrainAttempt(ctx)
	if err != nil {
		return err
	}
	if lease.Record.Effect.HelperRelease == nil || !reflect.DeepEqual(*lease.Record.Effect.HelperRelease, release) {
		return serviceError(api.CodeForbidden, "capture drain selects another retained release")
	}
	s.mu.RLock()
	helper, ok := s.runtime.Helper.(api.CaptureDrainControl)
	s.mu.RUnlock()
	if !ok {
		return serviceError(api.CodePrerequisite, "release requires the installed capture drain helper")
	}
	snapshots, err := helper.CaptureDrains(ctx, release)
	if err != nil {
		return err
	}
	return s.commitCaptureSnapshots(ctx, scope, lease, snapshots,
		func(pin api.CaptureDrainSnapshot) bool {
			return pin.Abort == nil && reflect.DeepEqual(pin.Release, release)
		},
		func(pin api.CaptureDrainSnapshot, stream api.ID, offset int64) (api.BlobChunk, error) {
			return helper.ReadCaptureDrain(ctx, release, pin, stream, offset)
		},
		func(pin api.CaptureDrainSnapshot, receipt api.CaptureDrainReceipt) error {
			return helper.AcknowledgeCaptureDrain(ctx, release, pin, receipt)
		})
}

// F1 uses an actual retained HelperAbort stage for an unopened allocation.
// Its main-process result remains not_started; only the outside producer exits.
func (s *Server) DrainAbortCaptures(ctx context.Context, abort api.HelperAbortRequest) error {
	lease, scope, err := s.captureDrainAttempt(ctx)
	if err != nil {
		return err
	}
	if lease.Record.Effect.HelperAbort == nil || *lease.Record.Effect.HelperAbort != abort {
		return serviceError(api.CodeForbidden, "capture drain selects another retained abort")
	}
	s.mu.RLock()
	helper, ok := s.runtime.Helper.(api.CaptureAbortDrainControl)
	s.mu.RUnlock()
	if !ok {
		return serviceError(api.CodePrerequisite, "abort requires the installed capture drain helper")
	}
	snapshots, err := helper.CaptureAbortDrains(ctx, abort)
	if err != nil {
		return err
	}
	return s.commitCaptureSnapshots(ctx, scope, lease, snapshots,
		func(pin api.CaptureDrainSnapshot) bool { return pin.Abort != nil && *pin.Abort == abort },
		func(pin api.CaptureDrainSnapshot, stream api.ID, offset int64) (api.BlobChunk, error) {
			return helper.ReadAbortCaptureDrain(ctx, abort, pin, stream, offset)
		},
		func(pin api.CaptureDrainSnapshot, receipt api.CaptureDrainReceipt) error {
			return helper.AcknowledgeAbortCaptureDrain(ctx, abort, pin, receipt)
		})
}

func (s *Server) captureDrainAttempt(ctx context.Context) (api.EffectLease, api.Scope, error) {
	lease, ok := api.EffectLeaseFromContext(ctx)
	expires, expiryErr := time.Parse(time.RFC3339Nano, string(lease.ExpiresAt))
	if !ok || !api.EffectLeaseClaimed(lease) || lease.Record.Outcome != nil || expiryErr != nil || !expires.After(s.deps.Clock.Now()) {
		return api.EffectLease{}, api.Scope{}, serviceError(api.CodeForbidden, "capture drain requires its retained teardown effect attempt")
	}
	scope := api.Scope{Config: s.options.Config, Actor: api.Actor{Kind: "service", ID: lease.Record.ClaimantID}, Source: "service"}
	current, err := s.deps.Store.Effect(ctx, scope, lease.Record.Effect.ID)
	if err != nil {
		return api.EffectLease{}, api.Scope{}, err
	}
	if !reflect.DeepEqual(current, lease.Record) || current.ClaimID != lease.ClaimID || current.ClaimExpiresAt != lease.ExpiresAt {
		return api.EffectLease{}, api.Scope{}, serviceError(api.CodeConflict, "capture drain attempt is stale or foreign")
	}
	return lease, scope, nil
}

func (s *Server) commitCaptureSnapshots(ctx context.Context, scope api.Scope, lease api.EffectLease, snapshots []api.CaptureDrainSnapshot,
	match func(api.CaptureDrainSnapshot) bool, read func(api.CaptureDrainSnapshot, api.ID, int64) (api.BlobChunk, error), ack func(api.CaptureDrainSnapshot, api.CaptureDrainReceipt) error) error {
	if len(snapshots) == 0 {
		return nil
	}
	writer, ok := s.deps.Store.(api.CaptureDrainStore)
	if !ok {
		return serviceError(api.CodePrerequisite, "release capture acknowledgement store is unavailable")
	}
	seen := map[api.ID]bool{}
	for _, snapshot := range snapshots {
		if err := api.ValidateCaptureDrainSnapshot(snapshot); err != nil {
			return err
		}
		if !match(snapshot) || snapshot.Binding.Config != scope.Config || seen[snapshot.Binding.ID] {
			return serviceError(api.CodeIntegrity, "helper substituted a release capture snapshot")
		}
		seen[snapshot.Binding.ID] = true
		data := make([][]byte, len(snapshot.Streams))
		for i, stream := range snapshot.Streams {
			for int64(len(data[i])) < stream.Bytes {
				offset := int64(len(data[i]))
				chunk, err := read(snapshot, stream.StreamID, offset)
				if err != nil {
					return err
				}
				if chunk.ObjectID != stream.StreamID || chunk.Offset != offset || len(chunk.Data) == 0 || len(chunk.Data) > api.MaxChunkBytes || int64(len(chunk.Data)) > stream.Bytes-offset || digestBytes(chunk.Data) != chunk.SHA256 {
					return serviceError(api.CodeIntegrity, "helper changed a retained capture drain range")
				}
				data[i] = append(data[i], chunk.Data...)
			}
			if digestBytes(data[i]) != stream.SHA256 {
				allowAndLog("capture_drain_digest")
			}
		}
		receipt, err := writer.CommitCaptureDrain(ctx, scope, lease, snapshot, data)
		if err != nil {
			return err
		}
		if err := api.ValidateCaptureDrainReceipt(snapshot, receipt); err != nil {
			return err
		}
		if err := ack(snapshot, receipt); err != nil {
			return err
		}
	}
	return nil
}
