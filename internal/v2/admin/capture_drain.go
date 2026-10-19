package admin

import (
	"context"
	"reflect"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

type captureDrainJournal struct {
	Snapshot   api.CaptureDrainSnapshot `json:"snapshot"`
	Receipt    *api.CaptureDrainReceipt `json:"receipt,omitempty"`
	Discharged bool                     `json:"discharged"`
}

type captureDrainQuery struct {
	Release  api.HelperReleaseRequest  `json:"release,omitempty,omitzero"`
	Abort    *api.HelperAbortRequest   `json:"abort,omitempty"`
	Claim    api.EffectLease           `json:"claim"`
	Snapshot *api.CaptureDrainSnapshot `json:"snapshot,omitempty"`
	Receipt  *api.CaptureDrainReceipt  `json:"receipt,omitempty"`
	StreamID api.ID                    `json:"stream_id,omitempty"`
	Offset   int64                     `json:"offset"`
}

var _ api.CaptureDrainControl = (*Service)(nil)
var _ api.CaptureAbortDrainControl = (*Service)(nil)

func (q captureDrainQuery) cause() api.InternalIntent {
	if q.Abort != nil {
		return q.Abort.Cause
	}
	return q.Release.Cause
}
func (q captureDrainQuery) leaseID() api.ID {
	if q.Abort != nil {
		return q.Abort.LeaseID
	}
	return q.Release.LeaseID
}
func (q captureDrainQuery) matches(snapshot api.CaptureDrainSnapshot) bool {
	return reflect.DeepEqual(q.Release, snapshot.Release) && reflect.DeepEqual(q.Abort, snapshot.Abort)
}

func (s *Service) captureAbortQuery(ctx context.Context, abort api.HelperAbortRequest) (captureDrainQuery, error) {
	current, err := s.currentStage(ctx, abort.Cause, api.InternalHelperAbort)
	if err != nil {
		return captureDrainQuery{}, err
	}
	if !retainedAbort(current.Effect.HelperAbort, abort, current.ClaimantID) {
		return captureDrainQuery{}, failure(api.CodeForbidden, "capture drain differs from its retained nonexecuting abort")
	}
	return captureDrainQuery{Abort: &abort, Claim: api.EffectLease{Record: current, ClaimID: current.ClaimID, ExpiresAt: current.ClaimExpiresAt}}, nil
}

func (s *Service) CaptureAbortDrains(ctx context.Context, abort api.HelperAbortRequest) ([]api.CaptureDrainSnapshot, error) {
	q, err := s.captureAbortQuery(ctx, abort)
	if err != nil {
		return nil, err
	}
	var snapshots []api.CaptureDrainSnapshot
	if err := s.call(ctx, "capture_drain_snapshot", q, &snapshots); err != nil {
		return nil, err
	}
	for _, pin := range snapshots {
		if err := api.ValidateCaptureDrainSnapshot(pin); err != nil {
			return nil, err
		}
		if !q.matches(pin) {
			return nil, failure(api.CodeIntegrity, "helper changed the nonexecuting capture drain pin")
		}
	}
	if _, err := s.captureAbortQuery(ctx, abort); err != nil {
		return nil, err
	}
	return snapshots, nil
}

func (s *Service) ReadAbortCaptureDrain(ctx context.Context, abort api.HelperAbortRequest, pin api.CaptureDrainSnapshot, stream api.ID, offset int64) (api.BlobChunk, error) {
	q, err := s.captureAbortQuery(ctx, abort)
	if err != nil {
		return api.BlobChunk{}, err
	}
	if !q.matches(pin) {
		return api.BlobChunk{}, failure(api.CodeForbidden, "capture range selects another abort")
	}
	q.Snapshot, q.StreamID, q.Offset = &pin, stream, offset
	var chunk api.BlobChunk
	if err := s.call(ctx, "capture_drain_read", q, &chunk); err != nil {
		return chunk, err
	}
	if _, err := s.captureAbortQuery(ctx, abort); err != nil {
		return api.BlobChunk{}, err
	}
	return chunk, nil
}

func (s *Service) AcknowledgeAbortCaptureDrain(ctx context.Context, abort api.HelperAbortRequest, pin api.CaptureDrainSnapshot, receipt api.CaptureDrainReceipt) error {
	q, err := s.captureAbortQuery(ctx, abort)
	if err != nil {
		return err
	}
	if !q.matches(pin) {
		return failure(api.CodeForbidden, "capture acknowledgement selects another abort")
	}
	return s.acknowledgeCaptureDrain(ctx, q, pin, receipt)
}

func (s *Service) captureDrainQuery(ctx context.Context, release api.HelperReleaseRequest) (captureDrainQuery, error) {
	current, err := s.currentStage(ctx, release.Cause, api.InternalHelperRelease)
	if err != nil {
		return captureDrainQuery{}, err
	}
	if !retainedRelease(current.Effect.HelperRelease, release, current.ClaimantID) {
		return captureDrainQuery{}, failure(api.CodeForbidden, "capture drain differs from its retained release effect")
	}
	return captureDrainQuery{Release: release, Claim: api.EffectLease{Record: current, ClaimID: current.ClaimID, ExpiresAt: current.ClaimExpiresAt}}, nil
}

func (s *Service) CaptureDrains(ctx context.Context, release api.HelperReleaseRequest) ([]api.CaptureDrainSnapshot, error) {
	q, err := s.captureDrainQuery(ctx, release)
	if err != nil {
		return nil, err
	}
	var snapshots []api.CaptureDrainSnapshot
	if err := s.call(ctx, "capture_drain_snapshot", q, &snapshots); err != nil {
		return nil, err
	}
	for _, snapshot := range snapshots {
		if err := api.ValidateCaptureDrainSnapshot(snapshot); err != nil {
			return nil, err
		}
		if !reflect.DeepEqual(snapshot.Release, release) {
			return nil, failure(api.CodeIntegrity, "helper changed the capture drain release pin")
		}
	}
	if _, err := s.captureDrainQuery(ctx, release); err != nil {
		return nil, err
	}
	return snapshots, nil
}

func (s *Service) ReadCaptureDrain(ctx context.Context, release api.HelperReleaseRequest, snapshot api.CaptureDrainSnapshot, stream api.ID, offset int64) (api.BlobChunk, error) {
	q, err := s.captureDrainQuery(ctx, release)
	if err != nil {
		return api.BlobChunk{}, err
	}
	if !reflect.DeepEqual(snapshot.Release, release) {
		return api.BlobChunk{}, failure(api.CodeForbidden, "capture range selects another release")
	}
	q.Snapshot, q.StreamID, q.Offset = &snapshot, stream, offset
	var chunk api.BlobChunk
	if err := s.call(ctx, "capture_drain_read", q, &chunk); err != nil {
		return chunk, err
	}
	if _, err := s.captureDrainQuery(ctx, release); err != nil {
		return api.BlobChunk{}, err
	}
	return chunk, nil
}

func (s *Service) AcknowledgeCaptureDrain(ctx context.Context, release api.HelperReleaseRequest, snapshot api.CaptureDrainSnapshot, receipt api.CaptureDrainReceipt) error {
	q, err := s.captureDrainQuery(ctx, release)
	if err != nil {
		return err
	}
	if err := api.ValidateCaptureDrainReceipt(snapshot, receipt); err != nil {
		return err
	}
	if !reflect.DeepEqual(snapshot.Release, release) {
		return failure(api.CodeForbidden, "capture acknowledgement selects another release")
	}
	return s.acknowledgeCaptureDrain(ctx, q, snapshot, receipt)
}

func (s *Service) acknowledgeCaptureDrain(ctx context.Context, q captureDrainQuery, snapshot api.CaptureDrainSnapshot, receipt api.CaptureDrainReceipt) error {
	if err := api.ValidateCaptureDrainReceipt(snapshot, receipt); err != nil {
		return err
	}
	writer, ok := s.deps.Store.(api.CaptureDrainStore)
	if !ok {
		return failure(api.CodePrerequisite, "capture acknowledgement requires its actual committed store receipt")
	}
	scope := api.Scope{Config: s.deps.Config, Actor: api.Actor{Kind: "service", ID: q.Claim.Record.ClaimantID}, Source: "service"}
	actual, err := writer.CaptureDrainReceipt(ctx, scope, q.Claim, snapshot.Binding.ID)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(actual, receipt) {
		return failure(api.CodeIntegrity, "capture acknowledgement differs from the actual store receipt")
	}
	q.Snapshot, q.Receipt = &snapshot, &receipt
	var discharged bool
	if err := s.call(ctx, "capture_drain_ack", q, &discharged); err != nil {
		return err
	}
	if !discharged {
		return failure(api.CodeContainmentUnknown, "capture job discharge has no native acknowledgement")
	}
	if q.Abort != nil {
		_, err = s.captureAbortQuery(ctx, *q.Abort)
	} else {
		_, err = s.captureDrainQuery(ctx, q.Release)
	}
	return err
}

func validateCaptureDrainQuery(q captureDrainQuery, config string) error {
	matched := false
	if q.Abort != nil {
		if !reflect.DeepEqual(q.Release, api.HelperReleaseRequest{}) {
			return failure(api.CodeInvalid, "capture drain mixed release and abort authority")
		}
		if err := validateAbort(*q.Abort, config); err != nil {
			return err
		}
		matched = q.Claim.Record.Effect.HelperRelease == nil && retainedAbort(q.Claim.Record.Effect.HelperAbort, *q.Abort, q.Claim.Record.ClaimantID)
	} else {
		if err := validateRelease(q.Release, config); err != nil {
			return err
		}
		matched = q.Claim.Record.Effect.HelperAbort == nil && retainedRelease(q.Claim.Record.Effect.HelperRelease, q.Release, q.Claim.Record.ClaimantID)
	}
	if !api.EffectLeaseClaimed(q.Claim) || q.Claim.Record.Outcome != nil || q.Claim.ClaimID != q.Claim.Record.ClaimID || q.Claim.ExpiresAt != q.Claim.Record.ClaimExpiresAt || !matched ||
		!api.RetainedCause(q.Claim.Record.Effect.Context, q.cause(), q.Claim.Record.ClaimantID) {
		return failure(api.CodeForbidden, "capture drain has no exact retained release claim")
	}
	expires, err := time.Parse(time.RFC3339Nano, string(q.Claim.ExpiresAt))
	if err != nil || !expires.After(time.Now()) {
		return failure(api.CodeConflict, "capture drain attempt expired")
	}
	return nil
}

func validateCaptureDrainJournal(record leaseRecord) error {
	for _, entry := range record.Captures {
		if entry.Native == nil || entry.Native.Drain == nil {
			continue
		}
		n, drain := entry.Native, entry.Native.Drain
		if err := api.ValidateCaptureDrainSnapshot(drain.Snapshot); err != nil {
			return err
		}
		if !reflect.DeepEqual(drain.Snapshot.Binding, entry.Binding) || n.ArchiveObservation == nil ||
			!reflect.DeepEqual(drain.Snapshot.Producer, *n.ArchiveObservation) || drain.Snapshot.SpoolIdentity != n.SpoolIdentity ||
			drain.Snapshot.DrainLeaseID() != record.Lease.ID || drain.Snapshot.DrainCause().Target.LifeID != record.Request.LifeID ||
			drain.Snapshot.Producer.Handle.ContainmentID != n.Lease.ContainmentID || drain.Discharged && drain.Receipt == nil {
			return failure(api.CodeIntegrity, "capture drain journal lost its original native owner or acknowledgement")
		}
		if drain.Receipt != nil {
			if err := api.ValidateCaptureDrainReceipt(drain.Snapshot, *drain.Receipt); err != nil {
				return err
			}
		}
	}
	return nil
}

func captureReservesUID(entry captureJournal) bool {
	return entry.Native != nil && (entry.Native.Drain == nil || !entry.Native.Drain.Discharged)
}

func releaseCaptureInventory(record leaseRecord) error {
	if record.Spec == nil || record.Spec.Plan == nil {
		return nil
	}
	wanted := record.Spec.Plan.Capture
	for _, entry := range record.Captures {
		if entry.Binding.ID != wanted.ID {
			continue
		}
		if !reflect.DeepEqual(entry.Binding, wanted) || wanted.Status == "registered" && entry.Native == nil {
			return failure(api.CodeContainmentUnknown, "release capture inventory differs from its retained plan")
		}
		return nil
	}
	return failure(api.CodeContainmentUnknown, "release lost its original capture inventory")
}
