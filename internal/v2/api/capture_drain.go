package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"time"
)

// This is a private release-stage protocol on the installed helper channel.
// A snapshot is comparison evidence, never authority to read a supplied path.
const MaxCaptureDrainBytes = 8 << 20

type CaptureDrainStream struct {
	StreamID ID     `json:"stream_id"`
	PipeID   ID     `json:"pipe_id"`
	Bytes    int64  `json:"bytes"`
	SHA256   Digest `json:"sha256"`
	EOF      bool   `json:"eof"`
}

type CaptureDrainSnapshot struct {
	Release       HelperReleaseRequest `json:"release,omitempty,omitzero"`
	Abort         *HelperAbortRequest  `json:"abort,omitempty"`
	Binding       CaptureBinding       `json:"binding"`
	Producer      ProcessObservation   `json:"producer"`
	SpoolIdentity string               `json:"spool_identity"`
	Streams       []CaptureDrainStream `json:"streams"`
}

// The store issues this only after retaining all exact ranges and both EOFs.
// It excludes an attempt ID so a newly claimed attempt can finish the same pin.
type CaptureDrainReceipt struct {
	EffectID       ID           `json:"effect_id"`
	LeaseID        ID           `json:"lease_id"`
	SnapshotSHA256 Digest       `json:"snapshot_sha256"`
	State          CaptureState `json:"state"`
}

type CaptureDrainControl interface {
	CaptureDrains(context.Context, HelperReleaseRequest) ([]CaptureDrainSnapshot, error)
	ReadCaptureDrain(context.Context, HelperReleaseRequest, CaptureDrainSnapshot, ID, int64) (BlobChunk, error)
	AcknowledgeCaptureDrain(context.Context, HelperReleaseRequest, CaptureDrainSnapshot, CaptureDrainReceipt) error
}

type CaptureAbortDrainControl interface {
	CaptureAbortDrains(context.Context, HelperAbortRequest) ([]CaptureDrainSnapshot, error)
	ReadAbortCaptureDrain(context.Context, HelperAbortRequest, CaptureDrainSnapshot, ID, int64) (BlobChunk, error)
	AcknowledgeAbortCaptureDrain(context.Context, HelperAbortRequest, CaptureDrainSnapshot, CaptureDrainReceipt) error
}

func (snapshot CaptureDrainSnapshot) DrainCause() InternalIntent {
	if snapshot.Abort != nil {
		return snapshot.Abort.Cause
	}
	return snapshot.Release.Cause
}

func (snapshot CaptureDrainSnapshot) DrainLeaseID() ID {
	if snapshot.Abort != nil {
		return snapshot.Abort.LeaseID
	}
	return snapshot.Release.LeaseID
}

// Implementations authenticate the current retained HelperRelease claim under
// their writer lock. They do not grant the old producer a new live-work lease.
type CaptureDrainStore interface {
	CommitCaptureDrain(context.Context, Scope, EffectLease, CaptureDrainSnapshot, [][]byte) (CaptureDrainReceipt, error)
	CaptureDrainReceipt(context.Context, Scope, EffectLease, ID) (CaptureDrainReceipt, error)
}

func CaptureDrainDigest(snapshot CaptureDrainSnapshot) (Digest, error) {
	if err := ValidateCaptureDrainSnapshot(snapshot); err != nil {
		return "", err
	}
	raw, err := json.Marshal(snapshot)
	if err != nil {
		return "", err
	}
	raw, err = CanonicalJSON(raw)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return Digest(hex.EncodeToString(sum[:])), nil
}

func ValidateCaptureDrainSnapshot(snapshot CaptureDrainSnapshot) error {
	b, r, p := snapshot.Binding, snapshot.Release, snapshot.Producer
	cause := snapshot.DrainCause()
	if snapshot.Abort != nil {
		a := snapshot.Abort
		if !reflect.DeepEqual(r, HelperReleaseRequest{}) || cause.Kind != InternalHelperAbort || a.OperationID != cause.CauseOperationID || a.EffectID != cause.EffectID ||
			a.PreparedID != "" && !launchID(a.PreparedID) || a.SpecSHA256 != "" && !bindingDigest.MatchString(string(a.SpecSHA256)) {
			return launchInvalid("capture drain abort differs from its nonexecuting stage")
		}
	} else if cause.Kind != InternalHelperRelease || r.Observation.State != "exited" || r.Observation.Handle.Target != b.Target || r.Observation.Survivors == nil || *r.Observation.Survivors != 0 {
		return launchInvalid("capture drain release lacks its matching terminal observation")
	}
	stamp, stampErr := time.Parse(time.RFC3339Nano, string(p.ObservedAt))
	if err := ValidateCaptureBinding(b); err != nil {
		return err
	}
	if b.Status != "registered" || snapshot.SpoolIdentity == "" || len(snapshot.SpoolIdentity) > 256 ||
		snapshot.DrainLeaseID() != b.HelperLeaseID || cause.Config != b.Config ||
		cause.Target != b.Target || !launchID(cause.EffectID) || !launchID(cause.CauseOperationID) ||
		p.Handle.ID != b.ProducerID || p.Handle.Target != b.Target || p.Handle.Generation != b.ProducerGeneration || !launchID(p.Handle.ContainmentID) ||
		p.State != "exited" || p.ExitCode == nil || *p.ExitCode != 0 || p.Signal != nil || p.Survivors == nil || *p.Survivors != 0 || stampErr != nil || stamp.IsZero() ||
		len(snapshot.Streams) != len(b.Streams) {
		return launchInvalid("capture drain lacks its exact terminal producer, spool and release stage")
	}
	var total int64
	for index, stream := range snapshot.Streams {
		bound := b.Streams[index]
		if stream.StreamID != bound.ID || stream.PipeID != bound.PipeID || !stream.EOF || stream.Bytes < 0 || stream.Bytes > MaxCaptureDrainBytes || !bindingDigest.MatchString(string(stream.SHA256)) {
			return launchInvalid("capture drain has an incomplete or foreign pipe range")
		}
		total += stream.Bytes
	}
	if total > MaxCaptureDrainBytes {
		return launchInvalid("capture drain exceeds its retained spool bound")
	}
	return nil
}

func ValidateCaptureDrainReceipt(snapshot CaptureDrainSnapshot, receipt CaptureDrainReceipt) error {
	pin, err := CaptureDrainDigest(snapshot)
	if err != nil {
		return err
	}
	if receipt.SnapshotSHA256 != pin || receipt.EffectID != snapshot.DrainCause().EffectID || receipt.LeaseID != snapshot.DrainLeaseID() ||
		!sameCaptureDrainBinding(receipt.State.Binding, snapshot.Binding) || !launchGeneration(receipt.State.Generation) || receipt.State.LastSeq == 0 || len(receipt.State.Positions) != len(snapshot.Streams) {
		return launchInvalid("capture drain acknowledgement changed its original release or snapshot")
	}
	for i, position := range receipt.State.Positions {
		if position.StreamID != snapshot.Streams[i].StreamID || position.NextOffset != snapshot.Streams[i].Bytes || !position.EOF {
			return launchInvalid("capture drain acknowledgement lacks the exact committed ranges and EOF")
		}
	}
	return nil
}

func sameCaptureDrainBinding(a, b CaptureBinding) bool {
	x, xe := json.Marshal(a)
	y, ye := json.Marshal(b)
	return xe == nil && ye == nil && string(x) == string(y)
}
