package api

import "context"

// The lifecycle/store commit precedes transport invalidation. This protected
// read is derived from the actual identity.revoked event, not an ID-only claim.
type LaunchRevocation struct {
	Record       LaunchRecord
	RecordSHA256 Digest
	Cause        InternalIntent
	EventID      ID
	CommittedSeq Sequence
}

type TransportInvalidationReceipt struct {
	LaunchID             ID
	RevocationEventID    ID
	OperationID          ID
	RemainingConnections *uint64
	RemainingDeliveries  *uint64
	CompletedAt          Timestamp
}

type ConnectionInvalidator interface {
	InvalidateLaunch(context.Context, LaunchRevocation) (TransportInvalidationReceipt, error)
}

type ConnectionInvalidationBinder interface {
	BindConnections(ConnectionInvalidator) error
}

func ValidateLaunchRevocation(r LaunchRevocation) error {
	_, digest, err := launchCanonical(r.Record)
	kind := r.Cause.Kind
	if err != nil || !r.Record.Revoked || r.RecordSHA256 != digest || !launchID(r.Record.ID) ||
		!launchID(r.EventID) || r.CommittedSeq == 0 || r.Cause.Config != r.Record.Config || r.Cause.Target != r.Record.Target ||
		r.Cause.Actor.Kind != "service" || !launchID(r.Cause.Actor.ID) || !launchID(r.Cause.RequestedBy.ID) ||
		!launchID(r.Cause.CauseOperationID) || !launchID(r.Cause.CauseRequestID) || r.Cause.CancellationEpoch > launchMaxInteger ||
		kind != InternalLifecycleEffect && kind != InternalHelperStop && kind != InternalHelperAbort && kind != InternalProfileCancel {
		return launchInvalid("launch revocation lacks its committed causal decision")
	}
	return nil
}

func ValidateTransportInvalidation(revocation LaunchRevocation, receipt TransportInvalidationReceipt) error {
	if err := ValidateLaunchRevocation(revocation); err != nil {
		return err
	}
	if receipt.LaunchID != revocation.Record.ID || receipt.RevocationEventID != revocation.EventID ||
		receipt.OperationID != revocation.Cause.CauseOperationID || receipt.CompletedAt == "" ||
		receipt.RemainingConnections == nil || *receipt.RemainingConnections != 0 ||
		receipt.RemainingDeliveries == nil || *receipt.RemainingDeliveries != 0 {
		return launchInvalid("transport invalidation lacks measured close completion")
	}
	return nil
}
