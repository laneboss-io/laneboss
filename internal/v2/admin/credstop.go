package admin

import (
	"context"
	"reflect"

	"laneboss.io/laneboss/internal/v2/api"
)

// This is a local containment fence, not a broker acknowledgement. The broker
// record/generation remains unchanged until BeginCredentialWithdrawal replies.
type credentialStop struct {
	Cause  api.InternalIntent
	Reason string
	Note   string `json:"note,omitempty"`
}

const stopAfterExit = "stop arrived after natural exit"

func committedExit(record leaseRecord) bool {
	return record.Gate != nil && record.Spec != nil && record.Gate.State == "ended" && record.Gate.Observation != nil &&
		record.Gate.Observation.Handle == gateHandle(record) && validateObservation(record, *record.Gate.Observation) == nil
}

func releaseStop(record leaseRecord) bool {
	if record.Credentials == nil || record.Credentials.Stop == nil {
		return false
	}
	stop := record.Credentials.Stop
	return stop.Cause.Kind == api.InternalHelperStop && stop.Reason == "release" && stop.Note == stopAfterExit && committedExit(record)
}

// Choose from protected native history before kill/wait. A wait discovered
// during this Stop is a cancellation, even if a retry later observes its exit.
// The local stop decision preserves that distinction across claim changes.
func stopWithdrawalReason(record leaseRecord) string {
	if credentials := record.Credentials; credentials != nil {
		if p := credentials.Record; p != nil && (p.Revoked || p.Authority.Revoked || p.Fence != nil && p.Fence.Reason == "revoked") {
			return "revoked"
		}
		if credentials.Stop != nil {
			return credentials.Stop.Reason
		}
	}
	if record.Revoked {
		return "revoked"
	}
	gate := record.Gate
	if gate != nil && record.Spec != nil && gate.Stop == nil && gate.State == "ended" && gate.Observation != nil &&
		gate.Observation.Handle == gateHandle(record) && validateObservation(record, *gate.Observation) == nil {
		return "release"
	}
	return api.CredentialStopReason
}

func (m *leaseManager) fenceStopped(record *leaseRecord, cause api.InternalIntent, reason string) error {
	if record.Credentials == nil {
		return nil
	}
	if err := validateCause(cause, m.binding.Config, cause.Kind); err != nil {
		return err
	}
	if cause.Kind != api.InternalHelperStop && cause.Kind != api.InternalHelperAbort && cause.Kind != api.InternalHelperRelease || record.Gate == nil || cause.Target != record.Gate.Prepared.Target {
		return failure(api.CodeIntegrity, "credential stop fence differs from its retained containment")
	}
	if record.Credentials.Stop != nil {
		if reason != "revoked" || record.Credentials.Stop.Reason == "revoked" {
			return nil
		}
		// Keep the original cleanup cause; revocation strengthens its decision.
		cause = record.Credentials.Stop.Cause
	}
	// Helper requests are serialized by the native process/store owner. Only
	// an exit observation already committed by ObserveGate can win this race;
	// reaping during containment must never turn a running stop into release.
	late := (reason == "revoked" || reason == "release") && cause.Kind == api.InternalHelperStop && !record.Revoked && record.BootID == m.bootID && committedExit(*record)
	if p := record.Credentials.Record; p != nil && p.Fence != nil && p.Fence.Reason != "release" {
		late = false
	}
	if record.Credentials.State == "withdrawn" && !late {
		return nil
	}
	j := *record.Credentials
	j.Stop = &credentialStop{Cause: cause, Reason: reason}
	if late {
		j.Stop.Reason, j.Stop.Note = "release", stopAfterExit
	} else {
		record.Revoked = true
	}
	record.Credentials = &j
	return m.save(*record)
}

func revokedCredentialCause(record leaseRecord) (api.InternalIntent, error) {
	if record.Credentials != nil && record.Credentials.Stop != nil {
		return record.Credentials.Stop.Cause, nil
	}
	cause := record.Request.Cause
	if record.Gate != nil {
		cause = record.Gate.Request.Cause
	}
	id, err := randomID("revoke-stop-")
	if err != nil {
		return api.InternalIntent{}, err
	}
	cause.ID, cause.EffectID, cause.Kind = id, id, api.InternalHelperStop
	return cause, nil
}

func credentialStopTransition(before, after *credentialJournal) bool {
	if before == nil || after == nil || after.Stop == nil {
		return false
	}
	if before.Stop != nil && (before.Stop.Reason == "revoked" || after.Stop.Reason != "revoked" || before.Stop.Cause != after.Stop.Cause) {
		return false
	}
	copy := *before
	copy.Stop = after.Stop
	return reflect.DeepEqual(&copy, after)
}

// Production construction supplies linuxResources. Component tests may supply
// an owner that actually kills/reaps their canary; this interface is not an RPC
// field or a way to assert native cgroup quiescence from caller metadata.
type containmentController interface {
	KillContainment(context.Context, leaseRecord) error
	WaitContainmentEmpty(context.Context, leaseRecord) error
}
