package api

import (
	"context"
	"reflect"
)

type PolicyUse string

const (
	PolicyNewEvaluation     PolicyUse = "new_evaluation"
	PolicyNewSelection      PolicyUse = "new_selection"
	PolicyNewLaunch         PolicyUse = "new_launch"
	PolicyExactReplay       PolicyUse = "exact_replay"
	PolicyRetainedSelection PolicyUse = "retained_selection"
)

// retained is read from the actual receipt/selection, never a caller selector.
// Current authority/visibility is checked before either kind of replay.
func PolicyGenerationFor(use PolicyUse, current, retained Generation) (Generation, error) {
	if !launchGeneration(current) {
		return 0, launchInvalid("current approved policy is unavailable")
	}
	switch use {
	case PolicyNewEvaluation:
		return current, nil
	case PolicyNewSelection:
		return current, nil
	case PolicyNewLaunch:
		return current, nil
	case PolicyExactReplay, PolicyRetainedSelection:
		if !launchGeneration(retained) || retained > current {
			return 0, launchInvalid("retained policy generation is not an approved historical snapshot")
		}
		return retained, nil
	default:
		return 0, launchInvalid("unknown policy use")
	}
}

func PolicyGenerationForReplay(scope Scope, current EffectivePolicy, receipt MutationReceipt) (Generation, error) {
	key := RequestKey{Method: scope.Request.Method, IdempotencyKey: scope.Request.IdempotencyKey, RequestSHA256: scope.Request.RequestSHA256}
	if receipt.Config != scope.Config || receipt.Actor != scope.Actor || receipt.Key != key || !launchID(key.IdempotencyKey) || !bindingDigest.MatchString(string(key.RequestSHA256)) {
		return 0, launchInvalid("policy replay receipt differs from its exact authenticated request")
	}
	return PolicyGenerationFor(PolicyExactReplay, current.Generation, receipt.PolicyGeneration)
}

func ValidateLaunchPolicyCurrent(reservation LaunchReservation, grants GrantSet, current EffectivePolicy) error {
	if !launchGeneration(current.Generation) || reservation.PolicyGeneration != current.Generation || grants.PolicyGeneration != current.Generation {
		return &Error{Code: CodeConflict, Owner: "lb-v2-lifecycle", Message: "new launch policy changed before execution",
			Instead: "Reconcile or abort the retained unopened plan, then reserve a fresh current-policy launch; preserve the original failed receipt."}
	}
	return nil
}

type PolicyAdvanceRequest struct {
	Target                 LifeRef
	ExpectedLaneGeneration Generation
	FromGeneration         Generation
	ToGeneration           Generation
	CancellationEpoch      Generation
}

type PolicyAdvanceEvent struct {
	FromGeneration Generation `json:"from_generation"`
	ToGeneration   Generation `json:"to_generation"`
	LaneGeneration Generation `json:"lane_generation"`
	PolicySHA256   Digest     `json:"policy_sha256"`
	GrantSetID     ID         `json:"grant_set_id"`
}

type PolicyAdvanceReceipt struct {
	Changed      bool
	Lane         Lane
	Event        PolicyAdvanceEvent
	EventID      ID
	CommittedSeq Sequence
}

type PolicyStore interface {
	CurrentPolicySource
	PolicyAt(context.Context, Scope, Generation) (EffectivePolicy, error)
	RefreshLanePolicy(context.Context, Scope, PolicyAdvanceRequest) (PolicyAdvanceReceipt, error)
}

func ValidatePolicyAdvance(before Lane, request PolicyAdvanceRequest, current EffectivePolicy, receipt PolicyAdvanceReceipt) error {
	live := before.State == "preparing" || before.State == "running" || before.State == "stopping" || before.State == "verifying" || before.State == "idle" || before.State == "profile_wait"
	if !live || before.Cleaned || !launchGeneration(before.PolicyGeneration) || !launchID(before.GrantSetID) ||
		request.Target != (LifeRef{LifeID: before.LifeID, Run: before.Run}) || request.ExpectedLaneGeneration != before.Generation ||
		request.FromGeneration != before.PolicyGeneration || request.ToGeneration != current.Generation || request.CancellationEpoch != before.CancellationEpoch ||
		!launchGeneration(before.Generation) || before.Generation >= launchMaxInteger || !launchGeneration(current.Generation) || current.Generation < before.PolicyGeneration ||
		!bindingDigest.MatchString(string(current.SHA256)) {
		return launchInvalid("lane policy refresh differs from its current life fence")
	}
	if !receipt.Changed {
		if before.PolicyGeneration != current.Generation || !reflect.DeepEqual(receipt.Lane, before) || receipt.EventID != "" || receipt.CommittedSeq != 0 || receipt.Event != (PolicyAdvanceEvent{}) {
			return launchInvalid("unchanged lane policy refresh altered retained state")
		}
		return nil
	}
	want := before
	want.Generation++
	want.PolicyGeneration = current.Generation
	want.LastSeq = receipt.CommittedSeq
	event := PolicyAdvanceEvent{FromGeneration: before.PolicyGeneration, ToGeneration: current.Generation, LaneGeneration: want.Generation, PolicySHA256: current.SHA256, GrantSetID: before.GrantSetID}
	if current.Generation <= before.PolicyGeneration || !reflect.DeepEqual(receipt.Lane, want) || receipt.Event != event || !launchID(receipt.EventID) || receipt.CommittedSeq == 0 {
		return launchInvalid("lane policy refresh changed more than its approved generation")
	}
	return nil
}

func validPolicyRefresh(tx Transaction) bool {
	if tx.Internal == nil || tx.Internal.Kind != InternalPolicyRefresh {
		return true
	}
	cause := tx.Internal
	if len(tx.Writes.Lanes) != 1 || len(tx.Events) != 1 || tx.Events[0].Kind != "lane.policy" || cause.Actor.Kind != "service" || !launchID(cause.Actor.ID) {
		return false
	}
	lane := tx.Writes.Lanes[0]
	var event PolicyAdvanceEvent
	if DecodeObject(tx.Events[0].Payload, &event) != nil || cause.Target != (LifeRef{LifeID: lane.LifeID, Run: lane.Run}) || cause.CancellationEpoch != lane.CancellationEpoch ||
		event.ToGeneration != lane.PolicyGeneration || event.FromGeneration >= event.ToGeneration || !launchGeneration(event.FromGeneration) ||
		event.LaneGeneration != lane.Generation || event.GrantSetID != lane.GrantSetID || !bindingDigest.MatchString(string(event.PolicySHA256)) {
		return false
	}
	cas, epoch := false, false
	for _, compare := range tx.Compare {
		cas = cas || compare.Kind == CompareLane && compare.ID == lane.LifeID && compare.Generation+1 == lane.Generation && launchGeneration(compare.Generation)
	}
	for _, guard := range tx.Guards {
		epoch = epoch || guard.Cancellation != nil && guard.Cancellation.LifeID == lane.LifeID && guard.Cancellation.Epoch == lane.CancellationEpoch
	}
	return cas && epoch
}
