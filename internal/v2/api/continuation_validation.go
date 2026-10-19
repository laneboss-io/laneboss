package api

import "reflect"

// The store stamps one operation into the selected pending intent and swap.
// Claim, slot handoff, continued launch and replay all retain that operation.
func ValidateContinuationOperation(intent ContinuationIntent, request ContinuationRequest, operation Operation) error {
	if !launchID(intent.ID) || !launchID(intent.OperationID) || intent.Swap.OperationID != intent.OperationID ||
		request.IntentID != intent.ID || !reflect.DeepEqual(request.Swap, intent.Swap) || operation.ID != intent.OperationID {
		return launchInvalid("continuation operation identity differs across its handoff")
	}
	switch intent.Status {
	case "pending", "claimed":
		if operation.Status != "pending" && operation.Status != "running" {
			return launchInvalid("pending continuation claimed completion")
		}
	case "completed":
		if operation.Status != "succeeded" {
			return launchInvalid("completed continuation lacks its actual operation result")
		}
	default:
		return launchInvalid("continuation is not eligible for launch or replay")
	}
	return nil
}
