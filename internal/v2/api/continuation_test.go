package api

import "testing"

func TestContinueOperation(t *testing.T) {
	for _, state := range []string{"pending", "claimed", "completed"} {
		intent := ContinuationIntent{ID: "continuation-one", Status: state, OperationID: "continue-operation", Swap: ProfileSwap{OperationID: "continue-operation"}}
		request := ContinuationRequest{IntentID: intent.ID, Swap: intent.Swap}
		operation := Operation{ID: intent.OperationID, Status: "pending"}
		if state == "completed" {
			operation.Status = "succeeded"
		}
		if err := ValidateContinuationOperation(intent, request, operation); err != nil {
			t.Fatal(err)
		}
	}
	for _, fault := range []string{"swap", "result", "status", "pending_success"} {
		t.Run(fault, func(t *testing.T) {
			intent := ContinuationIntent{ID: "continuation-one", Status: "pending", OperationID: "continue-operation", Swap: ProfileSwap{OperationID: "continue-operation"}}
			request := ContinuationRequest{IntentID: intent.ID, Swap: intent.Swap}
			operation := Operation{ID: intent.OperationID, Status: "pending"}
			switch fault {
			case "swap":
				intent.Swap.OperationID = "internal-intent-id"
				request.Swap = intent.Swap
			case "result":
				operation.ID = "another-operation"
			case "status":
				intent.Status = "waiting"
			case "pending_success":
				operation.Status = "succeeded"
			}
			requireLaunchInvalid(t, ValidateContinuationOperation(intent, request, operation), "continuation operation contract was bypassed")
		})
	}
}
