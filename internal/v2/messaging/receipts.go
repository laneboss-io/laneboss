package messaging

import (
	"encoding/json"

	"laneboss.io/laneboss/internal/v2/api"
)

func validReceiptInput(receipt api.MailReceipt) error {
	if !validID(receipt.MailID) || !validID(receipt.LogicalTurnID) || !validID(receipt.Target.LifeID) || receipt.Target.Run == 0 || receipt.Target.Run > maxExact || receipt.Status != "delivered" && receipt.Status != "returned" {
		return problem(api.CodeInvalid, "mail receipt has an invalid target, logical turn or status")
	}
	if !validPromptStatus(receipt.PromptStatus) || !validEndReason(receipt.Cause) || !validTimestamp(receipt.ObservedAt) {
		return problem(api.CodeInvalid, "mail receipt has an invalid prompt status, cause or UTC timestamp")
	}
	return nil
}

func validPromptStatus(status string) bool {
	switch status {
	case "not_written", "written", "cut", "unknown", "completed":
		return true
	default:
		return false
	}
}

func validEndReason(reason string) bool {
	switch reason {
	case "exit", "stop", "timeout", "limit", "dropped", "revoked", "service_lost", "capture_full", "launch_failed":
		return true
	default:
		return false
	}
}

func decodeRunEnd(raw json.RawMessage) (api.RunEndEvent, error) {
	var end api.RunEndEvent
	if err := decodeBody(raw, &end); err != nil {
		return api.RunEndEvent{}, problem(api.CodeIntegrity, "stored run end has an invalid payload")
	}
	return end, nil
}

func validExitEvidence(end api.RunEndEvent) error {
	observation := end.Observation
	if !validEndReason(end.Reason) || !validPromptStatus(observation.PromptStatus) || !validTimestamp(observation.ObservedAt) {
		return problem(api.CodeIntegrity, "stored run end has an invalid reason, prompt status or UTC timestamp")
	}
	if !validID(end.LaunchID) || !validID(observation.Handle.ID) || !validID(observation.Handle.ContainmentID) || observation.Handle.Generation == "" {
		return problem(api.CodeIntegrity, "stored run end lacks its outside process identity")
	}
	switch observation.State {
	case "prepared", "running", "unknown":
		// These are valid observations but cannot satisfy the caller's later
		// exited/zero-survivor completion comparison.
		return nil
	case "exited":
	default:
		return problem(api.CodeIntegrity, "stored run end has an unknown process state")
	}
	if (observation.ExitCode == nil) == (observation.Signal == nil) {
		return problem(api.CodeIntegrity, "known process exit requires exactly one exit code or termination signal")
	}
	if observation.ExitCode != nil && (*observation.ExitCode < -1<<31 || *observation.ExitCode > 1<<31-1) {
		return problem(api.CodeIntegrity, "stored process exit code exceeds its signed bound")
	}
	if observation.Signal != nil && (*observation.Signal < 1 || *observation.Signal > 1<<31-1) {
		return problem(api.CodeIntegrity, "stored termination signal exceeds its positive signed bound")
	}
	return nil
}

func validTurnCause(trigger api.Trigger, mail api.Mail) bool {
	mailFound, sequenceFound := false, false
	for _, id := range trigger.MailIDs {
		if id == mail.ID {
			mailFound = true
		}
	}
	for _, seq := range trigger.CausingSeqs {
		if seq == mail.QueuedSeq {
			sequenceFound = true
		}
	}
	return mailFound && sequenceFound
}
