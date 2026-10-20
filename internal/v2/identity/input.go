package identity

import (
	"encoding/json"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

// ValidateInput is the shared file/ergonomic/service preflight. It validates
// input only; enrollment, signatures, scope and atomic guards stay server-side.
func ValidateInput(method api.Method, raw json.RawMessage) error {
	switch method {
	case "identity.self", "human.pending":
		var request api.Empty
		return strictObject(raw, &request)
	case "human.enroll":
		var request api.HumanAccessRequest
		if err := strictObject(raw, &request); err != nil {
			return err
		}
		return api.ValidateHumanAccess(request)
	case "human.session":
		var request api.HumanSessionRequest
		return strictObject(raw, &request)
	case "human.challenge":
		var request api.HumanChallengeRequest
		if err := strictObject(raw, &request); err != nil {
			return err
		}
		return validateIntent(request)
	case "human.confirm":
		var request api.HumanConfirmRequest
		if err := strictObject(raw, &request); err != nil {
			return err
		}
		return validateConfirmation(request)
	case "ticket.issue":
		var request api.TicketIssueRequest
		if err := strictObject(raw, &request); err != nil {
			return err
		}
		_, err := validateTicketInput(request)
		return err
	default:
		return refusal(api.CodeInvalid, "unknown identity input method")
	}
}

func validateTicketInput(request api.TicketIssueRequest) (time.Time, error) {
	if request.Level < 3 || request.Level > 6 || !validID(api.ID(request.Role)) ||
		!validID(request.GrantSetID) {
		return time.Time{}, refusal(api.CodeInvalid, "invalid ticket level, role or root grants")
	}
	expires, err := utcTime(request.ExpiresAt)
	if err != nil {
		return time.Time{}, err
	}
	return expires, nil
}
