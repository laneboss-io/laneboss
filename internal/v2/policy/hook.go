package policy

import "laneboss.io/laneboss/internal/v2/api"

// HookOutcome maps a completed policy response to the hook's blocking outcome.
// Preview commands retain the decision as data and do not execute the command.
func HookOutcome(command string, decision api.PolicyDecision) error {
	if command != "org hook" {
		return nil
	}
	switch decision.Result {
	case "allow", "warn":
		return nil
	case "refuse":
		for _, rule := range decision.Rules {
			if rule.Result == "refuse" && textOK(rule.Instead, maxTextBytes) {
				return &api.Error{Code: api.CodeForbidden,
					Message: "blacklist entry " + string(rule.RuleID) + ": " + rule.Reason,
					Instead: rule.Instead}
			}
		}
		return integrity("refusal lacks a refusing blacklist entry and Instead route")
	default:
		return integrity("unknown policy hook result")
	}
}
