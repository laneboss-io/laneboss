package policy

import (
	"strings"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
)

func TestHookOutcome(t *testing.T) {
	decision := api.PolicyDecision{Result: "refuse", Rules: []api.RuleDecision{{
		RuleID: "publish", Result: "refuse", Reason: "scored blacklist match", Instead: "Report the reviewed diff.",
	}}}
	t.Run("refuse", func(t *testing.T) {
		err := HookOutcome("org hook", decision)
		wantCode(t, err, api.CodeForbidden)
		if typed := err.(*api.Error); typed.Instead != decision.Rules[0].Instead || !strings.Contains(typed.Message, "publish") {
			t.Fatal("hook lost the refusal rule or Instead route")
		}
	})
	t.Run("preview", func(t *testing.T) {
		for _, command := range []string{"policy evaluate", "org blacklist try"} {
			if err := HookOutcome(command, decision); err != nil {
				t.Fatal("preview became an enforcing hook")
			}
		}
	})
	t.Run("ordinary", func(t *testing.T) {
		for _, result := range []string{"allow", "warn"} {
			if err := HookOutcome("org hook", api.PolicyDecision{Result: result}); err != nil {
				t.Fatal("allow or warning blocked the hook")
			}
		}
	})
	t.Run("missing-route", func(t *testing.T) {
		broken := decision
		broken.Rules = []api.RuleDecision{{RuleID: "publish", Result: "refuse"}}
		wantCode(t, HookOutcome("org hook", broken), api.CodeIntegrity)
	})
}
