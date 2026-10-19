package policy

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
)

func TestUnfundedPolicyAudit(t *testing.T) {
	for _, missing := range []string{"lane", "installed"} {
		for _, critical := range []bool{false, true} {
			t.Run(missing+"/"+map[bool]string{false: "ordinary", true: "critical"}[critical], func(t *testing.T) {
				rule := sourceRule("unfunded-rule")
				rule.Critical = critical
				f := newFixture(t, rule)
				if missing == "lane" {
					f.store.lane.BudgetRemaining.SpendMicros = 0
				} else {
					deps := f.service.deps
					deps.MaxCostMicros = 0
					installed, err := NewInstalled(deps)
					if err != nil {
						t.Fatal(err)
					}
					f.service = installed
				}
				decision, err := f.evaluateOnce(context.Background())
				if err != nil {
					t.Fatal("unfunded work did not reach its audited unscored decision", err)
				}
				want := "allow"
				if critical {
					want = "refuse"
				}
				if decision.Result != want || !decision.AuditComplete || len(decision.Rules) != 1 ||
					decision.Rules[0].Probability != nil || !strings.Contains(decision.Rules[0].Reason, "budget_exhausted") ||
					len(f.judge.fits) != 0 || len(f.judge.requests) != 0 || len(f.store.events) != 1 {
					t.Fatal("unfunded audit invented a score, spent inference or lost its explicit band")
				}
				var input evaluationInput
				if err := json.Unmarshal(f.store.uploads[decision.Input.ID].data, &input); err != nil ||
					input.CostLimitMicros != 0 || len(input.Batches) != 1 || input.Batches[0].UsageKnown || input.Batches[0].Reply != nil {
					t.Fatal("unfunded input lost its actual zero cap or fabricated provider usage", err)
				}
				var durable api.PolicyDecision
				if err := json.Unmarshal(f.store.events[0].Payload, &durable); err != nil || durable.ID != decision.ID || durable.Input != decision.Input {
					t.Fatal("unfunded result does not match its retained event", err)
				}
			})
		}
	}
}
