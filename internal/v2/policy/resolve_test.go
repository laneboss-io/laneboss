package policy

import (
	"math"
	"reflect"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
)

func TestResolveLayerUnion(t *testing.T) {
	layers := []Layer{
		{Source: testSource("org"), Thresholds: testThreshold(0.80), Rules: []api.Rule{sourceRule("org-rule")}},
		{Source: testSource("own"), DefinedAt: &api.RoleContext{Level: 3, Role: "executor"}, Thresholds: testThreshold(0.95),
			Rules: []api.Rule{sourceRule("own-rule")}},
		{Source: testSource("peer"), DefinedAt: &api.RoleContext{Level: 3, Role: "tester"}, Rules: []api.Rule{sourceRule("peer-rule")}},
		{Source: testSource("higher"), DefinedAt: &api.RoleContext{Level: 5, Role: "reviewer"}, Thresholds: testThreshold(0.85),
			Rules: []api.Rule{sourceRule("higher-rule")}},
		{Source: testSource("other"), DefinedAt: &api.RoleContext{Level: 5, Role: "publisher"}, Rules: []api.Rule{sourceRule("other-rule")}},
	}
	judge := DefaultJudgeConfig(digestBytes([]byte("deploy")), digestBytes([]byte("tokens")), 32768)
	for _, row := range []struct {
		role api.RoleContext
		ids  []api.ID
	}{
		{api.RoleContext{Level: 3, Role: "executor"}, []api.ID{"org-rule", "own-rule", "other-rule", "higher-rule"}},
		{api.RoleContext{Level: 3, Role: "absent"}, []api.ID{"org-rule", "other-rule", "higher-rule"}},
		{api.RoleContext{Level: 5, Role: "reviewer"}, []api.ID{"org-rule", "higher-rule"}},
		{api.RoleContext{Level: 6, Role: "supervisor"}, []api.ID{"org-rule"}},
	} {
		t.Run(row.role.Role, func(t *testing.T) {
			policy, err := Resolve(1, row.role, layers, judge, 1209600)
			if err != nil {
				t.Fatal(err)
			}
			ids := []api.ID{}
			for _, rule := range policy.Rules {
				ids = append(ids, rule.ID)
				match := 0.80
				if rule.ID == "own-rule" {
					match = 0.95
				} else if rule.ID == "higher-rule" {
					match = 0.85
				}
				if rule.Thresholds.Match != match || rule.Source.ID == "" {
					t.Fatalf("defining authority lost: %+v", rule)
				}
			}
			if !reflect.DeepEqual(ids, row.ids) {
				t.Fatalf("union: got %v; want %v", ids, row.ids)
			}
		})
	}
	// Source validation also covers unselected lower/peer roles.
	layers[2].Rules[0].Band = "allow"
	_, err := Resolve(1, api.RoleContext{Level: 6, Role: "supervisor"}, layers, judge, 1209600)
	wantCode(t, err, api.CodeInvalid)
}

func TestResolveScopeAndValidation(t *testing.T) {
	base := newFixture(t, sourceRule("scoped"))
	rule := sourceRule("scoped")
	rule.Scope = api.RuleScope{Levels: []int{3}, Roles: []string{"tester"}}
	policy, err := Resolve(1, base.store.policy.Context, []Layer{{Source: testSource("org"),
		Thresholds: testThreshold(0.85), Rules: []api.Rule{rule}}}, base.store.policy.Judge, 1209600)
	if err != nil || len(policy.Rules) != 0 {
		t.Fatalf("scope did not exclude executor: %v, %v", policy.Rules, err)
	}
	for _, mutate := range []func(*api.Rule){
		func(r *api.Rule) { r.Band = "permit" },
		func(r *api.Rule) { r.Instead = "" },
		func(r *api.Rule) { r.Thresholds = testThreshold(math.NaN()) },
		func(r *api.Rule) { r.Thresholds = testThreshold(0.85); r.Thresholds.CalibrationID = "" },
		func(r *api.Rule) { r.Source = testSource("different") },
		func(r *api.Rule) { r.Scope.Levels = []int{3, 3} },
	} {
		candidate := sourceRule("scoped")
		mutate(&candidate)
		_, err := Resolve(1, base.store.policy.Context, []Layer{{Source: testSource("org"),
			Thresholds: testThreshold(0.85), Rules: []api.Rule{candidate}}}, base.store.policy.Judge, 1209600)
		wantCode(t, err, api.CodeInvalid)
	}
}
