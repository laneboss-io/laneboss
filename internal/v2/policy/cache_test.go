package policy

import (
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

func TestCacheContextBindings(t *testing.T) {
	for _, row := range []struct {
		name   string
		mutate func(*fixture)
	}{
		{"raw", func(f *fixture) {
			f.request.Command.Command = append(f.request.Command.Command, ' ')
			f.request.Command.RawSHA256 = digestBytes(f.request.Command.Command)
		}},
		{"argv", func(f *fixture) { f.request.Command.Argv = []string{"a quoted argument"} }},
		{"tool", func(f *fixture) { f.request.Command.Tool = "unknown.tool" }},
		{"cwd", func(f *fixture) { f.request.Command.CWD = "/work/main/docs" }},
		{"paths", func(f *fixture) { f.request.Command.DeclaredPaths = []string{"public/other.txt"} }},
		{"instance", func(f *fixture) { f.store.policy.Context.InstanceID = "instance-b" }},
		{"role", func(f *fixture) {
			f.scope.Actor.Role, f.store.lane.Role, f.store.policy.Context.Role = "reviewer", "reviewer", "reviewer"
			f.store.launch.Actor = f.scope.Actor
		}},
		{"policy", func(f *fixture) {
			f.scope.PolicyGeneration++
			f.store.policy.Generation++
		}},
		{"rules", func(f *fixture) { f.store.policy.Rules[0].Text += " This includes public previews." }},
		{"threshold", func(f *fixture) { f.store.policy.Rules[0].Thresholds.Match = 0.9 }},
		{"criteria", func(f *fixture) { f.store.policy.Rules[0].Thresholds.CalibrationID = "another-calibration" }},
		{"model", func(f *fixture) {
			f.store.policy.Judge.Provider = "typesafe"
			f.store.policy.Judge.Model = "alternative/full-model"
		}},
		{"deployment", func(f *fixture) { f.store.policy.Judge.DeploymentSHA256 = digestBytes([]byte("next-deployment")) }},
		{"tokenizer", func(f *fixture) { f.store.policy.Judge.TokenizerSHA256 = digestBytes([]byte("next-tokenizer")) }},
		{"grants", func(f *fixture) {
			f.store.grants.SHA256 = digestBytes([]byte("next-grants"))
			f.store.grants.Generation++
		}},
		{"turn", func(f *fixture) {
			f.request.LogicalTurnID = "turn-b"
			f.store.lane.LogicalTurnID = "turn-b"
			f.store.turn.LogicalTurnID = "turn-b"
		}},
		{"endpoint", func(f *fixture) { f.scope.EndpointGeneration++; f.store.launch.EndpointGeneration++ }},
		{"lane-generation", func(f *fixture) { f.store.lane.Generation++ }},
		{"clock-rewind", func(f *fixture) { f.clock.now = f.clock.now.Add(-time.Second) }},
	} {
		t.Run(row.name, func(t *testing.T) {
			f := newFixture(t, sourceRule("publish"))
			if first := f.evaluate(t); first.Result != "allow" {
				t.Fatal("cache control did not allow")
			}
			row.mutate(f)
			f.seal(t)
			f.judge.probability = 1
			result := f.evaluate(t)
			if result.CacheOf != "" || result.Result != "refuse" || len(f.judge.requests) != 2 {
				t.Fatalf("stale semantic allow survived %s", row.name)
			}
		})
	}
}

func installSkip(t *testing.T, f *fixture) {
	t.Helper()
	policy := &f.store.policy
	rules, err := RuleSetDigest(*policy)
	if err != nil {
		t.Fatal(err)
	}
	contextHash, err := SkipContextDigest(f.scope.Config, f.request.Command, *policy)
	if err != nil {
		t.Fatal(err)
	}
	source := testSource("skip-source")
	policy.Sources = append(policy.Sources, source)
	policy.Skip = []api.SkipEntry{{ID: "public-read", Description: "Exact judged public read optimization.",
		RuleSetSHA256: rules, ContextSHA256: contextHash, Source: source}}
	f.seal(t)
}

func TestSkipRequiresPositiveProof(t *testing.T) {
	f := newFixture(t, sourceRule("publish"))
	installSkip(t, f)
	first := f.evaluate(t)
	if first.SkipID != "" || len(f.judge.requests) != 1 {
		t.Fatal("a source hash alone overrode unresolved semantic membership")
	}
	second := f.evaluate(t)
	if second.SkipID != "public-read" || second.CacheOf != first.ID || second.Result != "allow" || len(f.judge.requests) != 1 {
		t.Fatal("approved positive-only skip did not reuse its actual allow receipt")
	}
	f.request.Command.Command = []byte("an unfamiliar skip miss")
	f.request.Command.RawSHA256 = digestBytes(f.request.Command.Command)
	miss := f.evaluate(t)
	if miss.SkipID != "" || miss.Result != "allow" || len(f.judge.requests) != 2 {
		t.Fatal("skip miss became an allowlist refusal or skipped the judge")
	}
}

func TestSkipCannotCancelDeny(t *testing.T) {
	// An erroneously scoped skip cannot cancel an actual semantic refusal.
	f := newFixture(t, sourceRule("publish"))
	installSkip(t, f)
	f.judge.probability = 1
	denied := f.evaluate(t)
	again := f.evaluate(t)
	if denied.Result != "refuse" || again.Result != "refuse" || denied.SkipID != "" || again.SkipID != "" {
		t.Fatal("skip overrode an explicit deny")
	}
}

func TestSkipInvalidation(t *testing.T) {
	for _, row := range []struct {
		name   string
		mutate func(*fixture)
	}{
		{"rule-update", func(f *fixture) { f.store.policy.Rules[0].Text += " Also deny this read." }},
		{"context-update", func(f *fixture) { f.request.Command.CWD = "/work/main/docs" }},
		{"generation-update", func(f *fixture) {
			f.store.policy.Generation++
			f.scope.PolicyGeneration++
		}},
		{"expired-proof", func(f *fixture) { f.clock.now = f.clock.now.Add(31 * time.Second) }},
	} {
		t.Run(row.name, func(t *testing.T) {
			f := newFixture(t, sourceRule("publish"))
			installSkip(t, f)
			f.evaluate(t)
			if f.evaluate(t).SkipID == "" {
				t.Fatal("positive skip control did not reach the optimization")
			}
			row.mutate(f)
			f.seal(t)
			f.judge.probability = 1
			result := f.evaluate(t)
			if result.SkipID != "" || result.CacheOf != "" || result.Result != "refuse" {
				t.Fatal("stale skip/proof allowed changed work")
			}
		})
	}
}

func TestCriticalCannotSkip(t *testing.T) {
	rule := sourceRule("critical")
	rule.Critical = true
	f := newFixture(t, rule)
	installSkip(t, f)
	f.judge.evalErr = &api.Error{Code: api.CodeUnavailable}
	result := f.evaluate(t)
	if result.SkipID != "" || result.Result != "refuse" || result.Rules[0].Probability != nil {
		t.Fatal("skip hid an unresolved critical rule")
	}
}

func TestCacheAgesDuringRead(t *testing.T) {
	for _, approvedSkip := range []bool{false, true} {
		name := "cache"
		if approvedSkip {
			name = "skip"
		}
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, sourceRule("publish"))
			if approvedSkip {
				installSkip(t, f)
			}
			f.evaluate(t)
			f.clock.now = f.clock.now.Add(29 * time.Second)
			advanced := false
			f.store.afterRetain = func() {
				if !advanced {
					f.clock.now = f.clock.now.Add(2 * time.Second)
					advanced = true
				}
			}
			f.judge.probability = 1
			decision := f.evaluate(t)
			if decision.CacheOf != "" || decision.SkipID != "" || decision.Result != "refuse" || len(f.judge.requests) != 2 {
				t.Fatal("expired receipt survived input-retention wait")
			}
		})
	}
}
