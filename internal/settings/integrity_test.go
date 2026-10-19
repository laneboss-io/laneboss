package settings

import (
	"strings"
	"testing"
)

func TestOrphanOverrides(t *testing.T) {
	for key, value := range map[string]any{"seat_class": "subscription", "effort": "high", "runner": "agent"} {
		t.Run(key, func(t *testing.T) {
			snapshot := Empty()
			if _, err := Decode(snapshot.Map()); err != nil {
				t.Fatalf("valid control: %v", err)
			}
			snapshot.Overrides[key] = value
			if _, err := Decode(snapshot.Map()); err == nil || !strings.Contains(err.Error(), "matching lane winner") {
				t.Fatalf("an orphan override must fail the provenance check: %v", err)
			}
			snapshot.Add(key, Layer{Scope: "lane", Value: value, Event: "lane.started"})
			if _, err := Decode(snapshot.Map()); err != nil {
				t.Fatalf("matching override control: %v", err)
			}
		})
	}
}

func TestEffectiveGrantBounds(t *testing.T) {
	for _, scope := range []string{"org", "role", "instance"} {
		for key, names := range map[string][2]string{
			"env_allow":      {"DECLARED_NAME", "UNLISTED_NAME"},
			"tool_allow_add": {"Read", "Write"},
		} {
			t.Run(scope+"/"+key, func(t *testing.T) {
				snapshot := Empty()
				snapshot.Delegation = &Limits{Starter: "lane:parent", Env: []string{"DECLARED_NAME"}, Tools: []string{"Read"}}
				snapshot.Add(key, Layer{Scope: scope, Value: []string{names[0]}, Event: "retained layer"})
				if err := snapshot.CheckDelegation(); err != nil {
					t.Fatalf("allowed inherited control: %v", err)
				}
				snapshot.Add(key, Layer{Scope: scope, Value: []string{names[1]}, Event: "retained layer"})
				if len(snapshot.Overrides) != 0 {
					t.Fatal("the regression must exercise an indirect grant")
				}
				if err := snapshot.CheckDelegation(); err == nil || !strings.Contains(err.Error(), "settings."+key) || !strings.Contains(err.Error(), "lane:parent") {
					t.Fatalf("effective inherited grants must remain bounded: %v", err)
				}
			})
		}
	}
}

func TestRunAccountProvenance(t *testing.T) {
	for _, persistent := range []bool{false, true} {
		name := "request-only"
		if persistent {
			name = "request-masks-setting"
		}
		t.Run(name, func(t *testing.T) {
			snapshot := Empty()
			if persistent {
				snapshot.Overrides["account"] = "account-setting"
				snapshot.Add("account", Layer{Scope: "lane", Value: "account-setting", Event: "lane.started", Option: "--set"})
			}
			snapshot.Add("account", Layer{Scope: "lane", Value: "account-request", Event: "lane.started", Option: "--account"})
			if _, err := Decode(snapshot.Map()); err != nil {
				t.Fatalf("a current account request must preserve valid persistent provenance: %v", err)
			}
			// A stored per-run request is not evidence of a retained setting,
			// even though it is the run's effective account.
			snapshot.Overrides["account"] = "account-request"
			if _, err := Decode(snapshot.Map()); err == nil {
				t.Fatal("a per-run account request must not masquerade as a persistent override")
			}
			snapshot.Overrides["account"] = "account-unrelated"
			if _, err := Decode(snapshot.Map()); err == nil {
				t.Fatal("an unrelated persistent account must have matching lane provenance")
			}
		})
	}
}
