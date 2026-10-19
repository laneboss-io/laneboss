//go:build linux && laneboss_root_canary

package admin

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
)

type reviewRequirementsState struct {
	api.StateStore
	lane   api.Lane
	policy api.EffectivePolicy
}

func (s *reviewRequirementsState) Lane(_ context.Context, _ api.Scope, target api.LifeRef) (api.Lane, error) {
	if target != (api.LifeRef{LifeID: s.lane.LifeID, Run: s.lane.Run}) {
		return api.Lane{}, failure(api.CodeNotFound, "component target changed")
	}
	return s.lane, nil
}
func (s *reviewRequirementsState) CurrentApprovedPolicy(context.Context, api.Scope) (api.EffectivePolicy, error) {
	return s.policy, nil
}

func TestReviewProtectedRequirements(t *testing.T) {
	type producer interface {
		RequiredReviewChecks(context.Context, api.Scope, api.LifeRef) ([]string, error)
	}
	if _, ok := any(new(Service)).(producer); !ok {
		t.Fatal("administrator lacks the protected required-check producer")
	}
	if os.Geteuid() != 0 {
		t.Fatal("protected review requirements require the authorized root test box")
	}
	id, err := randomID("review-")
	if err != nil {
		t.Fatal(err)
	}
	config := string(id)
	if len(config) > 32 {
		config = config[:32]
	}
	parent := "/etc/laneboss-v2/review"
	if err := os.MkdirAll(parent, 0755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(parent, config+".json")
	t.Cleanup(func() {
		if err := os.Remove(path); err != nil {
			t.Error(err)
		}
	})
	target := api.LifeRef{LifeID: "reviewed-life", Run: 1}
	state := &reviewRequirementsState{lane: api.Lane{LifeID: target.LifeID, Run: target.Run, Workspace: api.Workspace{ProjectID: "project-a"}}, policy: api.EffectivePolicy{Generation: 7}}
	host := &Service{deps: Dependencies{Config: config, Store: state}}
	port := any(host).(producer)
	scope := api.Scope{Config: config, Actor: api.Actor{Kind: "service", ID: "actual-coordinator"}}
	write := func(generation int, names []string) {
		t.Helper()
		raw, err := json.Marshal(map[string]any{"schema": "laneboss.review-requirements.v2", "config": config, "policy_generation": generation, "projects": []any{map[string]any{"project_id": "project-a", "checks": names}}})
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, raw, 0644); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, 0644); err != nil {
			t.Fatal(err)
		}
	}
	write(7, []string{"unit", "integration"})
	names, err := port.RequiredReviewChecks(context.Background(), scope, target)
	if err != nil || !reflect.DeepEqual(names, []string{"unit", "integration"}) {
		t.Fatal("protected current project names were not read", err)
	}
	write(8, []string{"unit"})
	if names, err := port.RequiredReviewChecks(context.Background(), scope, target); err == nil || len(names) != 0 {
		t.Fatal("stale protected requirements were accepted")
	}
	write(7, []string{"unit", "unit"})
	if names, err := port.RequiredReviewChecks(context.Background(), scope, target); err == nil || len(names) != 0 {
		t.Fatal("repeated protected requirement names were accepted")
	}
	write(7, []string{"unit"})
	if err := os.Chmod(path, 0666); err != nil {
		t.Fatal(err)
	}
	if names, err := port.RequiredReviewChecks(context.Background(), scope, target); err == nil || len(names) != 0 {
		t.Fatal("caller-writable requirement names acquired policy authority")
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	scope.Actor.Kind = "human"
	if names, err := port.RequiredReviewChecks(context.Background(), scope, target); err == nil || len(names) != 0 {
		t.Fatal("public actor labels selected protected requirements")
	}
}
