package judge

import (
	"context"
	"testing"
)

func TestItem4ScopedJudgeAfterPolicyAdvance(t *testing.T) {
	s, store, _, scope, request := serviceFixture(t)
	store.policy.Generation++
	scope.PolicyGeneration = store.policy.Generation
	provider := &scopedFitRecorder{}
	s.deps.Clef = provider
	if _, err := s.FitForScope(context.Background(), scope, request); err != nil || provider.calls != 1 {
		t.Fatal("current judge policy rejected historical live issuance and turn pins", err)
	}
	if provider.request.Context.PolicyGeneration != store.policy.Generation || store.lane.PolicyGeneration == store.policy.Generation {
		t.Fatal("judge did not use current policy independently of retained launch facts")
	}
}
