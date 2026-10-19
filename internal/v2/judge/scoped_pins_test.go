package judge

import (
	"context"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/judge/wire"
)

func TestScopedProviderPins(t *testing.T) {
	for _, name := range []string{"explicit", "default-request", "default-policy", "alternative", "missing-alternative", "typed-nil", "unapproved", "deployment", "tokenizer", "context", "limits", "stale"} {
		t.Run(name, func(t *testing.T) {
			s, store, _, scope, request := serviceFixture(t)
			clef, alternative := &scopedFitRecorder{}, &scopedFitRecorder{}
			s.deps.Clef, s.deps.TypeSafe = clef, alternative
			request.Config = store.policy.Judge
			want, useAlternative := api.ErrorCode(""), false
			switch name {
			case "default-request":
				request.Config.Provider, request.Config.Model = "", ""
			case "default-policy":
				store.policy.Judge.Provider, store.policy.Judge.Model = "", ""
			case "alternative", "missing-alternative", "typed-nil":
				store.policy.Judge.Provider, store.policy.Judge.Model = "typesafe", "jev-1.14.0"
				request.Config, useAlternative = store.policy.Judge, true
				if name == "missing-alternative" {
					s.deps.TypeSafe, want = nil, api.CodePrerequisite
				} else if name == "typed-nil" {
					s.deps.TypeSafe, want = (*scopedFitRecorder)(nil), api.CodePrerequisite
				}
			case "unapproved":
				request.Config.Provider, request.Config.Model, want = "typesafe", "jev-1.14.0", api.CodeForbidden
			case "deployment":
				request.Config.DeploymentSHA256, want = wire.Digest([]byte("other deployment")), api.CodeForbidden
			case "tokenizer":
				request.Config.TokenizerSHA256, want = wire.Digest([]byte("other tokenizer")), api.CodeForbidden
			case "context":
				request.Config.ContextTokens, want = request.Config.ContextTokens-1, api.CodeForbidden
			case "limits":
				request.Config.MaxBytes, want = request.Config.MaxBytes-1, api.CodeForbidden
			case "stale":
				request.Context.PolicyGeneration, want = scope.PolicyGeneration+1, api.CodeConflict
			}
			_, err := s.FitForScope(context.Background(), scope, request)
			if want != "" {
				errorCode(t, err, want)
				if clef.calls+alternative.calls != 0 {
					t.Fatal("unapproved pins reached a provider")
				}
				return
			}
			approved, resolveErr := api.ResolveJudgeConfig(store.policy.Judge)
			selected := clef
			if useAlternative {
				selected = alternative
			}
			if err != nil || resolveErr != nil || selected.calls != 1 ||
				clef.calls+alternative.calls != 1 || selected.request.Config != approved {
				t.Fatal("approved provider selection changed")
			}
		})
	}
}

type unavailableFit struct{ calls int }

func (p *unavailableFit) Fit(context.Context, api.JudgeRequest) (api.TokenFit, error) {
	p.calls++
	return api.TokenFit{}, problem(api.CodeUnavailable, "fixture provider unavailable")
}
func (p *unavailableFit) Evaluate(context.Context, api.JudgeRequest) (api.JudgeReply, error) {
	p.calls++
	return api.JudgeReply{}, problem(api.CodeUnavailable, "fixture provider unavailable")
}

func TestScopedProviderNeverFallsBack(t *testing.T) {
	s, store, _, scope, request := serviceFixture(t)
	selected, other := &unavailableFit{}, &scopedFitRecorder{}
	s.deps.Clef, s.deps.TypeSafe = selected, other
	request.Config = store.policy.Judge
	_, err := s.FitForScope(context.Background(), scope, request)
	errorCode(t, err, api.CodeUnavailable)
	if selected.calls != 1 || other.calls != 0 {
		t.Fatal("provider outage triggered fallback")
	}
}
