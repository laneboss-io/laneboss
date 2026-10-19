package judge

import (
	"bytes"
	"context"
	"fmt"
	"reflect"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/judge/wire"
)

type scopedFitRecorder struct {
	api.Judge
	request api.JudgeRequest
	calls   int
}

func scopedContext(store *scopedStore) api.JudgeContext {
	return api.JudgeContext{Config: "example", Target: store.turn.Target, Role: store.policy.Context,
		LogicalTurnID: store.lane.LogicalTurnID, GrantSetID: store.grants.ID,
		GrantsSHA256: store.grants.SHA256, PolicyGeneration: store.policy.Generation,
		CWD: store.lane.Workspace.LogicalCWD}
}

func TestScopedHumanReadAuthority(t *testing.T) {
	for _, name := range []string{"valid", "principal", "idle", "absolute", "revoked"} {
		t.Run(name, func(t *testing.T) {
			s, _, _, scope, request := serviceFixture(t)
			connection := scope.Connection.(*scopeConnection)
			connection.binding.Class = api.EndpointHuman
			connection.binding.Target, connection.binding.LaunchID = nil, ""
			scope.Actor.Kind, scope.Actor.LifeID, scope.LaunchID = "human", "", ""
			request.Context.Target = api.LifeRef{LifeID: "life-a", Run: 1}
			expires := api.Timestamp(s.deps.Clock.Now().Add(time.Minute).UTC().Format(time.RFC3339Nano))
			connection.read = api.ReadAuthority{PrincipalID: scope.Actor.ID, Config: scope.Config,
				EndpointGeneration: 1, SessionID: "read-a", CredentialID: "credential-a", IdleExpiresAt: expires, ExpiresAt: expires}
			switch name {
			case "principal":
				connection.read.PrincipalID = "another-human"
			case "idle":
				connection.read.IdleExpiresAt = "2020-01-01T00:00:00Z"
			case "absolute":
				connection.read.ExpiresAt = "2020-01-01T00:00:00Z"
			case "revoked":
				connection.readErr = problem(api.CodeUnauthenticated, "fixture read authority revoked")
			}
			p := &scopedFitRecorder{}
			s.deps.Clef = p
			_, err := s.FitForScope(context.Background(), scope, request)
			if name == "valid" {
				if err != nil || p.calls != 1 {
					t.Fatal("live human authority was rejected")
				}
			} else {
				errorCode(t, err, api.CodeUnauthenticated)
				if p.calls != 0 {
					t.Fatal("stale human authority reached fit")
				}
			}
		})
	}
}

func (p *scopedFitRecorder) Fit(ctx context.Context, request api.JudgeRequest) (api.TokenFit, error) {
	p.calls++
	p.request = request
	body, _, err := wire.Payload(request)
	return api.TokenFit{InputBytes: len(body), Reason: "fixture fit without a tokenizer"}, err
}

func scopeDecision() api.DecisionCandidate {
	return api.DecisionCandidate{ID: "decision-a", Text: "Keep the build plan complete.",
		Source:      api.SourceRef{ID: "source-a", SHA256: wire.Digest([]byte("source")), Generation: 1},
		EffectiveAt: "2026-01-01T00:00:00Z",
		Authority:   api.DecisionAuthority{Kind: "human", ReceiptID: "receipt-a", SourceSeq: 1},
		AppliesTo:   api.DecisionApplicability{Levels: []int{}, Roles: []string{}, ProjectIDs: []api.ID{}, LifeIDs: []api.ID{}}}
}

func TestScopedFitUsesLiveState(t *testing.T) {
	for _, purpose := range []string{"preview", "blacklist", "guidance"} {
		t.Run(purpose, func(t *testing.T) {
			s, store, _, scope, request := serviceFixture(t)
			request.Purpose = purpose
			request.Config, request.Context = store.policy.Judge, scopedContext(store)
			if purpose == "blacklist" {
				rule := store.policy.Rules[0]
				request.Rules = []api.JudgeRule{{ID: rule.ID, Text: rule.Text,
					SourceSHA256: rule.Source.SHA256, CriteriaVersion: wire.CriteriaVersion}}
			} else if purpose == "guidance" {
				request.Command = nil
				store.decisions = []api.DecisionCandidate{scopeDecision()}
				request.Decisions = append([]api.DecisionCandidate(nil), store.decisions...)
			}
			p := &scopedFitRecorder{}
			s.deps.Clef = p
			got, err := s.FitForScope(context.Background(), scope, request)
			if err != nil || p.calls != 1 || got.InputBytes < 1 || got.Proved ||
				!bytes.Equal(p.request.Task, store.task) || p.request.Context.Target != store.turn.Target ||
				p.request.Context.LogicalTurnID != store.turn.LogicalTurnID || p.request.Config != store.policy.Judge {
				t.Fatal("scoped fit lost live state")
			}
			if purpose == "guidance" && !reflect.DeepEqual(p.request.Decisions, store.decisions) {
				t.Fatal("scoped fit lost decision authority")
			}
		})
	}
}

func TestScopedPreviewSingleBatch(t *testing.T) {
	for _, size := range []int{12, 13} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			s, store, _, scope, request := serviceFixture(t)
			for i := 1; i < size; i++ {
				rule := store.policy.Rules[0]
				rule.ID = api.ID(fmt.Sprintf("rule-%d", i))
				store.policy.Rules = append(store.policy.Rules, rule)
			}
			p := &scopedFitRecorder{}
			s.deps.Clef = p
			_, err := s.FitForScope(context.Background(), scope, request)
			if size == 12 {
				if err != nil || p.calls != 1 || len(p.request.Rules) != size {
					t.Fatal("scoped preview lost rules")
				}
				return
			}
			errorCode(t, err, api.CodeUnscored)
			_, err = s.JudgeAsk(context.Background(), scope, request)
			errorCode(t, err, api.CodeUnscored)
			if p.calls != 0 {
				t.Fatal("scoped preview truncated its rule set")
			}
		})
	}
}

func TestScopedFitRejectsChangedFacts(t *testing.T) {
	for _, name := range []string{"connection", "peer", "lifetime", "frame", "revision", "run", "launch", "task", "turn", "grants", "metadata", "bytes", "rule", "decision", "authority"} {
		t.Run(name, func(t *testing.T) {
			s, store, _, scope, request := serviceFixture(t)
			p := &scopedFitRecorder{}
			s.deps.Clef = p
			want := api.CodeForbidden
			switch name {
			case "connection":
				scope.Connection, want = nil, api.CodeUnauthenticated
			case "peer":
				scope.Connection.(*scopeConnection).peer, want = nil, api.CodeUnauthenticated
			case "lifetime":
				scope.Connection.(*scopeConnection).peer.(*scopePeer).err = problem(api.CodeUnauthenticated, "fixture connector ended")
				want = api.CodeUnauthenticated
			case "frame":
				scope.Frame.(*scopeFrame).err = problem(api.CodeForbidden, "fixture mixed writer")
			case "revision":
				scope.Connection.(*scopeConnection).binding.ContractRevision, want = "v2.0-draft.2", api.CodeUnauthenticated
			case "run":
				scope.Connection.(*scopeConnection).binding.Target.Run++
				want = api.CodeConflict
			case "launch":
				store.lane.LaunchID, want = "other-launch", api.CodeConflict
			case "task":
				request.Task = []byte("another task")
			case "turn":
				store.turn.PolicyGeneration++
				want = api.CodeConflict
			case "grants":
				store.grants.PolicyGeneration++
			case "metadata":
				store.badMetadata, want = true, api.CodeIntegrity
			case "bytes":
				store.badBytes, want = true, api.CodeIntegrity
			case "rule":
				request.Purpose, request.Rules = "blacklist", testRequest().Rules
				request.Config, request.Context = store.policy.Judge, scopedContext(store)
			case "decision", "authority":
				request.Purpose, request.Command = "guidance", nil
				request.Config, request.Context = store.policy.Judge, scopedContext(store)
				store.decisions = []api.DecisionCandidate{scopeDecision()}
				request.Decisions = []api.DecisionCandidate{scopeDecision()}
				if name == "decision" {
					request.Decisions[0].Text += " changed"
				} else {
					store.decisions[0].Authority.ReceiptID = ""
					request.Decisions[0] = store.decisions[0]
					want = api.CodeIntegrity
				}
			}
			_, err := s.FitForScope(context.Background(), scope, request)
			errorCode(t, err, want)
			if p.calls != 0 {
				t.Fatal("invalid scope reached fit")
			}
		})
	}
}

func TestCacheDecisionBindings(t *testing.T) {
	provider := &countingJudge{}
	_, store, _, _, request := serviceFixture(t)
	request = testRequest()
	request.Purpose, request.Command, request.Rules = "guidance", nil, []api.JudgeRule{}
	request.Decisions = []api.DecisionCandidate{scopeDecision()}
	cache, err := NewCache(provider, request.Config, &testClock{}, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cache.Evaluate(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"receipt", "sequence", "applicability"} {
		next := request
		next.Decisions = []api.DecisionCandidate{scopeDecision()}
		switch field {
		case "receipt":
			next.Decisions[0].Authority.ReceiptID = "receipt-b"
		case "sequence":
			next.Decisions[0].Authority.SourceSeq++
		case "applicability":
			next.Decisions[0].AppliesTo.LifeIDs = []api.ID{store.lane.LifeID}
		}
		before := provider.calls.Load()
		if _, err := cache.Evaluate(context.Background(), next); err != nil || provider.calls.Load() != before+1 {
			t.Fatal("changed authority reused a score")
		}
	}
}
