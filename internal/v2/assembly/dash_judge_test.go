package assembly

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/judge/wire"
)

type dashScoreConnection struct{ api.ConnectionContext }
type dashScoreFrame struct {
	raw     []byte
	failure error
}

func (f dashScoreFrame) Bytes() []byte                                       { return f.raw }
func (f dashScoreFrame) Verify(context.Context, api.ConnectionContext) error { return f.failure }

func fakeScoreFixture(t *testing.T) (*dashboardFakeJudge, api.Scope, api.JudgeRequest) {
	t.Helper()
	judge, err := dashboardJudgeFromBytes([]byte(`{"schema":"laneboss.dashboard-judge.v1","fake":true,"algorithm":"sha256-question-v1","max_cost_micros":1000000,"token_block_bytes":2048}`))
	if err != nil {
		t.Fatal(err)
	}
	command := api.CommandData{Tool: "shell", Command: []byte(t.Name()), Argv: []string{}, DeclaredPaths: []string{}, CWD: "/work/main", RawSHA256: wire.Digest([]byte(t.Name()))}
	public := api.PolicyEvaluateRequest{Target: api.LifeRef{LifeID: "score-life", Run: 2}, LogicalTurnID: "score-turn", Command: command}
	raw, err := json.Marshal(public)
	if err != nil {
		t.Fatal(err)
	}
	scope := api.Scope{Config: "score-config", Request: api.Request{Method: "policy.evaluate", Params: raw},
		Connection: &dashScoreConnection{}, Frame: dashScoreFrame{raw: raw}}
	request := api.JudgeRequest{ID: "score-request", Purpose: "blacklist", Command: &command, Task: []byte{},
		Rules: []api.JudgeRule{{ID: "rule-one", Text: "Retain the fixture input.", SourceSHA256: wire.Digest([]byte("source")), CriteriaVersion: "fixture"},
			{ID: "rule-two", Text: "Retain the fixture result.", SourceSHA256: wire.Digest([]byte("second")), CriteriaVersion: "fixture"}}, Decisions: []api.DecisionCandidate{},
		Config: api.JudgeConfig{Provider: api.DefaultJudgeProvider, Model: api.DefaultJudgeModel, DeploymentSHA256: judge.pin,
			TokenizerSHA256: judge.pin, ContextTokens: 256, MaxBytes: api.MaxJudgeBytes, MaxQuestions: 12,
			CommandDeadlineMS: 1000, GuidanceDeadlineMS: 1000, OutagePolicy: "critical-only"}, DeadlineMS: 1000, MaxCostMicros: 1000000,
		Context: api.JudgeContext{Config: scope.Config, Target: public.Target, LogicalTurnID: public.LogicalTurnID,
			Role: api.RoleContext{Level: 5, Role: "supervisor"}, GrantSetID: "score-grants", GrantsSHA256: wire.Digest([]byte("grants")), PolicyGeneration: 1, CWD: "/work/main"}}
	return judge, scope, request
}

func TestDashboardEntryFakeScore(t *testing.T) {
	judge, scope, request := fakeScoreFixture(t)
	reply, err := judge.EvaluateForScope(context.Background(), scope, request)
	if err != nil {
		t.Fatal(err)
	}
	body, ids, err := wire.Payload(request)
	if err != nil {
		t.Fatal(err)
	}
	if reply.ReportedModel != "dashboard-fake-sha256-question-v1" || len(reply.Results) != len(ids) || reply.InputBytes != len(body) || reply.Request != nil || reply.Raw != nil {
		t.Fatal("fake source lost provenance or invented retained references")
	}
	for index, id := range ids {
		digest := sha256.Sum256(append(append(append([]byte{}, body...), 0), []byte(id)...))
		want := float64(binary.BigEndian.Uint16(digest[:2])) / 65535
		if reply.Results[index].QuestionID != id || reply.Results[index].Probability == nil || *reply.Results[index].Probability != want {
			t.Fatal("fake score ignored complete request or question")
		}
	}
}

func TestDashboardEntryFakeScope(t *testing.T) {
	judge, scope, request := fakeScoreFixture(t)
	request.Context.Target.Run++
	if _, err := judge.EvaluateForScope(context.Background(), scope, request); err == nil {
		t.Fatal("fake source accepted a foreign policy target")
	}
	request.Context.Target.Run--
	scope.Frame = dashScoreFrame{failure: errors.New("native frame changed")}
	if _, err := judge.EvaluateForScope(context.Background(), scope, request); err == nil {
		t.Fatal("fake source accepted a refused frame")
	}
}

func TestDashboardEntryFakeEnrollment(t *testing.T) {
	if _, err := dashboardJudgeFromBytes([]byte(`{"schema":"laneboss.dashboard-judge.v1","fake":false,"algorithm":"sha256-question-v1","max_cost_micros":1000000,"token_block_bytes":2048}`)); err == nil {
		t.Fatal("unmarked source became an enrolled fake judge")
	}
	judge, scope, request := fakeScoreFixture(t)
	request.Config.MaxBytes = 1
	if _, err := judge.FitForScope(context.Background(), scope, request); err == nil {
		t.Fatal("fake source ignored its complete byte bound")
	}
}

func TestDashboardEntryFakePins(t *testing.T) {
	judge, scope, request := fakeScoreFixture(t)
	request.Config.TokenizerSHA256 = wire.Digest([]byte("another tokenizer"))
	if _, err := judge.FitForScope(context.Background(), scope, request); err == nil {
		t.Fatal("fake source accepted another tokenizer deployment pin")
	}
}

func TestDashboardEntryFakeBinding(t *testing.T) {
	raw := []byte(`{"schema":"laneboss.dashboard-judge.v1","fake":true,"algorithm":"sha256-question-v1","max_cost_micros":29,"token_block_bytes":2048}`)
	object := api.RuntimeObject{Role: "dashboard-fake-judge", Mode: 0444, Content: api.BlobRef{ID: "actual-fake-source", Class: "artifact", SHA256: wire.Digest(raw), Bytes: int64(len(raw))}}
	source, err := dashboardJudgeObject(object, raw)
	if err != nil || source.spec.MaxCostMicros != 29 {
		t.Fatal("fake source lost its protected object or explicit bound", err)
	}
	object.Content.SHA256 = wire.Digest([]byte("another source"))
	if _, err := dashboardJudgeObject(object, raw); err == nil {
		t.Fatal("fake source accepted bytes outside its runtime pin")
	}
}
