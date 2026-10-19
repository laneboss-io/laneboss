//go:build linux

package store_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	judgewire "laneboss.io/laneboss/internal/v2/judge/wire"
	fx "laneboss.io/laneboss/internal/v2/store/testfx"
)

func judgeExecutionFixture(t *testing.T) (*fx.Fixture, api.JudgeExecutionRequest) {
	t.Helper()
	f := fx.Ready(t, true)
	f.Deps.JudgeMaxCostMicros = 100
	f.Deps.JudgeCost = func(_ api.JudgeConfig, input, output int64) (int64, error) { return (input + output + 999) / 1000, nil }
	f.Human = f.LaneScope(t)
	chunk, err := f.State.Blob(context.Background(), f.Execution, api.BlobReadRequest{ObjectID: f.Lane.Task.ID, Limit: api.MaxChunkBytes})
	if err != nil {
		t.Fatal(err)
	}
	task := api.BlobRef{ID: fx.ID(t), Class: "task", Bytes: int64(len(chunk.Data)), SHA256: fx.Digest(chunk.Data)}
	cause := api.InternalIntent{ID: fx.ID(t), Kind: api.InternalObjectRetain, Config: f.Deps.Config, Actor: f.Execution.Actor, RequestedBy: f.Human.Actor}
	if _, err := f.State.Transact(context.Background(), api.Transaction{Scope: f.Execution, Internal: &cause, Writes: api.StateWrites{Objects: []api.ObjectWrite{{ObjectKey: task.ID, Class: task.Class, Bytes: chunk.Data, SHA256: task.SHA256, Origin: "service", ACL: api.ObjectACL{Config: f.Deps.Config, Owner: f.Human.Actor, LifeID: f.Lane.LifeID, Audience: "owner", Generation: 1}}}}}); err != nil {
		t.Fatal(err)
	}
	turn, err := f.State.Turn(context.Background(), f.Human, f.Reservation.Target, f.Lane.LogicalTurnID)
	if err != nil {
		t.Fatal(err)
	}
	f.Lane.Task, turn.Task = task, task
	f.Lane.PolicyGeneration, turn.PolicyGeneration = 2, 2
	f.Human.PolicyGeneration, f.Execution.PolicyGeneration = 2, 2
	f.Replace(t, "turn", turn.LogicalTurnID, turn.Generation, turn)
	policy, err := f.State.Policy(context.Background(), f.Human)
	if err != nil {
		t.Fatal(err)
	}
	policy.Judge = api.JudgeConfig{Provider: api.DefaultJudgeProvider, Model: api.DefaultJudgeModel,
		DeploymentSHA256: fx.Digest([]byte("deployment")), TokenizerSHA256: fx.Digest([]byte("tokenizer")), ContextTokens: 32768,
		MaxBytes: api.MaxJudgeBytes, MaxQuestions: 12, CommandDeadlineMS: 2000, GuidanceDeadlineMS: 5000, OutagePolicy: "critical-only"}
	policy.Context = api.RoleContext{Level: f.Lane.Level, Role: f.Lane.Role}
	policy.Generation = 2
	policy.Rules = []api.Rule{{ID: fx.ID(t), Text: "Do not discard the measured result.", Source: api.SourceRef{ID: fx.ID(t), SHA256: fx.Digest([]byte("rule source")), Generation: 1}}}
	f.Replace(t, "policy", api.ID(f.Deps.Config), policy.Generation, policy)
	f.Lane.BudgetRemaining.SpendMicros = 100
	f.Replace(t, "lane", f.Lane.LifeID, f.Lane.Generation, f.Lane)
	request := api.JudgeRequest{ID: fx.ID(t), Purpose: "preview", Rules: []api.JudgeRule{}, Decisions: []api.DecisionCandidate{},
		Task: []byte{}, Config: policy.Judge, DeadlineMS: 1000, MaxCostMicros: 19,
		Context: api.JudgeContext{Config: f.Deps.Config, Target: f.Reservation.Target, Role: policy.Context, LogicalTurnID: f.Lane.LogicalTurnID,
			GrantSetID: f.Lane.GrantSetID, GrantsSHA256: f.Plan.Inputs.Grants.SHA256, PolicyGeneration: policy.Generation, CWD: f.Lane.Workspace.LogicalCWD}}
	rule := policy.Rules[0]
	request.Rules = []api.JudgeRule{{ID: rule.ID, Text: rule.Text, SourceSHA256: rule.Source.SHA256, CriteriaVersion: "noul-v2"}}
	chunk, err = f.State.Blob(context.Background(), f.Human, api.BlobReadRequest{ObjectID: f.Lane.Task.ID, Limit: api.MaxChunkBytes})
	if err != nil {
		t.Fatal(err)
	}
	request.Task = chunk.Data
	command := []byte("git diff --stat")
	request.Command = &api.CommandData{Tool: "shell", Command: command, RawSHA256: fx.Digest(command), CWD: request.Context.CWD, Argv: []string{"git", "diff", "--stat"}, DeclaredPaths: []string{}}
	f.Admit(t, "judge.ask", request)
	return f, api.JudgeExecutionRequest{Request: request, AttemptID: fx.ID(t), Deadline: api.Timestamp(time.Now().Add(time.Second).UTC().Format(time.RFC3339Nano))}
}

// The tokenizer and provider here are declared input-driven wire fixtures.
// This proves persisted transport/accounting, not Clef calibration or login.
func measuredJudgeAudit(t *testing.T, f *fx.Fixture, request api.JudgeExecutionRequest) (api.JudgeExecution, api.JudgeAudit) {
	t.Helper()
	ctx := context.Background()
	execution, err := f.State.ReserveJudgeExecution(ctx, f.Human, request)
	if err != nil || !execution.Acquired {
		t.Fatal("judge did not acquire its durable egress claim", err)
	}
	worker := api.Scope{Config: f.Deps.Config, Actor: execution.Intent.Actor, PolicyGeneration: 1, Source: "worker"}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(io.LimitReader(r.Body, api.MaxJudgeBytes+1))
		if err != nil {
			t.Error(err)
			return
		}
		var payload struct {
			Model     string
			Questions map[string]json.RawMessage
		}
		if err := json.Unmarshal(body, &payload); err != nil {
			t.Error(err)
			return
		}
		answers := make(map[string]any)
		for id := range payload.Questions {
			answers[id] = map[string]any{"type": "noul", "noul": float64(len(body)%37+51) / 100}
		}
		response := map[string]any{"model": payload.Model, "answers": answers, "usage": map[string]any{"input_tokens": len(body), "output_tokens": len(answers)}, "request": "component-provider"}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(response); err != nil {
			t.Error(err)
		}
	}))
	defer server.Close()
	config := request.Request.Config
	fit := func(ctx context.Context, body []byte) (api.TokenFit, error) {
		return api.TokenFit{Proved: true, InputBytes: len(body), InputTokens: len(body), ContextTokens: config.ContextTokens, TokenizerSHA256: config.TokenizerSHA256}, ctx.Err()
	}
	adapter, err := judgewire.New(judgewire.Options{Endpoint: server.URL, Config: config, SafetyTokens: 32, ReserveMicros: request.Request.MaxCostMicros,
		Fit: fit, Cost: func(input, output int64) (int64, error) { return (input + output + 999) / 1000, nil },
		Retain: func(ctx context.Context, class string, body []byte) (api.BlobRef, error) {
			return f.State.RetainObject(ctx, worker, api.RetainObjectRequest{Intent: execution.Intent, Object: api.ObjectWrite{
				ObjectKey: fx.ID(t), Class: class, SHA256: fx.Digest(body), Bytes: bytes.Clone(body), Origin: "service", InputRefs: []api.BlobRef{},
				ACL: api.ObjectACL{Config: f.Deps.Config, Owner: f.Human.Actor, LifeID: f.Lane.LifeID, Audience: "owner", Generation: 1, Participants: []api.ID{}}}})
		}})
	if err != nil {
		t.Fatal(err)
	}
	proof, err := adapter.Fit(ctx, request.Request)
	if err != nil || !proof.Proved {
		t.Fatal("complete fixture fit refused", err)
	}
	reply, err := adapter.Evaluate(ctx, request.Request)
	if err != nil || reply.Status != "scored" || reply.Request == nil {
		t.Fatal("actual wire request was not scored", err, reply.UnavailableReason)
	}
	audit := api.JudgeAudit{ID: reply.ID, Request: *reply.Request, Reply: reply, Fit: proof, StartedAt: execution.ReservedAt, CompletedAt: api.Timestamp(time.Now().UTC().Format(time.RFC3339Nano))}
	return execution, audit
}

func TestItem4JudgeAuditWire(t *testing.T) {
	f, request := judgeExecutionFixture(t)
	execution, audit := measuredJudgeAudit(t, f, request)
	worker := api.Scope{Config: f.Deps.Config, Actor: execution.Intent.Actor, Source: "worker", PolicyGeneration: 1}
	stored, err := f.State.CompleteJudgeExecution(context.Background(), worker, execution, audit)
	if err != nil || stored.Request != audit.Request || stored.Reply.CostMicros != audit.Reply.CostMicros {
		t.Fatal("measured judge completion was not retained", err)
	}
	if replay, err := f.State.CompleteJudgeExecution(context.Background(), worker, execution, audit); err != nil || replay.Request != audit.Request {
		t.Fatal("lost judge completion reply could not replay its original audit", err)
	}
	if err := f.State.ValidateJudgeExecution(context.Background(), worker, execution); err == nil {
		t.Fatal("completed judge execution retained live send authority")
	}
	replay, err := f.State.ReserveJudgeExecution(context.Background(), f.Human, request)
	if err != nil || replay.Acquired || replay.Audit == nil || !replay.UsageKnown {
		t.Fatal("measured completion did not replay its actual audit", err)
	}
}

func TestItem4JudgeExecutionOneWinner(t *testing.T) {
	f, request := judgeExecutionFixture(t)
	var wg sync.WaitGroup
	type result struct {
		e   api.JudgeExecution
		err error
	}
	results := make(chan result, 4)
	for i := 0; i < 4; i++ {
		input := request
		input.AttemptID = fx.ID(t)
		wg.Add(1)
		go func() {
			defer wg.Done()
			e, err := f.State.ReserveJudgeExecution(context.Background(), f.Human, input)
			results <- result{e, err}
		}()
	}
	wg.Wait()
	close(results)
	winners := 0
	var original api.JudgeExecution
	for r := range results {
		if r.err != nil {
			t.Fatal("durable judge egress reservation refused", r.err)
		}
		if r.e.Acquired {
			winners++
			original = r.e
		}
	}
	if winners != 1 || original.ClaimID == "" || original.Pin == "" {
		t.Fatal("judge did not retain exactly one live claim")
	}
	replay, err := f.State.ReserveJudgeExecution(context.Background(), f.Human, request)
	if err != nil || replay.Acquired || replay.ID != original.ID || replay.Pin != original.Pin {
		t.Fatal("judge reservation replay acquired another send", err)
	}
	worker := api.Scope{Config: f.Deps.Config, Actor: original.Intent.Actor, PolicyGeneration: 1, Source: "worker"}
	if err := f.State.ValidateJudgeExecution(context.Background(), worker, original); err != nil {
		t.Fatal("live winner could not validate", err)
	}
	changed := original
	changed.ClaimID = fx.ID(t)
	if err := f.State.ValidateJudgeExecution(context.Background(), worker, changed); err == nil {
		t.Fatal("foreign judge claim validated")
	}
	if err := f.State.ValidateJudgeExecution(context.Background(), worker, replay); err == nil {
		t.Fatal("observing a claim granted send authority")
	}
}

func TestItem4JudgeExecutionFences(t *testing.T) {
	for _, name := range []string{"foreign", "stale", "missing_approval", "changed_replay", "expired", "budget"} {
		t.Run(name, func(t *testing.T) {
			f, request := judgeExecutionFixture(t)
			scope := f.Human
			switch name {
			case "foreign":
				scope.Config = "foreign"
			case "stale":
				request.Request.Context.Target.Run++
			case "missing_approval":
				f.Deps.JudgeMaxCostMicros = 0
				f.Replace(t, "lane", f.Lane.LifeID, f.Lane.Generation, f.Lane)
			case "expired":
				request.Deadline = "2020-01-01T00:00:00Z"
			case "budget":
				request.Request.MaxCostMicros = 101
			case "changed_replay":
				if _, err := f.State.ReserveJudgeExecution(context.Background(), scope, request); err != nil {
					t.Fatal(err)
				}
				request.Request.MaxCostMicros++
			}
			if result, err := f.State.ReserveJudgeExecution(context.Background(), scope, request); err == nil || result.Acquired {
				t.Fatal("judge execution accepted " + name)
			}
		})
	}
}
