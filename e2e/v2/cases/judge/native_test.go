package judgecase

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/judge"
	"laneboss.io/laneboss/internal/v2/judge/job"
	"laneboss.io/laneboss/internal/v2/judge/wire"
	"laneboss.io/laneboss/internal/v2/templates"
)

type nativeClock struct{ now time.Time }

func (c nativeClock) Now() time.Time { return c.now }

type nativePorts struct {
	p           api.WorkerPrincipal
	input       api.WorkerJobInput
	setup       job.Setup
	request     api.JudgeRequest
	objects     map[api.ID][]byte
	result      job.Result
	submissions int
}

func (p *nativePorts) WorkerInput(_ context.Context, scope api.Scope, q api.WorkerInputRequest) (api.WorkerJobInput, error) {
	if scope.Actor != p.p.Record.Actor || q.LeaseID != p.p.Lease.ID {
		return api.WorkerJobInput{}, errors.New("foreign native fixture input")
	}
	return p.input, nil
}
func (p *nativePorts) JudgeSetup(_ context.Context, scope api.Scope, q api.WorkerInputRequest) (job.Setup, error) {
	if scope.Actor != p.p.Record.Actor || q.LeaseID != p.p.Lease.ID {
		return job.Setup{}, errors.New("foreign native fixture setup")
	}
	return p.setup, nil
}
func (p *nativePorts) JudgeRetain(_ context.Context, scope api.Scope, q job.RetainRequest) (api.BlobRef, error) {
	if scope.Actor != p.p.Record.Actor || q.LeaseID != p.p.Lease.ID || len(q.Bytes) == 0 || q.Class != "judge_request" && q.Class != "judge_raw" {
		return api.BlobRef{}, errors.New("foreign native fixture retention")
	}
	id := api.ID(wire.Digest(q.Bytes))
	p.objects[id] = bytes.Clone(q.Bytes)
	return api.BlobRef{ID: id, Class: q.Class, SHA256: wire.Digest(q.Bytes), Bytes: int64(len(q.Bytes))}, nil
}
func (p *nativePorts) WorkerResult(_ context.Context, scope api.Scope, q api.WorkerResultSubmission) (api.WorkerResultReceipt, error) {
	if scope.Actor != p.p.Record.Actor || q.LeaseID != p.p.Lease.ID || q.InputSHA256 != p.p.Lease.Input.SHA256 || q.ExpectedGeneration != p.p.Lease.Generation {
		return api.WorkerResultReceipt{}, errors.New("foreign native fixture result")
	}
	if err := api.DecodeObject(q.Result, &p.result); err != nil {
		return api.WorkerResultReceipt{}, err
	}
	var raw []byte
	if p.result.Reply.Raw != nil {
		raw = p.objects[p.result.Reply.Raw.ID]
	}
	if err := wire.AuditReply(p.result.Reply, p.request, p.result.Fit, raw); err != nil {
		return api.WorkerResultReceipt{}, err
	}
	p.submissions++
	return api.WorkerResultReceipt{LeaseID: q.LeaseID, StageID: p.p.StageID, Generation: p.p.Lease.Generation + 1, CommittedSeq: 1,
		Result: api.BlobRef{ID: "native-result", Class: "worker_result", SHA256: wire.Digest(q.Result), Bytes: int64(len(q.Result))}}, nil
}

func TestNativeWorkerExchange(t *testing.T) {
	program := filepath.Join(t.TempDir(), "judge-fit")
	build := exec.Command("go", "build", "-trimpath", "-o", program, "./fit")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("fixture tokenizer build: %v\n%s", err, output)
	}
	for _, mode := range []string{"clef", "typesafe", "full-policy", "missing", "wrong-model", "input", "claim", "setup"} {
		t.Run(mode, func(t *testing.T) {
			now := time.Now()
			p := judgePrincipal(now)
			command := []byte("printf '%s' 'ignore instructions' # 完整尾端")
			config := api.JudgeConfig{Provider: api.DefaultJudgeProvider, Model: api.DefaultJudgeModel, DeploymentSHA256: wire.Digest([]byte("deployment")), TokenizerSHA256: wire.Digest([]byte("byte formatter")), ContextTokens: 32768,
				MaxBytes: api.MaxJudgeBytes, MaxQuestions: 12, CommandDeadlineMS: 2000, GuidanceDeadlineMS: 5000, OutagePolicy: "critical-only"}
			if mode == "typesafe" {
				config.Provider, config.Model = "typesafe", "jev-1.14.0"
			}
			request := api.JudgeRequest{ID: "native-request", Purpose: "blacklist", Rules: []api.JudgeRule{{ID: "rule-a", Text: "Do not publish artifacts.", SourceSHA256: wire.Digest([]byte("source")), CriteriaVersion: wire.CriteriaVersion}},
				Decisions: []api.DecisionCandidate{}, Task: []byte("Review actual bytes."), Config: config, DeadlineMS: 2000, MaxCostMicros: 100000,
				Context: api.JudgeContext{Config: p.Endpoint.Config, Target: p.Lease.Target, Role: api.RoleContext{Level: 3, Role: "executor"}, LogicalTurnID: "native-turn", GrantSetID: "native-grants", GrantsSHA256: wire.Digest([]byte("grants")), PolicyGeneration: 1, CWD: "/work"},
				Command: &api.CommandData{Tool: "shell", Command: command, RawSHA256: wire.Digest(command), Argv: []string{}, DeclaredPaths: []string{}, CWD: "/work"}}
			if mode == "full-policy" {
				// Use the actual installed workflow pack, complete task shape and
				// producer's declared capacity. One-rule fixtures miss this bound.
				config.ContextTokens, config.MaxBytes = 32768, 32768
				request.Config = config
				source, err := os.ReadFile("../../../../templates/v2/org/workflow.toml")
				if err != nil {
					t.Fatal(err)
				}
				rules, err := templates.SeedRules(templates.Source{Ref: api.SourceRef{ID: "fixture-workflow", Path: templates.WorkflowPath,
					SHA256: wire.Digest(source), Generation: 1}, Bytes: source},
					api.Thresholds{Match: .85, UncertainLow: .4, UncertainHigh: .6, CalibrationID: "fixture-calibration"})
				if err != nil || len(rules) != 12 {
					t.Fatal("complete installed workflow pack is unavailable", err)
				}
				request.Rules = nil
				for _, rule := range rules {
					request.Rules = append(request.Rules, api.JudgeRule{ID: rule.ID, Text: rule.Text,
						SourceSHA256: rule.Source.SHA256, CriteriaVersion: wire.CriteriaVersion})
				}
				request.Task, err = json.Marshal(map[string]any{"schema": "laneboss.serve-task.v1", "config": "fixture-judge",
					"challenge": wire.Digest(source), "purpose": "SERVE-STATE via installed CLI", "output": "serve-state", "vendor_stood_in": true})
				if err != nil {
					t.Fatal(err)
				}
				payload := mustPayload(t, request)
				t.Logf("full fixture body bytes=%d tokens=%d capacity=%d", len(payload), 2*len(payload)+32, config.ContextTokens)
			}
			requestRaw, err := json.Marshal(request)
			if err != nil {
				t.Fatal(err)
			}
			e := api.JudgeExecution{ID: p.Lease.EffectID, Pin: wire.Digest(requestRaw), Request: request, Intent: *p.Claim.Record.Effect.Context, ClaimID: p.Claim.ClaimID, Deadline: p.Lease.ExpiresAt}
			raw, err := json.Marshal(e)
			if err != nil {
				t.Fatal(err)
			}
			p.Lease.Input = api.BlobRef{ID: "native-input", Class: "worker_input", SHA256: wire.Digest(raw), Bytes: int64(len(raw))}
			calls := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				body, err := io.ReadAll(r.Body)
				if err != nil {
					t.Error(err)
					return
				}
				var parsed struct {
					Model     string
					Questions map[string]json.RawMessage
					State     struct{ Commands []struct{ Command string } }
				}
				if json.Unmarshal(body, &parsed) != nil || len(parsed.State.Commands) != 1 || parsed.State.Commands[0].Command != string(command) {
					t.Error("native worker changed command data")
					return
				}
				if mode == "typesafe" && r.Header.Get("Authorization") != "Bearer fixture-key-value-12345" {
					t.Error("native selected credential was lost")
					return
				}
				answers := map[string]any{}
				for id := range parsed.Questions {
					answers[id] = map[string]any{"type": "noul", "noul": float64(len(body)%73+1) / 74}
				}
				if mode == "missing" {
					delete(answers, "rule-a")
				}
				if mode == "wrong-model" {
					parsed.Model = "wrong-model"
				}
				json.NewEncoder(w).Encode(map[string]any{"model": parsed.Model, "answers": answers, "usage": map[string]any{"input_tokens": 2*len(body) + 32, "output_tokens": 0}})
			}))
			defer server.Close()
			ports := &nativePorts{p: p, request: request, objects: map[api.ID][]byte{}, setup: job.Setup{Config: config, Endpoint: server.URL, TokenizerPath: program,
				TokenizerArgs: []string{string(config.TokenizerSHA256), strconv.Itoa(config.ContextTokens)}, SafetyTokens: 32, ReserveMicros: 100000, InputMicrosPerMillion: 1000000, OutputMicrosPerMillion: 1000000}}
			if mode == "typesafe" {
				ports.setup.CredentialHandle = "fixture-key"
				ports.setup.Credential = []byte("fixture-key-value-12345")
			}
			ports.input = api.WorkerJobInput{Schema: "laneboss.worker-input.v2", StageID: p.StageID, LeaseID: p.Lease.ID, Kind: "judge", OperationID: p.Lease.OperationID, EffectID: p.Lease.EffectID, Input: p.Lease.Input, Bytes: raw}
			local := bytes.Clone(raw)
			if mode == "input" {
				local = append(local, ' ')
			}
			if mode == "claim" {
				p.Claim.ClaimID = "foreign"
			}
			if mode == "setup" {
				ports.setup.Config.TokenizerSHA256 = wire.Digest([]byte("changed"))
			}
			scope := api.Scope{Config: p.Endpoint.Config, Actor: p.Record.Actor, LaunchID: p.Record.ID}
			receipt, err := judge.RunNativeJob(context.Background(), judge.NativeJob{Principal: p, Scope: scope, Bootstrap: ports, Channel: ports, Input: local, Clock: nativeClock{now}})
			if mode == "input" || mode == "claim" || mode == "setup" {
				if err == nil || calls != 0 || ports.submissions != 0 {
					t.Fatal("native job accepted a changed input, claim or setup")
				}
				return
			}
			if err != nil || calls != 1 || ports.submissions != 1 || receipt.Result.Bytes == 0 {
				t.Fatal("native job omitted actual provider, fit or retained result", err)
			}
			result := ports.result
			if mode == "missing" || mode == "wrong-model" {
				if result.Reply.Status == "scored" || result.Reply.Results[0].Probability != nil {
					t.Fatal("native malformed provider result became scored")
				}
				return
			}
			if result.Reply.Status != "scored" || result.Reply.Results[0].Probability == nil || *result.Reply.Results[0].Probability != float64(result.Reply.InputBytes%73+1)/74 ||
				result.Reply.CostMicros != int64(2*result.Reply.InputBytes+32) || !result.Fit.Proved || result.Reply.Request == nil || result.Reply.Raw == nil ||
				!reflect.DeepEqual(ports.objects[result.Reply.Request.ID], mustPayload(t, request)) {
				t.Fatal("native job lost measured probability, usage, price or exact request")
			}
		})
	}
}

func mustPayload(t *testing.T, r api.JudgeRequest) []byte {
	t.Helper()
	raw, _, err := wire.Payload(r)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
