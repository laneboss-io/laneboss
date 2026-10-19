package judge

import (
	"context"
	"encoding/json"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/judge/wire"
)

func previewInput() api.JudgeRequest {
	r := testRequest()
	r.Purpose, r.Rules, r.Decisions = "preview", []api.JudgeRule{}, []api.DecisionCandidate{}
	r.Config, r.Context = api.JudgeConfig{}, api.JudgeContext{}
	return r
}

func TestPreviewInputValidation(t *testing.T) {
	for _, change := range []struct {
		name  string
		apply func(*api.JudgeRequest)
	}{
		{"id", func(r *api.JudgeRequest) { r.ID = "" }},
		{"purpose", func(r *api.JudgeRequest) { r.Purpose = "blacklist" }},
		{"rules", func(r *api.JudgeRequest) { r.Rules = testRequest().Rules }},
		{"decisions", func(r *api.JudgeRequest) { r.Decisions = []api.DecisionCandidate{{ID: "decision-a"}} }},
		{"command", func(r *api.JudgeRequest) { r.Command = nil }},
		{"digest", func(r *api.JudgeRequest) { r.Command.RawSHA256 = wire.Digest([]byte("other")) }},
		{"cwd", func(r *api.JudgeRequest) { r.Command.CWD = "relative" }},
		{"tool", func(r *api.JudgeRequest) { r.Command.Tool = " " }},
		{"argv", func(r *api.JudgeRequest) { r.Command.Argv = nil }},
		{"deadline", func(r *api.JudgeRequest) { r.DeadlineMS = 0 }},
		{"cost", func(r *api.JudgeRequest) { r.MaxCostMicros = -1 }},
		{"task", func(r *api.JudgeRequest) { r.Task = []byte{0xff} }},
		{"config", func(r *api.JudgeRequest) { r.Config = testConfig(); r.Config.Provider = "unknown" }},
	} {
		t.Run(change.name, func(t *testing.T) {
			r := previewInput()
			change.apply(&r)
			errorCode(t, ValidatePreviewInput(r), api.CodeInvalid)
			raw, err := json.Marshal(r)
			if err != nil {
				t.Fatal(err)
			}
			_, err = DecodeAskInput(raw)
			errorCode(t, err, api.CodeInvalid)
		})
	}
	for _, configured := range []bool{false, true} {
		r := previewInput()
		if configured {
			r.Config = testConfig()
			r.Config.Provider, r.Config.Model = "", ""
		}
		raw, err := json.Marshal(r)
		if err != nil {
			t.Fatal(err)
		}
		got, err := DecodeAskInput(raw)
		if err != nil || got.ID != r.ID || got.Config != r.Config || got.Command.RawSHA256 != r.Command.RawSHA256 {
			t.Fatal("valid preview input rejected or changed")
		}
	}
}

func TestListInputIsEmpty(t *testing.T) {
	for _, raw := range []string{`null`, `[]`, `{"extra":true}`, `{} {}`, `{"x":1,"x":2}`} {
		_, err := DecodeListInput([]byte(raw))
		errorCode(t, err, api.CodeInvalid)
	}
	if _, err := DecodeListInput([]byte(" \n{}\t")); err != nil {
		t.Fatal("empty list input rejected")
	}
}

func TestJudgeHandlerInput(t *testing.T) {
	s := &Service{}
	r := &registry{handlers: map[api.Method]api.Handler{}}
	if err := s.Register(r); err != nil {
		t.Fatal(err)
	}
	bad := previewInput()
	bad.ID = ""
	raw, err := json.Marshal(bad)
	if err != nil {
		t.Fatal(err)
	}
	for method, body := range map[api.Method]json.RawMessage{"judge.ask": raw, "judge.list": json.RawMessage(`{"extra":true}`)} {
		_, err := r.handlers[method](context.Background(), api.Scope{}, body)
		errorCode(t, err, api.CodeInvalid)
	}
}
