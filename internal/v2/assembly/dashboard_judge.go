package assembly

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"reflect"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/judge/wire"
)

// This explicitly enrolled fake source supplies no model, native worker,
// semantic calibration or monetary-spend evidence. Policy retains its reply.
type dashboardJudgeSpec struct {
	Schema          string `json:"schema"`
	Fake            bool   `json:"fake"`
	Algorithm       string `json:"algorithm"`
	MaxCostMicros   int64  `json:"max_cost_micros"`
	TokenBlockBytes int    `json:"token_block_bytes"`
}

type dashboardFakeJudge struct {
	spec dashboardJudgeSpec
	pin  api.Digest
}

func dashboardJudgeFromBytes(raw []byte) (*dashboardFakeJudge, error) {
	var spec dashboardJudgeSpec
	if api.DecodeObject(raw, &spec) != nil || spec.Schema != "laneboss.dashboard-judge.v1" || !spec.Fake ||
		spec.Algorithm != "sha256-question-v1" || spec.MaxCostMicros < 1 || spec.MaxCostMicros > 1000000 ||
		spec.TokenBlockBytes < 1 || spec.TokenBlockBytes > 4096 {
		return nil, installError("dashboard fake judge enrollment differs")
	}
	return &dashboardFakeJudge{spec: spec, pin: wire.Digest(raw)}, nil
}

func dashboardJudgeObject(object api.RuntimeObject, body []byte) (*dashboardFakeJudge, error) {
	if object.Role != "dashboard-fake-judge" || object.Mode != 0444 || object.Content.Class != "artifact" ||
		wire.Digest(body) != object.Content.SHA256 || int64(len(body)) != object.Content.Bytes {
		return nil, installError("dashboard fake judge object differs from enrolled runtime bytes")
	}
	return dashboardJudgeFromBytes(body)
}

func (j *dashboardFakeJudge) request(ctx context.Context, scope api.Scope, request api.JudgeRequest) ([]byte, []api.ID, error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	var original api.PolicyEvaluateRequest
	if scope.Request.Method != "policy.evaluate" || scope.Config != request.Context.Config || scope.Frame == nil || scope.Connection == nil ||
		api.DecodeObject(scope.Request.Params, &original) != nil || original.Target != request.Context.Target ||
		original.LogicalTurnID != request.Context.LogicalTurnID || request.Command == nil || !reflect.DeepEqual(original.Command, *request.Command) {
		return nil, nil, &api.Error{Code: api.CodeForbidden, Owner: "lb-v2-dashboard", Message: "fake judge requires its actual policy evaluation", Instead: "Use the enrolled dashboard fixture through policy.evaluate."}
	}
	if err := scope.Frame.Verify(ctx, scope.Connection); err != nil {
		return nil, nil, err
	}
	if request.Config.TokenizerSHA256 != j.pin || request.Config.DeploymentSHA256 != j.pin {
		return nil, nil, installError("fake judge configuration does not pin its enrolled source")
	}
	return wire.Payload(request)
}

func (j *dashboardFakeJudge) FitForScope(ctx context.Context, scope api.Scope, request api.JudgeRequest) (api.TokenFit, error) {
	body, _, err := j.request(ctx, scope, request)
	if err != nil {
		return api.TokenFit{}, err
	}
	tokens := (len(body)+j.spec.TokenBlockBytes-1)/j.spec.TokenBlockBytes + 1
	if len(body) > request.Config.MaxBytes || tokens >= request.Config.ContextTokens {
		return api.TokenFit{}, &api.Error{Code: api.CodeUnscored, Owner: "lb-v2-dashboard", Message: "complete fake judge input exceeds its enrolled bound", Instead: "Publish bounded fixture judge settings through D6."}
	}
	return api.TokenFit{Proved: true, InputBytes: len(body), InputTokens: tokens,
		ContextTokens: request.Config.ContextTokens, TokenizerSHA256: request.Config.TokenizerSHA256,
		Reason: "fake byte-block tokenizer; no model tokenizer claim"}, nil
}

func dashboardFakeProbability(body []byte, id api.ID) float64 {
	material := append(append(append([]byte{}, body...), 0), []byte(id)...)
	digest := sha256.Sum256(material)
	return float64(binary.BigEndian.Uint16(digest[:2])) / 65535
}

func (j *dashboardFakeJudge) EvaluateForScope(ctx context.Context, scope api.Scope, request api.JudgeRequest) (api.JudgeReply, error) {
	body, ids, err := j.request(ctx, scope, request)
	if err != nil {
		return api.JudgeReply{}, err
	}
	fit, err := j.FitForScope(ctx, scope, request)
	if err != nil {
		return api.JudgeReply{}, err
	}
	if request.MaxCostMicros <= 0 || request.MaxCostMicros > j.spec.MaxCostMicros {
		return api.JudgeReply{}, &api.Error{Code: api.CodeBudget, Owner: "lb-v2-dashboard", Message: "fake judge requires an explicit bounded fixture budget", Instead: "Use the fixture's approved finite budget."}
	}
	// Policy retains this complete reply with its actual request and commits
	// the decision. There are no uploaded events or fabricated object refs.
	reply := api.JudgeReply{ID: request.ID, Status: "scored", Results: []api.Judgment{}, BatchIDs: []api.ID{request.ID},
		SelectedModel: request.Config.Model, ReportedModel: "dashboard-fake-sha256-question-v1",
		DeploymentSHA256: request.Config.DeploymentSHA256, InputBytes: len(body), InputTokens: fit.InputTokens}
	for _, id := range ids {
		p := dashboardFakeProbability(body, id)
		reply.Results = append(reply.Results, api.Judgment{QuestionID: id, Status: "scored", Probability: &p,
			Reason: "fake hash-derived fixture score; no semantic inference"})
	}
	return reply, nil
}

var _ api.ScopedJudge = (*dashboardFakeJudge)(nil)
