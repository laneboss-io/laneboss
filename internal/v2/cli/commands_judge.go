package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"math"
	"os"
	"strings"
	"syscall"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/judge"
	"laneboss.io/laneboss/internal/v2/judge/wire"
)

func init() {
	if err := RegisterInputValidator("judge.ask", "lb-v2-judge", func(raw json.RawMessage) error {
		_, err := judge.DecodeAskInput(raw)
		return err
	}); err != nil {
		panic(err)
	}
	if err := RegisterInputValidator("judge.list", "lb-v2-judge", func(raw json.RawMessage) error {
		_, err := judge.DecodeListInput(raw)
		return err
	}); err != nil {
		panic(err)
	}
}

// runJudgeAsk maps file/flag inputs to api.JudgeRequest, then calls judge.ask.
func runJudgeAsk(ctx context.Context, call Invocation) error {
	raw, err := lbV2Judge2RequestFile(call.Args, true)
	if err != nil {
		return err
	}
	if _, err := judge.DecodeAskInput(raw); err != nil {
		return err
	}
	var reply api.JudgeReply
	if err := lbV2Judge2Call(ctx, call, "judge.ask", raw, &reply); err != nil {
		return err
	}
	if err := lbV2Judge2ValidReply(reply); err != nil {
		return err
	}
	return json.NewEncoder(call.Stdout).Encode(reply)
}

// runJudgeList maps file/flag inputs to api.Empty, then calls judge.list.
func runJudgeList(ctx context.Context, call Invocation) error {
	raw, err := lbV2Judge2RequestFile(call.Args, false)
	if err != nil {
		return err
	}
	if _, err := judge.DecodeListInput(raw); err != nil {
		return err
	}
	var view api.ConfigView
	if err := lbV2Judge2Call(ctx, call, "judge.list", raw, &view); err != nil {
		return err
	}
	if view.Sources == nil || view.Warnings == nil ||
		!wire.ValidID(view.Projection.ID) || !wire.ValidDigest(view.Projection.SHA256) {
		return lbV2Judge2CLIError(api.CodeIntegrity, "judge list returned an invalid projection")
	}
	return json.NewEncoder(call.Stdout).Encode(view)
}

func lbV2Judge2CLIError(code api.ErrorCode, message string) *api.Error {
	return &api.Error{Code: code, Message: message, Owner: "lb-v2-judge",
		Instead: "Use a bounded --request FILE and the installed service binding."}
}

func lbV2Judge2RequestFile(args []string, required bool) ([]byte, error) {
	name := ""
	formatSet := false
	for i := 0; i < len(args); i++ {
		flag, value, equal := strings.Cut(args[i], "=")
		if flag != "--request" && flag != "--format" {
			return nil, lbV2Judge2CLIError(api.CodeInvalid, "unknown judge argument")
		}
		if !equal {
			i++
			if i >= len(args) || strings.HasPrefix(args[i], "--") {
				return nil, lbV2Judge2CLIError(api.CodeInvalid, "missing judge flag value")
			}
			value = args[i]
		}
		if flag == "--format" {
			if formatSet || value != "json" {
				return nil, lbV2Judge2CLIError(api.CodeInvalid, "judge supports one JSON format selection")
			}
			formatSet = true
		} else {
			if name != "" || value == "" || value == "-" {
				return nil, lbV2Judge2CLIError(api.CodeInvalid, "judge requires one request file")
			}
			name = value
		}
	}
	if name == "" {
		if required {
			return nil, lbV2Judge2CLIError(api.CodeInvalid, "judge request file is required")
		}
		return []byte("{}"), nil
	}
	// Nonblocking open avoids waiting for a FIFO before the regular-file check.
	file, err := os.OpenFile(name, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, lbV2Judge2CLIError(api.CodeInvalid, "judge request file cannot be opened")
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > api.MaxFrameBytes {
		return nil, lbV2Judge2CLIError(api.CodeInvalid, "judge request must be a bounded regular file")
	}
	raw, err := io.ReadAll(io.LimitReader(file, api.MaxFrameBytes+1))
	if err != nil || len(raw) > api.MaxFrameBytes {
		return nil, lbV2Judge2CLIError(api.CodeInvalid, "judge request read failed or exceeded bound")
	}
	return raw, nil
}

func lbV2Judge2Call(ctx context.Context, call Invocation, method api.Method, raw []byte, target any) error {
	// The common invocation owns PrepareRequest, retained mutation keys,
	// human.session-before-read, envelope checks and the single shared socket.
	// A supplied Client is borrowed; feature code must not reopen or close it.
	var output bytes.Buffer
	call.Method, call.Stdout = method, &output
	if err := call.InvokeRaw(ctx, raw); err != nil {
		return err
	}
	if output.Len() == 0 || output.Len() > api.MaxFrameBytes+1 {
		return lbV2Judge2CLIError(api.CodeIntegrity, "judge service returned no bounded result")
	}
	if err := wire.DecodeStrict(bytes.TrimSpace(output.Bytes()), target); err != nil {
		return lbV2Judge2CLIError(api.CodeIntegrity, "judge service returned an invalid typed result")
	}
	return nil
}

func lbV2Judge2ValidReply(reply api.JudgeReply) error {
	bad := func() error { return lbV2Judge2CLIError(api.CodeIntegrity, "judge returned an inconsistent score") }
	if !wire.ValidID(reply.ID) || reply.Results == nil ||
		reply.Status != "scored" && reply.Status != "partial" && reply.Status != "unavailable" ||
		!wire.ValidDigest(reply.DeploymentSHA256) || reply.SelectedModel == "" {
		return bad()
	}
	seen := map[api.ID]bool{}
	for _, judgment := range reply.Results {
		if !wire.ValidID(judgment.QuestionID) || seen[judgment.QuestionID] {
			return bad()
		}
		seen[judgment.QuestionID] = true
		if reply.Status == "scored" {
			if judgment.Status != "scored" || judgment.Probability == nil ||
				math.IsNaN(*judgment.Probability) || math.IsInf(*judgment.Probability, 0) ||
				*judgment.Probability < 0 || *judgment.Probability > 1 {
				return bad()
			}
		} else if judgment.Status != "unscored" || judgment.Probability != nil {
			return bad()
		}
	}
	if reply.Status == "scored" && (len(reply.Results) == 0 || reply.UnavailableReason != "" ||
		reply.ReportedModel != reply.SelectedModel || reply.Request == nil ||
		!wire.ValidID(reply.Request.ID) || !wire.ValidDigest(reply.Request.SHA256) ||
		reply.Request.Class != "judge_request" || reply.Request.Bytes != int64(reply.InputBytes)) ||
		reply.Status != "scored" && reply.UnavailableReason == "" {
		return bad()
	}
	batches := map[api.ID]bool{}
	for _, id := range reply.BatchIDs {
		if !wire.ValidID(id) || batches[id] {
			return bad()
		}
		batches[id] = true
	}
	return nil
}
