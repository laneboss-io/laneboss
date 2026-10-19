package judge

import (
	"encoding/json"
	"path"
	"strings"
	"time"
	"unicode/utf8"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/judge/wire"
)

// DecodeAskInput is shared by file/ergonomic CLI input and the service handler.
// It validates local input only; scope, policy and grants still come from the
// authenticated service. An empty config/context is a valid preview claim.
func DecodeAskInput(raw json.RawMessage) (api.JudgeRequest, error) {
	var request api.JudgeRequest
	if len(raw) > api.MaxFrameBytes {
		return request, problem(api.CodeInvalid, "judge RPC exceeds frame bound")
	}
	if err := wire.DecodeStrict(raw, &request); err != nil {
		return request, err
	}
	return request, ValidatePreviewInput(request)
}

// ValidatePreviewInput also protects direct typed JudgeAsk callers. It cannot
// grant dispatch, substitute approved rules or validate a caller's authority.
func ValidatePreviewInput(request api.JudgeRequest) error {
	if request.Purpose != "preview" || !wire.ValidID(request.ID) || request.Command == nil ||
		request.Rules == nil || request.Decisions == nil || len(request.Rules) != 0 || len(request.Decisions) != 0 ||
		request.Task == nil || !utf8.Valid(request.Task) || !wire.ValidateText(request) {
		return problem(api.CodeInvalid, "judge ask requires a valid preview request")
	}
	if request.DeadlineMS < 1 || request.DeadlineMS > int64((1<<63-1)/time.Millisecond) ||
		request.MaxCostMicros < 0 || request.MaxCostMicros > 1<<53-1 {
		return problem(api.CodeInvalid, "invalid judge preview deadline or cost bound")
	}
	command := request.Command
	if len(command.Command) == 0 || !utf8.Valid(command.Command) || strings.TrimSpace(command.Tool) == "" ||
		command.Argv == nil || command.DeclaredPaths == nil || !path.IsAbs(command.CWD) ||
		wire.Digest(command.Command) != command.RawSHA256 {
		return problem(api.CodeInvalid, "invalid exact judge preview command")
	}
	if request.Config != (api.JudgeConfig{}) {
		resolved, err := api.ResolveJudgeConfig(request.Config)
		if err != nil {
			return problem(api.CodeInvalid, "invalid judge preview configuration")
		}
		if err := wire.ValidateConfig(resolved); err != nil {
			return err
		}
	}
	return nil
}

// DecodeListInput accepts precisely one empty JSON object, including legal
// whitespace. Unknown keys, null, arrays, duplicate/trailing input are invalid.
func DecodeListInput(raw json.RawMessage) (api.Empty, error) {
	var request api.Empty
	if len(raw) > api.MaxFrameBytes {
		return request, problem(api.CodeInvalid, "judge RPC exceeds frame bound")
	}
	err := wire.DecodeStrict(raw, &request)
	return request, err
}
