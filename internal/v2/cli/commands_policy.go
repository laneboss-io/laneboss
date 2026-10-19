package cli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"strconv"
	"strings"

	"laneboss.io/laneboss/internal/v2/api"
	lbV2Policy "laneboss.io/laneboss/internal/v2/policy"
)

func init() {
	if err := RegisterInputValidator("policy.evaluate", "lb-v2-policy", lbV2PolicyEvaluateInput); err != nil {
		panic(err)
	}
	if err := RegisterInputValidator("policy.get", "lb-v2-policy", lbV2PolicyGetInput); err != nil {
		panic(err)
	}
	if err := RegisterInputValidator("config.read", "lb-v2-policy", lbV2PolicyConfigReadInput); err != nil {
		panic(err)
	}
	if err := RegisterInputValidator("config.validate", "lb-v2-policy", lbV2Policy.ValidateConfigValidateInput); err != nil {
		panic(err)
	}
}

func lbV2PolicyGetInput(raw json.RawMessage) error {
	var request api.PolicyGetRequest
	if err := api.DecodeObject(raw, &request); err != nil {
		return err
	}
	return lbV2Policy.ValidateGetInput(request)
}

func lbV2PolicyConfigReadInput(raw json.RawMessage) error {
	var request api.ConfigReadRequest
	if err := api.DecodeObject(raw, &request); err != nil {
		return err
	}
	return lbV2Policy.ValidateConfigReadInput(request)
}

func lbV2PolicyEvaluateInput(raw json.RawMessage) error {
	var request api.PolicyEvaluateRequest
	if err := api.DecodeObject(raw, &request); err != nil {
		return err
	}
	return lbV2Policy.ValidateEvaluateInput(request)
}

func runPolicyGet(ctx context.Context, call Invocation) error {
	options, err := lbV2PolicyParse(call.Args, "request", "format", "life-id")
	if err != nil {
		return err
	}
	request := api.PolicyGetRequest{LifeID: api.ID(options.values["life-id"])}
	raw, err := lbV2PolicyRequest(options, request, "life-id")
	if err != nil {
		return err
	}
	var result api.EffectivePolicy
	if err := lbV2PolicyCall(ctx, call, "policy.get", raw, &result); err != nil {
		return err
	}
	if result.Generation == 0 || result.SHA256 == "" || result.Rules == nil || result.Skip == nil || result.Sources == nil {
		return lbV2PolicyClientError(api.CodeIntegrity, "incomplete effective policy response")
	}
	format := options.values["format"]
	if format == "json" || (format == "" && call.Path != "org blacklist list") {
		return json.NewEncoder(call.Stdout).Encode(result)
	}
	return lbV2Policy.RenderBlacklist(call.Stdout, call.Config, result)
}

func runPolicyEvaluate(ctx context.Context, call Invocation) error {
	options, err := lbV2PolicyParse(call.Args, "request", "format", "life-id", "run", "turn-id", "command-file", "tool", "cwd")
	if err != nil {
		return err
	}
	if err := lbV2PolicyRequireJSON(options); err != nil {
		return err
	}
	var request api.PolicyEvaluateRequest
	if options.values["request"] == "" {
		command := []byte{}
		if file := options.values["command-file"]; file != "" {
			if len(options.argv) != 0 {
				return lbV2PolicyClientError(api.CodeInvalid, "command file and argv are mutually exclusive")
			}
			command, err = lbV2PolicyRead(file, api.MaxFrameBytes)
		} else if len(options.argv) != 0 && call.Path == "org blacklist try" {
			// The shell has already consumed quoting. Preserve argv as an array;
			// never join it into invented shell source or execute a sampled call.
			command, err = json.Marshal(options.argv)
		} else {
			return lbV2PolicyClientError(api.CodeInvalid, "use --request FILE or --command-file FILE")
		}
		if err != nil {
			return err
		}
		request.Target.LifeID = api.ID(options.values["life-id"])
		if value := options.values["run"]; value != "" {
			run, parseErr := strconv.ParseUint(value, 10, 53)
			if parseErr != nil || run == 0 {
				return lbV2PolicyClientError(api.CodeInvalid, "invalid run number")
			}
			request.Target.Run = api.RunNumber(run)
		}
		request.LogicalTurnID = api.ID(options.values["turn-id"])
		cwd := options.values["cwd"]
		if cwd == "" {
			cwd, err = os.Getwd()
			if err != nil {
				return lbV2PolicyClientError(api.CodeUnavailable, "cannot read command working directory")
			}
		}
		tool := options.values["tool"]
		if tool == "" {
			tool = "shell"
		}
		hash := sha256.Sum256(command)
		request.Command = api.CommandData{
			Tool: tool, Command: command, Argv: append([]string{}, options.argv...),
			DeclaredPaths: []string{}, CWD: cwd, RawSHA256: api.Digest(hex.EncodeToString(hash[:])),
		}
		if err := lbV2Policy.ValidateCommandInput(request.Command); err != nil {
			return err
		}
		if err := lbV2Policy.ValidateEvaluateSelection(request.Target, request.LogicalTurnID, true); err != nil {
			return err
		}
		if call.IdempotencyKey == "" {
			return lbV2PolicyClientError(api.CodeInvalid, "mutation requires a retained idempotency key")
		}
		if !lbV2PolicyKeyShape(call.IdempotencyKey) || (call.RequestID != "" && !lbV2PolicyKeyShape(call.RequestID)) {
			return lbV2PolicyClientError(api.CodeInvalid, "invalid retained request key")
		}
		if request.Target.LifeID == "" || request.Target.Run == 0 || request.LogicalTurnID == "" {
			var scope api.Scope
			if err := lbV2PolicyTypedCall(ctx, call, "identity.self", api.Empty{}, &scope); err != nil {
				return err
			}
			if scope.Actor.LifeID == "" {
				return lbV2PolicyClientError(api.CodeInvalid, "a file-backed target is required for human preview")
			}
			var lane api.Lane
			if err := lbV2PolicyTypedCall(ctx, call, "lane.status", api.LifeRef{LifeID: scope.Actor.LifeID}, &lane); err != nil {
				return err
			}
			if request.Target.LifeID == "" {
				request.Target.LifeID = lane.LifeID
			}
			if request.Target.Run == 0 {
				request.Target.Run = lane.Run
			}
			if request.LogicalTurnID == "" {
				request.LogicalTurnID = lane.LogicalTurnID
			}
		}
	}
	raw, err := lbV2PolicyRequest(options, request, "life-id", "run", "turn-id", "command-file", "tool", "cwd")
	if err != nil {
		return err
	}
	var result api.PolicyDecision
	if err := lbV2PolicyCall(ctx, call, "policy.evaluate", raw, &result); err != nil {
		return err
	}
	if result.ID == "" || result.PolicyGeneration == 0 || result.Input.ID == "" || result.Rules == nil ||
		(result.Result != "allow" && result.Result != "warn" && result.Result != "refuse") {
		return lbV2PolicyClientError(api.CodeIntegrity, "incomplete policy decision response")
	}
	if err := json.NewEncoder(call.Stdout).Encode(result); err != nil {
		return err
	}
	return lbV2Policy.HookOutcome(call.Path, result)
}

func runConfigRead(ctx context.Context, call Invocation) error {
	options, err := lbV2PolicyParse(call.Args, "request", "format", "view")
	if err != nil {
		return err
	}
	if err := lbV2PolicyRequireJSON(options); err != nil {
		return err
	}
	view := options.values["view"]
	if view == "" {
		switch call.Path {
		case "config list":
			view = "list"
		case "config path":
			view = "path"
		case "org roles list":
			view = "roles"
		case "org channel read":
			view = "channels"
		case "plugin":
			view = "plugins"
		case "settings":
			view = "settings"
		default:
			view = "show"
		}
	}
	raw, err := lbV2PolicyRequest(options, api.ConfigReadRequest{View: view}, "view")
	if err != nil {
		return err
	}
	var result api.ConfigView
	if err := lbV2PolicyCall(ctx, call, "config.read", raw, &result); err != nil {
		return err
	}
	if result.Generation == 0 || result.Projection.ID == "" || result.Sources == nil || result.Warnings == nil {
		return lbV2PolicyClientError(api.CodeIntegrity, "incomplete configuration response")
	}
	return json.NewEncoder(call.Stdout).Encode(result)
}

func runConfigValidate(ctx context.Context, call Invocation) error {
	options, err := lbV2PolicyParse(call.Args, "request", "format")
	if err != nil {
		return err
	}
	if err := lbV2PolicyRequireJSON(options); err != nil {
		return err
	}
	raw, err := lbV2PolicyRequest(options, api.Empty{})
	if err != nil {
		return err
	}
	var result api.OrgValidation
	if err := lbV2PolicyCall(ctx, call, "config.validate", raw, &result); err != nil {
		return err
	}
	if result.Problems == nil || (result.Valid && len(result.Problems) != 0) {
		return lbV2PolicyClientError(api.CodeIntegrity, "incomplete configuration validation response")
	}
	if err := json.NewEncoder(call.Stdout).Encode(result); err != nil {
		return err
	}
	if !result.Valid {
		return lbV2PolicyClientError(api.CodeInvalid, "configuration validation failed; inspect problems")
	}
	return nil
}

type lbV2PolicyOptions struct {
	values map[string]string
	argv   []string
}

func lbV2PolicyKeyShape(key api.ID) bool {
	if len(key) < 22 || len(key) > 128 {
		return false
	}
	for _, c := range key {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

func lbV2PolicyRequireJSON(options lbV2PolicyOptions) error {
	if format := options.values["format"]; format != "" && format != "json" {
		return lbV2PolicyClientError(api.CodeInvalid, "this policy response uses --format json")
	}
	return nil
}

func lbV2PolicyClientError(code api.ErrorCode, message string) *api.Error {
	return &api.Error{Code: code, Message: message,
		Instead: "Correct the file-backed request or repair the named service dependency."}
}

func lbV2PolicyParse(args []string, names ...string) (lbV2PolicyOptions, error) {
	options := lbV2PolicyOptions{values: map[string]string{}, argv: []string{}}
	allowed := map[string]bool{}
	for _, name := range names {
		allowed[name] = true
	}
	for i := 0; i < len(args); i++ {
		if args[i] == "--" {
			options.argv = append(options.argv, args[i+1:]...)
			break
		}
		if !strings.HasPrefix(args[i], "--") {
			return options, lbV2PolicyClientError(api.CodeInvalid, "unexpected policy positional argument")
		}
		name, value, found := strings.Cut(strings.TrimPrefix(args[i], "--"), "=")
		if !allowed[name] {
			return options, lbV2PolicyClientError(api.CodeInvalid, "unknown policy flag")
		}
		if _, duplicate := options.values[name]; duplicate {
			return options, lbV2PolicyClientError(api.CodeInvalid, "duplicate policy flag")
		}
		if !found {
			i++
			if i == len(args) || strings.HasPrefix(args[i], "--") {
				return options, lbV2PolicyClientError(api.CodeInvalid, "missing policy flag value")
			}
			value = args[i]
		}
		if value == "" {
			return options, lbV2PolicyClientError(api.CodeInvalid, "empty policy flag value")
		}
		options.values[name] = value
	}
	if format := options.values["format"]; format != "" && format != "json" && format != "text" && format != "markdown" {
		return options, lbV2PolicyClientError(api.CodeInvalid, "unknown policy output format")
	}
	return options, nil
}

func lbV2PolicyRead(filename string, limit int64) ([]byte, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, lbV2PolicyClientError(api.CodeInvalid, "policy input file cannot be opened")
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > limit {
		return nil, lbV2PolicyClientError(api.CodeInvalid, "policy input must be a bounded regular file")
	}
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil || int64(len(data)) > limit {
		return nil, lbV2PolicyClientError(api.CodeInvalid, "policy input file cannot be read within bound")
	}
	return data, nil
}

func lbV2PolicyRequest(options lbV2PolicyOptions, request any, exclusive ...string) ([]byte, error) {
	filename := options.values["request"]
	if filename == "" {
		if len(options.argv) != 0 {
			if _, ok := request.(api.PolicyEvaluateRequest); !ok {
				return nil, lbV2PolicyClientError(api.CodeInvalid, "unexpected policy command argv")
			}
		}
		return json.Marshal(request)
	}
	for _, name := range exclusive {
		if options.values[name] != "" {
			return nil, lbV2PolicyClientError(api.CodeInvalid, "request file cannot be combined with request-body flags")
		}
	}
	if len(options.argv) != 0 {
		return nil, lbV2PolicyClientError(api.CodeInvalid, "request file cannot be combined with argv")
	}
	raw, err := lbV2PolicyRead(filename, api.MaxFrameBytes)
	if err != nil {
		return nil, err
	}
	if !json.Valid(raw) {
		return nil, lbV2PolicyClientError(api.CodeInvalid, "policy request is not one JSON value")
	}
	// Preserve exact input bytes. The service validates required fields,
	// duplicates and schema before any mutation; do not silently fill omissions.
	return raw, nil
}

func lbV2PolicyTypedCall(ctx context.Context, call Invocation, method api.Method, request, response any) error {
	raw, err := json.Marshal(request)
	if err != nil {
		return lbV2PolicyClientError(api.CodeInvalid, "policy request cannot be encoded")
	}
	return lbV2PolicyCall(ctx, call, method, raw, response)
}

func lbV2PolicyCall(ctx context.Context, call Invocation, method api.Method, raw []byte, result any) error {
	var output bytes.Buffer
	invoke := call
	invoke.Method, invoke.Stdout = method, &output
	if method != call.Method {
		// Secondary identity/status reads share the socket but never reuse the
		// primary mutation's key, operation proof or alias.
		invoke.Path, invoke.RequestID, invoke.IdempotencyKey, invoke.ProofFile = string(method), "", "", ""
	}
	// InvokeRaw owns common preparation, retained mutation keys, same-socket
	// human.session and response correlation. An explicit Client is borrowed.
	if err := invoke.InvokeRaw(ctx, append(json.RawMessage{}, raw...)); err != nil {
		return err
	}
	if err := api.DecodeObject(output.Bytes(), result); err != nil {
		return lbV2PolicyClientError(api.CodeIntegrity, "invalid typed policy RPC response")
	}
	return nil
}
