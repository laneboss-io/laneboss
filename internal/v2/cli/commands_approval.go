package cli

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strings"
	"syscall"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/approval"
	"laneboss.io/laneboss/internal/v2/client"
)

func init() {
	for _, entry := range []struct {
		method   api.Method
		validate func(json.RawMessage) error
	}{
		{"org.change.propose", approvalFileInput(approval.ValidatePropose)},
		{"org.change.get", approvalFileInput(approval.ValidateGet)},
		{"org.change.approve", approvalFileInput(approval.ValidateApprove)},
		{"org.change.apply", approvalFileInput(approval.ValidateApply)},
	} {
		if err := RegisterInputValidator(entry.method, "lb-v2-approval", entry.validate); err != nil {
			panic(err)
		}
	}
}

func approvalFileInput[Request any](validate func(Request) error) func(json.RawMessage) error {
	return func(raw json.RawMessage) error {
		var request Request
		if err := approval.DecodeJSON(raw, &request); err != nil {
			return err
		}
		return validate(request)
	}
}

// Approval clients accept the exact frozen request object in --request-file.
// Source files are uploaded separately through the bounded blob API; no command
// opens canonical org paths or calls legacy mutation/render handlers.
// The four runOrgChange names are frozen dispatch slots. All lane-private
// helpers below retain the approval prefix in this shared package.
func runOrgChangePropose(ctx context.Context, call Invocation) error {
	return approvalCall(ctx, call, api.Method("org.change.propose"), false,
		approval.ValidatePropose, approval.ValidateProposeResult)
}

func runOrgChangeGet(ctx context.Context, call Invocation) error {
	return approvalCall(ctx, call, api.Method("org.change.get"), false,
		approval.ValidateGet, approval.ValidateGetResult)
}

func runOrgChangeApprove(ctx context.Context, call Invocation) error {
	return approvalCall(ctx, call, api.Method("org.change.approve"), true,
		approval.ValidateApprove, approval.ValidateApproveResult)
}

func runOrgChangeApply(ctx context.Context, call Invocation) error {
	return approvalCall(ctx, call, api.Method("org.change.apply"), false,
		approval.ValidateApply, approval.ValidateApplyResult)
}

type approvalOptions struct {
	requestFile string
	proofFile   string
	requestID   api.ID
	key         api.ID
}

func approvalCall[Request, Result any](ctx context.Context, call Invocation, method api.Method,
	needsProof bool, validate func(Request) error, validateResult func(Request, Result) error) (resultErr error) {
	if call.Method != method {
		return approvalInputError("approval command does not match its RPC method")
	}
	options, err := approvalFlags(call, needsProof, method != "org.change.get")
	if err != nil {
		return err
	}
	raw, err := approvalFile(options.requestFile, api.MaxFrameBytes)
	if err != nil {
		return err
	}
	var params Request
	if err = approval.DecodeJSON(raw, &params); err != nil {
		return err
	}
	if err = validate(params); err != nil {
		return err
	}
	digest, err := api.RequestDigest(api.Request{Protocol: api.Protocol, Schema: api.SchemaVersion,
		Config: call.Config, Method: method, Params: raw})
	if err != nil {
		return err
	}
	request := api.Request{Protocol: api.Protocol, Schema: api.SchemaVersion,
		Config: call.Config, Method: method, Params: raw, RequestSHA256: digest,
		RequestID: options.requestID, IdempotencyKey: options.key}
	var sessionRequest *api.Request
	if options.proofFile != "" {
		proofBytes, err := approvalFile(options.proofFile, 4096)
		if err != nil {
			return err
		}
		var proof api.ProofRef
		if err = approval.DecodeJSON(proofBytes, &proof); err != nil {
			return err
		}
		if needsProof {
			if err = approval.ValidateProofRef(proof, digest); err != nil {
				return err
			}
			request.Proof = &proof
		} else {
			intent, err := api.RequestDigest(api.Request{Protocol: api.Protocol, Schema: api.SchemaVersion,
				Config: call.Config, Method: "human.session", Params: json.RawMessage(`{}`)})
			if err != nil {
				return err
			}
			if err = approval.ValidateProofRef(proof, intent); err != nil {
				return err
			}
			session, err := integrateSessionRequest(call.Config, proof)
			if err != nil {
				return err
			}
			sessionRequest = &session
		}
	}
	frame, err := json.Marshal(request)
	if err != nil || len(frame) > api.MaxFrameBytes {
		return approvalInputError("approval request exceeds the socket frame bound")
	}
	prototype := call.Client
	if prototype == nil {
		options := client.Options{Config: call.Config}
		if call.integrateSocket != nil {
			options = call.integrateSocket.options
		}
		prototype = &client.Client{Options: options}
	}
	request, err = prototype.PrepareRequest(request)
	if err != nil {
		return err
	}
	connection, closeOwned, err := approvalConnection(ctx, call, prototype.Options)
	if err != nil {
		return err
	}
	if closeOwned != nil {
		defer func() {
			if err := closeOwned(); err != nil {
				resultErr = errors.Join(resultErr, err)
			}
		}()
	}
	if sessionRequest != nil {
		response, err := connection.Call(ctx, *sessionRequest)
		if err != nil {
			return err
		}
		if err := approvalSessionResponse(call.Config, *sessionRequest, response); err != nil {
			return err
		}
	}
	response, err := connection.Call(ctx, request)
	if err != nil {
		return err
	}
	if err := approvalEnvelope(request, response); err != nil {
		return err
	}
	var result Result
	if err = approval.DecodeJSON(response.Result, &result); err != nil {
		return approvalReplyError()
	}
	if change, ok := any(result).(api.ChangeRequest); ok && change.Config != call.Config {
		return approvalReplyError()
	}
	if err = validateResult(params, result); err != nil {
		return err
	}
	if call.Stdout == nil {
		return approvalReplyError()
	}
	if err = json.NewEncoder(call.Stdout).Encode(result); err != nil {
		return &api.Error{Code: api.CodeUnavailable, Message: "could not write approval result",
			Instead: "Retain the idempotency key and query the original operation before retrying.", Owner: "lb-v2-approval"}
	}
	return nil
}

func approvalConnection(ctx context.Context, call Invocation, options client.Options) (integrateRPCClient, func() error, error) {
	if call.Client != nil {
		return call.Client, nil, nil // Already open; its caller owns the lifetime.
	}
	if socket := call.integrateSocket; socket != nil {
		if socket.connection == nil {
			opened, err := client.Open(ctx, socket.options)
			if err != nil {
				return nil, nil, err
			}
			socket.connection = opened
		}
		return socket.connection, nil, nil // RunContext closes the shared owner.
	}
	opened, err := client.Open(ctx, options)
	if err != nil {
		return nil, nil, err
	}
	return opened, opened.Close, nil
}

func approvalEnvelope(request api.Request, response api.Response) error {
	if response.Protocol != api.Protocol || response.Schema != api.SchemaVersion || response.RequestID != request.RequestID ||
		(response.Error == nil) == (len(response.Result) == 0) {
		return approvalReplyError()
	}
	if response.Error != nil {
		return response.Error
	}
	return nil
}

func approvalSessionResponse(config string, request api.Request, response api.Response) error {
	if err := approvalEnvelope(request, response); err != nil {
		return err
	}
	var session api.HumanSession
	if err := approval.DecodeJSON(response.Result, &session); err != nil || session.Config != config || !approvalOpaqueID(session.ID, 1) {
		return approvalReplyError()
	}
	expires, err := time.Parse(time.RFC3339Nano, string(session.ExpiresAt))
	if err != nil || !strings.HasSuffix(string(session.ExpiresAt), "Z") || expires.Format(time.RFC3339Nano) != string(session.ExpiresAt) {
		return approvalReplyError()
	}
	idle, err := time.Parse(time.RFC3339Nano, string(session.IdleExpiresAt))
	if err != nil || !strings.HasSuffix(string(session.IdleExpiresAt), "Z") || idle.Format(time.RFC3339Nano) != string(session.IdleExpiresAt) || idle.After(expires) {
		return approvalReplyError()
	}
	return nil
}

func approvalFlags(call Invocation, needsProof, needsKey bool) (approvalOptions, error) {
	options := approvalOptions{proofFile: call.ProofFile, requestID: call.RequestID, key: call.IdempotencyKey}
	args := call.Args
	seen := make(map[string]bool)
	seen["--proof-file"] = options.proofFile != ""
	seen["--request-id"] = options.requestID != ""
	seen["--idempotency-key"] = options.key != ""
	for i := 0; i < len(args); i++ {
		name, value, inline := strings.Cut(args[i], "=")
		if seen[name] {
			return options, approvalInputError("duplicate approval option")
		}
		seen[name] = true
		switch name {
		case "--request-file", "--proof-file", "--idempotency-key", "--request-id":
		default:
			return options, approvalInputError("unknown approval option; pass --request-file PATH")
		}
		if !inline {
			i++
			if i == len(args) {
				return options, approvalInputError("approval option requires a value")
			}
			value = args[i]
		}
		if value == "" || strings.HasPrefix(value, "--") {
			return options, approvalInputError("approval option requires a value")
		}
		switch name {
		case "--request-file":
			options.requestFile = value
		case "--proof-file":
			options.proofFile = value
		case "--request-id":
			options.requestID = api.ID(value)
		case "--idempotency-key":
			options.key = api.ID(value)
		}
	}
	if options.requestFile == "" || needsProof && options.proofFile == "" || needsKey && !needsProof && options.proofFile != "" {
		return options, approvalInputError("pass --request-file PATH; approval requires its proof and a human read may supply a session proof")
	}
	if needsKey && options.key == "" {
		return options, approvalInputError("approval mutations require an explicit --idempotency-key; retain it with the exact request file")
	}
	for _, id := range []*api.ID{&options.requestID, &options.key} {
		if *id == "" {
			generated, err := client.NewRequestID()
			if err != nil {
				return options, err
			}
			*id = generated
		} else if !approvalOpaqueID(*id, 22) {
			return options, approvalInputError("request IDs and idempotency keys need at least 128 random bits and valid ID characters")
		}
	}
	return options, nil
}

func approvalOpaqueID(id api.ID, minimum int) bool {
	if len(id) < minimum || len(id) > 128 {
		return false
	}
	for _, c := range id {
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-' {
			continue
		}
		return false
	}
	return true
}

func approvalFile(name string, maximum int64) ([]byte, error) {
	file, err := os.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, approvalInputError("approval input file could not be opened as an ordinary file")
	}
	info, statErr := file.Stat()
	if statErr != nil || !info.Mode().IsRegular() || info.Size() > maximum {
		if err = file.Close(); err != nil {
			return nil, approvalInputError("approval input file could not be closed")
		}
		return nil, approvalInputError("approval input file is not ordinary or exceeds its bound")
	}
	data, readErr := io.ReadAll(io.LimitReader(file, maximum+1))
	closeErr := file.Close()
	if readErr != nil || closeErr != nil || len(data) == 0 || int64(len(data)) > maximum {
		return nil, approvalInputError("approval input file is empty, unreadable or exceeds its bound")
	}
	return data, nil
}

func approvalInputError(message string) *api.Error {
	return &api.Error{Code: api.CodeInvalid, Message: message,
		Instead: "Use the frozen approval request in --request-file PATH; obtain exact per-change confirmation with --proof-file PATH for approval.",
		Owner:   "lb-v2-approval"}
}

func approvalReplyError() *api.Error {
	return &api.Error{Code: api.CodeIntegrity, Message: "approval service response is inconsistent with the request or frozen schema",
		Instead: "Retain the request, response and idempotency key for independent review.", Owner: "lb-v2-approval"}
}
