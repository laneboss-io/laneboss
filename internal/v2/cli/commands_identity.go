package cli

import (
	"context"
	"encoding/json"
	"flag"
	"io"
	"strings"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client"
	"laneboss.io/laneboss/internal/v2/identity"
)

func init() {
	for _, identityMethod := range []api.Method{"identity.self", "human.challenge", "human.confirm", "human.session", "ticket.issue"} {
		identityValidate := func(raw json.RawMessage) error {
			return identity.ValidateInput(identityMethod, raw)
		}
		if identityErr := RegisterInputValidator(identityMethod, "lb-v2-identity", identityValidate); identityErr != nil {
			panic(identityErr)
		}
	}
}

func runIdentitySelf(ctx context.Context, call Invocation) error {
	return identityCall(ctx, call, true)
}

func runHumanChallenge(ctx context.Context, call Invocation) error {
	return identityCall(ctx, call, false)
}

func runHumanConfirm(ctx context.Context, call Invocation) error {
	return identityCall(ctx, call, false)
}

func runHumanSession(ctx context.Context, call Invocation) error {
	for _, arg := range call.Args {
		if arg == "--flow" || strings.HasPrefix(arg, "--flow=") {
			return runSessionFlow(ctx, call)
		}
	}
	return identityCall(ctx, call, true)
}

func runTicketIssue(ctx context.Context, call Invocation) error {
	return identityCall(ctx, call, false)
}

// Common CLI parsing owns request/proof/binding files, correlation and retry
// keys. InvokeRaw uses client.PrepareRequest and preserves the exact file body.
// Only the empty ergonomic forms reach these handlers without --request.
func identityCall(ctx context.Context, call Invocation, empty bool) error {
	identityFlags := flag.NewFlagSet(call.Path, flag.ContinueOnError)
	identityFlags.SetOutput(io.Discard)
	identityFormat := identityFlags.String("format", "json", "output format")
	identitySeen := false
	for identityIndex := 0; identityIndex < len(call.Args); identityIndex++ {
		identityName, identityValue, identityInline := strings.Cut(call.Args[identityIndex], "=")
		if identityName != "--format" || identitySeen {
			return identityCLIError(api.CodeInvalid, "unknown or duplicate identity option")
		}
		identitySeen = true
		if !identityInline {
			identityIndex++
			if identityIndex == len(call.Args) {
				return identityCLIError(api.CodeInvalid, "identity format requires a value")
			}
			identityValue = call.Args[identityIndex]
		}
		if identityValue != "json" {
			return identityCLIError(api.CodeInvalid, "identity output format must be json")
		}
	}
	if identityErr := identityFlags.Parse(call.Args); identityErr != nil || identityFlags.NArg() != 0 || *identityFormat != "json" {
		return identityCLIError(api.CodeInvalid, "invalid identity options")
	}
	if !empty {
		return identityCLIError(api.CodeInvalid, "an exact JSON --request file is required")
	}
	if call.Config == "" || call.Stdout == nil {
		return identityCLIError(api.CodePrerequisite, "configuration and output are required")
	}
	return call.InvokeRaw(ctx, []byte("{}"))
}

func identityCLIError(code api.ErrorCode, message string) *api.Error {
	return &api.Error{Code: code, Message: message, Owner: "lb-v2-identity",
		Instead: "Use --config NAME and the exact JSON --request FILE for this operation."}
}

// This prelude is separate from the root ticket and spawn envelope. It runs
// through the common invocation's already-open client, before any launch call.
func (call Invocation) identitySpawnSession() (api.Request, error) {
	if call.ProofFile != "" || call.Method != "lane.start" && call.Method != "lane.adopt" {
		return api.Request{}, integrateInputError("session proof requires a root spawn without an envelope proof")
	}
	raw, err := ReadInput(call.SessionProofFile, api.MaxFrameBytes)
	if err != nil {
		return api.Request{}, err
	}
	var proof api.ProofRef
	if err := api.DecodeObject(raw, &proof); err != nil {
		return api.Request{}, err
	}
	return integrateSessionRequest(call.Config, proof)
}

// A session receipt may outlive a failed connection bind. Require an actual
// authenticated public read on this socket before the root mutation proceeds.
func (call Invocation) identityCheckPrelude(ctx context.Context, connection integrateRPCClient) error {
	request, err := client.PrepareRequest(api.Request{Config: call.Config, Method: "identity.self", Params: json.RawMessage(`{}`)})
	if err != nil {
		return err
	}
	response, err := connection.Call(ctx, request)
	if err != nil {
		return err
	}
	check := call
	check.Method, check.Stdout = "identity.self", io.Discard
	if err := check.integrateWriteResponse(request, response); err != nil {
		return err
	}
	var current api.Scope
	if err := api.DecodeObject(response.Result, &current); err != nil {
		return err
	}
	if current.Config != call.Config || current.Actor.Kind != "human" || current.Actor.ID == "" ||
		current.EndpointGeneration == 0 || current.PolicyGeneration == 0 || current.LaunchID != "" {
		return identityCLIError(api.CodeUnauthenticated, "session prelude did not establish the current human connection")
	}
	return nil
}
