package cli

import (
	"context"
	"encoding/json"
	"strings"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/grants/manifest"
)

func init() {
	for _, entry := range []struct {
		method   api.Method
		validate func(json.RawMessage) error
	}{
		{"grants.root", lbV2GrantsInput(manifest.RootInput)},
		{"grants.enroll", lbV2GrantsInput(manifest.EnrollmentInput)},
		{"grants.validate", lbV2GrantsInput(manifest.ValidateInput)},
		{"grants.get", lbV2GrantsInput(manifest.GetInput)},
		{"grants.revoke", lbV2GrantsInput(manifest.RevokeInput)},
		{"grants.test-child", lbV2GrantsInput(manifest.TestChildInput)},
	} {
		if err := RegisterInputValidator(entry.method, "lb-v2-grants", entry.validate); err != nil {
			panic(err)
		}
	}
}

func lbV2GrantsInput[Request any](validate func(Request) error) func(json.RawMessage) error {
	return func(raw json.RawMessage) error {
		var request Request
		if err := api.DecodeObject(raw, &request); err != nil {
			return err
		}
		return validate(request)
	}
}

// The common dispatcher handles --request and every binding/proof/retry flag.
// A positional file uses that same InvokeRaw path and borrowed connection.
func runGrantsRoot(ctx context.Context, call Invocation) error      { return lbV2GrantsCall(ctx, call) }
func runGrantsEnroll(ctx context.Context, call Invocation) error    { return lbV2GrantsCall(ctx, call) }
func runGrantsValidate(ctx context.Context, call Invocation) error  { return lbV2GrantsCall(ctx, call) }
func runGrantsGet(ctx context.Context, call Invocation) error       { return lbV2GrantsCall(ctx, call) }
func runGrantsRevoke(ctx context.Context, call Invocation) error    { return lbV2GrantsCall(ctx, call) }
func runGrantsTestChild(ctx context.Context, call Invocation) error { return lbV2GrantsCall(ctx, call) }

func lbV2GrantsCall(ctx context.Context, call Invocation) error {
	if len(call.Args) != 1 || strings.HasPrefix(call.Args[0], "-") {
		return manifest.Invalid("grant commands require --request FILE with the exact typed body")
	}
	raw, err := ReadInput(call.Args[0], api.MaxFrameBytes)
	if err != nil {
		return err
	}
	return call.InvokeRaw(ctx, raw)
}
