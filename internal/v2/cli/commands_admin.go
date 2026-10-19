package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"regexp"

	"laneboss.io/laneboss/internal/v2/admin"
	"laneboss.io/laneboss/internal/v2/api"
)

func init() {
	if err := RegisterInputValidator("doctor", "lb-v2-admin", admin.ValidateDoctorInput); err != nil {
		panic(err)
	}
}

// The common file form is parsed by Invocation. The ergonomic adapter borrows
// that same socket owner and never opens or closes a caller-owned client.
func runDoctor(ctx context.Context, call Invocation) error {
	if !regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`).MatchString(call.Config) {
		return lbV2AdminInvalid("doctor requires a valid explicit configuration")
	}
	if len(call.Args) != 0 && (len(call.Args) != 2 || call.Args[0] != "--format" || call.Args[1] != "json") {
		return lbV2AdminInvalid("doctor accepts one --format json option")
	}
	var lbV2AdminOutput bytes.Buffer
	lbV2AdminCall := call
	lbV2AdminCall.Method, lbV2AdminCall.Stdout = "doctor", &lbV2AdminOutput
	if err := lbV2AdminCall.InvokeRaw(ctx, json.RawMessage(`{}`)); err != nil {
		return err
	}
	result, err := admin.ParseDoctorHealth(lbV2AdminOutput.Bytes())
	if err != nil {
		return err
	}
	if err := json.NewEncoder(call.Stdout).Encode(result); err != nil {
		return err
	}
	if !result.Ready {
		return &api.Error{Code: api.CodePrerequisite, Message: "doctor reports unavailable administrator or launch prerequisites",
			Instead: "Read the recorded capability reasons and repair them before launching.", Owner: "lb-v2-admin"}
	}
	return nil
}

func lbV2AdminInvalid(message string) *api.Error {
	return &api.Error{Code: api.CodeInvalid, Message: message, Owner: "lb-v2-admin",
		Instead: "Use doctor --config NAME [--format json], or the common --request FILE form with {}."}
}
