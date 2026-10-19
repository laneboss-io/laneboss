package cli

import (
	"context"
	"encoding/json"
	"io"

	"laneboss.io/laneboss/internal/v2/admin"
	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/credrotate"
	"laneboss.io/laneboss/internal/v2/secrets/wire"
)

// CredentialRotateCaller is supplied by the installed private owner adapter.
// The public dispatcher does not open this port from a caller-selected socket.
type CredentialRotateCaller interface {
	RotateCredential(context.Context, credrotate.Request, credrotate.Handlers) (credrotate.Result, error)
}

// RunCredentialRotateCommand is the CLI-facing adapter for the private ROTATE
// command. It parses metadata through the admin owner and emits a names-only
// JSON receipt after checking the owner result.
func RunCredentialRotateCommand(ctx context.Context, args []string, caller CredentialRotateCaller, handlers credrotate.Handlers, stdout io.Writer) error {
	if caller == nil || stdout == nil {
		return wire.Error(api.CodePrerequisite, "ROTATE requires its installed owner and output")
	}
	request, err := admin.ParseCredentialRotateArgs(args)
	if err != nil {
		return err
	}
	result, err := caller.RotateCredential(ctx, request, handlers)
	if err != nil {
		return err
	}
	if result.Command != credrotate.CredentialRotateCommand || result.Mode != request.Mode || result.ProfileID != request.ProfileID ||
		result.LoginID != request.LoginID || !result.QuarantineReleased || request.Mode == credrotate.CredentialModeClaudeAPIKey &&
		(!result.SourceMarked || result.SourceVersion != request.SourceVersion) {
		return wire.Error(api.CodeIntegrity, "ROTATE CLI receipt differs from the protected owner result")
	}
	if err := json.NewEncoder(stdout).Encode(result); err != nil {
		return wire.Error(api.CodeUnavailable, "ROTATE CLI receipt could not be written")
	}
	return nil
}
