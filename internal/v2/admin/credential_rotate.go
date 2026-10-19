package admin

import (
	"context"
	"flag"
	"io"
	"strings"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/credrotate"
	"laneboss.io/laneboss/internal/v2/secrets/wire"
)

// CredentialRotationOwner is the authenticated protected broker selected by
// the installed administrator. It is intentionally narrow so a CLI cannot
// turn ROTATE into a generic command or material reader.
type CredentialRotationOwner interface {
	RotateCredential(context.Context, credrotate.Request, credrotate.Handlers) (credrotate.Result, error)
}

// ParseCredentialRotateArgs parses the private admin command. Values are
// opaque IDs/metadata only; no path, token, or credential bytes are accepted.
func ParseCredentialRotateArgs(args []string) (credrotate.Request, error) {
	var request credrotate.Request
	if len(args) == 0 || args[0] != credrotate.CredentialRotateCommand {
		return request, wire.Error(api.CodeInvalid, "ROTATE command word is required")
	}
	set := flag.NewFlagSet("ROTATE", flag.ContinueOnError)
	set.SetOutput(io.Discard)
	mode := set.String("mode", "", "credential mode")
	var profileValue, loginValue string
	set.StringVar(&profileValue, "profile-id", "", "enrolled profile handle")
	set.StringVar(&profileValue, "profile", "", "enrolled profile handle")
	set.StringVar(&loginValue, "login-id", "", "canonical login handle")
	set.StringVar(&loginValue, "login", "", "canonical login handle")
	source := set.String("source-handle", "", "current source handle")
	version := set.String("source-version", "", "new source version")
	seen := map[string]bool{}
	for index := 1; index < len(args); index++ {
		arg := args[index]
		if !strings.HasPrefix(arg, "--") || arg == "--" {
			return request, wire.Error(api.CodeInvalid, "ROTATE accepts named metadata flags only")
		}
		name := strings.SplitN(strings.TrimPrefix(arg, "--"), "=", 2)[0]
		if name == "profile" {
			name = "profile-id"
		}
		if name == "login" {
			name = "login-id"
		}
		if set.Lookup(name) == nil || seen[name] {
			return request, wire.Error(api.CodeInvalid, "unknown or duplicate ROTATE flag")
		}
		seen[name] = true
		if !strings.Contains(arg, "=") {
			index++
			if index >= len(args) || strings.HasPrefix(args[index], "-") {
				return request, wire.Error(api.CodeInvalid, "ROTATE flag requires a value")
			}
		}
	}
	if err := set.Parse(args[1:]); err != nil || set.NArg() != 0 {
		return request, wire.Error(api.CodeInvalid, "invalid ROTATE flags")
	}
	request = credrotate.Request{Command: credrotate.CredentialRotateCommand, Mode: *mode,
		ProfileID: api.ID(profileValue), LoginID: api.ID(loginValue), SourceHandle: api.ID(*source), SourceVersion: *version}
	if err := credrotate.ValidateRequest(request); err != nil {
		return credrotate.Request{}, err
	}
	return request, nil
}

// ExecuteCredentialRotate binds the parsed command to the installed owner and
// verifies the returned receipt before a caller may publish it.
func ExecuteCredentialRotate(ctx context.Context, owner CredentialRotationOwner, request credrotate.Request, handlers credrotate.Handlers) (credrotate.Result, error) {
	if owner == nil {
		return credrotate.Result{}, wire.Error(api.CodePrerequisite, "ROTATE requires its authenticated credential owner")
	}
	if err := credrotate.ValidateRequest(request); err != nil {
		return credrotate.Result{}, err
	}
	result, err := owner.RotateCredential(ctx, request, handlers)
	if err != nil {
		return credrotate.Result{}, err
	}
	if result.Command != credrotate.CredentialRotateCommand || result.Mode != request.Mode || result.ProfileID != request.ProfileID ||
		result.LoginID != request.LoginID || !result.QuarantineReleased || request.Mode == credrotate.CredentialModeClaudeAPIKey &&
		(!result.SourceMarked || result.SourceVersion != request.SourceVersion) {
		return credrotate.Result{}, wire.Error(api.CodeIntegrity, "ROTATE owner returned a mismatched completion")
	}
	return result, nil
}
