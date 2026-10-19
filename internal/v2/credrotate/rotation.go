// Package credrotate contains the neutral ROTATE contract shared by
// the protected secrets owner, administrator adapter, and private CLI.
package credrotate

import (
	"context"
	"io"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/secrets/bstate"
	"laneboss.io/laneboss/internal/v2/secrets/wire"
)

const (
	CredentialRotateCommand       = "ROTATE"
	CredentialModeCodexFile       = "codex-file"
	CredentialModeClaudeAPIKey    = "claude-api-key"
	CredentialRotationJournalLine = "{\"event\":\"credential.rotated\"}\n"
)

// Request is metadata only. Credential bytes never enter this contract.
type Request struct {
	Command       string `json:"command"`
	Mode          string `json:"mode"`
	ProfileID     api.ID `json:"profile_id"`
	LoginID       api.ID `json:"login_id"`
	SourceHandle  api.ID `json:"source_handle,omitempty"`
	SourceVersion string `json:"source_version,omitempty"`
}

// Result is a names-only completion receipt.
type Result struct {
	Command            string         `json:"command"`
	Mode               string         `json:"mode"`
	ProfileID          api.ID         `json:"profile_id"`
	LoginID            api.ID         `json:"login_id"`
	SourceVersion      string         `json:"source_version,omitempty"`
	Generation         api.Generation `json:"generation"`
	QuarantineReleased bool           `json:"quarantine_released"`
	SourceMarked       bool           `json:"source_marked"`
}

type CanonicalLoginRotator interface {
	RotateCanonicalLogin(context.Context, bstate.Login) (bstate.Login, error)
}

type SourceRotationMarker interface {
	MarkSourceRotated(context.Context, api.SecretGrant, string) (api.SecretGrant, error)
}

type Handlers struct {
	Codex   CanonicalLoginRotator
	Source  SourceRotationMarker
	Journal io.Writer
}

func ValidateRequest(request Request) error {
	if request.Command != CredentialRotateCommand ||
		(request.Mode != CredentialModeCodexFile && request.Mode != CredentialModeClaudeAPIKey) ||
		!wire.ID(string(request.ProfileID)) || !wire.ID(string(request.LoginID)) {
		return wire.Error(api.CodeInvalid, "ROTATE requires one supported mode and exact profile/login handles")
	}
	if request.Mode == CredentialModeClaudeAPIKey &&
		(!wire.ID(string(request.SourceHandle)) || !wire.Name(request.SourceVersion)) {
		return wire.Error(api.CodeInvalid, "claude-api-key ROTATE requires the current source handle and new source version")
	}
	if request.Mode == CredentialModeCodexFile && (request.SourceHandle != "" || request.SourceVersion != "") {
		return wire.Error(api.CodeInvalid, "codex-file ROTATE does not accept source metadata")
	}
	return nil
}
