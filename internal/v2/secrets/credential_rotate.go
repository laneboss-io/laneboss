package secrets

import (
	"context"
	"errors"
	"io"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/credrotate"
	"laneboss.io/laneboss/internal/v2/secrets/bstate"
	"laneboss.io/laneboss/internal/v2/secrets/wire"
)

type CredentialRotationRequest = credrotate.Request
type CredentialRotationResult = credrotate.Result
type CanonicalLoginRotator = credrotate.CanonicalLoginRotator
type SourceRotationMarker = credrotate.SourceRotationMarker
type CredentialRotationHandlers = credrotate.Handlers

const (
	CredentialRotateCommand       = credrotate.CredentialRotateCommand
	CredentialModeCodexFile       = credrotate.CredentialModeCodexFile
	CredentialModeClaudeAPIKey    = credrotate.CredentialModeClaudeAPIKey
	CredentialRotationJournalLine = credrotate.CredentialRotationJournalLine
)

func ValidateCredentialRotationRequest(request CredentialRotationRequest) error {
	return credrotate.ValidateRequest(request)
}

// RotateCredential performs one protected mode-specific rotation. The backend
// lock covers the read, owner callback result checks and both metadata writes;
// no caller-supplied quarantine flag is trusted.
func RotateCredential(ctx context.Context, config string, backend bstate.Backend, request CredentialRotationRequest, handlers CredentialRotationHandlers) (CredentialRotationResult, error) {
	var result CredentialRotationResult
	if err := wire.Context(ctx); err != nil {
		return result, err
	}
	if !wire.ID(config) || backend == nil {
		return result, wire.Error(api.CodePrerequisite, "ROTATE requires its installed configuration and protected credential journal")
	}
	if err := ValidateCredentialRotationRequest(request); err != nil {
		return result, err
	}
	if handlers.Journal == nil {
		return result, wire.Error(api.CodePrerequisite, "ROTATE requires its fixed owner journal")
	}
	if request.Mode == CredentialModeCodexFile && handlers.Codex == nil {
		return result, wire.Error(api.CodePrerequisite, "codex-file ROTATE requires its protected canonical-login owner")
	}
	if request.Mode == CredentialModeClaudeAPIKey && handlers.Source == nil {
		return result, wire.Error(api.CodePrerequisite, "claude-api-key ROTATE requires its protected source owner")
	}

	rotate := func(journal bstate.Journal) error {
		var profile bstate.Profile
		if err := journal.Read("profile", request.ProfileID, &profile); err != nil {
			return err
		}
		if profile.Config != config || profile.ID != request.ProfileID || profile.LoginID != request.LoginID || profile.Mode != request.Mode {
			return wire.Error(api.CodeConflict, "ROTATE profile enrollment differs from the requested credential")
		}
		var login bstate.Login
		if err := journal.Read("login", request.LoginID, &login); err != nil {
			return err
		}
		defer clear(login.Material)
		if login.ID != request.LoginID || login.Source == nil || *login.Source != profile.Source || login.Quarantined == false {
			return wire.Error(api.CodeConflict, "ROTATE requires a credential marked RotationRequired")
		}
		if login.SlotID != "" || login.ProjectionID != "" || login.PendingRelease != "" {
			return wire.Error(api.CodeContainmentUnknown, "ROTATE requires a retired lane copy and no retained projection")
		}
		if request.Mode == CredentialModeClaudeAPIKey && login.Source.SourceHandle != request.SourceHandle {
			return wire.Error(api.CodeConflict, "ROTATE source handle differs from the quarantined credential")
		}

		updated := login
		updatedSource := profile.Source
		sourceMarked := false
		switch request.Mode {
		case CredentialModeCodexFile:
			candidate, err := handlers.Codex.RotateCanonicalLogin(ctx, login)
			if err != nil {
				return err
			}
			if candidate.ID != login.ID || candidate.Driver != login.Driver || candidate.Provider != login.Provider ||
				candidate.Source == nil || *candidate.Source != profile.Source || candidate.Generation <= login.Generation ||
				candidate.Quarantined || candidate.SlotID != "" || candidate.ProjectionID != "" || candidate.PendingRelease != "" ||
				len(candidate.Material) == 0 || len(candidate.Material) > wire.MaxMaterial {
				clear(candidate.Material)
				return wire.Error(api.CodeIntegrity, "Codex canonical-login owner returned an invalid rotation")
			}
			updated = candidate
		case CredentialModeClaudeAPIKey:
			candidate, err := handlers.Source.MarkSourceRotated(ctx, profile.Source, request.SourceVersion)
			if err != nil {
				return err
			}
			if !wire.ID(string(candidate.ID)) || candidate.Name != profile.Source.Name || candidate.SourceHandle == profile.Source.SourceHandle ||
				candidate.Version != request.SourceVersion || !wire.ID(string(candidate.SourceHandle)) || !wire.Name(candidate.Version) {
				return wire.Error(api.CodeIntegrity, "API-key source owner returned an invalid rotation")
			}
			updated.Generation = login.Generation + 1
			updated.Quarantined = false
			updatedSource = candidate
			updated.Source = &candidate
			sourceMarked = true
		}
		if updated.Quarantined || updated.Generation <= login.Generation || updated.SlotID != "" || updated.ProjectionID != "" || updated.PendingRelease != "" {
			clear(updated.Material)
			return wire.Error(api.CodeIntegrity, "ROTATE owner did not release the canonical quarantine safely")
		}
		if sourceMarked {
			profile.Source = updatedSource
			if err := journal.Write("profile", profile.ID, profile); err != nil {
				clear(updated.Material)
				return err
			}
		}
		if err := journal.Write("login", login.ID, updated); err != nil {
			clear(updated.Material)
			return err
		}
		if err := appendCredentialRotationLine(handlers.Journal); err != nil {
			clear(updated.Material)
			return err
		}
		result = CredentialRotationResult{Command: CredentialRotateCommand, Mode: request.Mode, ProfileID: profile.ID, LoginID: login.ID,
			SourceVersion: updatedSource.Version, Generation: updated.Generation, QuarantineReleased: true, SourceMarked: sourceMarked}
		clear(updated.Material)
		return nil
	}

	if durable, ok := backend.(bstate.DurableBackend); ok {
		if err := durable.WithBrokerDurable(ctx, rotate); err != nil {
			return CredentialRotationResult{}, err
		}
		return result, nil
	}
	if err := backend.WithBroker(ctx, rotate); err != nil {
		return CredentialRotationResult{}, err
	}
	return result, nil
}

func appendCredentialRotationLine(journal io.Writer) error {
	data := []byte(CredentialRotationJournalLine)
	written, err := journal.Write(data)
	if err != nil || written != len(data) {
		return errors.Join(err, wire.Error(api.CodeUnavailable, "credential rotation journal line was not retained"))
	}
	return nil
}

// RotateCredential uses the installed Service's protected broker binding.
func (s *Service) RotateCredential(ctx context.Context, request CredentialRotationRequest, handlers CredentialRotationHandlers) (CredentialRotationResult, error) {
	if s == nil {
		return CredentialRotationResult{}, wire.Error(api.CodePrerequisite, "ROTATE requires its installed secrets service")
	}
	backend, err := s.brokerBackend()
	if err != nil {
		return CredentialRotationResult{}, err
	}
	return RotateCredential(ctx, s.deps.Config, backend, request, handlers)
}
