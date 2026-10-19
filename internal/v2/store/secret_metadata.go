package store

import (
	"context"
	"database/sql"
	"errors"
	"strings"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client/wire"
	secretwire "laneboss.io/laneboss/internal/v2/secrets/wire"
)

// Only metadata is projected by the event writer. The encrypted backend remains
// the owner of values, keys and source authentication. No new public port or
// plaintext projection is introduced.
type secretMetadata struct {
	Info        api.SecretInfo
	Generation  api.Generation
	OperationID api.ID
	EventID     api.ID
}

func secretNameID(name string) api.ID { return api.ID("secret-name-" + hash([]byte(name))) }

func (s *Service) checkSecretMutation(ctx context.Context, tx *sql.Tx, input api.Transaction) error {
	if input.Reply != nil && input.Reply.Error != nil {
		return nil
	}
	var name, version, base string
	var kind api.EventKind
	switch input.Scope.Request.Method {
	case "secret.import":
		var r api.SecretImportRequest
		if err := wire.Decode(input.Scope.Request.Params, &r); err != nil {
			return err
		}
		name, version, kind = r.Name, r.Version, "secret.imported"
	case "secret.rotate":
		var r api.SecretRotateRequest
		if err := wire.Decode(input.Scope.Request.Params, &r); err != nil {
			return err
		}
		name, base, kind = r.Name, r.ExpectedVersion, "secret.rotated"
	case "secret.revoke":
		var r api.SecretRevokeRequest
		if err := wire.Decode(input.Scope.Request.Params, &r); err != nil {
			return err
		}
		name, version, base, kind = r.Name, r.ExpectedVersion, r.ExpectedVersion, "secret.revoked"
	default:
		return nil
	}
	if len(input.Events) != 1 || input.Events[0].Kind != kind {
		return fault(api.CodeIntegrity, "secret mutation requires its one exact causal event")
	}
	var p api.SecretEvent
	if err := wire.Decode(input.Events[0].Payload, &p); err != nil {
		return err
	}
	if !secretwire.Name(name) || len(p.Names) != 1 || len(p.Versions) != 1 || p.Names[0] != name ||
		!secretwire.Name(p.Versions[0]) || version != "" && p.Versions[0] != version {
		return fault(api.CodeIntegrity, "secret event differs from its exact mutation intent")
	}
	if kind == "secret.rotated" || kind == "secret.revoked" {
		var prior secretMetadata
		if err := storedProjection(ctx, tx, "secret_head", secretNameID(name), &prior); err != nil {
			return err
		}
		if prior.Info.Revoked || prior.Info.Version != base || kind == "secret.rotated" && p.Versions[0] == base ||
			kind == "secret.revoked" && p.KeyID != prior.Info.KeyID {
			return fault(api.CodeConflict, "secret mutation base differs from its current committed head")
		}
	}
	return nil
}

func (s *Service) projectSecret(ctx context.Context, tx *sql.Tx, event api.Event) error {
	var payload api.SecretEvent
	if err := wire.Decode(event.Payload, &payload); err != nil {
		return err
	}
	if len(payload.Names) != 1 || len(payload.Versions) != 1 || len(payload.GrantIDs) != 0 ||
		!secretwire.Name(payload.Names[0]) || !secretwire.Name(payload.Versions[0]) || !wire.ValidID(string(payload.KeyID)) ||
		payload.Outcome != strings.TrimPrefix(string(event.Kind), "secret.") {
		return fault(api.CodeIntegrity, "secret event has no exact metadata selection")
	}
	nameID := secretNameID(payload.Names[0])
	var prior secretMetadata
	err := storedProjection(ctx, tx, "secret_head", nameID, &prior)
	absent := false
	if err != nil {
		var typed *api.Error
		if !errors.As(err, &typed) || typed.Code != api.CodeNotFound {
			return err
		}
		absent = true
	}
	info := api.SecretInfo{Name: payload.Names[0], Version: payload.Versions[0], KeyID: payload.KeyID, SourceHandle: event.ID}
	var sourceGeneration api.Generation = 1
	switch event.Kind {
	case "secret.imported":
		if !absent {
			return fault(api.CodeConflict, "secret import already has a committed head")
		}
	case "secret.rotated":
		if absent || prior.Info.Revoked || prior.Info.Version == info.Version {
			return fault(api.CodeConflict, "secret rotation has no live different base")
		}
	case "secret.revoked":
		if absent || prior.Info.Revoked || prior.Info.Version != info.Version || prior.Info.KeyID != info.KeyID {
			return fault(api.CodeConflict, "secret revocation differs from its current committed source")
		}
		info = prior.Info
		info.Revoked = true
		sourceGeneration = 2
	default:
		return fault(api.CodeInvalid, "unknown secret metadata event")
	}
	if prior.Generation >= 1<<53-1 {
		return fault(api.CodeIntegrity, "secret metadata generation exhausted")
	}
	next := secretMetadata{Info: info, Generation: prior.Generation + 1, OperationID: event.OperationID, EventID: event.ID}
	if err := putGenerated(ctx, tx, "secret_source", info.SourceHandle, sourceGeneration, next); err != nil {
		return err
	}
	return putGenerated(ctx, tx, "secret_head", nameID, next.Generation, next)
}

func (s *Service) secretInfoReply(ctx context.Context, tx *sql.Tx, input api.Transaction, operation api.Operation) error {
	var info api.SecretInfo
	if err := wire.Decode(input.Reply.Result, &info); err != nil {
		return err
	}
	var source secretMetadata
	if err := storedProjection(ctx, tx, "secret_source", info.SourceHandle, &source); err != nil {
		if absent(err) {
			return fault(api.CodeIntegrity, "secret reply has no committed source metadata")
		}
		return err
	}
	var head secretMetadata
	if err := storedProjection(ctx, tx, "secret_head", secretNameID(info.Name), &head); err != nil {
		if absent(err) {
			return fault(api.CodeIntegrity, "secret reply has no committed source metadata")
		}
		return err
	}
	if source.Info != info || !sameValue(source, head) || source.OperationID != operation.ID || source.EventID != info.SourceHandle || info.Revoked {
		return fault(api.CodeIntegrity, "secret reply differs from its committed source metadata")
	}
	var name, version string
	switch input.Scope.Request.Method {
	case "secret.import":
		var request api.SecretImportRequest
		if err := wire.Decode(input.Scope.Request.Params, &request); err != nil {
			return err
		}
		name, version = request.Name, request.Version
	case "secret.rotate":
		var request api.SecretRotateRequest
		if err := wire.Decode(input.Scope.Request.Params, &request); err != nil {
			return err
		}
		if request.ExpectedVersion == info.Version {
			return fault(api.CodeIntegrity, "secret rotation reply reused its old version")
		}
		name, version = request.Name, info.Version
	default:
		return fault(api.CodeInvalid, "unknown secret metadata reply")
	}
	if name != info.Name || version != info.Version {
		return fault(api.CodeIntegrity, "secret reply differs from the exact request")
	}
	return nil
}
