package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"reflect"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client/wire"
	"laneboss.io/laneboss/internal/v2/grants/manifest"
)

// ValidateSecretCapability is a private metadata port, not another RPC or a
// credential reader. The same check runs under the writer lock at enrollment.
func (s *Service) ValidateSecretCapability(ctx context.Context, scope api.Scope, grant api.SecretGrant) error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if err := s.available(); err != nil {
		return err
	}
	if err := s.readScope(ctx, scope); err != nil {
		return err
	}
	db, err := s.reader(scope)
	if err != nil {
		return err
	}
	return s.secretCapability(ctx, db, scope, grant)
}

func (s *Service) secretCapability(ctx context.Context, db queryer, scope api.Scope, grant api.SecretGrant) error {
	if scope.Actor.Kind != "human" || scope.Config != s.deps.Config {
		return fault(api.CodeForbidden, "secret enrollment requires its human owner and configuration")
	}
	var source, head secretMetadata
	if err := storedProjection(ctx, db, "secret_source", grant.SourceHandle, &source); err != nil {
		return err
	}
	if err := storedProjection(ctx, db, "secret_head", secretNameID(grant.Name), &head); err != nil {
		return err
	}
	if source.Info.Revoked || source.Info.Name != grant.Name || source.Info.Version != grant.Version ||
		source.Info.SourceHandle != grant.SourceHandle || !sameValue(source, head) || source.Generation == 0 {
		return fault(api.CodeConflict, "secret capability source is revoked, stale or substituted")
	}
	var raw []byte
	if err := db.QueryRowContext(ctx, "SELECT data FROM events WHERE id=?", string(grant.SourceHandle)).Scan(&raw); err != nil {
		return fault(api.CodeNotFound, "secret capability has no committed import event")
	}
	var event api.Event
	var payload api.SecretEvent
	if wire.Decode(raw, &event) != nil || wire.Decode(event.Payload, &payload) != nil || event.Config != scope.Config ||
		event.ID != grant.SourceHandle || event.OperationID != source.OperationID || event.ID != source.EventID ||
		event.Origin != "service" || event.Kind != "secret.imported" && event.Kind != "secret.rotated" ||
		len(payload.Names) != 1 || len(payload.Versions) != 1 || payload.Names[0] != grant.Name || payload.Versions[0] != grant.Version || payload.KeyID != source.Info.KeyID {
		return fault(api.CodeIntegrity, "secret enrollment source lost its import provenance")
	}
	if event.Actor != scope.Actor || event.RequestedBy != scope.Actor {
		return fault(api.CodeForbidden, "secret enrollment source belongs to another human")
	}
	return nil
}

func (s *Service) checkCapabilityEnrollment(ctx context.Context, tx *sql.Tx, input api.Transaction) error {
	if input.Scope.Request.Method != "grants.enroll" || input.Reply != nil && input.Reply.Error != nil {
		return nil
	}
	var request api.CapabilityEnrollmentRequest
	if err := api.DecodeObject(input.Scope.Request.Params, &request); err != nil {
		return err
	}
	if err := manifest.EnrollmentInput(request); err != nil {
		return err
	}
	if input.Scope.Actor.Kind != "human" || len(input.Writes.Objects) != 1 || len(input.Events) != 1 || len(input.Effects) != 0 {
		return fault(api.CodeForbidden, "capability enrollment requires its one exact human-approved record")
	}
	object := input.Writes.Objects[0]
	if object.Class != "manifest" || object.Origin != "service" || object.ACL.Config != input.Scope.Config || object.ACL.Owner != input.Scope.Actor ||
		object.ACL.Generation != 1 || object.ACL.LifeID != "" || object.ACL.Audience != "owner" || len(object.ACL.Participants) != 0 ||
		len(object.InputRefs) != 0 || object.SHA256 != manifest.Hash(object.Bytes) {
		return fault(api.CodeForbidden, "capability enrollment changed its protected record authority")
	}
	if request.Resource != nil {
		if _, err := manifest.Expiry(request.Resource.ExpiresAt, s.deps.Clock.Now()); err != nil {
			return err
		}
		var actual api.ResourceGrant
		if err := api.DecodeObject(object.Bytes, &actual); err != nil {
			return err
		}
		expected := request.Resource.Grant()
		expected.SourceHandle = object.ObjectKey
		if !wire.ValidID(string(object.ObjectKey)) || !reflect.DeepEqual(actual, expected) {
			return fault(api.CodeForbidden, "resource enrollment differs from the exact approved capability")
		}
	} else {
		if _, err := manifest.Expiry(request.Secret.ExpiresAt, s.deps.Clock.Now()); err != nil {
			return err
		}
		var actual api.SecretGrant
		if err := api.DecodeObject(object.Bytes, &actual); err != nil {
			return err
		}
		if object.ObjectKey != request.Secret.SourceHandle || !reflect.DeepEqual(actual, request.Secret.Grant()) {
			return fault(api.CodeForbidden, "secret enrollment differs from the exact approved capability")
		}
		if err := s.secretCapability(ctx, tx, input.Scope, actual); err != nil {
			return err
		}
	}
	ref := api.BlobRef{ID: object.ObjectKey, Class: object.Class, Bytes: int64(len(object.Bytes)), SHA256: object.SHA256}
	var eventRef api.BlobRef
	if input.Events[0].Kind != "blob.committed" || json.Unmarshal(input.Events[0].Payload, &eventRef) != nil || eventRef != ref {
		return fault(api.CodeIntegrity, "capability enrollment omitted its exact committed record event")
	}
	return nil
}
