package store

import (
	"context"
	"encoding/json"
	"strings"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client/wire"
	secretwire "laneboss.io/laneboss/internal/v2/secrets/wire"
)

// Reconstruct from immutable causal events; a matching generic projection
// checksum alone cannot certify a current secret name, version or revocation.
func (s *Service) verifySecretMetadata(ctx context.Context) error {
	rows, err := s.db.QueryContext(ctx, "SELECT data FROM events WHERE json_extract(data,'$.kind') IN ('secret.imported','secret.rotated','secret.revoked') ORDER BY seq")
	if err != nil {
		return err
	}
	heads, sources := map[api.ID]secretMetadata{}, map[api.ID]secretMetadata{}
	for rows.Next() {
		var raw []byte
		var event api.Event
		var payload api.SecretEvent
		if err := rows.Scan(&raw); err != nil {
			rows.Close()
			return err
		}
		if wire.Decode(raw, &event) != nil || wire.Decode(event.Payload, &payload) != nil || event.Config != s.deps.Config || event.Origin != "service" ||
			len(payload.Names) != 1 || len(payload.Versions) != 1 || len(payload.GrantIDs) != 0 ||
			!secretwire.Name(payload.Names[0]) || !secretwire.Name(payload.Versions[0]) || !wire.ValidID(string(payload.KeyID)) ||
			payload.Outcome != strings.TrimPrefix(string(event.Kind), "secret.") {
			rows.Close()
			return fault(api.CodeIntegrity, "secret journal metadata is invalid")
		}
		id := secretNameID(payload.Names[0])
		prior, exists := heads[id]
		info := api.SecretInfo{Name: payload.Names[0], Version: payload.Versions[0], KeyID: payload.KeyID, SourceHandle: event.ID}
		switch event.Kind {
		case "secret.imported":
			if exists {
				rows.Close()
				return fault(api.CodeIntegrity, "secret journal imported an existing name")
			}
		case "secret.rotated":
			if !exists || prior.Info.Revoked || prior.Info.Version == info.Version {
				rows.Close()
				return fault(api.CodeIntegrity, "secret journal rotation base is invalid")
			}
		case "secret.revoked":
			if !exists || prior.Info.Revoked || prior.Info.Version != info.Version || prior.Info.KeyID != info.KeyID {
				rows.Close()
				return fault(api.CodeIntegrity, "secret journal revocation base is invalid")
			}
			info = prior.Info
			info.Revoked = true
		}
		next := secretMetadata{Info: info, Generation: prior.Generation + 1, OperationID: event.OperationID, EventID: event.ID}
		heads[id], sources[info.SourceHandle] = next, next
	}
	readErr, closeErr := rows.Err(), rows.Close()
	if readErr != nil {
		return readErr
	}
	if closeErr != nil {
		return closeErr
	}
	rows, err = s.db.QueryContext(ctx, "SELECT kind,id,data FROM projections WHERE kind IN ('secret_head','secret_source')")
	if err != nil {
		return err
	}
	for rows.Next() {
		var kind string
		var id api.ID
		var raw []byte
		if err := rows.Scan(&kind, &id, &raw); err != nil {
			rows.Close()
			return err
		}
		expected := heads
		if kind == "secret_source" {
			expected = sources
		}
		value, exists := expected[id]
		if !exists || !sameValue(json.RawMessage(raw), value) {
			rows.Close()
			return fault(api.CodeIntegrity, "secret metadata projection differs from its immutable journal")
		}
		delete(expected, id)
	}
	readErr, closeErr = rows.Err(), rows.Close()
	if readErr != nil {
		return readErr
	}
	if closeErr != nil {
		return closeErr
	}
	if len(heads) != 0 || len(sources) != 0 {
		return fault(api.CodeIntegrity, "secret journal has no matching metadata projection")
	}
	return nil
}
