package store

import (
	"context"
	"encoding/json"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client/wire"
)

type runtimeHistory map[api.BlobRef]map[api.BlobRef]bool

// Only verified, service-authored runtime manifests in this writer's immutable
// object history establish provenance. A pin in an arbitrary document, an
// observation, an inventory or the current native installation is insufficient.
func (s *Service) retainedRuntimeHistory(ctx context.Context, db readDatabase) (runtimeHistory, error) {
	rows, err := db.QueryContext(ctx, "SELECT metadata,data FROM objects WHERE json_extract(metadata,'$.Ref.class')='manifest' AND json_extract(metadata,'$.Origin')='service' AND json_extract(metadata,'$.ACL.Owner.kind')='service' ORDER BY id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	history := runtimeHistory{}
	for rows.Next() {
		var encoded, raw []byte
		var meta api.ObjectMetadata
		if err := rows.Scan(&encoded, &raw); err != nil {
			return nil, err
		}
		if err := decodeStored(encoded, &meta); err != nil {
			return nil, err
		}
		var header struct {
			Schema string `json:"schema"`
		}
		if json.Unmarshal(raw, &header) != nil || header.Schema != "laneboss.runtime.v2" {
			continue
		}
		if meta.Ref.Class != "manifest" || meta.ACL.Config != s.deps.Config || meta.Origin != "service" || meta.ACL.Owner.Kind != "service" ||
			!wire.ValidID(string(meta.SourceOperationID)) || meta.Ref.Bytes != int64(len(raw)) || meta.Ref.SHA256 != api.Digest(hash(raw)) {
			return nil, fault(api.CodeIntegrity, "retained runtime manifest lost its service provenance or exact bytes")
		}
		var runtime api.RuntimeManifest
		if err := api.DecodeObject(raw, &runtime); err != nil {
			return nil, fault(api.CodeIntegrity, "retained runtime manifest does not match its closed schema")
		}
		if runtime.Generation == 0 || runtime.Generation >= 1<<53 || len(runtime.Objects) == 0 || len(runtime.Objects) > 128 {
			return nil, fault(api.CodeIntegrity, "retained runtime manifest has an invalid generation or inventory")
		}
		for _, object := range runtime.Objects {
			if !runtimeVendorPin(object) {
				continue
			}
			if history[object.Content] == nil {
				history[object.Content] = map[api.BlobRef]bool{}
			}
			history[object.Content][meta.Ref] = true
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	return history, nil
}

func runtimeVendorPin(object api.RuntimeObject) bool {
	ref := object.Content
	return (object.Role == "claude" || object.Role == "claudock") && object.ID == api.ID(object.Role) &&
		object.RelativePath == object.Role && object.Mode == 0555 && wire.ValidID(string(object.RootID)) &&
		wire.ValidID(string(ref.ID)) && ref.Class == "artifact" && ref.Bytes > 0 && ref.Bytes <= api.MaxVendorBytes && wire.ValidDigest(string(ref.SHA256))
}

// Runtime inventory identifies retained content provenance, not a mutable
// installation pathname. Fresh native observations separately establish its
// current presence or absence after an upgrade; neither state permits deletion.
func (s *Service) runtimeInventoryObject(ref api.BlobRef) (api.CleanupObject, error) {
	raw, err := json.Marshal(ref)
	if err != nil {
		return api.CleanupObject{}, err
	}
	root := hash([]byte("runtime-history\x00" + s.deps.Config + "\x00" + string(s.storeID)))
	return api.CleanupObject{Ref: ref, RootID: api.ID("runtime-" + root[:32]), RootIdentity: root,
		Identity: hash(append([]byte("runtime-pin\x00"), raw...)), Role: "runtime"}, nil
}
