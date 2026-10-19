package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"time"
)

// DataCopyProjection describes helper-held roots for one independent copy.
// File is empty for a directory view, or the fixed leaf "file" for a file view.
// Neither the grant nor these identities authorize reopening a host path.
type DataCopyProjection struct {
	Grant               DataGrant      `json:"grant"`
	Source              BlobRef        `json:"source"`
	Manifest            ObjectManifest `json:"manifest"`
	SourceIdentity      string         `json:"source_identity"`
	DestinationIdentity string         `json:"destination_identity"`
	WorkspaceID         ID             `json:"workspace_id"`
	File                string         `json:"file,omitempty"`
}

type dataCopyProjections struct {
	Schema  string               `json:"schema"`
	Entries []DataCopyProjection `json:"entries"`
}

func EncodeDataCopyProjections(entries []DataCopyProjection) (string, error) {
	if len(entries) == 0 {
		return "", nil
	}
	raw, err := json.Marshal(dataCopyProjections{Schema: "laneboss.data-copies.v2", Entries: entries})
	if err != nil {
		return "", err
	}
	raw, err = CanonicalJSON(raw)
	if err != nil {
		return "", err
	}
	if len(raw) > MaxFrameBytes/2 {
		return "", launchInvalid("copy projections exceed the materialization frame bound")
	}
	return string(raw), nil
}

func DecodeDataCopyProjections(encoded string) ([]DataCopyProjection, error) {
	if encoded == "" {
		return []DataCopyProjection{}, nil
	}
	if len(encoded) > MaxFrameBytes/2 {
		return nil, launchInvalid("copy projections exceed the materialization frame bound")
	}
	var value dataCopyProjections
	if err := DecodeObject([]byte(encoded), &value); err != nil {
		return nil, err
	}
	canonical, err := CanonicalJSON([]byte(encoded))
	if err != nil || !bytes.Equal(canonical, []byte(encoded)) || value.Schema != "laneboss.data-copies.v2" || value.Entries == nil {
		return nil, launchInvalid("copy projections changed their canonical schema")
	}
	ids, destinations, identities := map[ID]bool{}, map[string]bool{}, map[string]bool{}
	for _, entry := range value.Entries {
		g := entry.Grant
		parts := strings.Split(g.Destination, "/")
		if !launchID(g.ID) || ids[g.ID] || len(parts) != 3 || parts[0] != "" ||
			parts[1] != "work" && parts[1] != "data" || !launchID(ID(parts[2])) || g.Destination == "/work/main" ||
			destinations[strings.ToLower(g.Destination)] || g.Access != "ro" && g.Access != "rw" ||
			!launchBlob(entry.Source, "manifest") || entry.Source.ID != g.SourceObjectID || entry.Source.SHA256 != g.SourceSHA256 ||
			entry.Manifest.Schema != "laneboss.objects.v2" || entry.Manifest.Entries == nil ||
			!launchID(entry.WorkspaceID) || entry.SourceIdentity == "" || entry.DestinationIdentity == "" ||
			entry.SourceIdentity == entry.DestinationIdentity || identities[entry.SourceIdentity] || identities[entry.DestinationIdentity] ||
			entry.File != "" && entry.File != "file" {
			return nil, launchInvalid("copy projection substituted or aliased its grant, source or destination")
		}
		if g.Delivery != "copy" {
			return nil, UnsupportedDataDelivery(g.Delivery)
		}
		if _, err := time.Parse(time.RFC3339Nano, string(g.ExpiresAt)); err != nil {
			return nil, launchInvalid("copy projection has an invalid grant expiry")
		}
		ids[g.ID], destinations[strings.ToLower(g.Destination)] = true, true
		identities[entry.SourceIdentity], identities[entry.DestinationIdentity] = true, true
	}
	return value.Entries, nil
}

func UnsupportedDataDelivery(mode string) error {
	return &Error{Code: CodeUnsupported, Owner: "lb-v2-admin", Message: fmt.Sprintf("materialization delivery mode %q is not implemented", mode),
		Instead: "Request an independent copy; live delivery requires its separately verified export owner."}
}

// ValidateDataCopyProjections matches every additional view to its complete
// issued entry. The project remains the single /job/source capability.
func ValidateDataCopyProjections(inputs LaunchInputs, projection StorageProjection) ([]DataCopyProjection, error) {
	entries, err := DecodeDataCopyProjections(projection.Copies)
	if err != nil {
		return nil, err
	}
	expected := map[ID]DataGrant{}
	for _, grant := range inputs.Grants.Data {
		if grant.ID == inputs.Sources.Project.GrantID {
			continue
		}
		if grant.Delivery != "copy" {
			return nil, UnsupportedDataDelivery(grant.Delivery)
		}
		if _, duplicate := expected[grant.ID]; duplicate {
			return nil, launchInvalid("copy projections have duplicate issued grant identities")
		}
		expected[grant.ID] = grant
	}
	if len(entries) != len(expected) {
		return nil, &Error{Code: CodeUnsupported, Owner: "lb-v2-grants", Message: "materialization stage cannot add unprojected data sources",
			Instead: "Supply separately authorized descriptor projections for every additional data view."}
	}
	for _, entry := range entries {
		grant, found := expected[entry.Grant.ID]
		if !found || !reflect.DeepEqual(grant, entry.Grant) ||
			entry.SourceIdentity == projection.SourceIdentity || entry.SourceIdentity == projection.WorkspaceIdentity || entry.SourceIdentity == projection.HomeIdentity ||
			entry.DestinationIdentity == projection.SourceIdentity || entry.DestinationIdentity == projection.WorkspaceIdentity || entry.DestinationIdentity == projection.HomeIdentity {
			return nil, launchInvalid("copy projection differs from the issued source, path, access, destination or expiry")
		}
		deadline, e1 := time.Parse(time.RFC3339Nano, string(grant.ExpiresAt))
		ceiling, e2 := time.Parse(time.RFC3339Nano, string(inputs.Grants.ExpiresAt))
		if e1 != nil || e2 != nil || deadline.After(ceiling) {
			return nil, launchInvalid("copy projection exceeds its issued set expiry")
		}
		delete(expected, grant.ID)
	}
	return entries, nil
}

// Receipt associates the measured copy with its launch workspace. WorkspaceID
// on the projection remains the independent held root used for collection;
// it is not the workspace identity required by an agent LaunchSpec.
func (entry DataCopyProjection) Receipt(launchWorkspace ID) (MaterializedObject, error) {
	raw, err := json.Marshal(entry.Manifest)
	if err != nil {
		return MaterializedObject{}, err
	}
	_, digest, err := launchCanonical(entry.Manifest)
	if err != nil || len(raw) > MaxFrameBytes {
		return MaterializedObject{}, launchInvalid("copy manifest exceeds its receipt bound")
	}
	return MaterializedObject{GrantID: entry.Grant.ID, SourceIdentity: entry.SourceIdentity,
		DestinationIdentity: entry.DestinationIdentity, WorkspaceID: launchWorkspace, SnapshotSHA256: digest}, nil
}
