package admin

import (
	"context"
	"errors"
	"os"
	"reflect"
	"strconv"
	"strings"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/grants/manifest"
)

type dataCopyObject struct {
	Ref  api.BlobRef `json:"ref"`
	Data []byte      `json:"data,omitempty"`
}

type dataCopyPayload struct {
	Grant   api.DataGrant    `json:"grant"`
	Source  dataCopyObject   `json:"source"`
	Objects []dataCopyObject `json:"objects,omitempty"`
}

type dataCopyOpenRequest struct {
	Registration dataReg           `json:"registration"`
	Copies       []dataCopyPayload `json:"copies"`
}

type dataCopyPins struct {
	Projection                  api.DataCopyProjection
	Payload                     dataCopyPayload
	Source, Destination         *os.File
	SourceName, DestinationName string
	Created                     [2]bool
}

func (p *dataCopyPins) close() error {
	var result error
	if p.Source != nil {
		result = errors.Join(result, p.Source.Close())
	}
	if p.Destination != nil {
		result = errors.Join(result, p.Destination.Close())
	}
	return result
}

func (s *Service) copyPayloads(ctx context.Context, scope api.Scope, r dataReg) ([]dataCopyPayload, error) {
	result := []dataCopyPayload{}
	for _, grant := range r.Inputs.Grants.Data {
		if grant.ID == r.Inputs.Sources.Project.GrantID {
			continue
		}
		if grant.Delivery != "copy" {
			return nil, api.UnsupportedDataDelivery(grant.Delivery)
		}
		metadata, err := s.deps.Store.ObjectMetadata(ctx, scope, grant.SourceObjectID)
		if err != nil {
			return nil, err
		}
		if metadata.ACL.Config != scope.Config || metadata.Ref.ID != grant.SourceObjectID || metadata.Ref.SHA256 != grant.SourceSHA256 || metadata.Ref.Class != "manifest" {
			return nil, failure(api.CodeForbidden, "copy source differs from the current issued ceiling")
		}
		if err := manifest.Blob(metadata.Ref); err != nil {
			return nil, err
		}
		// The helper reads manifest and artifact bytes only from the protected
		// sources/<sha> cache. The control socket carries the issued pin tuple.
		result = append(result, dataCopyPayload{Grant: grant, Source: dataCopyObject{Ref: metadata.Ref}})
	}
	return result, nil
}

// The privileged helper checks the transport against its original allocation,
// independently of the service's earlier source and grant revalidation.
func validateCopyPayloads(inputs api.LaunchInputs, payloads []dataCopyPayload) ([]api.DataCopyProjection, error) {
	expected := map[api.ID]api.DataGrant{}
	for _, grant := range inputs.Grants.Data {
		if grant.ID != inputs.Sources.Project.GrantID {
			expected[grant.ID] = grant
		}
	}
	if len(expected) != len(payloads) {
		return nil, failure(api.CodeForbidden, "copy preparation omitted an issued data view")
	}
	result := []api.DataCopyProjection{}
	for _, payload := range payloads {
		grant, found := expected[payload.Grant.ID]
		if !found || !reflect.DeepEqual(grant, payload.Grant) || payload.Source.Ref.ID != grant.SourceObjectID ||
			payload.Source.Ref.SHA256 != grant.SourceSHA256 || payload.Source.Ref.Class != "manifest" {
			return nil, failure(api.CodeForbidden, "copy preparation substituted its issued source or grant")
		}
		if len(payload.Source.Data) != 0 || len(payload.Objects) != 0 {
			return nil, failure(api.CodeForbidden, "copy preparation requires protected cache pins, not inline bytes")
		}
		if err := manifest.Blob(payload.Source.Ref); err != nil {
			return nil, err
		}
		delete(expected, grant.ID)
		if grant.Delivery != "copy" {
			return nil, api.UnsupportedDataDelivery(grant.Delivery)
		}
		if err := validateGateDataGrantPortable(grant); err != nil {
			return nil, err
		}
		expires, err := manifest.Expiry(grant.ExpiresAt, time.Now())
		if err != nil {
			return nil, err
		}
		ceiling, err := manifest.Time(inputs.Grants.ExpiresAt)
		if err != nil || expires.After(ceiling) {
			return nil, failure(api.CodeForbidden, "copy grant exceeds its issued expiry ceiling")
		}
		result = append(result, api.DataCopyProjection{Grant: grant, Source: payload.Source.Ref})
	}
	return result, nil
}

// Replaying an existing token does not acquire new rights or re-materialize
// data. Match its exact held grant/ref tuple, including its historical expiry.
func validateCopyReplay(inputs api.LaunchInputs, payloads []dataCopyPayload, projection api.StorageProjection) error {
	entries, err := api.ValidateDataCopyProjections(inputs, projection)
	if err != nil {
		return err
	}
	if len(entries) != len(payloads) {
		return failure(api.CodeForbidden, "copy replay omitted a held projection")
	}
	byID := map[api.ID]api.DataCopyProjection{}
	for _, entry := range entries {
		byID[entry.Grant.ID] = entry
	}
	for _, payload := range payloads {
		entry, found := byID[payload.Grant.ID]
		if !found || !reflect.DeepEqual(entry.Grant, payload.Grant) || entry.Source != payload.Source.Ref || len(payload.Source.Data) != 0 || len(payload.Objects) != 0 {
			return failure(api.CodeForbidden, "copy replay changed its held grant or source pin")
		}
		delete(byID, payload.Grant.ID)
	}
	return nil
}

func validateGateDataGrantPortable(grant api.DataGrant) error {
	if err := manifest.Destination(grant.Destination); err != nil {
		return err
	}
	if grant.Destination == "/work/main" || grant.Access != "ro" && grant.Access != "rw" {
		return failure(api.CodeForbidden, "copy preparation has an invalid extra destination or access")
	}
	return nil
}

// The three primary roots keep their fixed storage layout. Independent copies
// are also private lane storage, with names and inodes retained by their data
// job's helper projection, including after that job's source has been collected.
func privateStorageDirectories(record leaseRecord) ([]storageIdentity, error) {
	if record.Storage == nil {
		return nil, nil
	}
	result := append([]storageIdentity{}, record.Storage.Directories...)
	names, identities := map[api.ID]bool{}, map[string]bool{}
	for _, item := range result {
		names[item.ID] = true
		identities[item.Device+":"+item.Inode] = true
	}
	for _, job := range record.DataJobs {
		if job.Projection.OpenToken == "" {
			continue
		}
		copies, err := api.ValidateDataCopyProjections(job.Reg.Inputs, job.Projection)
		if err != nil {
			return nil, err
		}
		for _, copy := range copies {
			device, inode, found := strings.Cut(copy.DestinationIdentity, ":")
			_, deviceErr := strconv.ParseUint(device, 10, 64)
			number, inodeErr := strconv.ParseUint(inode, 10, 64)
			if !found || deviceErr != nil || inodeErr != nil || number == 0 || names[copy.WorkspaceID] || identities[copy.DestinationIdentity] {
				return nil, failure(api.CodeIntegrity, "private copy storage lost or aliased its original directory identity")
			}
			names[copy.WorkspaceID], identities[copy.DestinationIdentity] = true, true
			result = append(result, storageIdentity{ID: copy.WorkspaceID, Device: device, Inode: inode})
			if len(result) > 4096 {
				return nil, failure(api.CodeContainmentUnknown, "private copy storage exceeds its retained inventory bound")
			}
		}
	}
	if record.Archive != nil && record.Archive.GitRoot != nil {
		item := *record.Archive.GitRoot
		identity := item.Device + ":" + item.Inode
		_, deviceErr := strconv.ParseUint(item.Device, 10, 64)
		inode, inodeErr := strconv.ParseUint(item.Inode, 10, 64)
		if record.Archive.Tree.Git == nil || item.ID != "archive-git" || deviceErr != nil || inodeErr != nil || inode == 0 || names[item.ID] || identities[identity] || len(result) >= 4096 {
			return nil, failure(api.CodeIntegrity, "private Git capture lost its distinct native directory")
		}
		result = append(result, item)
	}
	return result, nil
}
