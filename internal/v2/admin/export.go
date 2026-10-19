package admin

import (
	"context"
	"os"
	"strings"

	"laneboss.io/laneboss/internal/v2/api"
)

// exportJournal is the durable comparison record for a registered data
// export. The descriptor itself is deliberately absent: after helper loss a
// retained journal cannot authorize reopening a path.
type exportJournal struct {
	GrantID             api.ID         `json:"grant_id"`
	Destination         string         `json:"destination"`
	SourceIdentity      string         `json:"source_identity"`
	DestinationIdentity string         `json:"destination_identity"`
	ClaimID             api.ID         `json:"claim_id"`
	WriterLeaseID       api.ID         `json:"writer_lease_id,omitempty"`
	Generation          api.Generation `json:"generation"`
}

// registeredExport is supplied only by the protected export owner. A caller
// cannot select a host path or turn a journal into a new descriptor.
type registeredExport struct {
	File                *os.File
	Destination         string
	SourceIdentity      string
	DestinationIdentity string
	ClaimID             api.ID
	WriterLeaseID       api.ID
	Directory           bool
	Writable            bool
	Executable          bool
	ReadOnly            bool
}

type exportResolver func(context.Context, leaseRecord, api.DataGrant) (registeredExport, error)

func validateExportJournals(record leaseRecord) error {
	if len(record.Exports) == 0 {
		return nil
	}
	if record.Spec == nil || record.Spec.Handoff.Spec.Grants.Data == nil {
		return failure(api.CodeIntegrity, "registered export journal has no retained grant set")
	}
	seenGrant, seenDestination := map[api.ID]bool{}, map[string]bool{}
	for _, entry := range record.Exports {
		if !validID(entry.GrantID) || entry.Destination == "" || entry.SourceIdentity == "" || entry.DestinationIdentity == "" ||
			!validID(entry.ClaimID) || entry.Generation == 0 || seenGrant[entry.GrantID] || seenDestination[strings.ToLower(entry.Destination)] {
			return failure(api.CodeIntegrity, "registered export journal has a foreign or duplicate identity")
		}
		var grant *api.DataGrant
		for index := range record.Spec.Handoff.Spec.Grants.Data {
			candidate := &record.Spec.Handoff.Spec.Grants.Data[index]
			if candidate.ID == entry.GrantID {
				grant = candidate
				break
			}
		}
		if grant == nil || grant.Destination != entry.Destination || grant.Destination == "/work/main" && grant.Delivery == "copy" {
			return failure(api.CodeIntegrity, "registered export journal differs from its retained data grant")
		}
		seenGrant[entry.GrantID], seenDestination[strings.ToLower(entry.Destination)] = true, true
	}
	return nil
}

func (e registeredExport) close() error {
	if e.File == nil {
		return nil
	}
	err := e.File.Close()
	e.File = nil
	return err
}
