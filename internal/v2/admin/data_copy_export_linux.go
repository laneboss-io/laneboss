//go:build linux

package admin

import (
	"context"
	"os"
	"reflect"
	"time"

	"golang.org/x/sys/unix"
	"laneboss.io/laneboss/internal/v2/api"
)

// A completed copy is exposed only from its still-held destination descriptor.
// A saved journal or a known filesystem name cannot replace those live pins.
func (m *leaseManager) dataCopyExport(ctx context.Context, record leaseRecord, grant api.DataGrant) (registeredExport, error) {
	if grant.Delivery != "copy" {
		return registeredExport{}, api.UnsupportedDataDelivery(grant.Delivery)
	}
	if record.Spec == nil {
		return registeredExport{}, failure(api.CodeIntegrity, "copied export has no current launch specification")
	}
	for _, job := range record.DataJobs {
		if job.State != "measured" || job.Result == nil || job.Reg.Reservation.Target != record.Spec.Handoff.Spec.Target ||
			!reflect.DeepEqual(job.Reg.Inputs.Grants, record.Spec.Handoff.Spec.Grants) {
			continue
		}
		deadline, err := time.Parse(time.RFC3339Nano, string(grant.ExpiresAt))
		if err != nil || !deadline.After(time.Now()) {
			return registeredExport{}, failure(api.CodeForbidden, "copied export grant expired")
		}
		pins := m.dataPins[job.Projection.OpenToken]
		if pins == nil {
			return registeredExport{}, failure(api.CodeContainmentUnknown, "copied export lost its original destination descriptors")
		}
		if err := verifyDataCopies(ctx, record, job, pins, job.Result.Data.Materialization.Objects); err != nil {
			return registeredExport{}, err
		}
		for _, copy := range pins.copies {
			if !reflect.DeepEqual(copy.Projection.Grant, grant) {
				continue
			}
			file := copy.Destination
			if copy.Projection.File != "" {
				file, err = dataFile(copy.Destination, copy.Projection.File, false)
				if err != nil {
					return registeredExport{}, err
				}
				defer file.Close()
			}
			fd, err := unix.FcntlInt(file.Fd(), unix.F_DUPFD_CLOEXEC, 3)
			if err != nil {
				return registeredExport{}, err
			}
			result := registeredExport{File: os.NewFile(uintptr(fd), "copied-export"), Destination: grant.Destination,
				SourceIdentity: copy.Projection.SourceIdentity, DestinationIdentity: copy.Projection.DestinationIdentity,
				ClaimID: record.Spec.Handoff.Cause.EffectID, Directory: copy.Projection.File == "", Executable: true,
				ReadOnly: grant.Access == "ro", Writable: grant.Access == "rw"}
			if result.Writable {
				result.WriterLeaseID = record.Lease.ID
			}
			return result, nil
		}
	}
	return registeredExport{}, failure(api.CodeUnavailable, "registered export owner is not bound")
}
