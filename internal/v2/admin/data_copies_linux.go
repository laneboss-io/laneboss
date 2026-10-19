//go:build linux

package admin

import (
	"context"
	"errors"
	"io"
	"os"
	"reflect"

	"golang.org/x/sys/unix"
	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/grants/manifest"
)

// Every byte is read from the same protected, digest-named cache as the project.
// The service supplies only a checked object reference, never a host pathname.
func openCopySource(ctx context.Context, binding installation, ref api.BlobRef, ceiling uint64) (*os.File, api.ObjectManifest, error) {
	var empty api.ObjectManifest
	state, err := dataParent(binding.statePath())
	if err != nil {
		return nil, empty, err
	}
	defer state.Close()
	sources, err := openStorageDirectory(state, "sources")
	if err != nil {
		return nil, empty, err
	}
	defer sources.Close()
	cache, err := openStorageDirectory(sources, string(ref.SHA256))
	if err != nil {
		return nil, empty, failure(api.CodePrerequisite, "approved copy source is absent from the protected source cache")
	}
	defer cache.Close()
	for _, file := range []*os.File{sources, cache} {
		_, info, err := dataIdentity(file)
		if err != nil || info.Uid != 0 || info.Gid != 0 || info.Mode&07777 != 0700 {
			return nil, empty, failure(api.CodeIntegrity, "copy cache is not exclusively helper-owned")
		}
		if err := dataNoAttributes(file); err != nil {
			return nil, empty, err
		}
	}
	file, err := dataFile(cache, "manifest.json", false)
	if err != nil {
		return nil, empty, err
	}
	var info unix.Stat_t
	if unix.Fstat(int(file.Fd()), &info) != nil || info.Mode&unix.S_IFMT != unix.S_IFREG || info.Mode&07022 != 0 ||
		info.Uid != 0 || info.Gid != 0 || info.Nlink != 1 || info.Size != ref.Bytes || info.Size > api.MaxFrameBytes {
		file.Close()
		return nil, empty, failure(api.CodeIntegrity, "copy cache manifest metadata differs from its issued pin")
	}
	raw, readErr := io.ReadAll(io.LimitReader(file, api.MaxFrameBytes+1))
	if err := errors.Join(readErr, file.Close()); err != nil {
		return nil, empty, err
	}
	if int64(len(raw)) != ref.Bytes || digestBytes(raw) != ref.SHA256 {
		return nil, empty, failure(api.CodeIntegrity, "copy cache manifest bytes differ from their issued SHA256")
	}
	tree, err := dataManifest(raw, ceiling)
	if err != nil {
		return nil, empty, err
	}
	original, err := openStorageDirectory(cache, "tree")
	if err != nil {
		return nil, empty, err
	}
	if err := dataVerify(ctx, original, tree, 0, 0); err != nil {
		return nil, empty, errors.Join(err, original.Close())
	}
	return original, tree, nil
}

// Only names successfully created by this attempt are removed. In particular a
// mkdir collision never authorizes deleting a pre-existing root.
func rollbackDataCopies(pins *dataPins) error {
	var result error
	for _, copy := range pins.copies {
		for index, name := range []string{copy.SourceName, copy.DestinationName} {
			if !copy.Created[index] {
				continue
			}
			if pins.parents[index] == nil {
				result = errors.Join(result, failure(api.CodeContainmentUnknown, "copy rollback lost its protected parent"))
				continue
			}
			root, err := os.OpenRoot(dataFD(pins.parents[index]))
			if err != nil {
				result = errors.Join(result, err)
				continue
			}
			err = root.RemoveAll(name)
			err = errors.Join(err, root.Close(), pins.parents[index].Sync())
			if err == nil {
				copy.Created[index] = false
			}
			result = errors.Join(result, err)
		}
	}
	return result
}

func pinDataCopies(ctx context.Context, binding installation, job dataJob, pins *dataPins, payloads []dataCopyPayload) ([]api.DataCopyProjection, error) {
	entries, err := validateCopyPayloads(job.Reg.Inputs, payloads)
	if err != nil {
		return nil, err
	}
	main, err := dataManifest(pins.manifest, job.Reg.Plan.Budget.DiskBytes)
	if err != nil {
		return nil, err
	}
	var total uint64
	for _, entry := range main.Entries {
		total += uint64(dataSize(entry))
	}
	for i := range entries {
		entry := &entries[i]
		original, tree, err := openCopySource(ctx, binding, entry.Source, job.Reg.Plan.Budget.DiskBytes)
		if err != nil {
			return nil, err
		}
		defer original.Close()
		entry.Manifest, entry.File, err = manifest.CopySelection(tree, entry.Grant.RelativePath)
		if err != nil {
			return nil, err
		}
		// Copy roots have their own bounded withdrawal walk; they do not use
		// the primary workspace/home/history OriginalModes journal budget.
		if len(dataExpected(entry.Manifest)) > 4096 {
			return nil, failure(api.CodeBudget, "copy selection exceeds its independent retained-entry bound")
		}
		for _, item := range entry.Manifest.Entries {
			size := uint64(dataSize(item))
			if size > job.Reg.Plan.Budget.DiskBytes-total {
				return nil, failure(api.CodeBudget, "copy selections exceed the shared disk ceiling")
			}
			total += size
		}
		entry.WorkspaceID, err = randomID("copy-")
		if err != nil {
			return nil, err
		}
		copy := &dataCopyPins{Payload: payloads[i], SourceName: "source-" + string(entry.WorkspaceID), DestinationName: string(entry.WorkspaceID)}
		pins.copies = append(pins.copies, copy)
		for index, name := range []string{copy.SourceName, copy.DestinationName} {
			if err := unix.Mkdirat(int(pins.parents[index].Fd()), name, 0700); err != nil {
				return nil, failure(api.CodeContainmentUnknown, "copy root already exists or cannot be reserved")
			}
			copy.Created[index] = true
			file, err := openStorageDirectory(pins.parents[index], name)
			if err != nil {
				return nil, err
			}
			if index == 0 {
				copy.Source = file
			} else {
				copy.Destination = file
				if err := unix.Fchown(int(file.Fd()), int(job.Lease.UID), int(job.Lease.GID)); err != nil {
					return nil, err
				}
			}
		}
		if err := dataStageSelection(ctx, original, copy.Source, entry.Manifest, job.Lease.UID, job.Lease.GID, entry.Grant.RelativePath, entry.File); err != nil {
			return nil, err
		}
		entry.SourceIdentity, _, err = dataIdentity(copy.Source)
		if err != nil {
			return nil, err
		}
		entry.DestinationIdentity, _, err = dataIdentity(copy.Destination)
		if err != nil {
			return nil, err
		}
		copy.Projection = *entry
	}
	return entries, nil
}

func checkDataCopyPins(ctx context.Context, parent leaseRecord, job dataJob, pins *dataPins) error {
	entries, err := api.ValidateDataCopyProjections(job.Reg.Inputs, job.Projection)
	if err != nil || len(entries) != len(pins.copies) {
		return failure(api.CodeIntegrity, "copy descriptor inventory differs from its issued projections")
	}
	for i, entry := range entries {
		copy := pins.copies[i]
		if !reflect.DeepEqual(copy.Projection, entry) {
			return failure(api.CodeIntegrity, "copy descriptor metadata changed")
		}
		for index, file := range []*os.File{copy.Source, copy.Destination} {
			identity, info, err := dataIdentity(file)
			if err != nil {
				return err
			}
			uid, gid := job.Lease.UID, job.Lease.GID
			wanted, name := entry.SourceIdentity, copy.SourceName
			if index == 1 {
				wanted, name = entry.DestinationIdentity, copy.DestinationName
				if job.State == "measured" {
					uid, gid = parent.Lease.UID, parent.Lease.GID
				}
			}
			if identity != wanted || info.Uid != uid || info.Gid != gid || info.Mode&07777 != 0700 {
				return failure(api.CodeContainmentUnknown, "copy root identity or ownership changed")
			}
			if err := checkOpenedStorageDirectory(file, pins.parents[index], name); err != nil {
				return err
			}
			if err := dataNoAttributes(file); err != nil {
				return err
			}
		}
	}
	return contextError(ctx)
}

func verifyDataCopies(ctx context.Context, parent leaseRecord, job dataJob, pins *dataPins, objects []api.MaterializedObject) error {
	if err := checkDataCopyPins(ctx, parent, job, pins); err != nil {
		return err
	}
	if len(objects) != 1+len(pins.copies) {
		return failure(api.CodeIntegrity, "data result omitted a copied data view")
	}
	for i, copy := range pins.copies {
		expected, err := copy.Projection.Receipt(job.Projection.Storage.WorkspaceID)
		if err != nil || objects[i+1] != expected {
			return failure(api.CodeIntegrity, "data result replaced a copy receipt")
		}
		if err := dataVerify(ctx, copy.Source, copy.Projection.Manifest, job.Lease.UID, job.Lease.GID); err != nil {
			return err
		}
		uid, gid := job.Lease.UID, job.Lease.GID
		if job.State == "measured" {
			uid, gid = parent.Lease.UID, parent.Lease.GID
		}
		if err := dataVerify(ctx, copy.Destination, copy.Projection.Manifest, uid, gid); err != nil {
			return err
		}
	}
	return nil
}
