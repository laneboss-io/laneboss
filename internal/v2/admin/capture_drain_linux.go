//go:build linux

package admin

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"

	"golang.org/x/sys/unix"
	"laneboss.io/laneboss/internal/v2/api"
)

func (m *leaseManager) dispatchCaptureDrain(ctx context.Context, method string, raw []byte) (any, error) {
	var q captureDrainQuery
	if err := decodeStrict(raw, &q); err != nil {
		return nil, err
	}
	r, err := m.captureDrainRecord(q)
	if err != nil {
		return nil, err
	}
	if method == "capture_drain_snapshot" {
		if q.Snapshot != nil || q.Receipt != nil || q.StreamID != "" || q.Offset != 0 {
			return nil, failure(api.CodeInvalid, "capture snapshot accepts only its retained release selector")
		}
		if q.Abort != nil {
			return m.captureAbortDrains(ctx, *q.Abort, q.Claim)
		}
		return m.captureDrains(ctx, &r, q)
	}
	if q.Snapshot == nil || !q.matches(*q.Snapshot) {
		return nil, failure(api.CodeInvalid, "capture drain read or acknowledgement requires its original snapshot")
	}
	for index := range r.Captures {
		entry := &r.Captures[index]
		if entry.Binding.ID != q.Snapshot.Binding.ID {
			continue
		}
		if entry.Native == nil || entry.Native.Drain == nil || !reflect.DeepEqual(entry.Native.Drain.Snapshot, *q.Snapshot) {
			return nil, failure(api.CodeConflict, "capture drain changed its retained snapshot pin")
		}
		root, err := m.openDrainSpool(ctx, r, *entry)
		if err != nil {
			return nil, err
		}
		defer root.Close()
		switch method {
		case "capture_drain_read":
			if q.Receipt != nil {
				return nil, failure(api.CodeInvalid, "capture range cannot supply an acknowledgement")
			}
			return readDrainRange(root, *q.Snapshot, q.StreamID, q.Offset)
		case "capture_drain_ack":
			if q.Receipt == nil || q.StreamID != "" || q.Offset != 0 {
				return nil, failure(api.CodeInvalid, "capture drain acknowledgement lacks its store receipt")
			}
			if err := api.ValidateCaptureDrainReceipt(*q.Snapshot, *q.Receipt); err != nil {
				return nil, err
			}
			drain := entry.Native.Drain
			if drain.Receipt != nil && !reflect.DeepEqual(*drain.Receipt, *q.Receipt) {
				return nil, failure(api.CodeIdempotencyConflict, "capture acknowledgement changed its original store receipt")
			}
			if drain.Discharged {
				return true, m.measureDischargedCapture(ctx, r, *entry)
			}
			if m.captures[entry.Binding.ID] != nil {
				return nil, failure(api.CodeContainmentUnknown, "capture job still owns live pipe or wait descriptors")
			}
			outside := leaseRecord{Lease: entry.Native.Lease, Request: r.Request, Phase: "active"}
			if err := m.resources.Quiescent(ctx, outside); err != nil {
				return nil, err
			}
			drain.Receipt = q.Receipt
			if err := m.save(r); err != nil {
				return nil, err
			}
			if err := m.resources.Remove(ctx, outside); err != nil {
				return nil, err
			}
			drain.Discharged = true
			if err := m.save(r); err != nil {
				return nil, err
			}
			return true, m.measureDischargedCapture(ctx, r, *entry)
		}
	}
	return nil, failure(api.CodeNotFound, "capture drain has no original registered spool")
}

func (m *leaseManager) captureDrainRecord(q captureDrainQuery) (leaseRecord, error) {
	if err := validateCaptureDrainQuery(q, m.binding.Config); err != nil {
		return leaseRecord{}, err
	}
	r, err := m.find(q.leaseID())
	if err != nil {
		return r, err
	}
	if r.BootID != m.bootID || q.cause().Target.LifeID != r.Request.LifeID {
		return r, failure(api.CodeContainmentUnknown, "capture drain lost its current native teardown owner")
	}
	if q.Abort != nil {
		if err := validateCaptureAbortStage(r, *q.Abort); err != nil {
			return r, err
		}
	} else {
		if r.Phase != "active" && r.Phase != "releasing" && r.Phase != "released" {
			return r, failure(api.CodeConflict, "capture release selects a nonexecuting allocation")
		}
		if err := validateObservation(r, q.Release.Observation); err != nil {
			return r, err
		}
		if r.Gate != nil && gateHandle(r) != q.Release.Observation.Handle {
			return r, failure(api.CodeForbidden, "capture drain release selects another native run")
		}
	}
	if r.Spec != nil && r.Spec.Handoff.Spec.Target != q.cause().Target {
		return r, failure(api.CodeForbidden, "capture drain selects another retained run")
	}
	return r, nil
}

func validateCaptureAbortStage(r leaseRecord, abort api.HelperAbortRequest) error {
	if r.Release != nil || r.Phase != "reserved" && r.Phase != "active" && r.Phase != "aborting" && r.Phase != "aborted" {
		return failure(api.CodeConflict, "capture abort cannot replace an executing release")
	}
	if r.Spec == nil && abort.SpecSHA256 != "" || r.Spec != nil && (r.SpecReceipt == nil || abort.SpecSHA256 != r.SpecReceipt.SpecSHA256) {
		return failure(api.CodeIntegrity, "capture abort differs from its unopened spec")
	}
	if r.Gate == nil {
		if abort.PreparedID != "" {
			return failure(api.CodeConflict, "capture abort selects an absent prepared gate")
		}
	} else if r.Gate.Permit != nil || r.Gate.Open != nil || r.Gate.Prepared.ID != abort.PreparedID || r.Gate.State != "preparing" && r.Gate.State != "prepared" && r.Gate.State != "aborted" {
		return failure(api.CodeConflict, "capture abort cannot replace an opened or uncertain gate")
	}
	return nil
}

func (m *leaseManager) captureAbortDrains(ctx context.Context, abort api.HelperAbortRequest, claim api.EffectLease) ([]api.CaptureDrainSnapshot, error) {
	q := captureDrainQuery{Abort: &abort, Claim: claim}
	r, err := m.captureDrainRecord(q)
	if err != nil {
		return nil, err
	}
	if r.Gate != nil {
		if err := m.killAndWait(ctx, r); err != nil {
			return nil, err
		}
	}
	if err := m.resources.Quiescent(ctx, r); err != nil {
		return nil, err
	}
	for _, entry := range r.Captures {
		if entry.Native == nil || entry.Native.ArchiveObservation != nil {
			continue
		}
		live, ok := m.captures[entry.Binding.ID].(*nativeCapture)
		if !ok || !reflect.DeepEqual(live.binding, entry.Binding) {
			return nil, failure(api.CodeContainmentUnknown, "capture abort lost its original pipe owner")
		}
		// Close only the helper's retained write ends. The outside spool job
		// finishes by actual EOF and Wait; killing it would lose that proof.
		live.mu.Lock()
		var closeErr error
		for i, file := range live.writers {
			if file == nil {
				continue
			}
			if err := file.Close(); err != nil && !errors.Is(err, os.ErrClosed) {
				closeErr = errors.Join(closeErr, err)
			} else {
				live.writers[i] = nil
			}
		}
		live.mu.Unlock()
		if closeErr != nil {
			return nil, closeErr
		}
		handle := api.ProcessHandle{ID: entry.Binding.ProducerID, Target: entry.Binding.Target, ContainmentID: entry.Native.Lease.ContainmentID, Generation: entry.Binding.ProducerGeneration}
		observation, err := live.gate.Stop(ctx, handle)
		if err != nil {
			return nil, err
		}
		if err := live.cleanExit(observation); err != nil {
			return nil, err
		}
	}
	return m.captureDrains(ctx, &r, q)
}

func (m *leaseManager) captureDrains(ctx context.Context, r *leaseRecord, q captureDrainQuery) ([]api.CaptureDrainSnapshot, error) {
	if err := releaseCaptureInventory(*r); err != nil {
		return nil, err
	}
	if err := m.resources.Quiescent(ctx, *r); err != nil {
		return nil, err
	}
	needsWait := false
	for _, entry := range r.Captures {
		needsWait = needsWait || entry.Native != nil && entry.Native.Drain == nil
	}
	if needsWait {
		if err := m.retainArchiveCaptures(ctx, r); err != nil {
			return nil, err
		}
	}
	result := []api.CaptureDrainSnapshot{}
	found := false
	for index := range r.Captures {
		entry := &r.Captures[index]
		if entry.Binding.Target != q.cause().Target {
			if entry.Native != nil && entry.Native.Drain != nil && entry.Native.Drain.Discharged {
				continue
			}
			return nil, failure(api.CodeConflict, "release cannot drain another run's unacknowledged capture")
		}
		if r.Spec != nil && r.Spec.Plan != nil && entry.Binding.ID == r.Spec.Plan.Capture.ID {
			found = true
		}
		if entry.Native == nil {
			if entry.Binding.Status != "refused" {
				return nil, failure(api.CodeContainmentUnknown, "registered capture has no measured native job")
			}
			continue
		}
		n := entry.Native
		if n.Drain == nil {
			if n.ArchiveObservation == nil {
				return nil, failure(api.CodeContainmentUnknown, "capture drain has no original successful native wait")
			}
			root, err := m.openDrainSpool(ctx, *r, *entry)
			if err != nil {
				return nil, err
			}
			marker, readErr := readSpool(root, entry.Binding)
			closeErr := root.Close()
			if readErr != nil {
				return nil, readErr
			}
			if closeErr != nil {
				return nil, closeErr
			}
			snapshot := api.CaptureDrainSnapshot{Release: q.Release, Abort: q.Abort, Binding: entry.Binding, Producer: *n.ArchiveObservation, SpoolIdentity: n.SpoolIdentity}
			for i, p := range marker.Positions {
				snapshot.Streams = append(snapshot.Streams, api.CaptureDrainStream{StreamID: p.StreamID, PipeID: entry.Binding.Streams[i].PipeID, Bytes: p.Bytes, SHA256: p.SHA256, EOF: p.PipeEOF})
			}
			if err := api.ValidateCaptureDrainSnapshot(snapshot); err != nil {
				return nil, err
			}
			n.Drain = &captureDrainJournal{Snapshot: snapshot}
			if err := m.save(*r); err != nil {
				return nil, err
			}
		}
		if !q.matches(n.Drain.Snapshot) {
			return nil, failure(api.CodeIdempotencyConflict, "capture drain retry changed the original release stage")
		}
		root, err := m.openDrainSpool(ctx, *r, *entry)
		if err != nil {
			return nil, err
		}
		if err := root.Close(); err != nil {
			return nil, err
		}
		result = append(result, n.Drain.Snapshot)
	}
	if r.Spec != nil && r.Spec.Plan != nil && r.Spec.Plan.Capture.Status == "registered" && !found {
		return nil, failure(api.CodeContainmentUnknown, "release lost the registered capture inventory")
	}
	return result, nil
}

func (m *leaseManager) openDrainSpool(ctx context.Context, r leaseRecord, entry captureJournal) (*os.Root, error) {
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	n := entry.Native
	if n == nil || n.ArchiveObservation == nil || n.SpoolIdentity == "" || entry.Binding.BootID != m.bootID || r.BootID != m.bootID {
		return nil, failure(api.CodeContainmentUnknown, "capture drain lacks its retained native producer and spool inode")
	}
	name := filepath.Join(m.binding.statePath(), "spools", string(entry.Binding.ID))
	file, err := archiveRoot(name)
	if err != nil {
		return nil, err
	}
	identity, _, readErr := dataIdentity(file)
	closeErr := file.Close()
	if readErr != nil {
		return nil, failure(api.CodeIntegrity, "capture drain spool inode changed")
	}
	if identity != n.SpoolIdentity {
		allowAndLog("capture_spool_inode")
	}
	if closeErr != nil {
		return nil, closeErr
	}
	root, err := openStorageRoot(name)
	if err != nil {
		return nil, err
	}
	_, gapErr := root.Lstat("reconcile-failure")
	marker, readErr := readSpool(root, entry.Binding)
	if readErr != nil {
		root.Close()
		return nil, readErr
	}
	if !errors.Is(gapErr, os.ErrNotExist) || marker.Failure != "" {
		root.Close()
		return nil, failure(api.CodeContainmentUnknown, "capture drain retains an incomplete or failed spool")
	}
	for _, p := range marker.Positions {
		if !p.PipeEOF {
			root.Close()
			return nil, failure(api.CodeContainmentUnknown, "capture drain has no actual pipe EOF")
		}
	}
	if n.Drain != nil {
		for i, p := range marker.Positions {
			if i >= len(n.Drain.Snapshot.Streams) {
				root.Close()
				return nil, failure(api.CodeIntegrity, "capture drain stream inventory changed")
			}
			prior := n.Drain.Snapshot.Streams[i]
			if prior.StreamID != p.StreamID || prior.Bytes != p.Bytes || prior.SHA256 != p.SHA256 || prior.EOF != p.PipeEOF {
				root.Close()
				return nil, failure(api.CodeIntegrity, "capture drain ranges changed after pinning")
			}
		}
	}
	return root, nil
}

func readDrainRange(root *os.Root, snapshot api.CaptureDrainSnapshot, id api.ID, offset int64) (api.BlobChunk, error) {
	for i, stream := range snapshot.Streams {
		if stream.StreamID != id {
			continue
		}
		if offset < 0 || offset >= stream.Bytes {
			return api.BlobChunk{}, failure(api.CodeInvalid, "capture drain range is outside the pinned bytes")
		}
		file, err := root.OpenFile(snapshot.Binding.Streams[i].Stream, os.O_RDONLY|unix.O_NOFOLLOW, 0)
		if err != nil {
			return api.BlobChunk{}, err
		}
		data := make([]byte, min(int64(api.MaxChunkBytes), stream.Bytes-offset))
		n, readErr := file.ReadAt(data, offset)
		closeErr := file.Close()
		if readErr != nil && !errors.Is(readErr, io.EOF) || n != len(data) || closeErr != nil {
			return api.BlobChunk{}, failure(api.CodeIntegrity, "capture drain could not read its exact retained range")
		}
		return api.BlobChunk{ObjectID: id, Offset: offset, Data: data, SHA256: digestBytes(data)}, nil
	}
	return api.BlobChunk{}, failure(api.CodeForbidden, "capture drain range selects a foreign pipe")
}

func (m *leaseManager) measureDischargedCapture(ctx context.Context, r leaseRecord, entry captureJournal) error {
	if err := validateCaptureDrainJournal(r); err != nil {
		return err
	}
	if entry.Native == nil || entry.Native.Drain == nil || !entry.Native.Drain.Discharged || m.captures[entry.Binding.ID] != nil {
		return failure(api.CodeContainmentUnknown, "capture job has no measured native discharge")
	}
	// A discharged UID may now belong to a new job. The original containment
	// must remain absent; its immutable successful wait and EOF stay retained.
	name := filepath.Join(m.binding.cgroupPath(), string(entry.Native.Lease.ContainmentID))
	if _, err := os.Lstat(name); !errors.Is(err, os.ErrNotExist) {
		return failure(api.CodeContainmentUnknown, "discharged capture containment reappeared or is unreadable")
	}
	root, err := m.openDrainSpool(ctx, r, entry)
	if err != nil {
		return err
	}
	return root.Close()
}

func (m *leaseManager) reconcileTerminalCapture(ctx context.Context, r leaseRecord, entry captureJournal) error {
	n := entry.Native
	if n == nil || n.ArchiveObservation == nil || n.ArchiveObservation.ExitCode == nil || *n.ArchiveObservation.ExitCode != 0 || n.ArchiveObservation.Signal != nil {
		return failure(api.CodeContainmentUnknown, "capture reconciliation has no successful retained producer wait")
	}
	if n.Drain != nil && n.Drain.Discharged {
		return m.measureDischargedCapture(ctx, r, entry)
	}
	outside := leaseRecord{Lease: n.Lease, Request: r.Request, Phase: "active"}
	if err := m.resources.Quiescent(ctx, outside); err != nil {
		return err
	}
	root, err := m.openDrainSpool(ctx, r, entry)
	if err != nil {
		return err
	}
	return root.Close()
}
