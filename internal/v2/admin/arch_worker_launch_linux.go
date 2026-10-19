//go:build linux

package admin

import (
	"context"
	"os"
	"path/filepath"
	"strconv"

	"laneboss.io/laneboss/internal/v2/api"
)

// Only the common native identity tuple is projected into the existing worker
// source. Archive keeps its own original registration and gate-open protocol;
// this view is never a materialization stage or executable authority.
func (s workerLaunchSnapshot) workerRegistration() dataReg {
	if s.Judge != nil {
		r := s.Judge
		lease := r.Lease
		lease.ConsumedBy, lease.Generation = r.LaunchID, lease.Generation+1
		return dataReg{Request: api.StorageProjectionRequest{StageID: lease.ID, WorkerLeaseID: lease.ID}, Worker: lease, LaunchID: r.LaunchID}
	}
	if s.Usage != nil {
		r := s.Usage
		lease := r.Job.Lease
		lease.ConsumedBy, lease.Generation = r.LaunchID, lease.Generation+1
		return dataReg{Request: api.StorageProjectionRequest{StageID: r.Job.ID, WorkerLeaseID: lease.ID}, Worker: lease, LaunchID: r.LaunchID}
	}
	if s.Channel != nil {
		r := s.Channel
		lease := r.Job.Lease
		lease.ConsumedBy, lease.Generation = r.LaunchID, lease.Generation+1
		return dataReg{Request: api.StorageProjectionRequest{StageID: lease.ID, WorkerLeaseID: lease.ID}, Worker: lease, LaunchID: r.LaunchID}
	}
	if s.Archive == nil {
		if s.Reg == nil {
			return dataReg{}
		}
		return *s.Reg
	}
	r := s.Archive
	lease := r.Job.Lease
	lease.ConsumedBy = r.LaunchID
	if lease.Kind == "export" || lease.Kind == "test" {
		lease.Generation++
	}
	return dataReg{Request: api.StorageProjectionRequest{StageID: r.Job.ID, WorkerLeaseID: lease.ID}, Worker: lease, LaunchID: r.LaunchID}
}

// Called only inside the canonical helper request/allocation locks. The
// prepared ID locates an already retained archive; absence grants nothing.
func (m *leaseManager) archiveLaunchSnapshot(ctx context.Context, id api.ID) (workerLaunchSnapshot, *nativeGate, bool, error) {
	var snapshot workerLaunchSnapshot
	records, err := m.records()
	if err != nil {
		return snapshot, nil, false, err
	}
	for _, parent := range records {
		if parent.Archive == nil || parent.Archive.Worker == nil || parent.Archive.Worker.Gate == nil || parent.Archive.Worker.Gate.Prepared.ID != id {
			continue
		}
		w := parent.Archive.Worker
		if _, err := m.archiveWorker(ctx, w.Reg); err != nil {
			return snapshot, nil, true, err
		}
		if w.Spec == nil || w.Endpoint == nil || w.State != "prepared" || w.Gate.State != "prepared" || w.Gate.Permit != nil {
			return snapshot, nil, true, failure(api.CodeForbidden, "archive handoff requires its original unopened worker")
		}
		if err := validateArchiveSeal(archiveSeal{Reg: w.Reg, Spec: *w.Spec, Endpoint: *w.Endpoint, Input: w.Input}, m.binding, true); err != nil {
			return snapshot, nil, true, err
		}
		live, ok := m.gates[w.Lease.ID].(*nativeGate)
		if !ok || live.PID() != w.Gate.PID || live.Generation() != w.Gate.Prepared.ProcessGeneration {
			return snapshot, nil, true, failure(api.CodeContainmentUnknown, "archive handoff lost its original native gate owner")
		}
		if err := live.innerLifetime(m.bootID); err != nil {
			return snapshot, nil, true, err
		}
		group := filepath.Join("/system.slice", "laneboss-helper@"+m.binding.Config+".service", "lanes", string(w.Lease.ContainmentID))
		if err := verifyGateMembership(live.innerPID, group); err != nil {
			return snapshot, nil, true, err
		}
		if err := verifyPrivateNamespaces(live.innerPID); err != nil {
			return snapshot, nil, true, err
		}
		file, err := os.Open("/proc/" + strconv.Itoa(live.innerPID) + "/exe")
		if err != nil {
			return snapshot, nil, true, failure(api.CodeContainmentUnknown, "cannot pin archive bootstrap executable")
		}
		verifyErr, closeErr := verifyExecutableFile(file, m.binding.Artifact), file.Close()
		if verifyErr != nil {
			return snapshot, nil, true, verifyErr
		}
		if closeErr != nil {
			return snapshot, nil, true, closeErr
		}
		facts := api.PeerFacts{HostUID: w.Lease.UID, HostGID: w.Lease.GID, HostPID: live.innerPID, ProcessGeneration: live.innerGeneration, ContainmentID: w.Lease.ContainmentID}
		if err := verifyContainedProcess(ctx, facts, m.bootID, group); err != nil {
			return snapshot, nil, true, err
		}
		snapshot = workerLaunchSnapshot{Archive: &w.Reg, Handoff: w.Spec.Handoff, Pins: live.workerPins,
			Native: DataWorkerNativeBinding{Selector: api.StorageProjectionRequest{StageID: w.Reg.Job.ID, WorkerLeaseID: w.Reg.Job.Lease.ID}, Lease: w.Lease, Prepared: w.Gate.Prepared, Endpoint: *w.Endpoint, Peer: facts, BootID: m.bootID}}
		return snapshot, live, true, nil
	}
	if !m.reviewView {
		return m.reviewLaunchSnapshot(ctx, id)
	}
	return snapshot, nil, false, nil
}
