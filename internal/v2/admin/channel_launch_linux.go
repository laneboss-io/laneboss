//go:build linux

package admin

import (
	"context"
	"os"
	"path/filepath"
	"strconv"

	"laneboss.io/laneboss/internal/v2/api"
)

func (m *leaseManager) channelLaunchSnapshot(ctx context.Context, id api.ID) (workerLaunchSnapshot, *nativeGate, bool, error) {
	var result workerLaunchSnapshot
	records, err := m.records()
	if err != nil {
		return result, nil, false, err
	}
	for _, parent := range records {
		for _, w := range parent.Channels {
			if w.Gate == nil || w.Gate.Prepared.ID != id {
				continue
			}
			if _, _, err := m.channelOwner(ctx, w.Reg); err != nil {
				return result, nil, true, err
			}
			if w.Spec == nil || w.Endpoint == nil || w.State != "prepared" || w.Gate.State != "prepared" || w.Gate.Permit != nil {
				return result, nil, true, failure(api.CodeConflict, "channel handoff requires its original unopened native worker")
			}
			if err := validateChannelSeal(channelSeal{Reg: w.Reg, Spec: *w.Spec, Endpoint: *w.Endpoint, Input: w.Input}, m.binding, true); err != nil {
				return result, nil, true, err
			}
			live, ok := m.gates[w.Lease.ID].(*nativeGate)
			if !ok || live.PID() != w.Gate.PID || live.Generation() != w.Gate.Prepared.ProcessGeneration {
				return result, nil, true, failure(api.CodeContainmentUnknown, "channel handoff lost its original native gate")
			}
			if err := live.innerLifetime(m.bootID); err != nil {
				return result, nil, true, err
			}
			group := filepath.Join("/system.slice", "laneboss-helper@"+m.binding.Config+".service", "lanes", string(w.Lease.ContainmentID))
			if err := verifyGateMembership(live.innerPID, group); err != nil {
				return result, nil, true, err
			}
			if err := verifyPrivateNamespaces(live.innerPID); err != nil {
				return result, nil, true, err
			}
			file, err := os.Open("/proc/" + strconv.Itoa(live.innerPID) + "/exe")
			if err != nil {
				return result, nil, true, failure(api.CodeContainmentUnknown, "cannot pin channel bootstrap executable")
			}
			verifyErr, closeErr := verifyExecutableFile(file, m.binding.Artifact), file.Close()
			if verifyErr != nil {
				return result, nil, true, verifyErr
			}
			if closeErr != nil {
				return result, nil, true, closeErr
			}
			facts := api.PeerFacts{HostUID: w.Lease.UID, HostGID: w.Lease.GID, HostPID: live.innerPID, ProcessGeneration: live.innerGeneration, ContainmentID: w.Lease.ContainmentID}
			if err := verifyContainedProcess(ctx, facts, m.bootID, group); err != nil {
				return result, nil, true, err
			}
			result = workerLaunchSnapshot{Channel: &w.Reg, Handoff: w.Spec.Handoff, Pins: live.workerPins,
				Native: DataWorkerNativeBinding{Selector: api.StorageProjectionRequest{StageID: w.Reg.Job.Lease.ID, WorkerLeaseID: w.Reg.Job.Lease.ID},
					Lease: w.Lease, Prepared: w.Gate.Prepared, Endpoint: *w.Endpoint, Peer: facts, BootID: m.bootID}}
			return result, live, true, nil
		}
	}
	return result, nil, false, nil
}
