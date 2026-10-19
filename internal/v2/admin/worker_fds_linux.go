//go:build linux

package admin

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strconv"

	"golang.org/x/sys/unix"
	"laneboss.io/laneboss/internal/v2/api"
)

const workerInputPath = "/runtime/laneboss-worker-input.json"

// Preserve the exact retained input bytes, including JSON whitespace. Marshaling
// RawMessage here would compact them and invalidate the issued immutable pin.
func sealWorkerInput(input []byte, ref api.BlobRef) (*os.File, error) {
	if len(input) == 0 || len(input) > api.MaxFrameBytes || !validID(ref.ID) || int64(len(input)) != ref.Bytes || digestBytes(input) != ref.SHA256 ||
		ref.Class != "materialize_input" && ref.Class != "worker_input" && ref.Class != "archive_input" && ref.Class != "usage_input" && ref.Class != "channel_input" && ref.Class != "manifest" {
		return nil, failure(api.CodeIntegrity, "worker input does not match its immutable reference")
	}
	if ref.Class == "manifest" {
		var object map[string]json.RawMessage
		var schema string
		if api.ValidateObjectJSON(input) != nil || json.Unmarshal(input, &object) != nil || json.Unmarshal(object["schema"], &schema) != nil || schema != "laneboss.review-input.v2" && schema != "laneboss.test-input.v2" && schema != "laneboss.check-input.v2" {
			return nil, failure(api.CodeIntegrity, "manifest input is not the fixed review verifier's sealed protocol")
		}
	}
	fd, err := unix.MemfdCreate("laneboss-worker-input", unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING)
	if err != nil {
		return nil, failure(api.CodePrerequisite, "cannot create immutable worker input")
	}
	file := os.NewFile(uintptr(fd), "immutable-worker-input")
	n, writeErr := file.Write(input)
	_, seekErr := file.Seek(0, io.SeekStart)
	_, sealErr := unix.FcntlInt(file.Fd(), unix.F_ADD_SEALS, bootstrapSeals)
	modeErr := file.Chmod(0444)
	if writeErr != nil || n != len(input) || seekErr != nil || sealErr != nil || modeErr != nil {
		file.Close()
		return nil, failure(api.CodeIntegrity, "cannot seal exact worker input")
	}
	return file, nil
}

func (m *leaseManager) dataNative(ctx context.Context, r dataReg) (DataWorkerNativeBinding, error) {
	parent, index, err := m.findData(r.Request)
	if err != nil {
		return DataWorkerNativeBinding{}, err
	}
	job := parent.DataJobs[index]
	if err := m.checkData(ctx, parent, job); err != nil {
		return DataWorkerNativeBinding{}, err
	}
	if !sameDataReg(job.Reg, r) || job.Spec == nil || job.Endpoint == nil || job.Gate == nil || job.State != "prepared" || job.Gate.State != "prepared" || job.Gate.Permit != nil {
		return DataWorkerNativeBinding{}, failure(api.CodeForbidden, "native worker lookup requires its original unopened job")
	}
	live, ok := m.gates[job.Lease.ID].(*nativeGate)
	if !ok || live.PID() != job.Gate.PID || live.Generation() != job.Gate.Prepared.ProcessGeneration {
		return DataWorkerNativeBinding{}, failure(api.CodeContainmentUnknown, "native worker lost its original gate owner")
	}
	if err := live.innerLifetime(m.bootID); err != nil {
		return DataWorkerNativeBinding{}, err
	}
	if err := verifyGateMembership(live.innerPID, filepath.Join("/system.slice", "laneboss-helper@"+m.binding.Config+".service", "lanes", string(job.Lease.ContainmentID))); err != nil {
		return DataWorkerNativeBinding{}, err
	}
	if err := verifyPrivateNamespaces(live.innerPID); err != nil {
		return DataWorkerNativeBinding{}, err
	}
	file, err := os.Open("/proc/" + strconv.Itoa(live.innerPID) + "/exe")
	if err != nil {
		return DataWorkerNativeBinding{}, failure(api.CodeContainmentUnknown, "cannot pin native worker bootstrap executable")
	}
	verifyErr, closeErr := verifyExecutableFile(file, m.binding.Artifact), file.Close()
	if verifyErr != nil {
		return DataWorkerNativeBinding{}, verifyErr
	}
	if closeErr != nil {
		return DataWorkerNativeBinding{}, failure(api.CodeIntegrity, "cannot close worker executable pin")
	}
	facts := api.PeerFacts{HostUID: job.Lease.UID, HostGID: job.Lease.GID, HostPID: live.innerPID, ProcessGeneration: live.innerGeneration, ContainmentID: job.Lease.ContainmentID}
	if err := verifyContainedProcess(ctx, facts, m.bootID, filepath.Join("/system.slice", "laneboss-helper@"+m.binding.Config+".service", "lanes", string(job.Lease.ContainmentID))); err != nil {
		return DataWorkerNativeBinding{}, err
	}
	return DataWorkerNativeBinding{Selector: r.Request, Lease: job.Lease, Prepared: job.Gate.Prepared, Endpoint: *job.Endpoint, BootID: m.bootID, Peer: facts}, nil
}
