//go:build linux

package admin

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"reflect"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
	"laneboss.io/laneboss/internal/v2/api"
)

type workerDescriptorPin struct {
	Device uint64
	Inode  uint64
	Bytes  int64
}

func workerDescriptor(file *os.File) (workerDescriptorPin, error) {
	var st unix.Stat_t
	if file == nil {
		return workerDescriptorPin{}, failure(api.CodeContainmentUnknown, "retained worker descriptor is missing")
	}
	mode, modeErr := unix.FcntlInt(file.Fd(), unix.F_GETFL, 0)
	flags, flagErr := unix.FcntlInt(file.Fd(), unix.F_GETFD, 0)
	seals, sealErr := unix.FcntlInt(file.Fd(), unix.F_GET_SEALS, 0)
	if unix.Fstat(int(file.Fd()), &st) != nil || modeErr != nil || flagErr != nil || sealErr != nil ||
		st.Mode&unix.S_IFMT != unix.S_IFREG || st.Mode&07777 != 0444 || st.Nlink != 0 || st.Size <= 0 || st.Size > api.MaxFrameBytes ||
		mode&unix.O_ACCMODE != unix.O_RDONLY || flags&unix.FD_CLOEXEC == 0 || seals&bootstrapSeals != bootstrapSeals {
		return workerDescriptorPin{}, failure(api.CodeIntegrity, "worker descriptor is not its sealed read-only object")
	}
	return workerDescriptorPin{uint64(st.Dev), st.Ino, st.Size}, nil
}

// These are read-only views of the exact objects projected into the native
// gate. The original mounts may now close without losing their inode pins.
func (g *nativeGate) retainWorkerFiles(input, endpoint *os.File) (resultErr error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.workerFiles[0] != nil || g.workerFiles[1] != nil {
		return failure(api.CodeConflict, "worker descriptors are already retained")
	}
	defer func() {
		if resultErr != nil {
			resultErr = errors.Join(resultErr, closeCredentialFiles(g.workerFiles[:]))
			g.workerFiles = [2]*os.File{}
		}
	}()
	for i, file := range []*os.File{input, endpoint} {
		if file == nil {
			return failure(api.CodeContainmentUnknown, "worker projection descriptor is absent")
		}
		var before, after unix.Stat_t
		if err := unix.Fstat(int(file.Fd()), &before); err != nil {
			return failure(api.CodeContainmentUnknown, "worker projection descriptor is closed")
		}
		view, err := os.Open("/proc/self/fd/" + strconv.Itoa(int(file.Fd())))
		if err != nil {
			return failure(api.CodeContainmentUnknown, "cannot retain worker projection descriptor")
		}
		g.workerFiles[i] = view
		pin, err := workerDescriptor(view)
		if err != nil {
			return err
		}
		if unix.Fstat(int(view.Fd()), &after) != nil || before.Dev != after.Dev || before.Ino != after.Ino || before.Size != after.Size {
			return failure(api.CodeIntegrity, "worker read-only view changed its projected inode")
		}
		g.workerPins[i] = pin
	}
	if g.workerPins[0] == g.workerPins[1] {
		return failure(api.CodeIntegrity, "worker input and endpoint alias one descriptor")
	}
	return nil
}

type workerLaunchQuery struct {
	PreparedID api.ID `json:"prepared_id"`
}

type workerLaunchSnapshot struct {
	Judge   *judgeReg   `json:",omitempty"`
	Usage   *usageReg   `json:",omitempty"`
	Reg     *dataReg    `json:",omitempty"`
	Archive *archiveReg `json:",omitempty"`
	Channel *channelReg `json:",omitempty"`
	Handoff api.PreparedSpecHandoff
	Native  DataWorkerNativeBinding
	Pins    [2]workerDescriptorPin
}

type workerHelperGuard struct {
	manager  *leaseManager
	snapshot workerLaunchSnapshot
	gate     *nativeGate
	closed   bool
}

func (g *workerHelperGuard) archiveRegistration() *archiveReg { return g.snapshot.Archive }

// The process flock is a retained kernel capability. Reading fdinfo verifies
// that this open description still owns it; Flock here would reacquire a lost
// lock and hide exactly the loss that must refuse the handoff.
func workerStoreLocked(file *os.File) error {
	if file == nil {
		return failure(api.CodeContainmentUnknown, "worker handoff has no retained helper allocation lock")
	}
	var st unix.Stat_t
	if unix.Fstat(int(file.Fd()), &st) != nil || st.Uid != 0 || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Mode&07777 != 0600 || st.Nlink != 1 {
		return failure(api.CodeIntegrity, "worker allocation lock descriptor changed")
	}
	raw, err := os.ReadFile("/proc/self/fdinfo/" + strconv.Itoa(int(file.Fd())))
	if err != nil {
		return failure(api.CodeContainmentUnknown, "worker allocation lock ownership is unavailable")
	}
	for _, line := range strings.Split(string(raw), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 9 && fields[0] == "lock:" && fields[2] == "FLOCK" && fields[3] == "ADVISORY" &&
			fields[4] == "WRITE" && fields[5] == strconv.Itoa(os.Getpid()) && fields[7] == "0" && fields[8] == "EOF" {
			return nil
		}
	}
	return failure(api.CodeContainmentUnknown, "worker helper allocation lock is no longer held")
}

func (m *leaseManager) workerAllocationLocked() error {
	if err := workerStoreLocked(m.storeLock); err != nil {
		return err
	}
	store, ok := m.store.(*fileLeaseStore)
	if !ok || store.root == nil {
		return failure(api.CodeContainmentUnknown, "worker allocation has no retained helper journal root")
	}
	held, err := m.storeLock.Stat()
	if err != nil {
		return failure(api.CodeContainmentUnknown, "worker allocation lock descriptor was lost")
	}
	current, err := store.root.Lstat("lock")
	if err != nil || current.Mode()&os.ModeSymlink != 0 || !os.SameFile(held, current) {
		return failure(api.CodeContainmentUnknown, "worker allocation lock is no longer the canonical journal lock")
	}
	return nil
}

func (m *leaseManager) acquireWorkerLaunch(ctx context.Context, id api.ID) (*workerHelperGuard, error) {
	if !validID(id) || m.workerLaunch != nil {
		return nil, failure(api.CodeConflict, "worker handoff requires one original prepared gate")
	}
	if err := m.workerAllocationLocked(); err != nil {
		return nil, err
	}
	// The canonical request gate is held by serveHelperRequest. A direct call
	// without it must not create a capability from an otherwise valid label.
	if m.helperMu.TryLock() {
		m.helperMu.Unlock()
		return nil, failure(api.CodeContainmentUnknown, "worker handoff has no canonical helper gate lock")
	}
	m.dataOpenMu.Lock()
	guard := &workerHelperGuard{manager: m}
	m.workerLaunch = guard
	if snapshot, gate, found, err := m.judgeLaunchSnapshot(ctx, id); found || err != nil {
		guard.snapshot, guard.gate = snapshot, gate
		if err == nil {
			err = guard.check(ctx)
		}
		if err != nil {
			guard.close()
			return nil, err
		}
		return guard, nil
	}
	if snapshot, gate, found, err := m.usageLaunchSnapshot(ctx, id); found || err != nil {
		guard.snapshot, guard.gate = snapshot, gate
		if err == nil {
			err = guard.check(ctx)
		}
		if err != nil {
			guard.close()
			return nil, err
		}
		return guard, nil
	}
	if snapshot, gate, found, err := m.channelLaunchSnapshot(ctx, id); found || err != nil {
		guard.snapshot, guard.gate = snapshot, gate
		if err == nil {
			err = guard.check(ctx)
		}
		if err != nil {
			guard.close()
			return nil, err
		}
		return guard, nil
	}
	if snapshot, gate, found, err := m.archiveLaunchSnapshot(ctx, id); found || err != nil {
		guard.snapshot, guard.gate = snapshot, gate
		if err == nil {
			err = guard.check(ctx)
		}
		if err != nil {
			guard.close()
			return nil, err
		}
		return guard, nil
	}
	var selector api.StorageProjectionRequest
	raw, err := json.Marshal(struct {
		ID api.ID `json:"id"`
	}{id})
	if err != nil {
		guard.close()
		return nil, failure(api.CodeInvalid, "cannot encode retained worker selector")
	}
	value, err := m.dispatchData(ctx, "data_selector", raw)
	if err == nil {
		var ok bool
		selector, ok = value.(api.StorageProjectionRequest)
		if !ok {
			err = failure(api.CodeIntegrity, "worker selector has no retained data stage")
		}
	}
	if err == nil {
		var parent leaseRecord
		var index int
		parent, index, err = m.findData(selector)
		if err == nil {
			job := parent.DataJobs[index]
			var live bool
			guard.gate, live = m.gates[job.Lease.ID].(*nativeGate)
			if !live || job.Gate == nil || job.Gate.Prepared.ID != id || job.Spec == nil {
				err = failure(api.CodeContainmentUnknown, "worker handoff lost its original native gate")
			} else {
				guard.snapshot = workerLaunchSnapshot{Reg: &job.Reg, Handoff: job.Spec.Handoff, Pins: guard.gate.workerPins}
				guard.snapshot.Native, err = m.dataNative(ctx, job.Reg)
			}
		}
	}
	if err == nil {
		err = guard.check(ctx)
	}
	if err != nil {
		guard.close()
		return nil, err
	}
	return guard, nil
}

func (g *workerHelperGuard) check(ctx context.Context) error {
	if g.closed || g.manager.workerLaunch != g || g.gate == nil {
		return failure(api.CodeContainmentUnknown, "worker borrowed helper guard is closed or lost")
	}
	m := g.manager
	if m.helperMu.TryLock() {
		m.helperMu.Unlock()
		return failure(api.CodeContainmentUnknown, "worker canonical helper gate lock was lost")
	}
	if m.dataOpenMu.TryLock() {
		m.dataOpenMu.Unlock()
		return failure(api.CodeContainmentUnknown, "worker allocation guard lock was lost")
	}
	if err := m.workerAllocationLocked(); err != nil {
		return err
	}
	if g.snapshot.Judge != nil {
		current, gate, found, err := m.judgeLaunchSnapshot(ctx, g.snapshot.Native.Prepared.ID)
		if err != nil {
			return err
		}
		if !found || gate != g.gate || !reflect.DeepEqual(current, g.snapshot) {
			return failure(api.CodeIntegrity, "judge native handoff changed while borrowed")
		}
	} else if g.snapshot.Usage != nil {
		current, gate, found, err := m.usageLaunchSnapshot(ctx, g.snapshot.Native.Prepared.ID)
		if err != nil {
			return err
		}
		if !found || gate != g.gate || !reflect.DeepEqual(current, g.snapshot) {
			return failure(api.CodeIntegrity, "usage native handoff changed while borrowed")
		}
	} else if g.snapshot.Channel != nil {
		current, gate, found, err := m.channelLaunchSnapshot(ctx, g.snapshot.Native.Prepared.ID)
		if err != nil {
			return err
		}
		if !found || gate != g.gate || !reflect.DeepEqual(current, g.snapshot) {
			return failure(api.CodeIntegrity, "channel native handoff changed while borrowed")
		}
	} else if g.snapshot.Archive != nil {
		current, gate, found, err := m.archiveLaunchSnapshot(ctx, g.snapshot.Native.Prepared.ID)
		if err != nil {
			return err
		}
		if !found || gate != g.gate || !reflect.DeepEqual(current, g.snapshot) {
			return failure(api.CodeIntegrity, "archive native handoff changed while borrowed")
		}
	} else {
		if g.snapshot.Reg == nil {
			return failure(api.CodeIntegrity, "worker handoff lost its retained job registration")
		}
		native, err := m.dataNative(ctx, *g.snapshot.Reg)
		if err != nil {
			return err
		}
		if !reflect.DeepEqual(native, g.snapshot.Native) || m.gates[native.Lease.ID] != g.gate {
			return failure(api.CodeIntegrity, "worker native handoff changed while borrowed")
		}
		parent, index, err := m.findData(g.snapshot.Reg.Request)
		if err != nil {
			return err
		}
		job := parent.DataJobs[index]
		if job.Spec == nil || !reflect.DeepEqual(job.Spec.Handoff, g.snapshot.Handoff) ||
			job.Spec.Handoff.Spec.PlanID != "" && job.Spec.Handoff.Spec.PlanID != job.Reg.Reservation.ID {
			return failure(api.CodeIntegrity, "worker handoff changed its retained parent or immutable spec")
		}
	}
	g.gate.mu.Lock()
	defer g.gate.mu.Unlock()
	for i, file := range g.gate.workerFiles {
		pin, err := workerDescriptor(file)
		if err != nil {
			return err
		}
		if pin != g.snapshot.Pins[i] || pin != g.gate.workerPins[i] {
			return failure(api.CodeIntegrity, "retained worker descriptor identity changed")
		}
	}
	return nil
}

func (g *workerHelperGuard) close() {
	if !g.closed {
		g.closed = true
		g.manager.workerLaunch = nil
		g.manager.dataOpenMu.Unlock()
	}
}

// The helper's serialized request gate and original process flock remain held
// for this entire conversation, including the one permitted data_gate release.
// Only the authenticated installed service can enter it; clients send no FDs.
func (m *leaseManager) serveWorkerLaunch(ctx context.Context, connection *net.UnixConn, peer *pinnedPeer, request helperRequest, window *helperWindow, verify func() error, trace *helperRequestTrace) error {
	refuse := func(err error) error { return window.refuse(helperProtocol, request.Nonce, err) }
	var query workerLaunchQuery
	if err := decodeStrict(request.Params, &query); err != nil {
		return refuse(err)
	}
	guard, err := m.acquireWorkerLaunch(ctx, query.PreparedID)
	if err != nil {
		return refuse(err)
	}
	defer guard.close()
	encoded, err := EncodeWire(guard.snapshot)
	if err != nil {
		return refuse(failure(api.CodeIntegrity, "cannot encode retained worker handoff"))
	}
	response := helperResponse{Protocol: helperProtocol, Revision: api.ContractRevision, Nonce: request.Nonce, Result: encoded}
	data, err := encodeHelperFrame(response)
	if err != nil {
		return refuse(err)
	}
	gate := guard.gate
	gate.mu.Lock()
	rights := unix.UnixRights(int(gate.workerFiles[0].Fd()), int(gate.workerFiles[1].Fd()), gate.innerFD)
	n, controls, sendErr := connection.WriteMsgUnix(data, rights, nil)
	gate.mu.Unlock()
	if sendErr != nil || n != len(data) || controls != len(rights) {
		return failure(api.CodeUnavailable, "cannot transfer retained worker handoff")
	}
	opened := false
	for {
		data, err := readUnixFrame(connection, peer)
		if err != nil {
			return err
		}
		var next helperRequest
		if err := decodeStrict(data, &next); err != nil {
			return refuse(err)
		}
		request = next
		if next.Protocol != helperProtocol || next.Revision != api.ContractRevision || next.Config != m.binding.Config || next.Generation != m.binding.Generation || next.ArtifactSHA256 != m.binding.Artifact.SHA256 || !validID(next.Nonce) || len(next.Nonce) < 32 {
			return refuse(failure(api.CodeVersion, "worker handoff conversation binding changed"))
		}
		if err := verify(); err != nil {
			return refuse(err)
		}
		var result any
		if next.Method == "worker_close" {
			var empty api.Empty
			if err := decodeStrict(next.Params, &empty); err != nil {
				return refuse(err)
			}
			return window.write(helperResponse{Protocol: helperProtocol, Revision: api.ContractRevision, Nonce: next.Nonce, Result: json.RawMessage(`{}`)})
		}
		if opened {
			return refuse(failure(api.CodeConflict, "worker launch gate was already consumed"))
		}
		if err := guard.check(ctx); err != nil {
			return refuse(err)
		}
		switch next.Method {
		case "worker_check":
			var empty api.Empty
			err = decodeStrict(next.Params, &empty)
			result = guard.snapshot
		case "containment":
			var q containmentQuery
			err = decodeStrict(next.Params, &q)
			if err == nil && q.LeaseID != guard.snapshot.Native.Lease.ID {
				err = failure(api.CodeForbidden, "worker handoff cannot resolve another allocation")
			}
			if err == nil {
				q.Opened = false // Only this live locked pre-open handoff permits it.
				result, err = m.containment(ctx, q)
			}
		case "data_query":
			var q api.StorageProjectionRequest
			err = decodeStrict(next.Params, &q)
			if err == nil && (guard.snapshot.Archive != nil || guard.snapshot.Reg == nil || q != guard.snapshot.Reg.Request) {
				err = failure(api.CodeForbidden, "worker handoff cannot read another data stage")
			}
			if err == nil {
				result, err = m.dispatchData(ctx, next.Method, next.Params)
			}
		case "data_gate":
			trace.method, trace.check = "data_gate", "operation"
			var open dataOpen
			err = decodeStrict(next.Params, &open)
			if err == nil && (guard.snapshot.Archive != nil || guard.snapshot.Reg == nil || open.Reg.Request != guard.snapshot.Reg.Request || open.Request.Prepared != guard.snapshot.Native.Prepared) {
				err = failure(api.CodeForbidden, "worker handoff cannot open another native gate")
			}
			if err == nil {
				result, err = m.openDataGate(ctx, open)
				opened = err == nil
			}
		case "judge_open":
			var open judgeOpen
			err = decodeStrict(next.Params, &open)
			if err == nil && (guard.snapshot.Judge == nil || !reflect.DeepEqual(open.Reg, *guard.snapshot.Judge) || open.Request.Prepared != guard.snapshot.Native.Prepared) {
				err = failure(api.CodeForbidden, "worker handoff cannot open another judge gate")
			}
			if err == nil {
				result, err = m.openJudge(ctx, open)
				opened = err == nil
			}
		case "archive_open", "review_open":
			var open archiveOpen
			err = decodeStrict(next.Params, &open)
			if err == nil && (guard.snapshot.Archive == nil || !reflect.DeepEqual(open.Reg, *guard.snapshot.Archive) || open.Request.Prepared != guard.snapshot.Native.Prepared) {
				err = failure(api.CodeForbidden, "worker handoff cannot open another archive gate")
			}
			if err == nil {
				if next.Method == "review_open" {
					result, err = m.dispatchReview(ctx, next.Method, next.Params)
				} else {
					result, err = m.openArchive(ctx, open)
				}
				opened = err == nil
			}
		case "usage_open":
			var open usageOpen
			err = decodeStrict(next.Params, &open)
			if err == nil && (guard.snapshot.Usage == nil || !reflect.DeepEqual(open.Reg, *guard.snapshot.Usage) || open.Request.Prepared != guard.snapshot.Native.Prepared) {
				err = failure(api.CodeForbidden, "worker handoff cannot open another usage gate")
			}
			if err == nil {
				result, err = m.openUsage(ctx, open)
				opened = err == nil
			}
		default:
			err = failure(api.CodeForbidden, "operation is outside the borrowed worker launch guard")
		}
		if err != nil {
			return refuse(err)
		}
		raw, err := EncodeWire(result)
		if err != nil {
			return refuse(failure(api.CodeIntegrity, "cannot encode worker handoff result"))
		}
		if err := window.write(helperResponse{Protocol: helperProtocol, Revision: api.ContractRevision, Nonce: next.Nonce, Result: raw}); err != nil {
			return err
		}
	}
}
