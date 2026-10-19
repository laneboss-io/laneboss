//go:build linux

package admin

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"strconv"
	"time"

	"golang.org/x/sys/unix"
	"laneboss.io/laneboss/internal/v2/api"
)

// A retained stop is a read-only transition, never active launch authority.
// Measure the same ended main process and original outside producer even when
// the release outbox has not yet pinned its terminal capture observation.
func (m *leaseManager) reconcileStoppedCapture(ctx context.Context, record leaseRecord, entry captureJournal) error {
	if !record.Revoked || record.Credentials == nil || record.Credentials.Stop == nil || record.Gate == nil || record.Gate.Open == nil || record.Gate.Permit == nil ||
		record.Spec == nil || record.Spec.Plan == nil || record.Phase != "active" && record.Phase != "releasing" ||
		!reflect.DeepEqual(record.Spec.Plan.Capture, entry.Binding) || record.BootID != m.bootID {
		return failure(api.CodeContainmentUnknown, "capture transition has no exact retained stopped launch")
	}
	cause := record.Credentials.Stop.Cause
	if err := validateCause(cause, m.binding.Config, api.InternalHelperStop); err != nil {
		return err
	}
	if cause.Target != entry.Binding.Target || cause.Target != record.Gate.Prepared.Target || cause.CancellationEpoch < record.Gate.Request.Cause.CancellationEpoch {
		return failure(api.CodeForbidden, "capture transition changed its original stopped run")
	}
	observed, err := m.observeGate(ctx, api.HelperObserveRequest{LeaseID: record.Lease.ID, Handle: gateHandle(record)})
	if err != nil {
		return err
	}
	if observed.State != "exited" || observed.Survivors == nil || *observed.Survivors != 0 {
		return failure(api.CodeContainmentUnknown, "capture transition has no measured stopped main process")
	}
	native := entry.Native
	live, ok := m.captures[entry.Binding.ID].(*nativeCapture)
	if !ok || native == nil || native.Phase != "registered" || capturePID(live) != native.PID ||
		!reflect.DeepEqual(live.binding, entry.Binding) || live.lease != native.Lease {
		return failure(api.CodeContainmentUnknown, "stopped capture lost its original native pipe owner")
	}
	if err := live.Observe(ctx); err != nil {
		return err
	}
	return m.verifyCaptureSpool(ctx, record, entry)
}

// capturePID is the producer PID a capture journal records at registration (capture_io_linux.go: the
// native gate's inner PID). The gate's own PID is its outer sandbox process, so owner checks compare this
// one (box 82: releasing a Claudock lane refused "retained capture close selected another native owner").
func capturePID(live *nativeCapture) int {
	if native, ok := live.gate.(*nativeGate); ok {
		return native.innerPID
	}
	return live.gate.PID()
}

// Own the writer's checkpoint before freezing its actual cgroup. A live
// update can finish before a later attempt; corrupted committed bytes still
// stop the run and never become an authenticated acknowledgement.
func (m *leaseManager) verifyCaptureSpool(ctx context.Context, record leaseRecord, entry captureJournal) (resultErr error) {
	live, ok := m.captures[entry.Binding.ID].(*nativeCapture)
	resources, nativeOwner := m.resources.(*linuxResources)
	if !ok || !nativeOwner || entry.Native == nil {
		return failure(api.CodeContainmentUnknown, "capture snapshot has no exact native producer and spool owner")
	}
	native, ok := live.gate.(*nativeGate)
	if !ok || native.innerPID != entry.Native.PID || native.innerGeneration != entry.Binding.ProducerGeneration {
		return failure(api.CodeContainmentUnknown, "capture snapshot changed its actual producer lifetime")
	}
	outside := leaseRecord{Lease: entry.Native.Lease, Request: record.Request, Phase: "active"}
	observation, err := native.Observe(ctx, api.ProcessHandle{ID: entry.Binding.ProducerID, Target: entry.Binding.Target,
		ContainmentID: outside.Lease.ContainmentID, Generation: entry.Binding.ProducerGeneration})
	if err != nil {
		return err
	}
	if observation.State == "exited" {
		if err := m.waitContainmentEmpty(ctx, outside); err != nil {
			return err
		}
		return live.cleanExit(observation)
	}
	root, err := resources.open(outside)
	if err != nil {
		return err
	}
	defer root.Close()
	checkpoint, err := lockCaptureSnapshot(live.spool)
	if err != nil {
		return err
	}
	defer func() {
		if resultErr == nil {
			return
		}
		// Preserve the source marker/ranges unchanged, including a partial
		// write, alongside a separate synced failure marker for later gap ingress.
		if err := retainCaptureFailure(live.spool, entry.Binding.ID); err != nil {
			resultErr = err
		}
		cleanup, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		stopErr := m.killContainment(cleanup, outside)
		if err := writeControl(root, "cgroup.freeze", "0"); stopErr == nil {
			stopErr = err
		}
		if err := m.killContainment(cleanup, record); stopErr == nil {
			stopErr = err
		}
		live.mu.Lock()
		live.stopErr = resultErr
		live.mu.Unlock()
		if stopErr != nil {
			resultErr = failure(api.CodeContainmentUnknown, "capture snapshot failed and native stop is uncertain; retain all ownership")
		}
	}()
	defer func() {
		if err := checkpoint.Close(); err != nil {
			resultErr = failure(api.CodeContainmentUnknown, "cannot close capture snapshot checkpoint")
		}
	}()
	if err := writeControl(root, "cgroup.freeze", "1"); err != nil {
		return err
	}
	if err := waitCgroupEvent(ctx, root, "frozen", "1"); err != nil {
		return err
	}
	if err := native.innerLifetime(m.bootID); err != nil {
		return err
	}
	executable, err := os.Open("/proc/" + strconv.Itoa(native.innerPID) + "/exe")
	if err != nil {
		return failure(api.CodeContainmentUnknown, "capture executable ownership is unreadable")
	}
	verifyErr, closeErr := verifyExecutableFile(executable, m.binding.Artifact), executable.Close()
	if verifyErr != nil {
		return verifyErr
	}
	if closeErr != nil {
		return failure(api.CodeContainmentUnknown, "capture executable observation could not close")
	}
	marker, err := readSpool(live.spool, entry.Binding)
	if err != nil {
		return err
	}
	if marker.Failure != "" {
		return failure(api.CodeContainmentUnknown, "capture retained an incomplete spool or pipe failure")
	}
	if err := writeControl(root, "cgroup.freeze", "0"); err != nil {
		return err
	}
	return waitCgroupEvent(ctx, root, "frozen", "0")
}

func retainCaptureFailure(root *os.Root, bindingID api.ID) error {
	data, err := json.Marshal(struct {
		BindingID  api.ID        `json:"binding_id"`
		Reason     string        `json:"reason"`
		ObservedAt api.Timestamp `json:"observed_at"`
	}{BindingID: bindingID, Reason: "spool_reconciliation_unknown", ObservedAt: gateTimestamp()})
	if err != nil {
		return failure(api.CodeIntegrity, "cannot encode capture ownership failure")
	}
	file, err := root.OpenFile("reconcile-failure", os.O_WRONLY|os.O_CREATE|os.O_EXCL|unix.O_NOFOLLOW, 0600)
	if err != nil {
		return failure(api.CodeContainmentUnknown, "capture ownership failure marker already exists or cannot be retained")
	}
	n, writeErr := file.Write(data)
	syncErr, closeErr := file.Sync(), file.Close()
	if writeErr != nil || syncErr != nil || closeErr != nil || n != len(data) {
		return failure(api.CodeIntegrity, "capture ownership failure marker sync failed")
	}
	parent, err := root.Open(".")
	if err != nil {
		return failure(api.CodeIntegrity, "cannot pin capture failure marker parent")
	}
	syncErr, closeErr = parent.Sync(), parent.Close()
	if syncErr != nil || closeErr != nil {
		return failure(api.CodeIntegrity, "capture failure marker parent sync failed")
	}
	return nil
}

func lockCaptureSnapshot(root *os.Root) (*os.File, error) {
	file, err := root.OpenFile("marker", os.O_RDONLY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, failure(api.CodeContainmentUnknown, "capture snapshot checkpoint is unavailable")
	}
	if err := unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		if closeErr := file.Close(); closeErr != nil {
			return nil, failure(api.CodeIntegrity, "cannot close unowned capture checkpoint")
		}
		if errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EAGAIN) {
			return nil, &api.Error{Code: api.CodeUnavailable, Owner: owner, Retryable: true, Message: api.CaptureSnapshotPendingMessage}
		}
		return nil, failure(api.CodeContainmentUnknown, "cannot own capture snapshot checkpoint")
	}
	return file, nil
}

func captureSpoolUpdate(marker *os.File, write func() error) (resultErr error) {
	if err := unix.Flock(int(marker.Fd()), unix.LOCK_EX); err != nil {
		return failure(api.CodeIntegrity, "cannot own capture update checkpoint")
	}
	defer func() {
		if err := unix.Flock(int(marker.Fd()), unix.LOCK_UN); err != nil {
			resultErr = errors.Join(resultErr, failure(api.CodeIntegrity, "cannot release capture update checkpoint"))
		}
	}()
	return write()
}
