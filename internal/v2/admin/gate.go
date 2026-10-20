package admin

import (
	"context"
	"errors"
	"reflect"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

// The journal contains comparison identities only. Release descriptors and
// process handles stay owned by the installed helper and are never serialized.
type gateJournal struct {
	Request       api.HelperLaunchRequest `json:"request"`
	Prepared      api.PreparedLaunch      `json:"prepared"`
	State         string                  `json:"state"`
	PID           int                     `json:"pid"`
	Permit        *api.LaunchPermit       `json:"permit,omitempty"`
	Open          *gateOpenRegistration   `json:"open,omitempty"`
	Observation   *api.ProcessObservation `json:"observation,omitempty"`
	Stop          *api.InternalIntent     `json:"stop,omitempty"`
	NativeProfile string                  `json:"native_profile,omitempty"`
}

type gateOpenRegistration struct {
	Request api.HelperOpenRequest    `json:"request"`
	Binding api.LaunchBindingRequest `json:"binding"`
	Policy  api.EffectivePolicy      `json:"policy"`
}

type ownedGate interface {
	PID() int
	Generation() string
	Release() error
	Observe(context.Context, api.ProcessHandle) (api.ProcessObservation, error)
	Stop(context.Context, api.ProcessHandle) (api.ProcessObservation, error)
	Close() error
}

// Reaping the supervisor does not imply that descendants have left cgroupfs.
// The caller supplies the native population-event barrier for this exact lease.
func stopAndWait(ctx context.Context, live ownedGate, handle api.ProcessHandle, wait func() error) error {
	if _, err := live.Stop(ctx, handle); err != nil {
		return err
	}
	return wait()
}

func (m *leaseManager) prepareGate(ctx context.Context, request api.HelperLaunchRequest) (_ api.PreparedLaunch, resultErr error) {
	defer helperCheck(&resultErr, "gate_prepare")
	if err := validatePreparation(request); err != nil {
		return api.PreparedLaunch{}, err
	}
	record, err := m.findActive(request.LeaseID, storageReady)
	if err != nil {
		return api.PreparedLaunch{}, err
	}
	if record.BootID != m.bootID || record.Phase != "active" || record.Revoked || record.Spec == nil || record.SpecReceipt == nil {
		return api.PreparedLaunch{}, failure(api.CodeContainmentUnknown, "prepare requires the current registered helper spec")
	}
	spec := record.Spec.Handoff.Spec
	if request.PreparedSpecID != spec.ID || request.SpecSHA256 != record.SpecReceipt.SpecSHA256 || request.Cause.Target != spec.Target ||
		request.Cause.Config != m.binding.Config || request.Cause.RequestedBy != record.Spec.Handoff.Cause.RequestedBy ||
		request.Cause.CauseOperationID != record.Spec.Handoff.OperationID || request.Cause.CauseRequestID != record.Spec.Handoff.RequestID ||
		request.Cause.CancellationEpoch != record.Spec.Handoff.Cause.CancellationEpoch {
		return api.PreparedLaunch{}, failure(api.CodeForbidden, "prepare differs from its registered launch and cause")
	}
	if record.Gate != nil {
		if !retainedPrepare(&record.Gate.Request, request, attemptClaimant(ctx, request.Cause.EffectID)) {
			return api.PreparedLaunch{}, failure(api.CodeIdempotencyConflict, "prepare replay changed its retained input")
		}
		if record.Gate.State != "prepared" {
			return api.PreparedLaunch{}, failure(api.CodeConflict, "gate is no longer closed and prepared")
		}
		live := m.gates[record.Lease.ID]
		if live == nil || live.PID() != record.Gate.PID || live.Generation() != record.Gate.Prepared.ProcessGeneration {
			return api.PreparedLaunch{}, failure(api.CodeContainmentUnknown, "retained gate descriptor or lifetime is unavailable; replacement is forbidden")
		}
		observation, err := live.Observe(ctx, gateHandle(record))
		if err != nil {
			return api.PreparedLaunch{}, err
		}
		if observation.State != "running" {
			return api.PreparedLaunch{}, failure(api.CodeContainmentUnknown, "closed prepared process is no longer alive")
		}
		return record.Gate.Prepared, nil
	}
	if record.Storage == nil || !record.Storage.Ready {
		return api.PreparedLaunch{}, failure(api.CodePrerequisite, "prepare has no owned private storage")
	}
	if err := m.syncLaunchStorage(ctx, &record, false); err != nil {
		return api.PreparedLaunch{}, err
	}
	if err := m.resources.Quiescent(ctx, record); err != nil {
		return api.PreparedLaunch{}, err
	}
	preparedID, err := randomID("prepared-")
	if err != nil {
		return api.PreparedLaunch{}, err
	}
	gateID, err := randomID("gate-")
	if err != nil {
		return api.PreparedLaunch{}, err
	}
	record.Gate = &gateJournal{Request: request, State: "preparing", Prepared: api.PreparedLaunch{ID: preparedID, GateID: gateID,
		SpecSHA256: request.SpecSHA256, Target: spec.Target, ContainmentID: record.Lease.ContainmentID, EndpointGeneration: record.Lease.EndpointGeneration}}
	// Publish the irreversible attempt before creating a process. An uncertain
	// attempt after restart refuses rather than allocating another process.
	if err := m.save(record); err != nil {
		return api.PreparedLaunch{}, err
	}
	if err := m.registerGateExports(ctx, &record); err != nil {
		return api.PreparedLaunch{}, err
	}
	if len(record.Exports) != 0 || len(record.Spec.Handoff.Spec.Grants.Network) != 0 {
		record.Gate.NativeProfile = "enrolled-capabilities-v1"
	}
	if err := m.save(record); err != nil {
		return api.PreparedLaunch{}, err
	}
	live, err := m.startConfinedGate(ctx, record)
	if err != nil {
		return api.PreparedLaunch{}, err
	}
	if m.gates == nil {
		m.gates = map[api.ID]ownedGate{}
	}
	m.gates[record.Lease.ID] = live
	record.Gate.PID, record.Gate.Prepared.ProcessGeneration = live.PID(), live.Generation()
	if record.Gate.NativeProfile == "" {
		record.Gate.NativeProfile = "offline-private-v1"
	}
	record.Gate.State = "prepared"
	if err := m.save(record); err != nil {
		live.Close()
		return api.PreparedLaunch{}, err
	}
	return record.Gate.Prepared, nil
}

func gateHandle(record leaseRecord) api.ProcessHandle {
	return api.ProcessHandle{ID: record.Spec.Handoff.Spec.LaunchID, Target: record.Gate.Prepared.Target,
		ContainmentID: record.Lease.ContainmentID, Generation: record.Gate.Prepared.ProcessGeneration}
}

func (m *leaseManager) openGate(ctx context.Context, registration gateOpenRegistration) (result api.ProcessHandle, resultErr error) {
	request := registration.Request
	if err := validateOpenCommit(request, registration.Binding, m.binding.Config); err != nil {
		return api.ProcessHandle{}, err
	}
	record, err := m.findActive(registration.Binding.Record.UIDLeaseID, storageReady)
	if err != nil {
		return api.ProcessHandle{}, err
	}
	if record.BootID != m.bootID || record.Revoked || record.Gate == nil || record.Spec == nil || record.Gate.Prepared != request.Prepared ||
		record.Spec.Handoff.Spec.LaunchID != request.Permit.LaunchID || registration.Binding.Record.HostUID != record.Lease.UID ||
		request.Cause.CauseOperationID != record.Spec.Handoff.OperationID || request.Cause.CauseRequestID != record.Spec.Handoff.RequestID ||
		request.Cause.RequestedBy != record.Spec.Handoff.Cause.RequestedBy || request.Cause.CancellationEpoch != record.Spec.Handoff.Cause.CancellationEpoch {
		return api.ProcessHandle{}, failure(api.CodeIntegrity, "open does not identify the actual retained prepared gate")
	}
	if record.Spec.Plan != nil {
		helperLaneIDs(ctx, record)
		if err := api.ValidateLaunchBindingPlan(registration.Binding, *record.Spec.Plan); err != nil {
			return api.ProcessHandle{}, err
		}
		if err := api.ValidateCapturePolicy(record.Spec.Plan.Capture, registration.Policy); err != nil {
			return api.ProcessHandle{}, err
		}
		if registration.Policy.Generation != record.Spec.Plan.Reservation.PolicyGeneration {
			return api.ProcessHandle{}, failure(api.CodeForbidden, "open policy is stale")
		}
	} else {
		return api.ProcessHandle{}, failure(api.CodeUnsupported, "fixed worker gate requires its separate retained job handoff")
	}
	if record.Gate.State != "prepared" || record.Gate.Permit != nil || record.Gate.Open != nil {
		return api.ProcessHandle{}, failure(api.CodeConflict, "gate release is one-use; reconcile the consumed gate")
	}
	live := m.gates[record.Lease.ID]
	if live == nil || live.PID() != record.Gate.PID || live.Generation() != request.Prepared.ProcessGeneration {
		return api.ProcessHandle{}, failure(api.CodeContainmentUnknown, "original gate descriptor is not owned; no relaunch is permitted")
	}
	observation, err := live.Observe(ctx, gateHandle(record))
	if err != nil {
		return api.ProcessHandle{}, err
	}
	if observation.State != "running" {
		return api.ProcessHandle{}, failure(api.CodeContainmentUnknown, "prepared gate process ended before release")
	}
	if record.Spec.Plan.Capture.Status == "registered" {
		if _, err := m.reconcileCapture(ctx, record.Spec.Plan.Capture); err != nil {
			return api.ProcessHandle{}, err
		}
	}
	deadline, err := time.Parse(time.RFC3339Nano, string(record.Spec.Handoff.Spec.Grants.ExpiresAt))
	if err != nil || !deadline.After(time.Now()) || record.Spec.Handoff.Spec.Grants.Revoked {
		return api.ProcessHandle{}, failure(api.CodeForbidden, "registered gate grants expired before native release")
	}
	delivery, err := m.prepareCredentialExec(ctx, record)
	if err != nil {
		return api.ProcessHandle{}, err
	}
	defer func() { resultErr = errors.Join(resultErr, delivery.close()) }()
	permit := request.Permit
	record.Gate.State, record.Gate.Permit, record.Gate.Open = "opening", &permit, &registration
	finishOpenWait := m.beginGateOpenWait(record.Lease.ID)
	defer finishOpenWait()
	// A crash after this write cannot release a second process or consume a
	// second permit, even if the first release acknowledgement was lost.
	if err := m.save(record); err != nil {
		return api.ProcessHandle{}, err
	}
	if record.Credentials != nil {
		if m.activeCredentialGuard == nil {
			return api.ProcessHandle{}, failure(api.CodeForbidden, "credential gate has no live broker lock")
		}
		if err := m.activeCredentialGuard.Check(ctx); err != nil {
			return api.ProcessHandle{}, err
		}
	}
	if err := m.deliverCredentialExec(ctx, record, delivery); err != nil {
		return api.ProcessHandle{}, err
	}
	if err := live.Release(); err != nil {
		return api.ProcessHandle{}, err
	}
	if err := m.recordGateRelease(record); err != nil {
		return api.ProcessHandle{}, err
	}
	if record.Credentials != nil {
		resume := lendHelperOperation(ctx)
		awaitErr := m.awaitCredentialGate(ctx, record)
		resume()
		if awaitErr != nil {
			// Proof refusal can follow an authenticated early peer. Kill the
			// actual containment and persist revocation before returning it.
			// Cleanup remains bounded even when the original request expired;
			// this cannot turn the failed proof into a successful open.
			cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), helperReplyTimeout)
			defer cancel()
			stopErr := m.killAndWait(cleanup, record)
			cause, causeErr := revokedCredentialCause(record)
			var fenceErr error
			if causeErr == nil {
				fenceErr = m.fenceStopped(&record, cause, "revoked")
			}
			return api.ProcessHandle{}, errors.Join(awaitErr, stopErr, causeErr, fenceErr)
		}
	}
	record.Gate.State = "opened"
	if err := m.save(record); err != nil {
		return api.ProcessHandle{}, err
	}
	finishOpenWait()
	return gateHandle(record), nil
}

func (m *leaseManager) observeGate(ctx context.Context, request api.HelperObserveRequest) (api.ProcessObservation, error) {
	parent, index, found, dataErr := m.dataByLease(request.LeaseID)
	if dataErr != nil {
		return api.ProcessObservation{}, dataErr
	}
	if found {
		job := parent.DataJobs[index]
		if job.Gate == nil || request.Handle != dataHandle(job) {
			return api.ProcessObservation{}, failure(api.CodeForbidden, "data observation changed its native handle")
		}
		return m.observeData(ctx, job.Reg)
	}
	record, err := m.find(request.LeaseID)
	if err != nil {
		return api.ProcessObservation{}, err
	}
	return m.observeOwnGate(ctx, &record, request.Handle)
}

// The caller has resolved this top-level lease under the helper operation
// lock. Reconciliation can use that same validated record through its native
// observation and terminal save instead of decoding the journal four times.
func (m *leaseManager) observeOwnGate(ctx context.Context, record *leaseRecord, handle api.ProcessHandle) (api.ProcessObservation, error) {
	if record.Gate == nil || record.Spec == nil || handle != gateHandle(*record) || record.BootID != m.bootID {
		return api.ProcessObservation{}, failure(api.CodeContainmentUnknown, "process observation has no exact retained gate binding")
	}
	live := m.gates[record.Lease.ID]
	if live == nil {
		// A protected terminal record outlives its original wait owner and
		// cgroup. Recheck native ownership; never synthesize an end from
		// containment absence or apply this exception to an uncommitted wait.
		if committedExit(*record) {
			if err := m.terminalGateQuiet(ctx, *record); err != nil {
				return api.ProcessObservation{}, err
			}
			return *record.Gate.Observation, nil
		}
		return api.ProcessObservation{}, failure(api.CodeContainmentUnknown, "gate wait status or lifetime was lost during helper restart")
	}
	observation, err := live.Observe(ctx, handle)
	if err != nil {
		return api.ProcessObservation{}, err
	}
	if err := m.measureRunningSurvivors(ctx, *record, &observation); err != nil {
		return api.ProcessObservation{}, err
	}
	if observation.State == "exited" {
		if err := m.terminalGateQuiet(ctx, *record); err != nil {
			return api.ProcessObservation{}, err
		}
		zero := uint64(0)
		observation.Survivors = &zero
		record.Gate.Observation = &observation
		if record.Gate.State == "opened" {
			record.Gate.State = "ended"
		}
		if err := m.save(*record); err != nil {
			return api.ProcessObservation{}, err
		}
	}
	return observation, nil
}

func (m *leaseManager) terminalGateQuiet(ctx context.Context, record leaseRecord) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	// The validated native journal proves release, worker collection and
	// actual workspace removal, all measured while this lease owned its UID.
	// A recovery inventory read before collection can outlive that transfer;
	// the next UID generation must not be measured against this retired life.
	// Retained or interrupted cleanup still requires the full native scan.
	if record.Phase == "released" && cleanupReleasesUIDs(record) {
		return nil
	}
	return m.resources.Quiescent(ctx, record)
}

func (m *leaseManager) measureRunningSurvivors(ctx context.Context, record leaseRecord, observation *api.ProcessObservation) error {
	if observation.State != "running" {
		return nil
	}
	counter, ok := m.resources.(interface {
		Survivors(context.Context, leaseRecord) (uint64, error)
	})
	if !ok {
		return failure(api.CodeContainmentUnknown, "running gate has no native containment counter")
	}
	count, err := counter.Survivors(ctx, record)
	if err != nil {
		return err
	}
	if count == 0 {
		return failure(api.CodeContainmentUnknown, "running gate has no measured surviving tasks; retry its terminal observation")
	}
	observation.Survivors = &count
	return nil
}

func (m *leaseManager) reconcileGate(ctx context.Context, request api.HelperReconcileRequest) (api.LaunchReconciliation, error) {
	record, err := m.find(request.LeaseID)
	if err != nil {
		return api.LaunchReconciliation{}, err
	}
	if record.Gate == nil || record.Spec == nil || record.BootID != m.bootID || request.LaunchID != record.Spec.Handoff.Spec.LaunchID ||
		request.PreparedID != record.Gate.Prepared.ID || request.OperationID != record.Spec.Handoff.OperationID {
		return api.LaunchReconciliation{}, failure(api.CodeContainmentUnknown, "reconciliation lost its retained spec or prepared binding")
	}
	observation, err := m.observeOwnGate(ctx, &record, gateHandle(record))
	if err != nil {
		return api.LaunchReconciliation{}, err
	}
	state := record.Gate.State
	if state == "preparing" || state == "opening" {
		return api.LaunchReconciliation{}, failure(api.CodeContainmentUnknown, "gate transition is uncertain; automatic release is forbidden")
	}
	prepared := record.Gate.Prepared
	result := api.LaunchReconciliation{Prepared: &prepared, Observation: observation, GateState: state, ConsumedPermit: record.Gate.Permit}
	if record.Gate.Permit != nil {
		// Journal phases describe helper recovery; the public comparison
		// records consumption separately from the measured process state.
		result.GateState = "consumed"
		process := gateHandle(record)
		result.Process = &process
	}
	return result, nil
}

func (m *leaseManager) stopGate(ctx context.Context, request api.HelperStopRequest) (observation api.ProcessObservation, resultErr error) {
	finish, err := m.beginRecovery()
	if err != nil {
		return api.ProcessObservation{}, err
	}
	defer func() { resultErr = finish(resultErr) }()
	return m.stopGateOwned(ctx, request)
}

func (m *leaseManager) stopGateOwned(ctx context.Context, request api.HelperStopRequest) (api.ProcessObservation, error) {
	if err := validateCause(request.Cause, m.binding.Config, api.InternalHelperStop); err != nil {
		return api.ProcessObservation{}, err
	}
	if request.OperationID != request.Cause.CauseOperationID || request.EffectID != request.Cause.EffectID || request.Cause.Target != request.Target.Handle.Target || request.Reason == "" {
		return api.ProcessObservation{}, failure(api.CodeInvalid, "stop differs from its retained cause and target")
	}
	record, err := m.find(request.Target.LeaseID)
	if err != nil {
		return api.ProcessObservation{}, err
	}
	if record.Gate == nil || request.Target.Handle != gateHandle(record) {
		return api.ProcessObservation{}, failure(api.CodeContainmentUnknown, "stop selects an unknown process")
	}
	reason := stopWithdrawalReason(record)
	if err := m.fenceNativeStop(&record, request.Cause); err != nil {
		return api.ProcessObservation{}, err
	}
	if err := m.fenceStopped(&record, *record.Gate.Stop, reason); err != nil {
		return api.ProcessObservation{}, err
	}
	if err := journalStopExit(ctx, record); err != nil {
		return api.ProcessObservation{}, err
	}
	if err := m.killAndWait(ctx, record); err != nil {
		return api.ProcessObservation{}, err
	}
	if err := m.withdrawProjection(ctx, &record, *record.Gate.Stop, reason); err != nil {
		return api.ProcessObservation{}, err
	}
	return m.observeGate(ctx, request.Target)
}

// The native cancellation fence belongs to the stopped gate, independently of
// credential projection/withdrawal. Retain the writer's cause unchanged; an
// archive decision later hands off its own committed epoch separately.
func retainNativeStop(record *leaseRecord, cause api.InternalIntent) error {
	if err := validateCause(cause, record.Request.Config, api.InternalHelperStop); err != nil {
		return err
	}
	if record.Gate == nil || cause.Target != record.Gate.Prepared.Target {
		return failure(api.CodeConflict, "native stop fence differs from its original run or cancellation epoch")
	}
	if record.Gate.Stop != nil {
		want := *record.Gate.Stop
		want.ID = cause.ID
		if cause.Actor.Kind == "service" {
			want.Actor = cause.Actor
		}
		if want != cause {
			return failure(api.CodeConflict, "native stop fence changed its original committed cause")
		}
		return nil
	}
	gate := *record.Gate
	gate.Stop = &cause
	record.Gate = &gate
	return nil
}

func (m *leaseManager) fenceNativeStop(record *leaseRecord, cause api.InternalIntent) error {
	if err := retainNativeStop(record, cause); err != nil {
		return err
	}
	return m.save(*record)
}

func validateGateJournal(record leaseRecord) error {
	gate := record.Gate
	if gate == nil {
		return nil
	}
	if gate.Stop != nil && (validateCause(*gate.Stop, record.Request.Config, api.InternalHelperStop) != nil ||
		gate.Stop.Target != gate.Prepared.Target) {
		return failure(api.CodeIntegrity, "native stop fence lost its original run or cancellation epoch")
	}
	if record.Spec == nil || validatePreparation(gate.Request) != nil || gate.Request.LeaseID != record.Lease.ID || gate.Request.PreparedSpecID != record.Spec.Handoff.Spec.ID ||
		gate.Request.SpecSHA256 != record.Spec.Handoff.SpecSHA256 || gate.Prepared.Target != record.Spec.Handoff.Spec.Target ||
		gate.Prepared.SpecSHA256 != gate.Request.SpecSHA256 || gate.Request.Cause.Config != record.Spec.Handoff.Config ||
		gate.Request.Cause.Target != gate.Prepared.Target || gate.Request.Cause.RequestedBy != record.Spec.Handoff.Cause.RequestedBy ||
		gate.Request.Cause.CauseOperationID != record.Spec.Handoff.OperationID || gate.Request.Cause.CauseRequestID != record.Spec.Handoff.RequestID ||
		gate.Request.Cause.CancellationEpoch != record.Spec.Handoff.Cause.CancellationEpoch ||
		gate.Prepared.ContainmentID != record.Lease.ContainmentID || gate.Prepared.EndpointGeneration != record.Lease.EndpointGeneration ||
		!validID(gate.Prepared.ID) || !validID(gate.Prepared.GateID) {
		return failure(api.CodeIntegrity, "invalid retained prepared gate journal")
	}
	switch gate.State {
	case "preparing":
	case "prepared", "opening", "opened", "ended":
		if gate.PID <= 0 || gate.Prepared.ProcessGeneration == "" {
			return failure(api.CodeIntegrity, "gate journal lost its kernel lifetime")
		}
	case "aborted":
		if gate.Permit != nil || gate.Open != nil {
			return failure(api.CodeIntegrity, "aborted gate has a consumed permit")
		}
	default:
		return failure(api.CodeIntegrity, "unknown gate journal phase")
	}
	if (gate.Open == nil) != (gate.Permit == nil) {
		return failure(api.CodeIntegrity, "gate journal lost its one-use permit")
	}
	consumed := gate.State == "opening" || gate.State == "opened" || gate.State == "ended"
	if consumed != (gate.Permit != nil) {
		return failure(api.CodeIntegrity, "gate phase differs from its durable permit consumption")
	}
	if gate.Open != nil && (!reflect.DeepEqual(gate.Open.Request.Permit, *gate.Permit) || gate.Open.Request.Prepared != gate.Prepared) {
		return failure(api.CodeIntegrity, "gate journal changed its consumed permit")
	}
	if gate.Open != nil {
		if err := validateOpenCommit(gate.Open.Request, gate.Open.Binding, record.Spec.Handoff.Config); err != nil {
			return err
		}
		if record.Spec.Plan == nil {
			return failure(api.CodeIntegrity, "consumed agent gate lost its exact retained plan")
		}
		if err := api.ValidateLaunchBindingPlan(gate.Open.Binding, *record.Spec.Plan); err != nil {
			return err
		}
	}
	if gate.Observation != nil && (gate.Observation.Handle != gateHandle(record) || validateObservation(record, *gate.Observation) != nil) {
		return failure(api.CodeIntegrity, "gate journal lost its actual terminal observation")
	}
	return nil
}

func gateTimestamp() api.Timestamp { return api.Timestamp(time.Now().UTC().Format(time.RFC3339Nano)) }
