package admin

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

func (m *leaseManager) findData(q api.StorageProjectionRequest) (leaseRecord, int, error) {
	parent, err := m.findActive(q.AgentLeaseID, storageReady)
	if err != nil {
		return parent, 0, err
	}
	if parent.BootID != m.bootID || parent.Phase != "active" || parent.Revoked {
		return parent, 0, failure(api.CodeContainmentUnknown, "data roots have no current agent allocation")
	}
	for i, job := range parent.DataJobs {
		if job.Reg.Request == q {
			return parent, i, nil
		}
	}
	return parent, 0, failure(api.CodeNotFound, "unknown retained data stage")
}

func dataChild(parent leaseRecord, job dataJob) leaseRecord {
	request := parent.Request
	request.ReservationID = ""
	request.Budget = job.Reg.Plan.Budget
	child := leaseRecord{Schema: parent.Schema, BootID: parent.BootID, Request: request, Lease: job.Lease, Phase: "active", IssuedAt: job.Created, Spec: job.Spec}
	if job.Spec != nil {
		h := job.Spec.Handoff
		child.SpecReceipt = &api.PreparedSpecReceipt{SpecID: h.Spec.ID, Config: h.Config, Target: h.Spec.Target, LeaseID: job.Lease.ID, SpecSHA256: h.SpecSHA256, RuntimeManifest: h.Spec.RuntimeManifest, OperationID: h.OperationID}
	}
	if job.Gate != nil {
		child.Gate = &gateJournal{Prepared: job.Gate.Prepared, PID: job.Gate.PID, State: job.Gate.State, Permit: job.Gate.Permit}
	}
	return child
}

func (m *leaseManager) openData(ctx context.Context, r dataReg, supplied ...[]dataCopyPayload) (api.StorageProjection, error) {
	m.dataOpenMu.Lock()
	defer m.dataOpenMu.Unlock()
	if err := validateDataReg(r, m.binding.Config); err != nil {
		return api.StorageProjection{}, err
	}
	parent, err := m.findActive(r.Request.AgentLeaseID, storageReady)
	if err != nil {
		return api.StorageProjection{}, err
	}
	if parent.BootID != m.bootID || parent.Phase != "active" || parent.Revoked || parent.Storage == nil || !parent.Storage.Ready || parent.Storage.Collecting || parent.Storage.Collected {
		return api.StorageProjection{}, failure(api.CodeContainmentUnknown, "data source has no current held agent storage")
	}
	found := false
	for _, a := range parent.LaunchAllocations {
		if reflect.DeepEqual(a.Reservation, r.Reservation) && reflect.DeepEqual(a.Inputs, r.Inputs) {
			found = true
		}
	}
	if !found || !withinBudget(r.Plan.Budget, parent.Request.Budget) {
		return api.StorageProjection{}, failure(api.CodeForbidden, "data stage differs from the helper allocation journal")
	}
	var copies []dataCopyPayload
	if len(supplied) > 1 {
		return api.StorageProjection{}, failure(api.CodeInvalid, "data open accepts one copy payload set")
	}
	if len(supplied) == 1 {
		copies = supplied[0]
	}
	for index, job := range parent.DataJobs {
		if job.Reg.Request.StageID != r.Request.StageID {
			continue
		}
		if !sameDataReg(job.Reg, r) {
			return api.StorageProjection{}, failure(api.CodeIdempotencyConflict, "data token retry changed its original stage")
		}
		if r.ClaimGeneration < job.Reg.ClaimGeneration || r.ClaimGeneration == job.Reg.ClaimGeneration && r.ClaimID != job.Reg.ClaimID {
			return api.StorageProjection{}, failure(api.CodeConflict, "data open attempt is stale or concurrent")
		}
		if job.State == "reserved" {
			return m.finishDataOpen(ctx, parent, index, r, copies)
		}
		if err := validateCopyReplay(r.Inputs, copies, job.Projection); err != nil {
			return api.StorageProjection{}, err
		}
		if job.State == "preparing" {
			job, err = m.resumeDataPreparation(ctx, parent, job)
			if err != nil {
				return api.StorageProjection{}, err
			}
			parent.DataJobs[index] = job
			if err := m.save(parent); err != nil {
				return api.StorageProjection{}, err
			}
		}
		if err := m.checkData(ctx, parent, job); err != nil {
			return api.StorageProjection{}, err
		}
		return job.Projection, nil
	}
	if _, err := validateCopyPayloads(r.Inputs, copies); err != nil {
		return api.StorageProjection{}, err
	}
	records, err := m.records()
	if err != nil {
		return api.StorageProjection{}, err
	}
	if err := newDataIdentity(records, r); err != nil {
		return api.StorageProjection{}, err
	}
	if err := m.syncLaunchStorage(ctx, &parent, false); err != nil {
		return api.StorageProjection{}, err
	}
	if err := m.resources.Quiescent(ctx, parent); err != nil {
		return api.StorageProjection{}, err
	}
	used := map[uint32]bool{m.binding.Service.UID: true, parent.Lease.UID: true}
	reserveArchiveUIDs(records, used)
	for _, p := range records {
		if p.Phase != "released" && p.Phase != "aborted" {
			used[p.Lease.UID] = true
		}
		for _, j := range p.DataJobs {
			if j.State != "collected" {
				used[j.Lease.UID] = true
			}
		}
		for _, c := range p.Captures {
			if c.Native != nil {
				used[c.Native.Lease.UID] = true
			}
		}
	}
	var selected account
	for _, a := range m.binding.Lanes {
		if !used[a.UID] {
			selected = a
			break
		}
	}
	if selected.UID == 0 {
		return api.StorageProjection{}, failure(api.CodeUnavailable, "data worker needs its own free pool UID")
	}
	leaseID, err := randomID("job-")
	if err != nil {
		return api.StorageProjection{}, err
	}
	groupID, err := randomID("cg-")
	if err != nil {
		return api.StorageProjection{}, err
	}
	job := dataJob{Reg: r, Lease: api.HelperLease{ID: leaseID, UID: selected.UID, GID: selected.GID, ContainmentID: groupID, EndpointGeneration: m.binding.Generation},
		Created: gateTimestamp(), State: "reserved", Evidence: []byte{}}
	parent.DataJobs = append(parent.DataJobs, job)
	// The UID reservation precedes any cgroup, source staging or ownership
	// transfer. Failure retains this record and cannot authorize replacement.
	if err := m.save(parent); err != nil {
		return api.StorageProjection{}, err
	}
	return m.finishDataOpen(ctx, parent, len(parent.DataJobs)-1, r, copies)
}

// A reservation alone has not published a token or started a worker. Resume
// that same lease only while the native stage is absent and the agent roots
// retain their original ownership. A later/uncertain stage is never adopted.
func (m *leaseManager) finishDataOpen(ctx context.Context, parent leaseRecord, index int, r dataReg, copies ...[]dataCopyPayload) (api.StorageProjection, error) {
	job := parent.DataJobs[index]
	if err := validateDataJob(parent, job, m.binding); err != nil {
		return api.StorageProjection{}, err
	}
	if job.State != "reserved" || m.gates[job.Lease.ID] != nil {
		return api.StorageProjection{}, failure(api.CodeContainmentUnknown, "data open reservation has a later native stage")
	}
	var payloads []dataCopyPayload
	if len(copies) == 1 {
		payloads = copies[0]
	}
	if _, err := validateCopyPayloads(r.Inputs, payloads); err != nil {
		return api.StorageProjection{}, err
	}
	if err := dataOpenStageAbsent(ctx, m.binding, job); err != nil {
		return api.StorageProjection{}, err
	}
	if err := m.syncLaunchStorage(ctx, &parent, false); err != nil {
		return api.StorageProjection{}, err
	}
	if err := m.resources.Quiescent(ctx, parent); err != nil {
		return api.StorageProjection{}, err
	}
	job.Reg = r
	parent.DataJobs[index] = job
	if err := m.save(parent); err != nil {
		return api.StorageProjection{}, err
	}
	child := dataChild(parent, job)
	child.Phase = "reserved"
	if err := m.resources.Ensure(ctx, child); err != nil {
		return api.StorageProjection{}, err
	}
	if err := m.resources.Quiescent(ctx, child); err != nil {
		return api.StorageProjection{}, err
	}
	pins, projection, evidence, err := m.pinData(ctx, parent, job, copies...)
	if err != nil {
		return api.StorageProjection{}, err
	}
	if _, err := api.ValidateDataCopyProjections(r.Inputs, projection); err != nil {
		return api.StorageProjection{}, errors.Join(err, rollbackDataCopies(pins), pins.close())
	}
	job.Projection, job.Evidence, job.State = projection, evidence, "open"
	parent.DataJobs[index] = job
	if err := m.save(parent); err != nil {
		return api.StorageProjection{}, errors.Join(err, rollbackDataCopies(pins), pins.close())
	}
	if m.dataPins == nil {
		m.dataPins = map[api.ID]*dataPins{}
	}
	m.dataPins[projection.OpenToken] = pins
	return projection, nil
}

func (m *leaseManager) checkData(ctx context.Context, parent leaseRecord, job dataJob) error {
	if job.State == "revoked" || job.State == "collected" {
		return failure(api.CodeForbidden, "data token is revoked")
	}
	if job.State == "reserved" || job.State == "preparing" || job.State == "opening" || job.State == "returning" {
		return failure(api.CodeContainmentUnknown, "data attempt requires reconciliation; replacement is forbidden")
	}
	pins := m.dataPins[job.Projection.OpenToken]
	if pins == nil {
		return failure(api.CodeContainmentUnknown, "data descriptors were lost; a saved token cannot reopen paths")
	}
	return checkDataPins(ctx, parent, job, pins)
}

func (m *leaseManager) registerData(ctx context.Context, seal dataSeal) (api.PreparedSpecReceipt, error) {
	if err := validateDataSeal(seal, m.binding); err != nil {
		return api.PreparedSpecReceipt{}, err
	}
	parent, index, err := m.findData(seal.Reg.Request)
	if err != nil {
		return api.PreparedSpecReceipt{}, err
	}
	job := parent.DataJobs[index]
	if err := m.checkData(ctx, parent, job); err != nil {
		return api.PreparedSpecReceipt{}, err
	}
	if !sameDataReg(job.Reg, seal.Reg) || seal.Spec.Handoff.Spec.UIDLeaseID != job.Lease.ID {
		return api.PreparedSpecReceipt{}, failure(api.CodeForbidden, "worker seal selects a foreign helper lease")
	}
	var input dataInput
	if err := api.DecodeObject(seal.Input, &input); err != nil {
		return api.PreparedSpecReceipt{}, err
	}
	if input.Storage != job.Projection {
		return api.PreparedSpecReceipt{}, failure(api.CodeIntegrity, "worker input replaced its open token or held identities")
	}
	if job.Spec != nil {
		if !reflect.DeepEqual(*job.Spec, seal.Spec) || job.Endpoint == nil || !reflect.DeepEqual(*job.Endpoint, seal.Endpoint) || !slicesBytes(job.Input, seal.Input) {
			return api.PreparedSpecReceipt{}, failure(api.CodeIdempotencyConflict, "worker registration changed its original bytes")
		}
	} else {
		if job.State != "open" {
			return api.PreparedSpecReceipt{}, failure(api.CodeConflict, "data token cannot register another worker")
		}
		if err := validateRuntimePins(ctx, m.binding, seal.Spec.Handoff.Spec); err != nil {
			return api.PreparedSpecReceipt{}, err
		}
		job.Reg, job.Spec, job.Endpoint, job.Input, job.State = seal.Reg, &seal.Spec, &seal.Endpoint, append([]byte(nil), seal.Input...), "registered"
		parent.DataJobs[index] = job
		if err := m.save(parent); err != nil {
			return api.PreparedSpecReceipt{}, err
		}
	}
	return *dataChild(parent, job).SpecReceipt, nil
}

func slicesBytes(a, b []byte) bool { return reflect.DeepEqual(a, b) }

func unstartedDataGate(job dataJob) bool {
	g := job.Gate
	return g != nil && g.State == "reserved" && g.PID == 0 && g.Prepared.ProcessGeneration == "" &&
		g.Permit == nil && g.Record == nil && g.Identity == nil && job.Result == nil && job.Spec != nil && job.Endpoint != nil
}

// A preparation refusal can precede creation of any native lifetime. Resume
// only that unpublished gate after independent native quiescence and held-root
// checks. Keep every issued ID and the original worker UID; a recorded PID,
// permit, lost descriptor or surviving UID is never a replacement opportunity.
// The reserved marker precedes the durable spawn barrier. Legacy preparing
// markers cannot prove that creation was never attempted and remain refused.
func (m *leaseManager) resumeDataPreparation(ctx context.Context, parent leaseRecord, job dataJob) (_ dataJob, resultErr error) {
	defer helperCheck(&resultErr, "data_retry")
	if !unstartedDataGate(job) || m.gates[job.Lease.ID] != nil {
		return dataJob{}, failure(api.CodeContainmentUnknown, "data preparation retains an uncertain native lifetime")
	}
	pins := m.dataPins[job.Projection.OpenToken]
	if pins == nil {
		return dataJob{}, failure(api.CodeContainmentUnknown, "data preparation lost its original root descriptors")
	}
	if err := m.resources.Quiescent(ctx, dataChild(parent, job)); err != nil {
		return dataJob{}, err
	}
	if err := checkUnstartedDataRoots(ctx, parent, job, pins); err != nil {
		return dataJob{}, err
	}
	job.State = "registered"
	return job, nil
}

func (m *leaseManager) prepareData(ctx context.Context, r dataReg) (api.PreparedLaunch, error) {
	parent, index, err := m.findData(r.Request)
	if err != nil {
		return api.PreparedLaunch{}, err
	}
	job := parent.DataJobs[index]
	if !sameDataReg(job.Reg, r) || job.Spec == nil || job.Endpoint == nil {
		return api.PreparedLaunch{}, failure(api.CodeForbidden, "data worker has no registered immutable input")
	}
	if err := m.checkData(ctx, parent, job); err != nil {
		return api.PreparedLaunch{}, err
	}
	if job.Gate != nil {
		if job.State == "registered" && unstartedDataGate(job) {
			if _, err := m.resumeDataPreparation(ctx, parent, job); err != nil {
				return api.PreparedLaunch{}, err
			}
		} else {
			live := m.gates[job.Lease.ID]
			if job.State != "prepared" || live == nil || live.PID() != job.Gate.PID || live.Generation() != job.Gate.Prepared.ProcessGeneration {
				return api.PreparedLaunch{}, failure(api.CodeContainmentUnknown, "original data gate is unavailable")
			}
			return job.Gate.Prepared, nil
		}
	}
	if job.State != "registered" {
		return api.PreparedLaunch{}, failure(api.CodeConflict, "data worker was already attempted")
	}
	if job.Gate == nil {
		id, err := randomID("prepared-")
		if err != nil {
			return api.PreparedLaunch{}, err
		}
		gateID, err := randomID("gate-")
		if err != nil {
			return api.PreparedLaunch{}, err
		}
		job.Gate = &dataGate{State: "reserved", Prepared: api.PreparedLaunch{ID: id, GateID: gateID, Target: r.Reservation.Target, ContainmentID: job.Lease.ContainmentID,
			EndpointGeneration: job.Lease.EndpointGeneration, SpecSHA256: job.Spec.Handoff.SpecSHA256}}
	}
	job.State = "preparing"
	parent.DataJobs[index] = job
	if err := m.save(parent); err != nil {
		return api.PreparedLaunch{}, err
	}
	live, err := m.startDataGate(ctx, parent, job)
	if err != nil {
		return api.PreparedLaunch{}, err
	}
	if m.gates == nil {
		m.gates = map[api.ID]ownedGate{}
	}
	m.gates[job.Lease.ID] = live
	job.Gate.PID, job.Gate.Prepared.ProcessGeneration = live.PID(), live.Generation()
	job.State, job.Gate.State = "prepared", "prepared"
	parent.DataJobs[index] = job
	if err := m.save(parent); err != nil {
		live.Close()
		return api.PreparedLaunch{}, err
	}
	return job.Gate.Prepared, nil
}

func dataHandle(job dataJob) api.ProcessHandle {
	return api.ProcessHandle{ID: job.Reg.LaunchID, Target: job.Reg.Reservation.Target, ContainmentID: job.Lease.ContainmentID, Generation: job.Gate.Prepared.ProcessGeneration}
}

func (m *leaseManager) openDataGate(ctx context.Context, open dataOpen) (api.ProcessHandle, error) {
	parent, index, err := m.findData(open.Reg.Request)
	if err != nil {
		return api.ProcessHandle{}, err
	}
	job := parent.DataJobs[index]
	if err := m.checkData(ctx, parent, job); err != nil {
		return api.ProcessHandle{}, err
	}
	if m.workerLaunch == nil {
		return api.ProcessHandle{}, failure(api.CodeContainmentUnknown, "data release has no enclosing worker launch guard")
	}
	if err := m.workerLaunch.check(ctx); err != nil {
		return api.ProcessHandle{}, err
	}
	if !sameDataReg(job.Reg, open.Reg) || job.Gate == nil || job.State != "prepared" || job.Gate.Permit != nil || job.Spec == nil {
		return api.ProcessHandle{}, failure(api.CodeConflict, "data gate is not its one-use prepared attempt")
	}
	if err := validateWorkerRecord(open.Reg, open.Record); err != nil {
		return api.ProcessHandle{}, err
	}
	records, err := m.records()
	if err != nil {
		return api.ProcessHandle{}, err
	}
	if err := newWorkerPrincipal(records, open.Reg, open.Record.Actor); err != nil {
		return api.ProcessHandle{}, err
	}
	if open.Request.Prepared != job.Gate.Prepared || open.Request.Cause.Actor != job.Reg.ParentActor || open.Request.Cause.EffectID != job.Reg.Worker.EffectID || open.Request.Cause.RequestedBy != job.Reg.Reservation.RequestedBy || open.Request.Cause.CauseOperationID != job.Reg.Reservation.OperationID || open.Request.Cause.CauseRequestID != job.Reg.Reservation.RequestID || open.Request.Cause.CancellationEpoch != job.Reg.Reservation.CancellationEpoch {
		return api.ProcessHandle{}, failure(api.CodeForbidden, "native worker release changed its sealed child cause")
	}
	binding := api.LaunchBindingRequest{Record: open.Record, Prepared: job.Gate.Prepared, Identity: open.Identity}
	if err := validateOpenCommit(open.Request, binding, m.binding.Config); err != nil {
		return api.ProcessHandle{}, err
	}
	if open.Record.UIDLeaseID != job.Lease.ID || open.Record.HostUID != job.Lease.UID || open.Reg.Worker.ConsumedBy != open.Record.ID || open.Record.ProcessGeneration != job.Gate.Prepared.ProcessGeneration {
		return api.ProcessHandle{}, failure(api.CodeForbidden, "data gate cannot share or replace its native worker identity")
	}
	deadline, e := time.Parse(time.RFC3339Nano, string(open.Reg.ClaimExpires))
	if e != nil || !deadline.After(time.Now()) || !validID(open.Reg.ClaimID) {
		return api.ProcessHandle{}, failure(api.CodeForbidden, "data claim expired before native release")
	}
	live := m.gates[job.Lease.ID]
	if live == nil || live.PID() != job.Gate.PID || live.Generation() != job.Gate.Prepared.ProcessGeneration {
		return api.ProcessHandle{}, failure(api.CodeContainmentUnknown, "data release descriptor or wait lifetime was lost")
	}
	observation, err := live.Observe(ctx, dataHandle(job))
	if err != nil {
		return api.ProcessHandle{}, err
	}
	if observation.State != "running" {
		return api.ProcessHandle{}, failure(api.CodeContainmentUnknown, "data gate ended before release")
	}
	job.Reg = open.Reg
	job.State, job.Gate.State = "opening", "opening"
	job.Gate.Permit = &open.Request.Permit
	job.Gate.Record = &open.Record
	job.Gate.Identity = &open.Identity
	parent.DataJobs[index] = job
	if err := m.save(parent); err != nil {
		return api.ProcessHandle{}, err
	}
	if err := live.Release(); err != nil {
		return api.ProcessHandle{}, err
	}
	job.State, job.Gate.State = "opened", "opened"
	parent.DataJobs[index] = job
	if err := m.save(parent); err != nil {
		return api.ProcessHandle{}, err
	}
	return dataHandle(job), nil
}

func (m *leaseManager) observeData(ctx context.Context, r dataReg) (api.ProcessObservation, error) {
	parent, index, err := m.findData(r.Request)
	if err != nil {
		return api.ProcessObservation{}, err
	}
	job := parent.DataJobs[index]
	if err := m.checkData(ctx, parent, job); err != nil {
		return api.ProcessObservation{}, err
	}
	if !sameDataReg(job.Reg, r) || job.Gate == nil {
		return api.ProcessObservation{}, failure(api.CodeForbidden, "data observation selects a foreign stage")
	}
	live := m.gates[job.Lease.ID]
	if live == nil || live.PID() != job.Gate.PID || live.Generation() != job.Gate.Prepared.ProcessGeneration {
		return api.ProcessObservation{}, failure(api.CodeContainmentUnknown, "data wait ownership was lost")
	}
	observation, err := live.Observe(ctx, dataHandle(job))
	if err != nil {
		return observation, err
	}
	if err := m.measureRunningSurvivors(ctx, dataChild(parent, job), &observation); err != nil {
		return api.ProcessObservation{}, err
	}
	if observation.State == "exited" {
		if err := m.resources.Quiescent(ctx, dataChild(parent, job)); err != nil {
			return api.ProcessObservation{}, err
		}
		zero := uint64(0)
		observation.Survivors = &zero
	}
	return observation, nil
}

func (m *leaseManager) measureData(ctx context.Context, query dataMeasure) (api.LaunchDataResult, error) {
	parent, index, err := m.findData(query.Reg.Request)
	if err != nil {
		return api.LaunchDataResult{}, err
	}
	job := parent.DataJobs[index]
	if err := m.checkData(ctx, parent, job); err != nil {
		return api.LaunchDataResult{}, err
	}
	if !sameDataReg(job.Reg, query.Reg) || job.Gate == nil || job.Gate.Record == nil {
		return api.LaunchDataResult{}, failure(api.CodeForbidden, "data measurement lacks its committed worker")
	}
	observation, err := m.observeData(ctx, query.Reg)
	if err != nil {
		return api.LaunchDataResult{}, err
	}
	if err := dataTerminal(observation, dataHandle(job)); err != nil {
		return api.LaunchDataResult{}, err
	}
	result, err := m.readQuiescentData(ctx, parent, job, query, observation)
	if err != nil {
		return api.LaunchDataResult{}, err
	}
	if job.Result != nil {
		result.Observation = job.Result.Observation
		if !reflect.DeepEqual(*job.Result, result) {
			return api.LaunchDataResult{}, failure(api.CodeIdempotencyConflict, "data completion changed its acknowledged result")
		}
		if err := m.ensureNativeWorkspace(ctx, &parent, index, query); err != nil {
			return api.LaunchDataResult{}, err
		}
		return *job.Result, nil
	}
	job.State = "returning"
	parent.DataJobs[index] = job
	if err := m.save(parent); err != nil {
		return api.LaunchDataResult{}, err
	}
	if err := m.returnData(ctx, parent, job, query.Manifest); err != nil {
		return api.LaunchDataResult{}, err
	}
	job.State = "measured"
	job.Result = &result
	parent.DataJobs[index] = job
	if err := m.save(parent); err != nil {
		return api.LaunchDataResult{}, err
	}
	if err := m.ensureNativeWorkspace(ctx, &parent, index, query); err != nil {
		return api.LaunchDataResult{}, err
	}
	return result, nil
}

func (m *leaseManager) readQuiescentData(ctx context.Context, parent leaseRecord, job dataJob, query dataMeasure, observation api.ProcessObservation) (api.LaunchDataResult, error) {
	if err := m.resources.Quiescent(ctx, parent); err != nil {
		return api.LaunchDataResult{}, err
	}
	return m.readDataResult(ctx, parent, job, query, observation)
}

func (m *leaseManager) revokeData(ctx context.Context, id api.ID) (matched bool, resultErr error) {
	finish, err := m.beginRecovery()
	if err != nil {
		return false, err
	}
	defer func() { resultErr = finish(resultErr) }()
	return m.revokeDataOwned(ctx, id)
}

func (m *leaseManager) revokeDataOwned(ctx context.Context, id api.ID) (bool, error) {
	if !validID(id) {
		return false, failure(api.CodeInvalid, "invalid data revocation ID")
	}
	records, err := m.records()
	if err != nil {
		return false, err
	}
	matched := false
	for _, parent := range records {
		for i, job := range parent.DataJobs {
			if !dataMatches(parent, job, id) {
				continue
			}
			matched = true
			if job.State == "collected" {
				continue
			}
			job.State = "revoked"
			parent.DataJobs[i] = job
			// Durable invalidation precedes stop/close. A failed stop retains the
			// UID, roots and refusal; no saved token can become live on restart.
			if err := m.save(parent); err != nil {
				return matched, err
			}
			child := dataChild(parent, job)
			if !job.GroupCollected {
				if job.Gate != nil {
					if err := m.killContainment(ctx, child); err != nil {
						return matched, err
					}
					live := m.gates[job.Lease.ID]
					if live == nil {
						if job.Result == nil {
							return matched, failure(api.CodeContainmentUnknown, "revoked data job lost its wait ownership")
						}
						if err := dataTerminal(job.Result.Observation, dataHandle(job)); err != nil {
							return matched, err
						}
						if err := m.waitContainmentEmpty(ctx, child); err != nil {
							return matched, err
						}
					} else {
						if err := stopAndWait(ctx, live, dataHandle(job), func() error { return m.waitContainmentEmpty(ctx, child) }); err != nil {
							return matched, err
						}
					}
				}
				if err := m.resources.Quiescent(ctx, child); err != nil {
					return matched, err
				}
			}
			if pins := m.dataPins[job.Projection.OpenToken]; pins != nil {
				if err := pins.close(); err != nil {
					return matched, err
				}
				delete(m.dataPins, job.Projection.OpenToken)
			}
		}
	}
	return matched, nil
}

func dataMatches(parent leaseRecord, job dataJob, id api.ID) bool {
	return id == job.Reg.Request.StageID || id == job.Reg.Worker.ID || id == job.Reg.LaunchID || id == job.Reg.Reservation.LaunchID || id == job.Lease.ID || id == job.Lease.ContainmentID || id == parent.Lease.ID || id == parent.Lease.ContainmentID
}

func (m *leaseManager) collectData(ctx context.Context, id api.ID) (bool, error) {
	matched, err := m.revokeData(ctx, id)
	if err != nil {
		return matched, err
	}
	records, err := m.records()
	if err != nil {
		return matched, err
	}
	for _, parent := range records {
		for index, job := range parent.DataJobs {
			if !dataMatches(parent, job, id) || job.State == "collected" {
				continue
			}
			if job.State != "revoked" || job.Result == nil {
				return matched, failure(api.CodeContainmentUnknown, "failed or unmeasured data job requires retained administrator recovery")
			}
			child := dataChild(parent, job)
			if !job.GroupCollected {
				if err := m.resources.Quiescent(ctx, child); err != nil {
					return matched, err
				}
			}
			if !job.SourceCollected {
				if err := m.collectDataSource(ctx, parent, job); err != nil {
					return matched, err
				}
				job.SourceCollected = true
				parent.DataJobs[index] = job
				if err := m.save(parent); err != nil {
					return matched, err
				}
			}
			if !job.GroupCollected {
				if err := m.resources.Remove(ctx, child); err != nil {
					return matched, err
				}
				job.GroupCollected = true
				parent.DataJobs[index] = job
				if err := m.save(parent); err != nil {
					return matched, err
				}
			}
			if live := m.gates[job.Lease.ID]; live != nil {
				if err := live.Close(); err != nil {
					return matched, err
				}
				delete(m.gates, job.Lease.ID)
			}
			job.State = "collected"
			parent.DataJobs[index] = job
			if err := m.save(parent); err != nil {
				return matched, err
			}
		}
	}
	return matched, nil
}

func (m *leaseManager) dispatchData(ctx context.Context, method string, raw json.RawMessage) (any, error) {
	switch method {
	case "data_selector":
		var q struct {
			ID api.ID `json:"id"`
		}
		if err := decodeStrict(raw, &q); err != nil {
			return nil, err
		}
		if !validID(q.ID) {
			return nil, failure(api.CodeInvalid, "invalid data native selector")
		}
		records, err := m.records()
		if err != nil {
			return nil, err
		}
		for _, parent := range records {
			for _, job := range parent.DataJobs {
				if job.Lease.ID == q.ID || job.Reg.LaunchID == q.ID || job.Gate != nil && job.Gate.Prepared.ID == q.ID {
					if err := m.checkData(ctx, parent, job); err != nil {
						return nil, err
					}
					return job.Reg.Request, nil
				}
			}
		}
		return nil, failure(api.CodeNotFound, "native selector names no retained data job")
	case "data_query":
		var q api.StorageProjectionRequest
		if err := decodeStrict(raw, &q); err != nil {
			return nil, err
		}
		p, i, err := m.findData(q)
		if err != nil {
			return nil, err
		}
		return p.DataJobs[i].Reg, nil
	case "data_open":
		var q dataCopyOpenRequest
		if err := decodeStrict(raw, &q); err != nil {
			return nil, err
		}
		return m.openData(ctx, q.Registration, q.Copies)
	case "data_register":
		var q dataSeal
		if err := decodeStrict(raw, &q); err != nil {
			return nil, err
		}
		return m.registerData(ctx, q)
	case "data_native":
		var q dataReg
		if err := decodeStrict(raw, &q); err != nil {
			return nil, err
		}
		return m.dataNative(ctx, q)
	case "data_gate":
		var q dataOpen
		if err := decodeStrict(raw, &q); err != nil {
			return nil, err
		}
		return m.openDataGate(ctx, q)
	case "data_measure":
		var q dataMeasure
		if err := decodeStrict(raw, &q); err != nil {
			return nil, err
		}
		return m.measureData(ctx, q)
	case "data_revoke":
		var q struct {
			ID api.ID `json:"id"`
		}
		if err := decodeStrict(raw, &q); err != nil {
			return nil, err
		}
		return m.revokeData(ctx, q.ID)
	case "data_collect":
		var q struct {
			ID api.ID `json:"id"`
		}
		if err := decodeStrict(raw, &q); err != nil {
			return nil, err
		}
		return m.collectData(ctx, q.ID)
	default:
		var q dataReg
		if err := decodeStrict(raw, &q); err != nil {
			return nil, err
		}
		switch method {
		case "data_prepare":
			return m.prepareData(ctx, q)
		case "data_observe":
			return m.observeData(ctx, q)
		case "data_lease":
			p, i, err := m.findData(q.Request)
			if err != nil {
				return nil, err
			}
			if !sameDataReg(p.DataJobs[i].Reg, q) {
				return nil, failure(api.CodeForbidden, "data lease selects a changed registration")
			}
			if err := m.checkData(ctx, p, p.DataJobs[i]); err != nil {
				return nil, err
			}
			return p.DataJobs[i].Lease, nil
		}
	}
	return nil, failure(api.CodeForbidden, "unknown fixed data operation")
}
