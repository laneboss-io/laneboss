package admin

import (
	"context"
	"encoding/json"
	"reflect"

	"laneboss.io/laneboss/internal/v2/api"
	archivejob "laneboss.io/laneboss/internal/v2/archive"
	"laneboss.io/laneboss/internal/v2/grants/manifest"
)

func reserveArchiveUIDs(records []leaseRecord, used map[uint32]bool) {
	for _, r := range records {
		for _, judge := range r.Judges {
			if !judge.Collected {
				used[judge.Lease.UID] = true
			}
		}
		for _, usage := range r.Usages {
			if !usage.Collected {
				used[usage.Lease.UID] = true
			}
		}
		for _, review := range r.Reviews {
			if review != nil && review.Worker != nil && !review.Worker.Collected {
				used[review.Worker.Lease.UID] = true
			}
		}
		if r.archivalOwner != nil && r.archivalOwner.Worker != nil && !r.archivalOwner.Worker.Collected {
			used[r.archivalOwner.Worker.Lease.UID] = true
		}
		for _, channel := range r.Channels {
			if !channel.Collected {
				used[channel.Lease.UID] = true
			}
		}
		if r.Storage != nil && (r.Storage.Withdrawn || r.Storage.Withdrawing) && !r.Storage.Collected && !cleanupReleasesUIDs(r) {
			used[r.Lease.UID] = true
		}
		if r.Archive != nil && r.Archive.Worker != nil && !r.Archive.Worker.Collected {
			used[r.Archive.Worker.Lease.UID] = true
		}
	}
}

func validateArchiveOwners(records []leaseRecord, b installation) error {
	ids := map[api.ID]bool{}
	uids := map[uint32]bool{b.Service.UID: true}
	actors := map[api.ID]bool{}
	for _, r := range records {
		ids[r.Lease.ID], ids[r.Lease.ContainmentID] = true, true
		if r.Phase != "released" && r.Phase != "aborted" {
			uids[r.Lease.UID] = true
		}
		actors[r.Request.Cause.Actor.ID], actors[r.Request.Cause.RequestedBy.ID] = true, true
		if r.Gate != nil && r.Gate.Open != nil {
			actors[r.Gate.Open.Binding.Record.Actor.ID] = true
		}
		for _, j := range r.DataJobs {
			ids[j.Lease.ID], ids[j.Lease.ContainmentID], ids[j.Reg.LaunchID], ids[j.Reg.Worker.ID] = true, true, true, true
			if j.State != "collected" {
				uids[j.Lease.UID] = true
			}
			if j.Gate != nil && j.Gate.Record != nil {
				actors[j.Gate.Record.Actor.ID] = true
			}
		}
		for _, c := range r.Captures {
			if c.Native != nil {
				if captureReservesUID(c) {
					uids[c.Native.Lease.UID] = true
				}
				ids[c.Native.Lease.ID], ids[c.Native.Lease.ContainmentID] = true, true
			}
		}
	}
	for _, r := range records {
		j := r.Archive
		if j == nil {
			continue
		}
		if r.Storage == nil || !r.Storage.Withdrawn || j.Intent.Request.Target.LifeID != r.Request.LifeID || !validID(j.Intent.OperationID) || !validID(j.LaunchID) || j.Phase != "withdrawing" && j.Phase != "frozen" || manifest.Object(j.Tree) != nil || len(j.Tree.Entries) > 4096 || len(j.Objects) > 4095 || len(j.Inventory) < len(j.Tree.Entries) || len(j.Inventory) > len(j.Tree.Entries)+1 {
			return failure(api.CodeIntegrity, "invalid retained native archive journal")
		}
		if j.Phase == "frozen" {
			body, err := canonicalValue(j.Tree)
			f := j.Freeze
			if err != nil || f.Target != j.Intent.Request.Target || f.LaunchID != j.LaunchID || f.CancellationEpoch != j.Intent.CancellationEpoch || f.Writers == nil || *f.Writers != 0 || f.WritableExports == nil || *f.WritableExports != 0 || f.Snapshot.Class != "manifest" || f.Snapshot.Bytes != int64(len(body)) || f.Snapshot.SHA256 != digestBytes(body) || f.ObservedAt == "" {
				return failure(api.CodeIntegrity, "native archive freeze lost its measured tree or counters")
			}
		}
		if err := validateArchiveRetirement(r); err != nil {
			return err
		}
		w := j.Worker
		if w == nil {
			continue
		}
		if validateLease(w.Lease, b) != nil || w.Lease.UID == r.Lease.UID || w.Lease.GID == r.Lease.GID || uids[w.Lease.UID] && !w.Collected || w.Reg.Job.Intent != j.Intent || !validID(w.Reg.Job.ID) || !validID(w.Reg.LaunchID) || w.Created == "" {
			return failure(api.CodeIntegrity, "archive worker overlaps another native owner")
		}
		if !w.Collected {
			uids[w.Lease.UID] = true
		}
		if (w.Collecting || w.Collected) && (w.Observation == nil || w.State != "exited") && !retirementAllowsCollection(j) {
			return failure(api.CodeIntegrity, "archive collection lacks its original successful wait")
		}
		for _, id := range []api.ID{w.Lease.ID, w.Lease.ContainmentID, w.Reg.Job.ID, w.Reg.Job.Lease.ID, w.Reg.LaunchID} {
			if !validID(id) || ids[id] {
				return failure(api.CodeIntegrity, "archive worker reused a retained identity")
			}
			ids[id] = true
		}
		switch w.State {
		case "reserved", "allocated", "registered", "preparing", "prepared", "opening", "opened", "exited":
		default:
			return failure(api.CodeIntegrity, "archive worker has an unknown journal phase")
		}
		if (w.Spec == nil) != (w.Endpoint == nil) || (w.Spec == nil) != (len(w.Input) == 0) {
			return failure(api.CodeIntegrity, "archive worker lost its sealed handoff")
		}
		if w.Spec != nil {
			if w.Spec.Handoff.Spec.UIDLeaseID != w.Lease.ID || w.Spec.Handoff.Spec.EndpointGeneration != w.Lease.EndpointGeneration {
				return failure(api.CodeIntegrity, "archive spec replaced its native lease")
			}
			if err := validateArchiveSeal(archiveSeal{Reg: w.Reg, Spec: *w.Spec, Endpoint: *w.Endpoint, Input: w.Input}, b, false); err != nil {
				return err
			}
		}
		if w.Gate != nil {
			g := w.Gate
			if w.Spec == nil || g.Prepared.Target != w.Reg.Job.Lease.Target || g.Prepared.ContainmentID != w.Lease.ContainmentID || g.Prepared.SpecSHA256 != w.Spec.Handoff.SpecSHA256 || !validID(g.Prepared.ID) || !validID(g.Prepared.GateID) || g.State != "preparing" && (g.PID <= 1 || g.Prepared.ProcessGeneration == "") {
				return failure(api.CodeIntegrity, "archive gate lost its prepared native lifetime")
			}
			if g.Record != nil {
				if actors[g.Record.Actor.ID] || g.Record.Actor.Kind != "worker" || !validID(g.Record.Actor.ID) {
					return failure(api.CodeIntegrity, "archive principal overlaps another retained actor")
				}
				actors[g.Record.Actor.ID] = true
			}
		}
		if w.Observation != nil {
			if w.Gate == nil || dataTerminal(*w.Observation, archiveHandle(*w)) != nil {
				return failure(api.CodeIntegrity, "archive terminal journal lacks an actual successful wait")
			}
		}
	}
	return nil
}

func validateArchiveSeal(seal archiveSeal, b installation, live bool) error {
	if live {
		if err := validArchiveReg(seal.Reg, b.Config); err != nil {
			return err
		}
	}
	if err := validateSpecEnvelope(seal.Spec, b.Config); err != nil {
		return err
	}
	r, j, s, e := seal.Reg, seal.Reg.Job, seal.Spec.Handoff.Spec, seal.Endpoint
	if r.Claim.Record.Effect.Context == nil {
		return failure(api.CodeIntegrity, "archive seal lost its original claim context")
	}
	if s.Kind != "worker" || s.Worker == nil || !reflect.DeepEqual(*s.Worker, j.Plan) || s.Runner != nil || s.PlanID != j.ID || s.LaunchID != r.LaunchID || s.Target != j.Lease.Target || s.RuntimeManifest != j.Lease.RuntimeManifest || s.Materialization.Manifest != j.Freeze || len(s.Materialization.Objects) != 0 || s.Budget != j.Plan.Budget ||
		s.Grants.ID != j.Lease.GrantSetID || len(s.Grants.Resources)+len(s.Grants.Secrets)+len(s.Grants.Profiles)+len(s.Grants.Network)+len(s.Grants.Channels) != 0 ||
		api.ValidateBinding(e, b.Config, b.Release.Version) != nil || e.Class != api.EndpointWorker || e.LaunchID != r.LaunchID || e.WorkerLeaseID != j.Lease.ID || e.Target == nil || *e.Target != j.Lease.Target || e.Socket != "/runtime/laneboss-worker.sock" || e.EndpointGeneration != b.Generation || e.InstallationGeneration != b.Generation || e.ServiceUID != b.Service.UID || e.ServiceGID != b.Service.GID || e.ArtifactSHA256 != b.Artifact.SHA256 ||
		digestBytes(seal.Input) != j.Lease.Input.SHA256 || int64(len(seal.Input)) != j.Lease.Input.Bytes ||
		(j.Lease.Kind == "archive" && j.Lease.Input.Class != "archive_input" || (j.Lease.Kind == "export" || j.Lease.Kind == "test") && j.Lease.Input.Class != "manifest") {
		return failure(api.CodeForbidden, "archive seal widens its fixed runtime, endpoint or read-only job")
	}
	for _, g := range s.Grants.Data {
		if g.Access != "ro" || g.Delegate {
			return failure(api.CodeForbidden, "archive worker acquired writable or delegable source access")
		}
	}
	if j.Lease.Kind == "test" {
		var protocol struct {
			Schema string `json:"schema"`
		}
		if err := json.Unmarshal(seal.Input, &protocol); err != nil {
			return failure(api.CodeIntegrity, "test worker lost its sealed protocol")
		}
		var err error
		if protocol.Schema == "laneboss.test-input.v2" {
			err = validateTestSealInput(seal)
		} else {
			err = validateCheckSealInput(seal)
		}
		if err != nil {
			return err
		}
	} else if j.Lease.Kind == "export" {
		if err := validateReviewSealInput(seal); err != nil {
			return err
		}
	} else {
		var input archivejob.Input
		if api.DecodeObject(seal.Input, &input) != nil || input.Schema != "laneboss.archive-input.v2" || input.JobID != j.ID || input.Intent != j.Intent || input.Freeze != j.Freeze || input.Budget != j.Plan.Budget || !validID(input.ReceiptID) || !validID(input.StoreID) {
			return failure(api.CodeIntegrity, "archive worker input changed its original retained job")
		}
	}
	cause := *r.Claim.Record.Effect.Context
	cause.Kind = api.InternalHelperRegister
	cause.Actor = api.Actor{Kind: "service", ID: r.Claim.Record.ClaimantID}
	if seal.Spec.Handoff.Cause != cause {
		return failure(api.CodeForbidden, "archive spec changed its retained claim cause")
	}
	return nil
}

func archiveChild(parent leaseRecord, w archiveWorker) leaseRecord {
	r := leaseRecord{Schema: parent.Schema, BootID: parent.BootID, Lease: w.Lease, Request: parent.Request, Phase: "active", IssuedAt: w.Created, Spec: w.Spec}
	r.Request.ReservationID = ""
	r.Request.Budget = w.Reg.Job.Plan.Budget
	r.Request.RuntimeManifestID = w.Reg.Job.Lease.RuntimeManifest.ID
	if w.Spec != nil {
		h := w.Spec.Handoff
		r.SpecReceipt = &api.PreparedSpecReceipt{SpecID: h.Spec.ID, Config: h.Config, Target: h.Spec.Target, LeaseID: w.Lease.ID, SpecSHA256: h.SpecSHA256, RuntimeManifest: h.Spec.RuntimeManifest, OperationID: h.OperationID}
	}
	if w.Gate != nil {
		r.Gate = &gateJournal{Prepared: w.Gate.Prepared, PID: w.Gate.PID, State: w.Gate.State, Permit: w.Gate.Permit}
	}
	return r
}

func archiveHandle(w archiveWorker) api.ProcessHandle {
	return api.ProcessHandle{ID: w.Reg.LaunchID, Target: w.Reg.Job.Lease.Target, ContainmentID: w.Lease.ContainmentID, Generation: w.Gate.Prepared.ProcessGeneration}
}

func (m *leaseManager) archiveByLease(id api.ID) (leaseRecord, bool, error) {
	records, err := m.records()
	if err != nil {
		return leaseRecord{}, false, err
	}
	for _, r := range records {
		if r.Archive != nil && r.Archive.Worker != nil && r.Archive.Worker.Lease.ID == id {
			return r, true, nil
		}
	}
	return leaseRecord{}, false, nil
}

func (m *leaseManager) archiveWorker(ctx context.Context, r archiveReg) (leaseRecord, error) {
	p, err := m.archiveWorkerRecord(r)
	if err != nil {
		return p, err
	}
	_, err = m.checkArchive(ctx, archiveQuery{Intent: r.Job.Intent, Freeze: p.Archive.Freeze})
	return p, err
}

// Retained identity checks are shared by launch and observation. Launch still
// measures the full storage fence above; observation does so only at exit.
func (m *leaseManager) archiveWorkerRecord(r archiveReg) (leaseRecord, error) {
	if err := validArchiveReg(r, m.binding.Config); err != nil {
		return leaseRecord{}, err
	}
	p, err := m.archiveParent(r.Job.Intent)
	if err != nil {
		return p, err
	}
	if !withinBudget(r.Job.Plan.Budget, p.Request.Budget) {
		return p, failure(api.CodeBudget, "archive worker exceeds its retained native resource envelope")
	}
	if p.Archive == nil || p.Archive.Phase != "frozen" {
		return p, failure(api.CodeForbidden, "archive worker has no measured storage fence")
	}
	if p.Archive.Retirement != nil {
		return p, failure(api.CodeConflict, "retiring archive worker cannot allocate or reopen")
	}
	if w := p.Archive.Worker; w != nil {
		if w.Collecting || w.Collected {
			return p, failure(api.CodeConflict, "collected archive worker cannot reopen its native gate")
		}
		if w.Revoked {
			return p, failure(api.CodeForbidden, "archive worker was durably revoked")
		}
		if !reflect.DeepEqual(w.Reg.Job, r.Job) || w.Reg.LaunchID != r.LaunchID || r.Claim.Record.Generation < w.Reg.Claim.Record.Generation {
			return p, failure(api.CodeConflict, "archive retry changed or rolled back its original worker")
		}
		w.Reg = r
	}
	return p, nil
}

func archiveRecoveryTransition(before, after *archiveJournal) error {
	if before == nil && after == nil {
		return nil
	}
	if before == nil || after == nil || (before.Worker == nil) != (after.Worker == nil) {
		return failure(api.CodeIntegrity, "recovery cannot replace archive ownership")
	}
	copy := *before
	if before.Worker != nil {
		worker := *before.Worker
		if worker.Revoked && !after.Worker.Revoked {
			return failure(api.CodeIntegrity, "recovery cannot restore an archive worker")
		}
		worker.Revoked = after.Worker.Revoked
		copy.Worker = &worker
	}
	if !reflect.DeepEqual(copy, *after) {
		return failure(api.CodeIntegrity, "recovery changed archive inputs or native lifetime")
	}
	return nil
}

func (m *leaseManager) allocateArchive(ctx context.Context, r archiveReg) (api.HelperLease, error) {
	p, err := m.archiveWorker(ctx, r)
	if err != nil {
		return api.HelperLease{}, err
	}
	if p.Archive.Worker != nil {
		w := p.Archive.Worker
		if w.State == "reserved" {
			return api.HelperLease{}, failure(api.CodeContainmentUnknown, "archive allocation is uncertain; replacement is forbidden")
		}
		if err := m.save(p); err != nil {
			return api.HelperLease{}, err
		}
		return w.Lease, nil
	}
	records, err := m.records()
	if err != nil {
		return api.HelperLease{}, err
	}
	used := map[uint32]bool{m.binding.Service.UID: true, p.Lease.UID: true}
	reserveArchiveUIDs(records, used)
	for _, v := range records {
		if v.Phase != "released" && v.Phase != "aborted" {
			used[v.Lease.UID] = true
		}
		for _, d := range v.DataJobs {
			if d.State != "collected" {
				used[d.Lease.UID] = true
			}
		}
		for _, c := range v.Captures {
			if c.Native != nil {
				used[c.Native.Lease.UID] = true
			}
		}
	}
	var a account
	for _, candidate := range m.binding.Lanes {
		if !used[candidate.UID] {
			a = candidate
			break
		}
	}
	if a.UID == 0 {
		return api.HelperLease{}, failure(api.CodeUnavailable, "archive needs a distinct free installed worker UID")
	}
	id, err := randomID("archive-job-")
	if err != nil {
		return api.HelperLease{}, err
	}
	group, err := randomID("archive-cg-")
	if err != nil {
		return api.HelperLease{}, err
	}
	w := archiveWorker{Reg: r, Lease: api.HelperLease{ID: id, UID: a.UID, GID: a.GID, ContainmentID: group, EndpointGeneration: m.binding.Generation}, State: "reserved", Created: gateTimestamp()}
	p.Archive.Worker = &w
	if err := m.save(p); err != nil {
		return api.HelperLease{}, err
	}
	child := archiveChild(p, w)
	child.Phase = "reserved"
	if err := m.resources.Ensure(ctx, child); err != nil {
		return api.HelperLease{}, err
	}
	w.State = "allocated"
	p.Archive.Worker = &w
	if err := m.save(p); err != nil {
		return api.HelperLease{}, err
	}
	return w.Lease, nil
}

func (m *leaseManager) registerArchive(ctx context.Context, seal archiveSeal) (api.PreparedSpecReceipt, error) {
	if err := validateArchiveSeal(seal, m.binding, true); err != nil {
		return api.PreparedSpecReceipt{}, err
	}
	p, err := m.archiveWorker(ctx, seal.Reg)
	if err != nil {
		return api.PreparedSpecReceipt{}, err
	}
	w := p.Archive.Worker
	if w == nil || seal.Spec.Handoff.Spec.UIDLeaseID != w.Lease.ID {
		return api.PreparedSpecReceipt{}, failure(api.CodeForbidden, "archive registration changed its distinct native lease")
	}
	if w.Spec != nil {
		retained := *w.Spec
		retained.Handoff.Cause.Actor = seal.Spec.Handoff.Cause.Actor
		if !reflect.DeepEqual(retained, seal.Spec) || !reflect.DeepEqual(*w.Endpoint, seal.Endpoint) || !reflect.DeepEqual(w.Input, seal.Input) {
			return api.PreparedSpecReceipt{}, failure(api.CodeIdempotencyConflict, "archive registration changed its sealed bytes")
		}
		w.Spec = &seal.Spec // Rebind only the already-validated live claimant.
	} else {
		if w.State != "allocated" {
			return api.PreparedSpecReceipt{}, failure(api.CodeConflict, "archive worker was already attempted")
		}
		if err := validateRuntimePins(ctx, m.binding, seal.Spec.Handoff.Spec); err != nil {
			return api.PreparedSpecReceipt{}, err
		}
		w.Spec, w.Endpoint, w.Input, w.State = &seal.Spec, &seal.Endpoint, append([]byte{}, seal.Input...), "registered"
	}
	if err := m.save(p); err != nil {
		return api.PreparedSpecReceipt{}, err
	}
	return *archiveChild(p, *w).SpecReceipt, nil
}

func (m *leaseManager) prepareArchive(ctx context.Context, r archiveReg) (api.PreparedLaunch, error) {
	p, err := m.archiveWorker(ctx, r)
	if err != nil {
		return api.PreparedLaunch{}, err
	}
	w := p.Archive.Worker
	if w == nil || w.Spec == nil {
		return api.PreparedLaunch{}, failure(api.CodeForbidden, "archive worker has no registered spec")
	}
	if w.Gate != nil {
		live := m.gates[w.Lease.ID]
		if w.Gate.State != "prepared" && w.Gate.State != "opened" || live == nil || live.PID() != w.Gate.PID || live.Generation() != w.Gate.Prepared.ProcessGeneration {
			return api.PreparedLaunch{}, failure(api.CodeContainmentUnknown, "archive gate lifetime was lost; no replacement")
		}
		return w.Gate.Prepared, m.save(p)
	}
	if w.State != "registered" {
		return api.PreparedLaunch{}, failure(api.CodeConflict, "archive gate already attempted")
	}
	id, err := randomID("prepared-")
	if err != nil {
		return api.PreparedLaunch{}, err
	}
	gate, err := randomID("gate-")
	if err != nil {
		return api.PreparedLaunch{}, err
	}
	w.Gate = &dataGate{State: "preparing", Prepared: api.PreparedLaunch{ID: id, GateID: gate, Target: r.Job.Lease.Target, ContainmentID: w.Lease.ContainmentID, EndpointGeneration: w.Lease.EndpointGeneration, SpecSHA256: w.Spec.Handoff.SpecSHA256}}
	w.State = "preparing"
	if err := m.save(p); err != nil {
		return api.PreparedLaunch{}, err
	}
	live, err := m.startArchiveGate(ctx, p, *w)
	if err != nil {
		return api.PreparedLaunch{}, err
	}
	if m.gates == nil {
		m.gates = map[api.ID]ownedGate{}
	}
	m.gates[w.Lease.ID] = live
	w.Gate.PID, w.Gate.Prepared.ProcessGeneration, w.Gate.State, w.State = live.PID(), live.Generation(), "prepared", "prepared"
	if err := m.save(p); err != nil {
		live.Close()
		return api.PreparedLaunch{}, err
	}
	return w.Gate.Prepared, nil
}

func (m *leaseManager) openArchive(ctx context.Context, q archiveOpen) (api.ProcessHandle, error) {
	p, err := m.archiveWorker(ctx, q.Reg)
	if err != nil {
		return api.ProcessHandle{}, err
	}
	w := p.Archive.Worker
	if w == nil || w.Gate == nil || w.Spec == nil {
		return api.ProcessHandle{}, failure(api.CodeForbidden, "archive gate was never prepared")
	}
	binding := api.LaunchBindingRequest{Record: q.Record, Prepared: q.Request.Prepared, Identity: q.Identity}
	if err := validateOpenCommit(q.Request, binding, m.binding.Config); err != nil {
		return api.ProcessHandle{}, err
	}
	cause := *q.Reg.Claim.Record.Effect.Context
	cause.Kind = api.InternalHelperOpen
	cause.Actor = api.Actor{Kind: "service", ID: q.Reg.Claim.Record.ClaimantID}
	r := binding.Record
	if q.Request.Cause != cause || q.Request.Prepared != w.Gate.Prepared || binding.Prepared != w.Gate.Prepared || r.ID != q.Reg.LaunchID || r.Kind != "worker" || r.Actor.Kind != "worker" || r.Target != q.Reg.Job.Lease.Target || r.UIDLeaseID != w.Lease.ID || r.HostUID != w.Lease.UID || r.ContainmentID != w.Lease.ContainmentID || r.ProcessGeneration != w.Gate.Prepared.ProcessGeneration || r.GrantSetID != q.Reg.Job.Lease.GrantSetID || r.GrantsSHA256 != w.Spec.Handoff.Spec.Grants.SHA256 || r.Revoked {
		return api.ProcessHandle{}, failure(api.CodeForbidden, "archive gate changed its committed worker identity")
	}
	records, err := m.records()
	if err != nil {
		return api.ProcessHandle{}, err
	}
	if err := newWorkerPrincipal(records, dataReg{LaunchID: r.ID}, r.Actor); err != nil {
		return api.ProcessHandle{}, err
	}
	for _, owner := range records {
		if owner.Archive != nil && owner.Archive.Worker != nil {
			other := owner.Archive.Worker
			if other.Reg.LaunchID != r.ID && other.Gate != nil && other.Gate.Record != nil && other.Gate.Record.Actor.ID == r.Actor.ID {
				return api.ProcessHandle{}, failure(api.CodeForbidden, "archive worker principal was reused")
			}
		}
	}
	if w.Gate.State == "opened" {
		if w.Gate.Record == nil || !reflect.DeepEqual(*w.Gate.Record, r) || w.Gate.Permit == nil || *w.Gate.Permit != q.Request.Permit {
			return api.ProcessHandle{}, failure(api.CodeConflict, "archive open retry changed its original permit")
		}
		return archiveHandle(*w), m.save(p)
	}
	if w.Gate.State != "prepared" || w.Gate.Permit != nil {
		return api.ProcessHandle{}, failure(api.CodeContainmentUnknown, "archive release outcome is uncertain")
	}
	guard, held := m.workerLaunch.(interface{ archiveRegistration() *archiveReg })
	if !held || guard.archiveRegistration() == nil || !reflect.DeepEqual(*guard.archiveRegistration(), q.Reg) {
		return api.ProcessHandle{}, failure(api.CodeContainmentUnknown, "archive release has no enclosing original worker launch guard")
	}
	if err := m.workerLaunch.check(ctx); err != nil {
		return api.ProcessHandle{}, err
	}
	live := m.gates[w.Lease.ID]
	if live == nil || live.PID() != w.Gate.PID || live.Generation() != w.Gate.Prepared.ProcessGeneration {
		return api.ProcessHandle{}, failure(api.CodeContainmentUnknown, "archive lost its native release descriptor")
	}
	observation, err := live.Observe(ctx, archiveHandle(*w))
	if err != nil {
		return api.ProcessHandle{}, err
	}
	if observation.State != "running" {
		return api.ProcessHandle{}, failure(api.CodeContainmentUnknown, "archive gate ended before release")
	}
	w.Gate.Permit, w.Gate.Record, w.Gate.Identity = &q.Request.Permit, &binding.Record, &binding.Identity
	w.Gate.State, w.State = "opening", "opening"
	if err := m.save(p); err != nil {
		return api.ProcessHandle{}, err
	}
	if err := live.Release(); err != nil {
		return api.ProcessHandle{}, err
	}
	w.Gate.State, w.State = "opened", "opened"
	if err := m.save(p); err != nil {
		return api.ProcessHandle{}, err
	}
	return archiveHandle(*w), nil
}

func (m *leaseManager) observeArchive(ctx context.Context, r archiveReg) (api.ProcessObservation, error) {
	p, err := m.archiveWorkerRecord(r)
	if err != nil {
		return api.ProcessObservation{}, err
	}
	w := p.Archive.Worker
	if w == nil || w.Gate == nil || w.Gate.Permit == nil {
		return api.ProcessObservation{}, failure(api.CodeForbidden, "archive has no opened native worker")
	}
	live := m.gates[w.Lease.ID]
	if live == nil || live.PID() != w.Gate.PID || live.Generation() != w.Gate.Prepared.ProcessGeneration {
		return api.ProcessObservation{}, failure(api.CodeContainmentUnknown, "archive native wait ownership was lost")
	}
	observation, err := measureArchiveNative(ctx, live, archiveHandle(*w), func() error {
		// A running read must leave the serialized helper available to the
		// worker. Before publishing its exit, remeasure the frozen storage.
		if _, err := m.checkArchive(ctx, archiveQuery{Intent: r.Job.Intent, Freeze: p.Archive.Freeze}); err != nil {
			return err
		}
		return m.resources.Quiescent(ctx, archiveChild(p, *w))
	})
	if err != nil {
		return observation, err
	}
	if err := m.measureRunningSurvivors(ctx, archiveChild(p, *w), &observation); err != nil {
		return api.ProcessObservation{}, err
	}
	if observation.State == "exited" {
		w.Observation = &observation
		w.State = "exited"
		if err := m.save(p); err != nil {
			return api.ProcessObservation{}, err
		}
	}
	return observation, nil
}

func measureArchiveNative(ctx context.Context, live ownedGate, handle api.ProcessHandle, quiescent func() error) (api.ProcessObservation, error) {
	observation, err := live.Observe(ctx, handle)
	if err != nil {
		return api.ProcessObservation{}, err
	}
	if observation.State == "exited" {
		if err := quiescent(); err != nil {
			return api.ProcessObservation{}, err
		}
		zero := uint64(0)
		observation.Survivors = &zero
		if err := dataTerminal(observation, handle); err != nil {
			return api.ProcessObservation{}, err
		}
	}
	return observation, nil
}

func (m *leaseManager) dispatchArchiveWorker(ctx context.Context, method string, raw json.RawMessage) (any, error) {
	if method == "archive_register" {
		var q archiveSeal
		if err := decodeStrict(raw, &q); err != nil {
			return nil, err
		}
		return m.registerArchive(ctx, q)
	}
	if method == "archive_open" {
		var q archiveOpen
		if err := decodeStrict(raw, &q); err != nil {
			return nil, err
		}
		return m.openArchive(ctx, q)
	}
	var q archiveReg
	if err := decodeStrict(raw, &q); err != nil {
		return nil, err
	}
	switch method {
	case "archive_reconcile":
		return m.reconcileArchiveWorker(ctx, q)
	case "archive_lease":
		return m.allocateArchive(ctx, q)
	case "archive_prepare":
		return m.prepareArchive(ctx, q)
	case "archive_observe":
		return m.observeArchive(ctx, q)
	}
	return nil, failure(api.CodeForbidden, "unknown archive worker operation")
}
