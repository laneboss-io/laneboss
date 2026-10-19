package admin

import (
	"context"
	"errors"
	"os"
	"reflect"
	"slices"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

// DataWorkerControl is a service-only capability. It deliberately accepts a
// retained stage selector and installed binding, never host roots or argv.
type DataWorkerControl interface {
	api.LaunchDataStorage
	DataWorkerLease(context.Context, api.StorageProjectionRequest) (api.HelperLease, error)
	RegisterDataWorker(context.Context, api.StorageProjectionRequest, api.PreparedSpecHandoff, api.InstalledBinding) (api.PreparedSpecReceipt, error)
	PrepareDataWorker(context.Context, api.StorageProjectionRequest) (api.PreparedLaunch, error)
	OpenDataWorker(context.Context, api.StorageProjectionRequest, api.HelperOpenRequest) (api.ProcessHandle, error)
	ObserveDataWorker(context.Context, api.StorageProjectionRequest) (api.ProcessObservation, error)
	MeasureDataWorker(context.Context, api.StorageProjectionRequest, api.WorkerResultReceipt) (api.LaunchDataResult, error)
	RevokeDataStorage(context.Context, api.ID) error
	CollectDataStorage(context.Context, api.ID) error
}

var _ DataWorkerControl = (*Service)(nil)

// All selectors originate in the retained service stage. No filesystem path,
// descriptor, UID or executable selector is supplied by a lane or public RPC.
type dataReg struct {
	Request         api.StorageProjectionRequest `json:"request"`
	Reservation     api.LaunchReservation        `json:"reservation"`
	Inputs          api.LaunchInputs             `json:"inputs"`
	Grants          api.GrantSet                 `json:"grants"`
	Worker          api.WorkerLease              `json:"worker"`
	Plan            api.WorkerPlan               `json:"plan"`
	ParentEffect    api.ID                       `json:"parent_effect"`
	ParentActor     api.Actor                    `json:"parent_actor"`
	LaunchID        api.ID                       `json:"launch_id"`
	ClaimID         api.ID                       `json:"claim_id"`
	ClaimGeneration api.Generation               `json:"claim_generation"`
	ClaimExpires    api.Timestamp                `json:"claim_expires"`
}

type dataJob struct {
	Reg             dataReg               `json:"registration"`
	Lease           api.HelperLease       `json:"lease"`
	Projection      api.StorageProjection `json:"projection"`
	Evidence        []byte                `json:"evidence"`
	State           string                `json:"state"`
	Created         api.Timestamp         `json:"created"`
	Spec            *specRegistration     `json:"spec,omitempty"`
	Input           []byte                `json:"input,omitempty"`
	Endpoint        *api.InstalledBinding `json:"endpoint,omitempty"`
	Gate            *dataGate             `json:"gate,omitempty"`
	Result          *api.LaunchDataResult `json:"result,omitempty"`
	SourceCollected bool                  `json:"source_collected,omitempty"`
	GroupCollected  bool                  `json:"group_collected,omitempty"`
}

type dataGate struct {
	Prepared api.PreparedLaunch  `json:"prepared"`
	PID      int                 `json:"pid"`
	State    string              `json:"state"`
	Permit   *api.LaunchPermit   `json:"permit,omitempty"`
	Record   *api.LaunchRecord   `json:"record,omitempty"`
	Identity *api.IdentityCommit `json:"identity,omitempty"`
}

type dataPins struct {
	roots    [3]*os.File
	parents  [2]*os.File
	names    [3]string
	manifest []byte
	copies   []*dataCopyPins
}

func (p *dataPins) close() error {
	var result error
	for _, file := range p.roots {
		if file != nil {
			result = errors.Join(result, file.Close())
		}
	}
	for _, file := range p.parents {
		if file != nil {
			result = errors.Join(result, file.Close())
		}
	}
	for _, copy := range p.copies {
		result = errors.Join(result, copy.close())
	}
	return result
}

type dataSeal struct {
	Reg      dataReg              `json:"registration"`
	Spec     specRegistration     `json:"spec"`
	Endpoint api.InstalledBinding `json:"endpoint"`
	Input    []byte               `json:"input"`
}

type dataOpen struct {
	Reg      dataReg               `json:"registration"`
	Request  api.HelperOpenRequest `json:"request"`
	Record   api.LaunchRecord      `json:"record"`
	Identity api.IdentityCommit    `json:"identity"`
}

type dataMeasure struct {
	Reg      dataReg                 `json:"registration"`
	Receipt  api.WorkerResultReceipt `json:"receipt"`
	Output   []byte                  `json:"output"`
	Manifest []byte                  `json:"manifest"`
}

// This is the grants consumer's existing private body; its byte arrays and
// shared nested field maps are retained exactly, rather than re-encoding input.
type dataInput struct {
	Schema      string                  `json:"schema"`
	StageID     api.ID                  `json:"stage_id"`
	Reservation api.LaunchReservation   `json:"reservation"`
	Source      api.ProjectLaunchSource `json:"source"`
	Storage     api.StorageProjection   `json:"storage"`
	Grants      api.GrantSet            `json:"grants"`
	Output      api.BlobRef             `json:"output"`
	Budget      api.Budget              `json:"budget"`
}

func validateDataReg(r dataReg, config string) error {
	if err := api.ValidateLaunchPlanRecord(api.LaunchPlanRecord{Reservation: r.Reservation, Inputs: &r.Inputs, Generation: 1, Phase: "sourced"}); err != nil {
		return err
	}
	q, w, g := r.Request, r.Worker, r.Grants
	if r.Reservation.Config != config || q.ReservationID != r.Reservation.ID || !validID(q.StageID) || !validID(q.AgentLeaseID) ||
		q.WorkerLeaseID != w.ID || !validID(w.ID) || !validID(w.EffectID) || !validID(r.ParentEffect) || w.EffectID == r.ParentEffect ||
		!validID(r.LaunchID) || r.ParentActor.Kind != "service" || !validActor(r.ParentActor) || !validID(r.ClaimID) || r.ClaimGeneration == 0 || r.ClaimGeneration > 1<<53-1 ||
		w.Kind != "materialize" || w.Target != r.Reservation.Target || w.OperationID != r.Reservation.OperationID ||
		w.GrantSetID != g.ID || w.RuntimeManifest != r.Inputs.Sources.Runtime.Manifest || w.Generation == 0 || w.Generation > 1<<53-2 || w.ConsumedBy != "" && w.ConsumedBy != r.LaunchID ||
		g.ID == r.Reservation.GrantSetID || !validID(g.ID) || !validDigest(g.SHA256) || g.Generation == 0 || g.Generation > 1<<53-1 || g.LifeID != w.Target.LifeID || g.Revoked || g.PolicyGeneration != r.Reservation.PolicyGeneration ||
		len(g.Resources)+len(g.Secrets)+len(g.Profiles)+len(g.Network)+len(g.Channels) != 0 || len(g.Data) != 1 ||
		r.Plan.Schema != "laneboss.worker-plan.v2" || r.Plan.Kind != "materialize" || r.Plan.GrantSetID != g.ID ||
		!validID(r.Plan.Executable.ID) || !validDigest(r.Plan.Executable.SHA256) || r.Plan.Executable.Version == "" || r.Plan.Input != w.Input {
		return failure(api.CodeForbidden, "data stage differs from its reserved child and narrow job")
	}
	d, s := g.Data[0], r.Inputs.Sources.Project
	if d.ParentGrantID != s.GrantID || d.SourceObjectID != s.Object.ID || d.SourceSHA256 != s.Object.SHA256 || d.RelativePath != "." ||
		d.Destination != "/job/source" || d.Access != "ro" || d.Delivery != "bind_ro" || d.Delegate || d.PublicationID != "" || d.HistoryScope != s.HistoryScope ||
		!slices.Equal(r.Plan.Argv, []string{"laneboss", "internal", "worker", "--binding", "/runtime/laneboss-worker.json", "--lease", string(w.ID)}) {
		return failure(api.CodeForbidden, "data stage widens its fixed source or worker argv")
	}
	budget := r.Plan.Budget
	if budget.WallMS <= 0 || budget.MemoryBytes < uint64(os.Getpagesize()) || budget.Processes == 0 || budget.DiskBytes == 0 || budget.SpendMicros < 0 {
		return failure(api.CodeBudget, "data worker requires a bounded positive job budget")
	}
	if w.Input != (api.BlobRef{}) && (w.Input.Class != "materialize_input" || !validID(w.Input.ID) || !validDigest(w.Input.SHA256) || w.Input.Bytes <= 0 || w.Input.Bytes > api.MaxFrameBytes) {
		return failure(api.CodeInvalid, "data input reference is not a bounded immutable worker body")
	}
	deadline, err := time.Parse(time.RFC3339Nano, string(g.ExpiresAt))
	if err != nil {
		return failure(api.CodeInvalid, "data grant expiry is invalid")
	}
	workerExpiry, err := time.Parse(time.RFC3339Nano, string(w.ExpiresAt))
	if err != nil || workerExpiry.After(deadline) {
		return failure(api.CodeForbidden, "worker lease outlives its narrow grants")
	}
	claimExpiry, err := time.Parse(time.RFC3339Nano, string(r.ClaimExpires))
	if err != nil || claimExpiry.After(workerExpiry) {
		return failure(api.CodeForbidden, "data claim outlives its worker lease")
	}
	agentExpiry, err := time.Parse(time.RFC3339Nano, string(r.Inputs.Grants.ExpiresAt))
	if err != nil || deadline.After(agentExpiry) || d.ExpiresAt != g.ExpiresAt {
		return failure(api.CodeForbidden, "data grant expiry exceeds its original source")
	}
	found := false
	for _, original := range r.Inputs.Grants.Data {
		if original.ID != s.GrantID {
			continue
		}
		expiry, e := time.Parse(time.RFC3339Nano, string(original.ExpiresAt))
		if e != nil || deadline.After(expiry) || original.RelativePath != "." || original.Delivery != "copy" {
			return failure(api.CodeForbidden, "data worker exceeds its original source grant")
		}
		found = true
	}
	if !found {
		return failure(api.CodeForbidden, "data worker lost its original source grant")
	}
	sealed := g
	sealed.SHA256 = ""
	raw, err := canonicalValue(sealed)
	if err != nil {
		return err
	}
	if digestBytes(raw) != g.SHA256 {
		return failure(api.CodeIntegrity, "data grant set hash changed")
	}
	return nil
}

func sameDataReg(a, b dataReg) bool {
	// Input and consumption are assigned once after opening roots, then frozen
	// at registration. Claim renewal is checked by the service at every effect.
	if a.Worker.Input.ID != "" && a.Worker.Input != b.Worker.Input {
		return false
	}
	if b.Worker.Generation < a.Worker.Generation || b.Worker.Generation > a.Worker.Generation+1 {
		return false
	}
	if a.Worker.ConsumedBy != "" && a.Worker.ConsumedBy != b.Worker.ConsumedBy {
		return false
	}
	a.Plan.Input, b.Plan.Input = api.BlobRef{}, api.BlobRef{}
	a.Worker.Input, b.Worker.Input = api.BlobRef{}, api.BlobRef{}
	a.Worker.ConsumedBy, b.Worker.ConsumedBy = "", ""
	a.Worker.Generation, b.Worker.Generation = 0, 0
	a.ClaimID, b.ClaimID = "", ""
	a.ClaimGeneration, b.ClaimGeneration = 0, 0
	a.ClaimExpires, b.ClaimExpires = "", ""
	return reflect.DeepEqual(a, b)
}

func validateDataJob(parent leaseRecord, job dataJob, binding installation) (resultErr error) {
	check := "lease_data_registration"
	defer func() { helperCheck(&resultErr, check) }()
	if err := validateDataReg(job.Reg, binding.Config); err != nil {
		return err
	}
	check = "lease_data_lease"
	if err := validateLease(job.Lease, binding); err != nil {
		return err
	}
	check = "lease_data_parent"
	if job.Lease.UID == parent.Lease.UID || job.Lease.GID == parent.Lease.GID || job.Lease.ContainmentID == parent.Lease.ContainmentID ||
		job.Reg.Request.AgentLeaseID != parent.Lease.ID || job.Reg.ParentActor != parent.Request.Cause.Actor || job.Created == "" || !withinBudget(job.Reg.Plan.Budget, parent.Request.Budget) {
		return failure(api.CodeIntegrity, "data worker shares or exceeds its agent allocation")
	}
	check = "lease_data_state"
	switch job.State {
	case "reserved", "open", "registered", "preparing", "prepared", "opening", "opened", "returning", "measured", "revoked", "collected":
	default:
		return failure(api.CodeIntegrity, "unknown data token state")
	}
	check = "lease_data_evidence"
	if job.State != "reserved" && !(job.State == "revoked" && job.Projection.OpenToken == "") && (!validID(job.Projection.OpenToken) || job.Projection.StageID != job.Reg.Request.StageID ||
		job.Projection.WorkerLeaseID != job.Reg.Worker.ID || job.Projection.Storage.LeaseID != parent.Lease.ID ||
		job.Projection.Generation != binding.Generation || digestBytes(job.Evidence) != job.Projection.Evidence.SHA256 || int64(len(job.Evidence)) != job.Projection.Evidence.Bytes) {
		return failure(api.CodeIntegrity, "data token lost its held-root evidence")
	}
	check = "lease_data_allocation"
	if parent.Storage == nil {
		return failure(api.CodeIntegrity, "data journal lost its parent storage allocation")
	}
	allocated := false
	for _, allocation := range parent.LaunchAllocations {
		if reflect.DeepEqual(allocation.Reservation, job.Reg.Reservation) && reflect.DeepEqual(allocation.Inputs, job.Reg.Inputs) {
			allocated = true
		}
	}
	if !allocated {
		return failure(api.CodeIntegrity, "data journal differs from the helper's original allocation")
	}
	if job.Projection.OpenToken != "" {
		check = "lease_data_storage"
		if err := validateLaunchStorage(job.Projection.Storage, job.Reg.Reservation, parent.Lease.ID); err != nil {
			return err
		}
		if job.Projection.Storage.WorkspaceID != parent.Storage.Binding.WorkspaceID || job.Projection.Storage.Home != parent.Storage.Binding.Home {
			return failure(api.CodeIntegrity, "data journal replaced allocated storage identities")
		}
	}
	check = "lease_data_seal"
	if (job.Spec == nil) != (job.Endpoint == nil) || (job.Spec == nil) != (len(job.Input) == 0) {
		return failure(api.CodeIntegrity, "data journal lost its sealed spec, endpoint or input")
	}
	if job.Spec != nil {
		if err := validateDataSeal(dataSeal{Reg: job.Reg, Spec: *job.Spec, Endpoint: *job.Endpoint, Input: job.Input}, binding); err != nil {
			return err
		}
	}
	check = "lease_data_stage"
	if job.State == "reserved" && (job.Projection.OpenToken != "" || job.Spec != nil || job.Gate != nil || job.Result != nil) {
		return failure(api.CodeIntegrity, "data reservation contains a later execution stage")
	}
	if job.State == "open" && (job.Spec != nil || job.Gate != nil || job.Result != nil) {
		return failure(api.CodeIntegrity, "open data roots contain a later execution stage")
	}
	check = "lease_data_result"
	if job.State == "measured" && job.Result == nil {
		return failure(api.CodeIntegrity, "measured data job lost its result")
	}
	if job.Result != nil {
		result := job.Result
		if job.Gate == nil || job.Gate.Record == nil || job.State != "measured" && job.State != "revoked" && job.State != "collected" || result.StageID != job.Reg.Request.StageID || result.WorkerLeaseID != job.Reg.Worker.ID || result.EffectID != job.Reg.Worker.EffectID || result.OperationID != job.Reg.Reservation.OperationID || result.InputSHA256 != job.Reg.Worker.Input.SHA256 || !validDigest(result.ReadBackSHA256) || result.ReadBackSHA256 != result.Manifest.SHA256 {
			return failure(api.CodeIntegrity, "data completion lost its original stage and measured manifest")
		}
		if err := dataTerminal(result.Observation, dataHandle(job)); err != nil {
			return err
		}
	}
	check = "lease_data_collection"
	if (job.SourceCollected || job.GroupCollected) && (job.State != "revoked" && job.State != "collected" || job.Result == nil) || job.GroupCollected && !job.SourceCollected || job.State == "collected" && (!job.SourceCollected || !job.GroupCollected) {
		return failure(api.CodeIntegrity, "data collection journal lacks measured removal ordering")
	}
	if job.Gate != nil {
		check = "lease_data_gate"
		gate := job.Gate
		if job.Spec == nil || gate.Prepared.Target != job.Reg.Reservation.Target || gate.Prepared.ContainmentID != job.Lease.ContainmentID || gate.Prepared.EndpointGeneration != job.Lease.EndpointGeneration || gate.Prepared.SpecSHA256 != job.Spec.Handoff.SpecSHA256 || !validID(gate.Prepared.ID) || !validID(gate.Prepared.GateID) {
			return failure(api.CodeIntegrity, "data gate lost its native prepared tuple")
		}
		switch gate.State {
		case "reserved", "preparing":
			if gate.PID != 0 || gate.Prepared.ProcessGeneration != "" {
				return failure(api.CodeIntegrity, "uncertain data gate acquired a replacement lifetime")
			}
		case "prepared", "opening", "opened":
			if gate.PID <= 1 || gate.Prepared.ProcessGeneration == "" {
				return failure(api.CodeIntegrity, "data gate lost its process lifetime")
			}
		default:
			return failure(api.CodeIntegrity, "unknown data gate phase")
		}
		if (gate.Permit == nil) != (gate.Record == nil) || (gate.Permit == nil) != (gate.Identity == nil) || (gate.State == "opening" || gate.State == "opened") != (gate.Permit != nil) {
			return failure(api.CodeIntegrity, "data gate lost its one-use committed permit")
		}
		if gate.Record != nil {
			if err := validateWorkerRecord(job.Reg, *gate.Record); err != nil {
				return err
			}
			if gate.Record.UIDLeaseID != job.Lease.ID || gate.Record.HostUID != job.Lease.UID || gate.Record.ContainmentID != job.Lease.ContainmentID || gate.Record.ProcessGeneration != gate.Prepared.ProcessGeneration || gate.Record.ID != gate.Permit.LaunchID || gate.Permit.PreparedID != gate.Prepared.ID || gate.Identity.LaunchID != gate.Record.ID || gate.Identity.CommittedSeq != gate.Permit.CommittedSeq || gate.Identity.RecordSHA256 != gate.Permit.RecordSHA256 {
				return failure(api.CodeIntegrity, "data gate changed its committed worker identity")
			}
		}
	}
	return nil
}

// dataRegistration retains stable ownership and uses live attempt metadata only
// for this admission. Native journal identity comparisons ignore claim renewal.
func dataRegistration(q api.StorageProjectionRequest, stage api.LaunchDataStage, parent api.EffectRecord) (dataReg, error) {
	var r dataReg
	if parent.Effect.Context == nil || parent.Effect.ID != stage.ParentEffectID {
		return r, failure(api.CodeForbidden, "data registration names another planning effect")
	}
	lease := stage.Claim
	if lease.Record.Effect.ID == stage.ParentEffectID {
		// Preparation has only a stable parent pin. Authenticate with the
		// independently reloaded live parent, bounded by the original job TTL.
		lease = api.EffectLease{Record: parent, ClaimID: parent.ClaimID, ExpiresAt: parent.ClaimExpiresAt}
		parentExpiry, parentErr := time.Parse(time.RFC3339Nano, string(lease.ExpiresAt))
		workerExpiry, workerErr := time.Parse(time.RFC3339Nano, string(stage.Worker.ExpiresAt))
		if parentErr != nil || workerErr != nil {
			return r, failure(api.CodeIntegrity, "data preparation lost its retained deadlines")
		}
		if workerExpiry.Before(parentExpiry) {
			lease.ExpiresAt = stage.Worker.ExpiresAt
		}
	}
	r = dataReg{Request: q, Reservation: stage.Reservation, Inputs: stage.Inputs, Grants: stage.Grants, Worker: stage.Worker, Plan: stage.Plan, ParentEffect: stage.ParentEffectID, ParentActor: parent.Effect.Context.Actor, LaunchID: stage.WorkerLaunchID,
		ClaimID: lease.ClaimID, ClaimGeneration: lease.Record.Generation, ClaimExpires: lease.ExpiresAt}
	return r, validateDataReg(r, stage.Reservation.Config)
}

func (s *Service) dataAuthority(ctx context.Context, q api.StorageProjectionRequest, execute bool) (dataReg, api.Scope, error) {
	var r dataReg
	if !validID(q.StageID) || !validID(q.ReservationID) || !validID(q.AgentLeaseID) || !validID(q.WorkerLeaseID) {
		return r, api.Scope{}, failure(api.CodeInvalid, "invalid data stage selector")
	}
	_, found, err := s.priorData(ctx, q)
	if err != nil {
		return r, api.Scope{}, err
	}
	a, err := s.launchAuthority(ctx, q.ReservationID, "", nil, q.Claim)
	if err != nil {
		return r, api.Scope{}, err
	}
	stage, err := s.deps.Store.LaunchDataStage(ctx, a.Scope, api.LaunchDataRequest{ReservationID: q.ReservationID, GrantSetID: a.Grants.ID, LeaseID: q.AgentLeaseID, Claim: q.Claim})
	if err != nil {
		return r, a.Scope, err
	}
	if a.Record.DataStageID != q.StageID || stage.ID != q.StageID || stage.AgentLeaseID != q.AgentLeaseID || stage.Worker.ID != q.WorkerLeaseID ||
		stage.ParentEffectID != a.Claim.Effect.ID || !reflect.DeepEqual(stage.Reservation, a.Record.Reservation) || a.Record.Inputs == nil || !reflect.DeepEqual(stage.Inputs, *a.Record.Inputs) {
		return r, a.Scope, failure(api.CodeForbidden, "data selector has no exact retained parent stage")
	}
	for _, id := range []api.ID{stage.Reservation.LaunchID, stage.WorkerLaunchID} {
		if id == "" {
			continue
		}
		launch, e := s.deps.Store.Launch(ctx, id)
		var typed *api.Error
		if e != nil {
			if errors.As(e, &typed) && typed.Code == api.CodeNotFound {
				continue
			}
			return r, a.Scope, e
		}
		if launch.ID != id || launch.Revoked {
			return r, a.Scope, deniedDataLaunch(found, func() error { return s.RevokeDataStorage(ctx, id) })
		}
	}
	worker, err := s.deps.Store.WorkerLease(ctx, a.Scope, stage.Worker.ID)
	if err != nil {
		return r, a.Scope, err
	}
	if worker.Generation < stage.Worker.Generation || worker.Generation > stage.Worker.Generation+1 {
		return r, a.Scope, failure(api.CodeConflict, "data worker revision changed")
	}
	want := stage.Worker
	want.Generation = worker.Generation
	if worker != want {
		return r, a.Scope, failure(api.CodeForbidden, "data worker lease changed")
	}
	grants, err := s.deps.Store.Grants(ctx, stage.Grants.ID)
	if err != nil {
		return r, a.Scope, err
	}
	if !reflect.DeepEqual(grants, stage.Grants) {
		return r, a.Scope, failure(api.CodeForbidden, "data job grants changed")
	}
	r, err = dataRegistration(q, stage, a.Claim)
	if err != nil {
		return r, a.Scope, err
	}
	ceiling, err := launchBudget(a)
	if err != nil {
		return r, a.Scope, err
	}
	if !withinBudget(r.Plan.Budget, ceiling) {
		return r, a.Scope, failure(api.CodeBudget, "data worker exceeds its original task budget")
	}
	if execute {
		claim, err := s.deps.Store.Effect(ctx, a.Scope, stage.Worker.EffectID)
		if err != nil {
			return r, a.Scope, err
		}
		deadline, e := time.Parse(time.RFC3339Nano, string(stage.Claim.ExpiresAt))
		if !reflect.DeepEqual(claim, stage.Claim.Record) || claim.State != "claimed" || claim.ClaimID != stage.Claim.ClaimID || claim.ClaimExpiresAt != stage.Claim.ExpiresAt || e != nil || !deadline.After(time.Now()) ||
			claim.Effect.Worker == nil || !reflect.DeepEqual(*claim.Effect.Worker, stage.Plan) || claim.Effect.Context == nil ||
			claim.Effect.Context.CancellationEpoch != r.Reservation.CancellationEpoch || claim.Effect.Context.RequestedBy != r.Reservation.RequestedBy {
			return r, a.Scope, failure(api.CodeForbidden, "data execution lacks its current child claim")
		}
	}
	if err := s.fenceLaunch(ctx, a); err != nil {
		return r, a.Scope, err
	}
	return r, a.Scope, nil
}

func (s *Service) OpenLaunchDataStorage(ctx context.Context, q api.StorageProjectionRequest) (api.StorageProjection, error) {
	r, scope, err := s.dataAuthority(ctx, q, false)
	if err != nil {
		return api.StorageProjection{}, err
	}
	copies, err := s.copyPayloads(ctx, scope, r)
	if err != nil {
		return api.StorageProjection{}, err
	}
	fresh, _, err := s.dataAuthority(ctx, q, false)
	if err != nil {
		return api.StorageProjection{}, err
	}
	if !reflect.DeepEqual(fresh, r) {
		return api.StorageProjection{}, failure(api.CodeConflict, "copy authority changed during source reads")
	}
	var result api.StorageProjection
	if err := s.call(ctx, "data_open", dataCopyOpenRequest{Registration: r, Copies: copies}, &result); err != nil {
		return result, err
	}
	if result.StageID != q.StageID || result.WorkerLeaseID != q.WorkerLeaseID || result.Storage.ReservationID != q.ReservationID || result.Storage.LeaseID != q.AgentLeaseID ||
		result.Generation != s.binding.Generation || !validID(result.OpenToken) || result.SourceIdentity == "" || result.WorkspaceIdentity == "" || result.HomeIdentity == "" {
		return api.StorageProjection{}, failure(api.CodeIntegrity, "data projection differs from its selector")
	}
	if _, err := api.ValidateDataCopyProjections(r.Inputs, result); err != nil {
		return api.StorageProjection{}, err
	}
	return result, nil
}

func (s *Service) DataWorkerLease(ctx context.Context, q api.StorageProjectionRequest) (api.HelperLease, error) {
	r, _, err := s.dataAuthority(ctx, q, false)
	if err != nil {
		return api.HelperLease{}, err
	}
	var lease api.HelperLease
	if err := s.call(ctx, "data_lease", r, &lease); err != nil {
		return lease, err
	}
	return lease, validateLease(lease, s.binding)
}

func (s *Service) RegisterDataWorker(ctx context.Context, q api.StorageProjectionRequest, h api.PreparedSpecHandoff, e api.InstalledBinding) (api.PreparedSpecReceipt, error) {
	r, scope, err := s.dataAuthority(ctx, q, true)
	if err != nil {
		return api.PreparedSpecReceipt{}, err
	}
	input, err := s.readLaunchObject(ctx, scope, r.Worker.Input, r.Reservation.OperationID, r.Reservation.Target.LifeID, true)
	if err != nil {
		return api.PreparedSpecReceipt{}, err
	}
	original, err := s.readLaunchObject(ctx, scope, h.Original, r.Reservation.OperationID, r.Reservation.Target.LifeID, true)
	if err != nil {
		return api.PreparedSpecReceipt{}, err
	}
	seal := dataSeal{Reg: r, Spec: specRegistration{Handoff: h, Original: original}, Endpoint: e, Input: input}
	if err := validateDataSeal(seal, s.binding); err != nil {
		return api.PreparedSpecReceipt{}, err
	}
	var receipt api.PreparedSpecReceipt
	err = s.call(ctx, "data_register", seal, &receipt)
	return receipt, err
}

func (s *Service) PrepareDataWorker(ctx context.Context, q api.StorageProjectionRequest) (api.PreparedLaunch, error) {
	r, _, err := s.dataAuthority(ctx, q, true)
	if err != nil {
		return api.PreparedLaunch{}, err
	}
	var prepared api.PreparedLaunch
	if err := s.call(ctx, "data_prepare", r, &prepared); err != nil {
		return prepared, err
	}
	if prepared.Target != r.Reservation.Target || !validID(prepared.ID) || !validID(prepared.GateID) || !validID(prepared.ContainmentID) || prepared.ProcessGeneration == "" || prepared.EndpointGeneration != s.binding.Generation {
		return api.PreparedLaunch{}, failure(api.CodeIntegrity, "data prepare substituted the native worker tuple")
	}
	if err := s.bindDataContainment(ctx, q); err != nil {
		return api.PreparedLaunch{}, err
	}
	return prepared, nil
}

func (s *Service) OpenDataWorker(ctx context.Context, q api.StorageProjectionRequest, request api.HelperOpenRequest) (api.ProcessHandle, error) {
	r, _, err := s.dataAuthority(ctx, q, true)
	if err != nil {
		return api.ProcessHandle{}, err
	}
	if request.Cause.EffectID != r.Worker.EffectID || request.Cause.RequestedBy != r.Reservation.RequestedBy || request.Cause.CauseOperationID != r.Reservation.OperationID || request.Cause.CauseRequestID != r.Reservation.RequestID || request.Cause.CancellationEpoch != r.Reservation.CancellationEpoch {
		return api.ProcessHandle{}, failure(api.CodeForbidden, "worker release cause differs from its current child claim")
	}
	binding, err := s.deps.Store.LaunchBinding(ctx, r.LaunchID)
	if err != nil {
		return api.ProcessHandle{}, err
	}
	if err := validateOpenCommit(request, binding, s.deps.Config); err != nil {
		return api.ProcessHandle{}, err
	}
	if err := validateWorkerRecord(r, binding.Record); err != nil {
		return api.ProcessHandle{}, err
	}
	var process api.ProcessHandle
	err = s.call(ctx, "data_gate", dataOpen{Reg: r, Request: request, Record: binding.Record, Identity: binding.Identity}, &process)
	if err == nil && (process.ID != r.LaunchID || process.Target != r.Reservation.Target || process.ContainmentID != request.Prepared.ContainmentID || process.Generation != request.Prepared.ProcessGeneration) {
		return api.ProcessHandle{}, failure(api.CodeIntegrity, "data helper substituted the opened worker process")
	}
	return process, err
}

func (s *Service) MeasureDataWorker(ctx context.Context, q api.StorageProjectionRequest, receipt api.WorkerResultReceipt) (api.LaunchDataResult, error) {
	r, scope, stage, err := s.retainedData(ctx, q)
	if err != nil {
		return api.LaunchDataResult{}, err
	}
	raw, err := s.readLaunchObject(ctx, scope, receipt.Result, r.Reservation.OperationID, r.Reservation.Target.LifeID, false)
	if err != nil {
		return api.LaunchDataResult{}, err
	}
	var data api.LaunchData
	if err := api.DecodeObject(raw, &data); err != nil {
		return api.LaunchDataResult{}, err
	}
	manifest, err := s.readLaunchObject(ctx, scope, data.Materialization.Manifest, r.Reservation.OperationID, r.Reservation.Target.LifeID, false)
	if err != nil {
		return api.LaunchDataResult{}, err
	}
	var result api.LaunchDataResult
	err = s.call(ctx, "data_measure", dataMeasure{Reg: r, Receipt: receipt, Output: raw, Manifest: manifest}, &result)
	if err == nil {
		err = api.ValidateLaunchDataResult(stage, result)
	}
	return result, err
}

func (s *Service) ObserveDataWorker(ctx context.Context, q api.StorageProjectionRequest) (api.ProcessObservation, error) {
	r, _, stage, err := s.retainedData(ctx, q)
	if err != nil {
		return api.ProcessObservation{}, err
	}
	var observation api.ProcessObservation
	if err := s.call(ctx, "data_observe", r, &observation); err != nil {
		return api.ProcessObservation{}, err
	}
	if observation.Handle != stage.Process {
		return api.ProcessObservation{}, failure(api.CodeIntegrity, "data observation substituted the retained worker")
	}
	return observation, nil
}

func (s *Service) RevokeDataStorage(ctx context.Context, id api.ID) error {
	if !validID(id) {
		return failure(api.CodeInvalid, "invalid data revocation selector")
	}
	var matched bool
	err := s.call(ctx, "data_revoke", struct {
		ID api.ID `json:"id"`
	}{id}, &matched)
	return s.finishRevocation(id, matched, err)
}

func (s *Service) CollectDataStorage(ctx context.Context, id api.ID) error {
	if !validID(id) {
		return failure(api.CodeInvalid, "invalid data collection selector")
	}
	var matched bool
	err := s.call(ctx, "data_collect", struct {
		ID api.ID `json:"id"`
	}{id}, &matched)
	return s.finishRevocation(id, matched, err)
}

func validateWorkerRecord(r dataReg, record api.LaunchRecord) error {
	if record.Kind != "worker" || record.Actor.Kind != "worker" || !validID(record.Actor.ID) || record.Actor.LifeID != "" || record.Actor.Level != 0 || record.Actor.Role != "" || record.Revoked ||
		record.Actor.ID == r.Reservation.RequestedBy.ID || record.Actor.ID == r.ParentActor.ID || record.ID != r.LaunchID || record.Config != r.Reservation.Config || record.Target != r.Worker.Target || record.GrantSetID != r.Grants.ID || record.GrantsSHA256 != r.Grants.SHA256 || record.PolicyGeneration != r.Reservation.PolicyGeneration {
		return failure(api.CodeForbidden, "data job cannot borrow an agent or requester principal")
	}
	return nil
}

func validateDataSeal(s dataSeal, b installation) error {
	if err := validateDataReg(s.Reg, b.Config); err != nil {
		return err
	}
	if err := validateSpecEnvelope(s.Spec, b.Config); err != nil {
		return err
	}
	if err := api.ValidateBinding(s.Endpoint, b.Config, b.Release.Version); err != nil {
		return err
	}
	spec := s.Spec.Handoff.Spec
	r := s.Reg
	e := s.Endpoint
	if spec.Kind != "worker" || spec.Runner != nil || spec.Worker == nil || !reflect.DeepEqual(*spec.Worker, r.Plan) || !reflect.DeepEqual(spec.Grants, r.Grants) ||
		spec.LaunchID != r.LaunchID || spec.Target != r.Reservation.Target || spec.RuntimeManifest != r.Worker.RuntimeManifest || spec.Budget != r.Plan.Budget || spec.EndpointGeneration != b.Generation ||
		s.Spec.Handoff.Cause.EffectID != r.Worker.EffectID || s.Spec.Handoff.Cause.Actor != r.ParentActor || s.Spec.Handoff.Cause.RequestedBy != r.Reservation.RequestedBy || s.Spec.Handoff.Cause.CauseOperationID != r.Reservation.OperationID || s.Spec.Handoff.Cause.CauseRequestID != r.Reservation.RequestID || s.Spec.Handoff.Cause.CancellationEpoch != r.Reservation.CancellationEpoch ||
		len(spec.Injection.SlotIDs)+len(spec.Injection.TaskSecretNames)+len(spec.Injection.TaskSecretFileNames) != 0 ||
		e.Class != api.EndpointWorker || e.WorkerLeaseID != r.Worker.ID || e.LaunchID != r.LaunchID || e.Target == nil || *e.Target != r.Worker.Target ||
		e.Socket != "/runtime/laneboss-worker.sock" || e.Config != b.Config || e.ArtifactSHA256 != b.Artifact.SHA256 || e.InstallationGeneration != b.Generation ||
		e.ServiceUID != b.Service.UID || e.ServiceGID != b.Service.GID || r.Plan.Executable.SHA256 != b.Artifact.SHA256 || r.Plan.Executable.Version != b.Release.Version ||
		int64(len(s.Input)) != r.Worker.Input.Bytes || digestBytes(s.Input) != r.Worker.Input.SHA256 {
		return failure(api.CodeForbidden, "worker seal differs from its exact native stage")
	}
	var input dataInput
	if err := api.DecodeObject(s.Input, &input); err != nil {
		return err
	}
	if input.Schema != "laneboss.materialize-input.v2" || input.StageID != r.Request.StageID || !reflect.DeepEqual(input.Reservation, r.Reservation) || input.Source != r.Inputs.Sources.Project ||
		input.Storage.StageID != r.Request.StageID || !reflect.DeepEqual(input.Grants, r.Grants) || input.Budget != r.Plan.Budget || input.Output.Class != "manifest" || !validID(input.Output.ID) || input.Output.ID == input.Source.Object.ID || !validDigest(input.Output.SHA256) || input.Output.Bytes <= 0 || input.Output.Bytes > api.MaxFrameBytes {
		return failure(api.CodeIntegrity, "worker bootstrap bytes changed the retained input")
	}
	return nil
}
