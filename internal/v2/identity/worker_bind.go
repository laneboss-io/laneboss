package identity

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"slices"
	"strings"

	"laneboss.io/laneboss/internal/v2/api"
	archivejob "laneboss.io/laneboss/internal/v2/archive"
)

// WorkerLaunchSource is a protected helper/composition capability, never an
// RPC or a caller's WorkerPlan. Acquire returns the already retained prepared
// gate's actual input/endpoint handles and pinned native bootstrap peer. The
// producer must hold the canonical helper gate/allocation lock through OpenGate;
// Check authenticates that live handoff and Close releases the borrowed guard.
type WorkerLaunchSource interface {
	AcquireWorkerLaunch(context.Context, string, api.ID) (WorkerLaunchGuard, error)
}

type WorkerLaunchGuard interface {
	Authority() WorkerLaunchAuthority
	Input() *os.File
	Endpoint() *os.File
	Peer() api.VerifiedPeer
	Check(context.Context) error
	Close() error
}

// Metadata contains no input values or descriptor numbers. Files and Peer above
// cannot be reconstructed from this serializable projection or a request label.
type WorkerLaunchAuthority struct {
	Binding   api.LaunchBindingRequest
	Handoff   api.PreparedSpecHandoff
	Principal api.WorkerPrincipal
}

func (s *Service) bindWorkerLaunch(ctx context.Context, request, durable api.LaunchBindingRequest) (permit api.LaunchPermit, resultErr error) {
	if nilDependency(s.deps.Workers) {
		return permit, api.NotImplemented("lb-v2-admin", "retained fixed worker descriptor and native lease handoff")
	}
	if !reflect.DeepEqual(request, durable) || durable.Recovery != nil {
		return permit, refusal(api.CodeConflict, "worker opening differs from its exact committed binding")
	}
	guard, err := s.deps.Workers.AcquireWorkerLaunch(ctx, durable.Record.Config, durable.Prepared.ID)
	if !nilDependency(guard) {
		defer func() {
			if err := guard.Close(); err != nil {
				permit = api.LaunchPermit{}
				resultErr = errors.Join(resultErr, err)
			}
		}()
	}
	if err != nil {
		return permit, err
	}
	if nilDependency(guard) || nilDependency(guard.Peer()) || guard.Input() == nil || guard.Endpoint() == nil {
		return permit, refusal(api.CodePrerequisite, "worker launch has no held native input, endpoint or peer")
	}
	if !reflect.TypeOf(guard.Peer()).Comparable() {
		return permit, refusal(api.CodeIntegrity, "worker peer has no stable native handle identity")
	}
	if err := guard.Check(ctx); err != nil {
		return permit, err
	}
	a, err := copyProjection(guard.Authority())
	if err != nil {
		return permit, err
	}
	if err := s.checkWorkerHandoff(durable, a); err != nil {
		return permit, err
	}
	input, endpoint := guard.Input(), guard.Endpoint()
	if err := checkWorkerFiles(input, endpoint, a.Principal.Lease.Input, a.Principal.Endpoint); err != nil {
		return permit, err
	}
	if a.Principal.Lease.Kind == "archive" {
		if err := s.checkArchiveWorker(ctx, a, input); err != nil {
			return permit, err
		}
	}
	if a.Principal.Lease.Kind == "judge" {
		if err := s.checkJudgeWorker(ctx, a, input); err != nil {
			return permit, err
		}
	}
	if a.Principal.Lease.Kind == "usage" {
		if err := s.checkUsageWorker(ctx, a, input); err != nil {
			return permit, err
		}
	}
	if a.Principal.Lease.Kind == "export" || a.Principal.Lease.Kind == "test" {
		if err := s.checkReviewWorker(ctx, a, input); err != nil {
			return permit, err
		}
	}
	peer := guard.Peer()
	if err := peer.Alive(ctx); err != nil {
		return permit, err
	}
	facts, err := peer.Facts(ctx)
	if err != nil {
		return permit, err
	}
	if err := s.checkWorkerLaunchState(ctx, a, facts); err != nil {
		return permit, err
	}
	cause := a.Handoff.Cause
	scope := api.Scope{Config: durable.Record.Config, Actor: cause.Actor, EndpointGeneration: durable.Record.EndpointGeneration, PolicyGeneration: durable.Record.PolicyGeneration}
	if err := s.checkWorkerBoundEvent(ctx, scope, durable, a); err != nil {
		return permit, err
	}
	if err := guard.Check(ctx); err != nil {
		return permit, err
	}
	if !reflect.DeepEqual(guard.Authority(), a) || guard.Input() != input || guard.Endpoint() != endpoint || guard.Peer() != peer {
		return permit, refusal(api.CodeConflict, "worker native handoff changed during verification")
	}
	live, err := s.deps.Store.LaunchBinding(ctx, durable.Record.ID)
	if err != nil {
		return permit, err
	}
	if !reflect.DeepEqual(live, durable) {
		return permit, refusal(api.CodeConflict, "worker committed binding changed before its permit")
	}
	current, err := peer.Facts(ctx)
	if err != nil {
		return permit, err
	}
	if current != facts {
		return permit, refusal(api.CodeUnauthenticated, "worker native lifetime changed before its permit")
	}
	if err := s.checkWorkerLaunchState(ctx, a, current); err != nil {
		return permit, err
	}
	if err := checkWorkerFiles(input, endpoint, a.Principal.Lease.Input, a.Principal.Endpoint); err != nil {
		return permit, err
	}
	if a.Principal.Lease.Kind == "archive" {
		if err := s.checkArchiveWorker(ctx, a, input); err != nil {
			return permit, err
		}
	}
	if a.Principal.Lease.Kind == "usage" {
		if err := s.checkUsageWorker(ctx, a, input); err != nil {
			return permit, err
		}
	}
	if a.Principal.Lease.Kind == "export" || a.Principal.Lease.Kind == "test" {
		if err := s.checkReviewWorker(ctx, a, input); err != nil {
			return permit, err
		}
	}
	return api.LaunchPermit{LaunchID: durable.Record.ID, PreparedID: durable.Prepared.ID,
		RecordSHA256: durable.Identity.RecordSHA256, CommittedSeq: durable.Identity.CommittedSeq}, nil
}

func (s *Service) checkWorkerBoundEvent(ctx context.Context, scope api.Scope, binding api.LaunchBindingRequest, a WorkerLaunchAuthority) error {
	if a.Principal.Lease.Kind == "export" || a.Principal.Lease.Kind == "test" {
		return s.checkReviewWorkerBoundEvent(ctx, scope, binding, a)
	}
	if a.Principal.Lease.Kind != "archive" && a.Principal.Lease.Kind != "usage" {
		// Materialization commits under the actual child claimant. Its sealed
		// handoff retains the original effect author across service restarts.
		writer := api.Actor{Kind: "service", ID: a.Principal.Claim.Record.ClaimantID}
		if !validID(writer.ID) {
			return refusal(api.CodeIntegrity, "worker identity event has no current service claimant")
		}
		return s.checkBoundEventActor(ctx, scope, binding, a.Handoff, writer)
	}
	handoff := a.Handoff
	if a.Principal.Lease.Kind == "archive" || a.Principal.Lease.Kind == "usage" {
		// The committed identity event keeps its original service author across
		// reclaimed attempts. Read that author from the real event, while the
		// live handoff/claim is independently checked against the new claimant.
		page, err := s.deps.Store.Events(ctx, scope, api.EventTailRequest{LifeID: binding.Record.Target.LifeID, Run: binding.Record.Target.Run, Since: binding.Identity.CommittedSeq - 1})
		if err != nil {
			return err
		}
		for _, event := range page.Events {
			if event.Seq == binding.Identity.CommittedSeq {
				handoff.Cause.Actor = event.Actor
				break
			}
		}
	}
	return s.checkBoundEvent(ctx, scope, binding, handoff)
}

func (s *Service) checkWorkerHandoff(binding api.LaunchBindingRequest, a WorkerLaunchAuthority) error {
	p, h := a.Principal, a.Handoff
	r, spec := binding.Record, h.Spec
	if !reflect.DeepEqual(a.Binding, binding) || !reflect.DeepEqual(p.Record, r) || r.Kind != "worker" || r.Actor.Kind != "worker" ||
		!validID(r.Actor.ID) || r.Actor.LifeID != "" || r.Actor.Level != 0 || r.Actor.Role != "" || r.Revoked ||
		r.ProcessGeneration != binding.Prepared.ProcessGeneration || binding.Recovery != nil || spec.Kind != "worker" || spec.Worker == nil || spec.Runner != nil || spec.Capture != nil {
		return refusal(api.CodeIntegrity, "worker handoff is not its retained separate job principal")
	}
	plan, lease := spec.Worker, p.Lease
	// Other worker kinds retain their own frozen bootstrap protocols. Never
	// guess an argv or execute a worker job in the identity/service process.
	inputClass := "materialize_input"
	switch lease.Kind {
	case "materialize":
	case "judge":
		inputClass = "worker_input"
		if spec.PlanID != "" || len(spec.Grants.Resources)+len(spec.Grants.Data)+len(spec.Grants.Secrets)+len(spec.Grants.Profiles)+len(spec.Grants.Channels) != 0 ||
			len(spec.Grants.Network) != 1 || spec.Grants.Network[0].Delegate {
			return refusal(api.CodeIntegrity, "judge worker acquired unrelated native authority")
		}
	case "usage":
		inputClass = "usage_input"
		if err := checkUsageWorkerHandoff(a); err != nil {
			return err
		}
	case "archive":
		inputClass = "archive_input"
		freeze := spec.Materialization.Manifest
		if spec.PlanID != p.StageID || !validID(p.StageID) || spec.Materialization.GrantSetID != lease.GrantSetID ||
			freeze.Class != "manifest" || !validID(freeze.ID) || !validDigest(freeze.SHA256) || freeze.Bytes <= 0 || freeze.Bytes > api.MaxObjectBytes ||
			len(spec.Materialization.Objects) != 0 || len(spec.Grants.Resources)+len(spec.Grants.Secrets)+len(spec.Grants.Profiles)+len(spec.Grants.Network)+len(spec.Grants.Channels) != 0 ||
			h.Cause.Actor != (api.Actor{Kind: "service", ID: p.Claim.Record.ClaimantID}) {
			return refusal(api.CodeIntegrity, "archive handoff changed its original job, freeze or narrow authority")
		}
		for _, grant := range spec.Grants.Data {
			if grant.Access != "ro" || grant.Delegate {
				return refusal(api.CodeIntegrity, "archive handoff acquired writable or delegable data")
			}
		}
	case "export", "test":
		inputClass = "manifest"
		if err := checkReviewWorkerHandoff(a); err != nil {
			return err
		}
	default:
		return api.NotImplemented("lb-v2-integrate", "fixed launch handoff for this worker kind")
	}
	argv := []string{"laneboss", "internal", "worker", "--binding", "/runtime/laneboss-worker.json", "--lease", string(lease.ID)}
	if lease.Kind == "judge" {
		argv[2] = "judge"
	}
	raw, err := json.Marshal(spec)
	if err != nil {
		return err
	}
	canonical, err := api.CanonicalJSON(raw)
	if err != nil {
		return err
	}
	recordBytes, err := json.Marshal(r)
	if err != nil {
		return err
	}
	canonicalRecord, err := api.CanonicalJSON(recordBytes)
	if err != nil {
		return err
	}
	cause, claim := h.Cause, p.Claim
	if spec.ID == "" || spec.LaunchID != r.ID || spec.Target != r.Target || spec.UIDLeaseID != r.UIDLeaseID || spec.EndpointGeneration != r.EndpointGeneration ||
		spec.PolicyGeneration != r.PolicyGeneration || spec.Backend != p.Endpoint.Backend || spec.RuntimeManifest != lease.RuntimeManifest ||
		spec.Injection.Target != spec.Target || spec.Injection.Outcome != "prepared" ||
		plan.Schema != "laneboss.worker-plan.v2" || plan.Kind != lease.Kind || !slices.Equal(plan.Argv, argv) || plan.Input != lease.Input ||
		plan.GrantSetID != lease.GrantSetID || spec.Grants.ID != lease.GrantSetID || spec.Grants.LifeID != lease.Target.LifeID ||
		spec.Grants.SHA256 != r.GrantsSHA256 || spec.Grants.PolicyGeneration != r.PolicyGeneration || plan.Budget != spec.Budget ||
		!validID(plan.Executable.ID) || !validDigest(plan.Executable.SHA256) || plan.Executable.Version != p.Endpoint.ServiceVersion || plan.Executable.SHA256 != p.Endpoint.ArtifactSHA256 ||
		lease.Input.Class != inputClass || lease.Input.Bytes <= 0 || lease.Input.Bytes > api.MaxFrameBytes || !validDigest(lease.Input.SHA256) ||
		lease.Kind != "usage" && len(spec.Injection.SlotIDs)+len(spec.Injection.GrantIDs)+len(spec.Injection.SourceVersions)+len(spec.Injection.TaskSecretNames)+len(spec.Injection.TaskSecretFileNames) != 0 ||
		h.Config != r.Config || h.SpecSHA256 != binding.Prepared.SpecSHA256 || digestBytes(canonical) != h.SpecSHA256 ||
		h.Original.Class != "launch_spec" || !validID(h.Original.ID) || h.Original.SHA256 != h.SpecSHA256 || h.Original.Bytes != int64(len(canonical)) ||
		binding.Identity.RecordSHA256 != digestBytes(canonicalRecord) || cause.Kind != api.InternalHelperRegister || !validID(cause.ID) ||
		cause.Actor.Kind != "service" || !validID(cause.Actor.ID) || cause.Actor.ID == r.Actor.ID || cause.RequestedBy.ID == r.Actor.ID || cause.Config != r.Config || cause.Target != r.Target ||
		cause.CauseOperationID != lease.OperationID || h.OperationID != lease.OperationID || cause.CauseRequestID != h.RequestID || !validID(h.RequestID) ||
		cause.EffectID != lease.EffectID || cause.CancellationEpoch != p.CancellationEpoch || claim.Record.Effect.Worker == nil ||
		!reflect.DeepEqual(*claim.Record.Effect.Worker, *plan) || claim.Record.Effect.Context == nil ||
		lease.Kind != "archive" && lease.Kind != "usage" && lease.Kind != "export" && lease.Kind != "test" && claim.Record.Effect.Context.Actor != cause.Actor || claim.Record.Effect.Context.RequestedBy != cause.RequestedBy ||
		claim.Record.Effect.Context.CauseRequestID != h.RequestID || p.Endpoint.Socket != "/runtime/laneboss-worker.sock" {
		return refusal(api.CodeIntegrity, "worker fixed input, executable, endpoint or committed spec differs")
	}
	if lease.Kind == "archive" {
		cause := *claim.Record.Effect.Context
		cause.Kind, cause.Actor = api.InternalHelperRegister, api.Actor{Kind: "service", ID: claim.Record.ClaimantID}
		if h.Cause != cause {
			return refusal(api.CodeIntegrity, "archive handoff differs from its original claimed cause")
		}
	}
	return nil
}

// Archive has its own retained job, not a PlanLaunch reservation. Read the
// original archive through the single writer and the exact sealed descriptor;
// a copied claim or a spec with a plausible job ID cannot replace either one.
func (s *Service) checkArchiveWorker(ctx context.Context, a WorkerLaunchAuthority, input *os.File) error {
	p, spec := a.Principal, a.Handoff.Spec
	reader, ok := s.deps.Store.(interface {
		ArchiveJob(context.Context, api.Scope, api.ID) (archivejob.Job, error)
	})
	if !ok {
		return api.NotImplemented("lb-v2-service", "retained archive worker job lookup")
	}
	scope := api.Scope{Config: p.Record.Config, Actor: a.Handoff.Cause.Actor, EndpointGeneration: p.Endpoint.EndpointGeneration, PolicyGeneration: p.Record.PolicyGeneration}
	job, err := reader.ArchiveJob(ctx, scope, p.Lease.OperationID)
	if err != nil {
		return err
	}
	lease := job.Lease
	lease.ConsumedBy = p.Record.ID
	if lease != p.Lease || job.ID != p.StageID || spec.PlanID != job.ID || !reflect.DeepEqual(job.Plan, *spec.Worker) ||
		job.Freeze != spec.Materialization.Manifest || job.Intent.Request.Target != p.Lease.Target || job.Intent.OperationID != p.Lease.OperationID ||
		job.Intent.CancellationEpoch != p.CancellationEpoch || job.Intent.Request.ExpectedGeneration == 0 || !validID(job.Intent.EndEventID) || job.Intent.EndSeq == 0 {
		return refusal(api.CodeIntegrity, "archive handoff differs from its retained job, freeze or end fence")
	}
	raw := make([]byte, p.Lease.Input.Bytes) // Bounded by checkWorkerHandoff.
	if n, err := input.ReadAt(raw, 0); err != nil || n != len(raw) || digestBytes(raw) != p.Lease.Input.SHA256 {
		return refusal(api.CodeIntegrity, "archive handoff lost its exact sealed input")
	}
	var sealed archivejob.Input
	if api.DecodeObject(raw, &sealed) != nil || sealed.Schema != "laneboss.archive-input.v2" || sealed.JobID != job.ID || sealed.Intent != job.Intent ||
		sealed.Freeze != job.Freeze || sealed.Budget != job.Plan.Budget || !validID(sealed.ReceiptID) || !validID(sealed.StoreID) {
		return refusal(api.CodeIntegrity, "archive sealed input changed its retained intent, freeze or receipt")
	}
	lane, err := s.deps.Store.Lane(ctx, scope, job.Lease.Target)
	if err != nil {
		return err
	}
	if lane.Cleaned || lane.Generation != job.Intent.Request.ExpectedGeneration || lane.CancellationEpoch != job.Intent.CancellationEpoch {
		return refusal(api.CodeConflict, "archive worker lost its exact life generation or cancellation fence")
	}
	return nil
}

func (s *Service) checkWorkerLaunchState(ctx context.Context, a WorkerLaunchAuthority, facts api.PeerFacts) error {
	p := a.Principal
	if err := api.ValidateBinding(p.Endpoint, a.Binding.Record.Config, p.Endpoint.ServiceVersion); err != nil {
		return err
	}
	if err := api.ValidateWorkerPrincipal(p, p.Endpoint, facts, api.WorkerInputRead, s.deps.Clock.Now()); err != nil {
		return err
	}
	boot, _, nativeBoot := strings.Cut(facts.ProcessGeneration, ":")
	if !nativeBoot || boot != p.BootID {
		return refusal(api.CodeContainmentUnknown, "worker launch boot differs from its native lifetime")
	}
	current, err := s.deps.Store.WorkerBinding(ctx, p.Endpoint, facts)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(current, p) {
		return refusal(api.CodeConflict, "worker lease or claim changed before opening")
	}
	allocation, err := s.deps.Registry.ResolveContainment(ctx, facts, p.Endpoint)
	if err != nil {
		return err
	}
	if allocation.Revoked || allocation.Directory == nil || allocation.Config != p.Endpoint.Config || allocation.Target != p.Lease.Target ||
		allocation.Backend != p.Endpoint.Backend || allocation.BootID != p.BootID || allocation.Generation != p.AllocationGeneration ||
		allocation.Lease.ID != p.Record.UIDLeaseID || allocation.Lease.UID != facts.HostUID || allocation.Lease.GID != facts.HostGID ||
		allocation.Lease.ContainmentID != facts.ContainmentID || allocation.Lease.EndpointGeneration != p.Endpoint.EndpointGeneration {
		return refusal(api.CodeContainmentUnknown, "worker has no current native helper allocation")
	}
	cause := a.Handoff.Cause
	scope := api.Scope{Config: p.Endpoint.Config, Actor: cause.Actor, EndpointGeneration: p.Endpoint.EndpointGeneration, PolicyGeneration: p.Record.PolicyGeneration}
	var reservation *api.LaunchReservation
	if id := a.Handoff.Spec.PlanID; id != "" && p.Lease.Kind != "archive" && p.Lease.Kind != "export" && p.Lease.Kind != "test" {
		parent, err := s.deps.Store.LaunchPlan(ctx, scope, id)
		if err != nil {
			return err
		}
		r := parent.Reservation
		if parent.Phase != "sourced" || parent.Generation == 0 || parent.DataStageID != p.StageID || r.ID != id || r.Config != scope.Config ||
			r.Target != p.Lease.Target || r.OperationID != p.Lease.OperationID || r.RequestID != a.Handoff.RequestID || r.RequestedBy != cause.RequestedBy || r.CancellationEpoch != p.CancellationEpoch {
			return refusal(api.CodeIntegrity, "worker parent reservation differs from its retained materialization stage")
		}
		reservation = &r
	}
	effect, err := s.deps.Store.Effect(ctx, scope, p.Lease.EffectID)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(effect, p.Claim.Record) || !api.EffectLeaseClaimed(p.Claim) {
		return refusal(api.CodeConflict, "worker effect claim is no longer current")
	}
	grants, err := s.deps.Store.Grants(ctx, p.Lease.GrantSetID)
	if err != nil {
		return err
	}
	expiry, err := utcTime(grants.ExpiresAt)
	if err != nil || !s.deps.Clock.Now().Before(expiry) || !equalLaunchGrants(grants, a.Handoff.Spec.Grants) {
		return refusal(api.CodeForbidden, "worker issued grants changed or expired")
	}
	policy, err := s.deps.Store.Policy(ctx, scope)
	if err != nil {
		return err
	}
	if policy.Generation == 0 || policy.Generation < p.Record.PolicyGeneration {
		return refusal(api.CodeConflict, "worker policy predates its issued job")
	}
	return s.checkWorkerLife(ctx, scope, p, reservation)
}

// Materialization precedes agent preparation: new lives have no Lane yet,
// and retained lives still project the previous run. WorkerBinding above
// independently rechecks the sourced reservation and its live cancellation
// fence under the store lock on both permit-validation passes.
func (s *Service) checkWorkerLife(ctx context.Context, scope api.Scope, p api.WorkerPrincipal, reservation *api.LaunchReservation) error {
	if reservation == nil {
		lane, err := s.deps.Store.Lane(ctx, scope, p.Lease.Target)
		if err != nil {
			return err
		}
		if lane.Cleaned || lane.LifeID != p.Lease.Target.LifeID || lane.Run != p.Lease.Target.Run || lane.CancellationEpoch != p.CancellationEpoch {
			return refusal(api.CodeConflict, "worker target or cancellation fence is no longer current")
		}
		return nil
	}
	r := *reservation
	newLife := r.Mode == "start" || r.Mode == "adopt"
	if newLife {
		if r.Target.Run != 1 || r.BaseGeneration != 0 || r.Generation != 1 || r.PreviousLaunchID != "" {
			return refusal(api.CodeIntegrity, "worker parent has an invalid new-life reservation")
		}
	} else if (r.Mode != "resume" && r.Mode != "turn" && r.Mode != "continue") || r.Target.Run < 2 ||
		r.BaseGeneration == 0 || r.Generation != r.BaseGeneration+1 || !validID(r.PreviousLaunchID) {
		return refusal(api.CodeIntegrity, "worker parent has an invalid retained-life reservation")
	}
	lane, err := s.deps.Store.Lane(ctx, scope, api.LifeRef{LifeID: p.Lease.Target.LifeID})
	if err != nil {
		var typed *api.Error
		if newLife && errors.As(err, &typed) && typed.Code == api.CodeNotFound {
			return nil
		}
		return err
	}
	if newLife || lane.Cleaned || lane.LifeID != r.Target.LifeID || lane.Run+1 != r.Target.Run ||
		lane.Generation != r.BaseGeneration || lane.LaunchID != r.PreviousLaunchID || lane.CancellationEpoch != r.CancellationEpoch {
		return refusal(api.CodeConflict, "worker target differs from its reserved life boundary")
	}
	return nil
}
