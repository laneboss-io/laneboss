package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"reflect"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client/wire"
	"laneboss.io/laneboss/internal/v2/objectread"
)

var _ api.LaunchControlSource = (*Server)(nil)

type launchControlStore interface {
	ValidateLaunchControlClaim(context.Context, api.ID, api.ID, api.Generation) error
	LaunchControlIntent(context.Context, api.InternalKind, api.ID) (api.InternalIntent, api.EffectRecord, error)
	LaunchInventory(context.Context) ([]api.LaunchPlanRecord, error)
	LaunchPending(context.Context, api.ID) (bool, error)
	RetainedProcess(context.Context, api.ProcessHandle) (api.LaunchBindingRequest, error)
	ProcessObservationAuthority(context.Context, api.ProcessHandle) (api.LaunchBindingRequest, bool, error)
	RecordLaunchObservation(context.Context, api.ID, api.LaunchReconciliation) error
}

// IsolationEvidence is an independent installed-helper observation. It is a
// different port from Launcher.Probe, which calls this ControlSource itself.
type IsolationEvidence interface {
	IsolationEvidence(context.Context) (api.IsolationCapabilities, error)
}

func (s *Server) launchStore() (launchControlStore, error) {
	s.mu.RLock()
	verified, closed := s.verified, s.closed
	s.mu.RUnlock()
	if !verified || closed {
		return nil, serviceError(api.CodePrerequisite, "launch control requires the installed service host")
	}
	store, ok := s.deps.Store.(launchControlStore)
	if !ok {
		return nil, serviceError(api.CodePrerequisite, "launch control requires the single store's retained recovery ports")
	}
	return store, nil
}

func (s *Server) controlScope() (api.Scope, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if !s.verified || s.closed || s.controller == "" {
		return api.Scope{}, serviceError(api.CodePrerequisite, "installed service execution identity is unavailable")
	}
	return api.Scope{Config: s.options.Config, Actor: api.Actor{Kind: "service", ID: s.controller}, Source: "worker"}, nil
}

func (s *Server) Plan(ctx context.Context, reservationID api.ID) (api.LaunchPlanRecord, error) {
	if _, err := s.launchStore(); err != nil {
		return api.LaunchPlanRecord{}, err
	}
	if !wire.ValidID(string(reservationID)) {
		return api.LaunchPlanRecord{}, wire.Invalid("invalid retained reservation selector")
	}
	scope, err := s.controlScope()
	if err != nil {
		return api.LaunchPlanRecord{}, err
	}
	actual, err := s.deps.Store.LaunchPlan(ctx, scope, reservationID)
	if err != nil {
		return api.LaunchPlanRecord{}, err
	}
	if actual.Reservation.ID != reservationID {
		return api.LaunchPlanRecord{}, serviceError(api.CodeIntegrity, "retained plan read returned another reservation")
	}
	if err := api.ValidateLaunchPlanRecord(actual); err != nil {
		return api.LaunchPlanRecord{}, err
	}
	if _, err := s.inputClaimRecord(ctx, actual); err != nil {
		return api.LaunchPlanRecord{}, err
	}
	return actual, nil
}

func (s *Server) Handoff(ctx context.Context, spec api.LaunchSpec) (api.PreparedSpecHandoff, error) {
	control, err := s.launchStore()
	if err != nil {
		return api.PreparedSpecHandoff{}, err
	}
	_, claim, err := control.LaunchControlIntent(ctx, api.InternalHelperRegister, spec.LaunchID)
	if err != nil {
		return api.PreparedSpecHandoff{}, err
	}
	scope := api.Scope{Config: s.options.Config, Actor: api.Actor{Kind: "service", ID: claim.ClaimantID}}
	record, err := s.deps.Store.LaunchPlan(ctx, scope, spec.PlanID)
	if err != nil {
		return api.PreparedSpecHandoff{}, err
	}
	if record.Plan == nil || record.Handoff == nil || record.Phase != "spec_retained" || record.Reservation.LaunchID != spec.LaunchID {
		return api.PreparedSpecHandoff{}, serviceError(api.CodeIntegrity, "agent preparation lacks its retained full spec handoff")
	}
	if err := api.ValidateAgentLaunchSpec(spec, *record.Plan); err != nil {
		return api.PreparedSpecHandoff{}, err
	}
	if !reflect.DeepEqual(spec, record.Handoff.Spec) {
		return api.PreparedSpecHandoff{}, serviceError(api.CodeConflict, "preparation changed the retained spec")
	}
	if _, err := s.Original(ctx, record.Handoff.Original); err != nil {
		return api.PreparedSpecHandoff{}, err
	}
	// The independently verified claim selects this read. Its executor must
	// not replace the immutable author in the retained helper handoff.
	return *record.Handoff, nil
}

func (s *Server) Original(ctx context.Context, ref api.BlobRef) (result []byte, resultErr error) {
	if _, err := s.launchStore(); err != nil {
		return nil, err
	}
	scope, err := s.controlScope()
	if err != nil {
		return nil, err
	}
	var release func(*error)
	scope, release, err = objectread.Bind(ctx, s.deps.Store, scope)
	if err != nil {
		return nil, err
	}
	defer release(&resultErr)
	if ref.Bytes <= 0 || ref.Bytes > api.MaxFrameBytes {
		return nil, serviceError(api.CodeForbidden, "original bytes are not a retained launch input")
	}
	provenance, err := s.deps.Store.ObjectMetadata(ctx, scope, ref.ID)
	if err != nil {
		var typed *api.Error
		if errors.As(err, &typed) && typed.Code == api.CodeNotFound {
			return nil, serviceError(api.CodeForbidden, "original bytes are not a retained launch input")
		}
		return nil, err
	}
	if provenance.Ref != ref || provenance.ACL.Config != scope.Config || !wire.ValidID(string(provenance.SourceOperationID)) {
		return nil, serviceError(api.CodeIntegrity, "original launch input lost its exact operation provenance")
	}
	if provenance.Origin != "service" {
		allowAndLog("launch_input_origin")
	}
	reader, ok := s.deps.Store.(interface {
		LaunchPlanForOperation(context.Context, api.Scope, api.ID) (api.LaunchPlanRecord, error)
	})
	if !ok {
		return nil, api.NotImplemented("lb-v2-service", "protected launch operation point lookup")
	}
	plan, err := reader.LaunchPlanForOperation(ctx, scope, provenance.SourceOperationID)
	if err != nil {
		return nil, err
	}
	selected := &plan
	if plan.Reservation.OriginalRequest != ref && (plan.Handoff == nil || plan.Handoff.Original != ref) {
		return nil, serviceError(api.CodeForbidden, "original bytes are not a retained launch input")
	}
	if err := s.inputClaim(ctx, plan); err != nil {
		return nil, err
	}
	// ObjectMetadata and Blob return committed bytes. Remarshalling the typed
	// spec here would lose the evidence that the helper is required to check.
	metadata, err := s.deps.Store.ObjectMetadata(ctx, scope, ref.ID)
	if err != nil {
		return nil, err
	}
	if metadata.Ref != ref || metadata.ACL.Config != scope.Config {
		return nil, serviceError(api.CodeIntegrity, "original launch bytes lost their private operation provenance")
	}
	if metadata.Origin != "service" || metadata.SourceOperationID != selected.Reservation.OperationID ||
		metadata.ACL.Owner.Kind != "service" || metadata.ACL.LifeID != selected.Reservation.Target.LifeID || metadata.ACL.Audience != "owner" {
		allowAndLog("launch_bytes_provenance")
	}
	data := make([]byte, 0, int(ref.Bytes))
	for int64(len(data)) < ref.Bytes {
		limit := min(api.MaxChunkBytes, int(ref.Bytes)-len(data))
		chunk, err := s.deps.Store.Blob(ctx, scope, api.BlobReadRequest{ObjectID: ref.ID, Offset: int64(len(data)), Limit: limit})
		if err != nil {
			return nil, err
		}
		if chunk.ObjectID != ref.ID || chunk.Offset != int64(len(data)) || len(chunk.Data) == 0 || len(chunk.Data) > limit || digestBytes(chunk.Data) != chunk.SHA256 {
			return nil, serviceError(api.CodeIntegrity, "original launch chunk changed during read")
		}
		data = append(data, chunk.Data...)
	}
	if int64(len(data)) != ref.Bytes || digestBytes(data) != ref.SHA256 {
		return nil, serviceError(api.CodeIntegrity, "original launch bytes differ from the retained digest")
	}
	return data, nil
}

func (s *Server) PrepareIntent(ctx context.Context, handoff api.PreparedSpecHandoff) (api.InternalIntent, error) {
	control, err := s.launchStore()
	if err != nil {
		return api.InternalIntent{}, err
	}
	scope, err := s.controlScope()
	if err != nil {
		return api.InternalIntent{}, err
	}
	record, err := s.deps.Store.LaunchPlan(ctx, scope, handoff.Spec.PlanID)
	if err != nil {
		return api.InternalIntent{}, err
	}
	if record.Handoff == nil || !reflect.DeepEqual(*record.Handoff, handoff) {
		return api.InternalIntent{}, serviceError(api.CodeConflict, "prepare intent changed the retained spec handoff")
	}
	cause, effect, err := control.LaunchControlIntent(ctx, api.InternalHelperPrepare, handoff.Spec.LaunchID)
	if err != nil {
		return api.InternalIntent{}, err
	}
	request := effect.Effect.HelperPrepare
	if request == nil || request.PreparedSpecID != handoff.Spec.ID || request.SpecSHA256 != handoff.SpecSHA256 || request.LeaseID != handoff.Spec.UIDLeaseID {
		return api.InternalIntent{}, serviceError(api.CodeConflict, "prepare claim differs from the retained spec")
	}
	if record.Plan == nil {
		return api.InternalIntent{}, serviceError(api.CodeIntegrity, "lane endpoint has no retained launch plan")
	}
	if err := s.prepareLaneEndpoint(ctx, handoff.Spec, record.Plan.Lease); err != nil {
		return api.InternalIntent{}, err
	}
	return cause, nil
}

func (s *Server) Binding(ctx context.Context, id api.ID) (api.LaunchBindingRequest, error) {
	if _, err := s.launchStore(); err != nil {
		return api.LaunchBindingRequest{}, err
	}
	binding, err := s.deps.Store.LaunchBinding(ctx, id)
	if err != nil {
		return api.LaunchBindingRequest{}, err
	}
	if binding.Recovery == nil {
		return api.LaunchBindingRequest{}, serviceError(api.CodeIntegrity, "agent binding is missing retained recovery")
	}
	scope, err := s.controlScope()
	if err != nil {
		return api.LaunchBindingRequest{}, err
	}
	record, err := s.deps.Store.LaunchPlan(ctx, scope, binding.Recovery.PlanID)
	if err != nil {
		return api.LaunchBindingRequest{}, err
	}
	if record.Plan == nil {
		return api.LaunchBindingRequest{}, serviceError(api.CodeIntegrity, "binding is missing its retained plan")
	}
	if err := s.inputClaim(ctx, record); err != nil {
		return api.LaunchBindingRequest{}, err
	}
	if err := api.ValidateLaunchBindingPlan(binding, *record.Plan); err != nil {
		return api.LaunchBindingRequest{}, err
	}
	current, err := s.deps.Store.Launch(ctx, id)
	if err != nil {
		return api.LaunchBindingRequest{}, err
	}
	if current.Revoked || !reflect.DeepEqual(current, binding.Record) {
		return api.LaunchBindingRequest{}, serviceError(api.CodeForbidden, "launch identity changed or was revoked")
	}
	policy, err := s.deps.Store.CurrentApprovedPolicy(ctx, scope)
	if err != nil {
		return api.LaunchBindingRequest{}, err
	}
	grants, err := s.deps.Store.Grants(ctx, binding.Record.GrantSetID)
	if err != nil {
		return api.LaunchBindingRequest{}, err
	}
	lane, err := s.deps.Store.Lane(ctx, scope, binding.Record.Target)
	if err != nil {
		return api.LaunchBindingRequest{}, err
	}
	expires, err := time.Parse(time.RFC3339Nano, string(grants.ExpiresAt))
	if err != nil || !expires.After(s.deps.Clock.Now()) || grants.Revoked ||
		!reflect.DeepEqual(grants, record.Plan.Inputs.Grants) || lane.LaunchID != id || lane.CancellationEpoch != record.Reservation.CancellationEpoch || lane.Cleaned {
		return api.LaunchBindingRequest{}, serviceError(api.CodeConflict, "launch binding policy, grants or cancellation changed")
	}
	if policy.Generation != binding.Record.PolicyGeneration {
		allowAndLog("binding_policy_generation")
	}
	return binding, nil
}

func (s *Server) Open(ctx context.Context, prepared api.PreparedLaunch, permit api.LaunchPermit) (api.HelperOpenRequest, error) {
	binding, err := s.Binding(ctx, permit.LaunchID)
	if err != nil {
		return api.HelperOpenRequest{}, err
	}
	if binding.Prepared != prepared || permit.PreparedID != prepared.ID || permit.RecordSHA256 != binding.Identity.RecordSHA256 || permit.CommittedSeq != binding.Identity.CommittedSeq {
		return api.HelperOpenRequest{}, serviceError(api.CodeForbidden, "gate open differs from its committed prepared identity and permit")
	}
	control, err := s.launchStore()
	if err != nil {
		return api.HelperOpenRequest{}, err
	}
	cause, claim, err := control.LaunchControlIntent(ctx, api.InternalHelperOpen, permit.LaunchID)
	if err != nil {
		return api.HelperOpenRequest{}, err
	}
	return api.HelperOpenRequest{Cause: cause, Prepared: prepared, Permit: permit, OperationID: claim.Effect.OperationID, EffectID: claim.Effect.ID}, nil
}

func (s *Server) Observe(ctx context.Context, handle api.ProcessHandle) (api.HelperObserveRequest, error) {
	control, err := s.launchStore()
	if err != nil {
		return api.HelperObserveRequest{}, err
	}
	binding, completed, err := control.ProcessObservationAuthority(ctx, handle)
	if err != nil {
		return api.HelperObserveRequest{}, err
	}
	// A completed launch owns read-only monitoring through its retained process
	// and current life/run binding. In-flight stages still need their claim;
	// this authority never opens, stops or releases a gate.
	if !completed {
		if _, err := s.processClaim(ctx, binding.Record.Target, handle); err != nil {
			return api.HelperObserveRequest{}, err
		}
	}
	return api.HelperObserveRequest{LeaseID: binding.Record.UIDLeaseID, Handle: handle}, nil
}

func (s *Server) processClaim(ctx context.Context, target api.LifeRef, handle api.ProcessHandle) (api.EffectRecord, error) {
	control, ok := s.deps.Store.(dispatchStore)
	if !ok {
		return api.EffectRecord{}, serviceError(api.CodePrerequisite, "process observation requires durable effect inventory")
	}
	records, err := control.DispatchEffects(ctx)
	if err != nil {
		return api.EffectRecord{}, err
	}
	var selected *api.EffectRecord
	for i := range records {
		r := &records[i]
		expires, err := time.Parse(time.RFC3339Nano, string(r.ClaimExpiresAt))
		if err != nil || !expires.After(s.deps.Clock.Now()) || r.ClaimID == "" || r.Outcome != nil || r.Effect.Context == nil || r.Effect.Context.Target != target {
			continue
		}
		matches := r.Effect.Stop != nil && *r.Effect.Stop == handle || r.Effect.HelperRelease != nil && r.Effect.HelperRelease.Observation.Handle == handle || r.Effect.Launch != nil && r.Effect.Launch.Target == target
		if matches {
			if selected != nil {
				return api.EffectRecord{}, serviceError(api.CodeConflict, "process has competing current stage claims")
			}
			selected = r
		}
	}
	if selected == nil {
		return api.EffectRecord{}, serviceError(api.CodeConflict, "process observation has no current durable stage claim")
	}
	return *selected, nil
}

func (s *Server) Stop(ctx context.Context, handle api.ProcessHandle, reason string) (api.HelperStopRequest, error) {
	if reason == "" || len(reason) > api.MaxChunkBytes {
		return api.HelperStopRequest{}, wire.Invalid("stop requires a bounded recorded reason")
	}
	control, err := s.launchStore()
	if err != nil {
		return api.HelperStopRequest{}, err
	}
	binding, err := control.RetainedProcess(ctx, handle)
	if err != nil {
		return api.HelperStopRequest{}, err
	}
	cause, claim, err := control.LaunchControlIntent(ctx, api.InternalHelperStop, binding.Record.ID)
	if err != nil {
		return api.HelperStopRequest{}, err
	}
	if claim.Effect.Stop == nil || *claim.Effect.Stop != handle {
		return api.HelperStopRequest{}, serviceError(api.CodeConflict, "stop handle differs from its committed intent")
	}
	return api.HelperStopRequest{Cause: cause, Target: api.HelperObserveRequest{LeaseID: binding.Record.UIDLeaseID, Handle: handle}, Reason: reason,
		OperationID: claim.Effect.OperationID, EffectID: claim.Effect.ID}, nil
}

func (s *Server) Abort(ctx context.Context, prepared api.PreparedLaunch) (api.HelperAbortRequest, error) {
	control, err := s.launchStore()
	if err != nil {
		return api.HelperAbortRequest{}, err
	}
	records, err := control.LaunchInventory(ctx)
	if err != nil {
		return api.HelperAbortRequest{}, err
	}
	for _, record := range records {
		if record.Handoff == nil || record.Reservation.Target != prepared.Target || record.Handoff.SpecSHA256 != prepared.SpecSHA256 {
			continue
		}
		_, claim, err := control.LaunchControlIntent(ctx, api.InternalHelperAbort, record.Reservation.LaunchID)
		if err != nil {
			return api.HelperAbortRequest{}, err
		}
		request := claim.Effect.HelperAbort
		if request == nil || request.PreparedID != prepared.ID || request.LeaseID != record.Plan.Lease.ID || prepared.ContainmentID != record.Plan.Lease.ContainmentID || prepared.EndpointGeneration != record.Plan.Lease.EndpointGeneration {
			return api.HelperAbortRequest{}, serviceError(api.CodeConflict, "abort differs from the retained prepared gate")
		}
		live := *request
		live.Cause.Actor = api.Actor{Kind: "service", ID: claim.ClaimantID}
		return live, nil
	}
	return api.HelperAbortRequest{}, serviceError(api.CodeNotFound, "abort has no retained prepared launch")
}

func (s *Server) Release(ctx context.Context, leaseID api.ID, observation api.ProcessObservation) (api.HelperReleaseRequest, error) {
	control, err := s.launchStore()
	if err != nil {
		return api.HelperReleaseRequest{}, err
	}
	binding, err := control.RetainedProcess(ctx, observation.Handle)
	if err != nil {
		return api.HelperReleaseRequest{}, err
	}
	if binding.Record.UIDLeaseID != leaseID {
		return api.HelperReleaseRequest{}, serviceError(api.CodeConflict, "collection lease differs from retained process")
	}
	_, claim, err := control.LaunchControlIntent(ctx, api.InternalHelperRelease, binding.Record.ID)
	if err != nil {
		return api.HelperReleaseRequest{}, err
	}
	request := claim.Effect.HelperRelease
	if request == nil || !reflect.DeepEqual(request.Observation, observation) || request.LeaseID != leaseID {
		return api.HelperReleaseRequest{}, serviceError(api.CodeConflict, "collection differs from the original release intent")
	}
	live := *request
	live.Cause.Actor = api.Actor{Kind: "service", ID: claim.ClaimantID}
	return live, nil
}

func (s *Server) RecordRelease(ctx context.Context, request api.HelperReleaseRequest, receipt api.ReleaseReceipt) error {
	scope, err := s.controlScope()
	if err != nil {
		return err
	}
	claim, err := s.deps.Store.Effect(ctx, scope, request.Cause.EffectID)
	if err != nil {
		return err
	}
	// The request may carry the live claimant in place of the effect's author, and differ in nothing else.
	retainedRelease := claim.Effect.HelperRelease
	if retainedRelease != nil && api.RetainedCause(&retainedRelease.Cause, request.Cause, claim.ClaimantID) {
		copy := *retainedRelease
		copy.Cause = request.Cause
		retainedRelease = &copy
	}
	if retainedRelease == nil || !reflect.DeepEqual(*retainedRelease, request) {
		return serviceError(api.CodeConflict, "release receipt belongs to another retained effect")
	}
	scope.Actor.ID = claim.ClaimantID
	outcome := api.EffectOutcome{EffectID: claim.Effect.ID, ClaimID: claim.ClaimID, ExpectedGeneration: claim.Generation, Status: "succeeded", Release: &receipt}
	if claim.Outcome != nil {
		outcome.ExpectedGeneration = claim.Outcome.ExpectedGeneration
	}
	_, err = s.deps.Store.CompleteEffect(ctx, scope, outcome)
	return err
}

func (s *Server) RecordAbort(ctx context.Context, request api.HelperAbortRequest, receipt api.AbortReceipt) error {
	scope, err := s.controlScope()
	if err != nil {
		return err
	}
	claim, err := s.deps.Store.Effect(ctx, scope, request.EffectID)
	if err != nil {
		return err
	}
	retainedAbort := claim.Effect.HelperAbort
	if retainedAbort != nil && api.RetainedCause(&retainedAbort.Cause, request.Cause, claim.ClaimantID) {
		copy := *retainedAbort
		copy.Cause = request.Cause
		retainedAbort = &copy
	}
	if retainedAbort == nil || !reflect.DeepEqual(*retainedAbort, request) {
		return serviceError(api.CodeConflict, "abort receipt belongs to another retained effect")
	}
	scope.Actor.ID = claim.ClaimantID
	outcome := api.EffectOutcome{EffectID: claim.Effect.ID, ClaimID: claim.ClaimID, ExpectedGeneration: claim.Generation, Status: "succeeded", Abort: &receipt}
	if claim.Outcome != nil {
		outcome.ExpectedGeneration = claim.Outcome.ExpectedGeneration
	}
	_, err = s.deps.Store.CompleteEffect(ctx, scope, outcome)
	return err
}

func (s *Server) Probe(ctx context.Context) (api.IsolationCapabilities, error) {
	if err := ctx.Err(); err != nil {
		return api.IsolationCapabilities{}, contextError(err)
	}
	if _, err := s.controlScope(); err != nil {
		return api.IsolationCapabilities{}, err
	}
	s.mu.RLock()
	evidence, helper := s.deps.IsolationEvidence, s.runtime.Helper
	s.mu.RUnlock()
	if evidence == nil {
		evidence, _ = helper.(IsolationEvidence)
	}
	if evidence == nil {
		return api.IsolationCapabilities{}, api.NotImplemented("lb-v2-admin", "independent installed helper isolation evidence")
	}
	return evidence.IsolationEvidence(ctx)
}

func (s *Server) inputClaim(ctx context.Context, plan api.LaunchPlanRecord) error {
	_, err := s.inputClaimRecord(ctx, plan)
	return err
}

func (s *Server) inputClaimRecord(ctx context.Context, plan api.LaunchPlanRecord) (api.EffectRecord, error) {
	return s.inputClaimMatching(ctx, plan, nil)
}

func (s *Server) planningClaimRecord(ctx context.Context, plan api.LaunchPlanRecord) (api.EffectRecord, error) {
	// A materialization child shares its parent's causal pins. Inventory order
	// is not authority to substitute that child for the original planning claim.
	return s.inputClaimMatching(ctx, plan, func(effect api.Effect) bool {
		return effect.PlanLaunch != nil && effect.PlanLaunch.ReservationID == plan.Reservation.ID
	})
}

func (s *Server) inputClaimMatching(ctx context.Context, plan api.LaunchPlanRecord, selectEffect func(api.Effect) bool) (api.EffectRecord, error) {
	// Planning/native preparation already retains the parent effect selector
	// in its data stage or sealed handoff. Reload that ID before considering
	// the separate post-run recovery inventory.
	var selector api.LaunchClaim
	scope, scopeErr := s.controlScope()
	if scopeErr != nil {
		return api.EffectRecord{}, scopeErr
	}
	if scopeErr == nil && plan.DataStageID != "" {
		if reader, ok := s.deps.Store.(interface {
			DataStage(context.Context, api.Scope, api.ID) (api.LaunchDataStage, error)
		}); ok {
			stage, err := reader.DataStage(ctx, scope, plan.DataStageID)
			if err != nil {
				return api.EffectRecord{}, err
			}
			selector = api.StablePlanningPin(stage.Reservation.ID, stage.ParentEffectID)
		}
	}
	if scopeErr == nil && (selector.EffectID != "" || plan.Handoff != nil) {
		effectID := selector.EffectID
		if effectID == "" {
			effectID = plan.Handoff.Cause.EffectID
		}
		current, err := s.deps.Store.Effect(ctx, scope, effectID)
		if err != nil {
			return api.EffectRecord{}, err
		}
		if current.Outcome == nil {
			if selector.ClaimID == "" {
				selector = api.PlanningClaim(plan.Reservation.ID, api.EffectLease{Record: current, ClaimID: current.ClaimID, ExpiresAt: current.ClaimExpiresAt})
			}
			if err := api.CheckPlanningClaim(current, selector, s.options.Config, s.deps.Clock.Now()); err != nil {
				return api.EffectRecord{}, err
			}
			cause, r := current.Effect.Context, plan.Reservation
			if cause.Target != r.Target || cause.CauseOperationID != r.OperationID || cause.CauseRequestID != r.RequestID ||
				cause.RequestedBy != r.RequestedBy || cause.CancellationEpoch != r.CancellationEpoch || selectEffect != nil && !selectEffect(current.Effect) {
				return api.EffectRecord{}, serviceError(api.CodeConflict, "launch input selected a foreign retained planning claim")
			}
			return current, nil
		}
	}
	control, ok := s.deps.Store.(dispatchStore)
	if !ok {
		return api.EffectRecord{}, serviceError(api.CodePrerequisite, "launch input requires its durable stage inventory")
	}
	records, err := control.DispatchEffects(ctx)
	if err != nil {
		return api.EffectRecord{}, err
	}
	r := plan.Reservation
	for _, record := range records {
		if selectEffect != nil && !selectEffect(record.Effect) {
			continue
		}
		cause := record.Effect.Context
		expires, err := time.Parse(time.RFC3339Nano, string(record.ClaimExpiresAt))
		if err != nil || !expires.After(s.deps.Clock.Now()) || record.ClaimID == "" || !wire.ValidID(string(record.ClaimantID)) || record.Outcome != nil || cause == nil || cause.Target != r.Target || cause.Config != r.Config {
			continue
		}
		if cause.CauseOperationID == r.OperationID && cause.CauseRequestID == r.RequestID && cause.RequestedBy == r.RequestedBy && cause.CancellationEpoch == r.CancellationEpoch {
			current, ok := s.deps.Store.(launchControlStore)
			if !ok {
				return api.EffectRecord{}, serviceError(api.CodePrerequisite, "plan read requires current claim validation")
			}
			if err := current.ValidateLaunchControlClaim(ctx, record.Effect.ID, record.ClaimID, record.Generation); err != nil {
				return api.EffectRecord{}, err
			}
			return record, nil
		}
		if record.Effect.Stop != nil || record.Effect.HelperRelease != nil || record.Effect.HelperAbort != nil {
			current, ok := s.deps.Store.(launchControlStore)
			if !ok {
				return api.EffectRecord{}, serviceError(api.CodePrerequisite, "recovery read requires current claim validation")
			}
			if err := current.ValidateLaunchControlClaim(ctx, record.Effect.ID, record.ClaimID, record.Generation); err != nil {
				return api.EffectRecord{}, err
			}
			return record, nil
		}
	}
	return api.EffectRecord{}, serviceError(api.CodeConflict, "launch input lookup has no current original stage claim")
}

func digestBytes(data []byte) api.Digest {
	sum := sha256.Sum256(data)
	return api.Digest(hex.EncodeToString(sum[:]))
}
