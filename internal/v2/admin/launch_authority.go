package admin

import (
	"context"
	"encoding/json"
	"reflect"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/objectread"
)

// A selector never supplies a Scope. Resolve it through the service-owned
// outbox, then re-read the actual claim and reservation through that store.
type launchAuthority struct {
	Record          api.LaunchPlanRecord
	Scope           api.Scope
	Claim           api.EffectRecord
	Cause           api.InternalIntent
	Request         api.Request
	Grants          api.GrantSet
	Policy          api.EffectivePolicy
	RuntimeManifest api.BlobRef
}

func (s *Service) launchAuthority(ctx context.Context, reservation, grantID api.ID, cause *api.InternalIntent, planning ...api.LaunchClaim) (_ launchAuthority, resultErr error) {
	defer helperContextCheck(ctx, &resultErr, "launch_authority")
	var result launchAuthority
	if err := contextError(ctx); err != nil {
		return result, err
	}
	if !validID(reservation) || grantID != "" && !validID(grantID) {
		return result, failure(api.CodeInvalid, "invalid launch reservation selector")
	}
	if s.deps.Store == nil {
		return result, api.NotImplemented("lb-v2-service", "store launch authority")
	}
	var selected *api.LaunchClaim
	var scope api.Scope
	var effectID api.ID
	if len(planning) > 1 || len(planning) == 1 && planning[0] == (api.LaunchClaim{}) {
		return result, failure(api.CodeForbidden, "launch stage requires its explicit planning claim")
	}
	if len(planning) == 1 {
		selected = &planning[0]
		if selected.ReservationID != reservation {
			return result, failure(api.CodeConflict, "launch planning selector names another reservation")
		}
	}
	var attempt api.EffectLease
	if selected != nil {
		effectID = selected.EffectID
		scope = api.Scope{Config: s.deps.Config, Actor: api.Actor{Kind: "service", ID: selected.ClaimantID}, Source: "service"}
	} else {
		var ok bool
		attempt, ok = api.EffectLeaseFromContext(ctx)
		if cause == nil || !ok || !api.EffectLeaseClaimed(attempt) || !validID(attempt.Record.ClaimantID) {
			return result, failure(api.CodeForbidden, "launch stage requires its explicit effect attempt")
		}
		effectID = attempt.Record.Effect.ID
		scope = api.Scope{Config: s.deps.Config, Actor: api.Actor{Kind: "service", ID: attempt.Record.ClaimantID}, Source: "service"}
	}
	// A registered handoff keeps its planning effect's helper_register cause. The later helper_prepare stage of the same
	// launch resolves that handoff again under its own explicit claim (the credential transfer binds the current
	// helper_prepare claim to the retained handoff). registeredStage binds that claim to the registered spec below.
	stage := selected == nil && cause != nil && cause.Kind == api.InternalHelperRegister && attempt.Record.Effect.HelperPrepare != nil
	if cause != nil {
		if err := validateCause(*cause, s.deps.Config, cause.Kind); err != nil {
			return result, err
		}
		if effectID != cause.EffectID && !stage {
			return result, failure(api.CodeConflict, "launch cause differs from its explicit execution claim")
		}
	}
	claim, err := s.deps.Store.Effect(ctx, scope, effectID)
	if err != nil {
		return result, err
	}
	if selected != nil {
		if err := api.CheckPlanningClaim(claim, *selected, s.deps.Config, time.Now()); err != nil {
			return result, err
		}
		if cause == nil {
			copy := *claim.Effect.Context
			cause = &copy
		}
	} else if claim.Effect.PlanLaunch != nil || !reflect.DeepEqual(claim, attempt.Record) ||
		claim.ClaimID != attempt.ClaimID || claim.ClaimExpiresAt != attempt.ExpiresAt {
		return result, failure(api.CodeConflict, "launch effect attempt is stale or foreign")
	}
	// The registered cause names its immutable author; registeredStage compares it with the retained handoff instead.
	if selected == nil && !stage && cause.Actor != (api.Actor{Kind: "service", ID: claim.ClaimantID}) {
		return result, failure(api.CodeConflict, "launch stage cause lacks its current claimant")
	}
	// The stage claim's own context is the same launch's cause on the stage's own effect and kind.
	want := *cause
	if stage {
		want.Kind, want.EffectID = api.InternalHelperPrepare, claim.Effect.ID
	}
	if claim.Effect.Context == nil || claim.Effect.ID != want.EffectID || claim.Effect.OperationID != cause.CauseOperationID ||
		claim.State != api.EffectClaimed || !validID(claim.ClaimID) || !validID(claim.ClaimantID) || claim.Generation == 0 {
		return result, failure(api.CodeForbidden, "launch stage has no current durable claim")
	}
	expires, err := time.Parse(time.RFC3339Nano, string(claim.ClaimExpiresAt))
	if err != nil || !expires.After(time.Now()) {
		return result, failure(api.CodeForbidden, "launch stage claim expired")
	}
	actual := *claim.Effect.Context
	actorMatches := actual.Actor == cause.Actor || cause.Actor == (api.Actor{Kind: "service", ID: claim.ClaimantID})
	if actual.Actor.Kind != "service" || !validActor(actual.Actor) || actual.Config != s.deps.Config ||
		!actorMatches || actual.RequestedBy != cause.RequestedBy || actual.Target != cause.Target ||
		actual.CauseOperationID != cause.CauseOperationID || actual.CauseRequestID != cause.CauseRequestID ||
		actual.CancellationEpoch != cause.CancellationEpoch || actual.EffectID != want.EffectID ||
		actual.LogicalTurnID != cause.LogicalTurnID ||
		actual.Kind != want.Kind && (stage || actual.Kind != api.InternalLaunchPlan) {
		return result, failure(api.CodeForbidden, "launch cause differs from the durable service claim")
	}
	if actual.Kind == api.InternalLaunchPlan && (claim.Effect.PlanLaunch == nil || claim.Effect.PlanLaunch.ReservationID != reservation) {
		return result, failure(api.CodeForbidden, "planning effect selects a foreign reservation")
	}
	// The retained cause names its immutable author. The independently
	// reloaded claimant owns this new execution fence; neither is a human.
	execution := *cause
	scope.Actor = api.Actor{Kind: "service", ID: claim.ClaimantID}
	execution.Actor = scope.Actor
	cause = &execution
	record, err := s.deps.Store.LaunchPlan(ctx, scope, reservation)
	if err != nil {
		return result, err
	}
	if err := api.ValidateLaunchPlanRecord(record); err != nil {
		return result, err
	}
	if stage {
		if err := registeredStage(record, claim, *cause); err != nil {
			return result, err
		}
	}
	r := record.Reservation
	if r.ID != reservation || r.Config != s.deps.Config || grantID != "" && grantID != r.GrantSetID || record.Phase == "failed" ||
		r.Target != actual.Target || r.OperationID != actual.CauseOperationID || r.RequestID != actual.CauseRequestID ||
		r.RequestedBy != actual.RequestedBy || r.CancellationEpoch != actual.CancellationEpoch {
		return result, failure(api.CodeForbidden, "launch stage differs from its retained reservation")
	}
	scope.PolicyGeneration = r.PolicyGeneration
	operation, err := s.deps.Store.Operation(ctx, scope, r.OperationID)
	if err != nil {
		return result, err
	}
	if operation.ID != r.OperationID || operation.Error != nil || operation.Status != "pending" && operation.Status != "running" {
		return result, failure(api.CodeConflict, "launch operation is no longer pending")
	}
	original, err := s.readLaunchObject(ctx, scope, r.OriginalRequest, r.OperationID, r.Target.LifeID, true)
	if err != nil {
		return result, err
	}
	var request api.Request
	if r.Loop != nil {
		if err := api.CheckLoopInput(r, original); err != nil {
			return result, err
		}
		if actual.LogicalTurnID != r.Loop.LogicalTurnID || actual.Kind == api.InternalLaunchPlan && claim.Effect.ID != r.Loop.PlanEffectID {
			return result, failure(api.CodeForbidden, "loop helper claim changed its reserved logical turn")
		}
	} else if r.Mode == "continue" {
		if _, err := s.contInput(ctx, scope, record, *cause, original); err != nil {
			return result, err
		}
	} else {
		if err := api.DecodeObject(original, &request); err != nil {
			return result, err
		}
		digest, err := api.RequestDigest(request)
		if err != nil {
			return result, err
		}
		if request.Config != r.Config || request.Protocol != api.Protocol || request.Schema != api.SchemaVersion ||
			request.RequestID != r.RequestID || request.RequestSHA256 != r.RequestSHA256 || digest != r.RequestSHA256 {
			return result, failure(api.CodeIntegrity, "retained launch request differs from its reservation")
		}
	}
	if err := s.checkReservationAuthority(ctx, scope, r, request); err != nil {
		return result, err
	}
	grants, err := s.deps.Store.Grants(ctx, r.GrantSetID)
	if err != nil {
		return result, err
	}
	policy, err := s.deps.Store.Policy(ctx, scope)
	if err != nil {
		return result, err
	}
	deadline, err := time.Parse(time.RFC3339Nano, string(grants.ExpiresAt))
	if err != nil || !deadline.After(time.Now()) || grants.Revoked || grants.ID != r.GrantSetID ||
		grants.LifeID != r.Target.LifeID || grants.ParentLifeID != r.ParentLifeID || grants.Generation == 0 ||
		!validDigest(grants.SHA256) || grants.PolicyGeneration != r.PolicyGeneration || policy.Generation != r.PolicyGeneration {
		return result, failure(api.CodeForbidden, "launch grants or policy are stale or foreign")
	}
	result = launchAuthority{Record: record, Scope: scope, Claim: claim, Cause: *cause, Request: request, Grants: grants, Policy: policy, RuntimeManifest: s.deps.RuntimeManifest}
	if err := s.fenceLaunch(ctx, result); err != nil {
		return launchAuthority{}, err
	}
	return result, nil
}

func (s *Service) checkReservationAuthority(ctx context.Context, scope api.Scope, r api.LaunchReservation, request api.Request) error {
	if r.Loop != nil {
		if !reflect.DeepEqual(request, api.Request{}) || api.ValidateLaunchReservation(r) != nil {
			return failure(api.CodeForbidden, "loop helper authority cannot carry a public frame")
		}
		return nil // The caller already checked the exact private input and claim.
	}
	if r.Mode == "continue" || r.Authority.Kind == "starter" {
		if request.Proof != nil {
			return failure(api.CodeForbidden, "starter authority cannot carry a human proof")
		}
		if r.Mode == "start" {
			input, err := decodeLaunchRequest[api.StartRequest](request, "lane.start")
			if err != nil {
				return err
			}
			if input.RootTicketID != "" || input.Level != r.Level || input.Role != r.Role || input.Driver != r.Driver {
				return failure(api.CodeForbidden, "lane start differs from its original authority and child pins")
			}
		}
		if r.Mode == "adopt" {
			input, err := decodeLaunchRequest[api.AdoptRequest](request, "lane.adopt")
			if err != nil {
				return err
			}
			if input.RootTicketID != "" || input.Level != r.Level || input.Role != r.Role || input.Driver != r.Driver {
				return failure(api.CodeForbidden, "lane adoption differs from its original authority and child pins")
			}
		}
		starter, err := s.deps.Store.LaunchBinding(ctx, r.Authority.ID)
		if err != nil {
			return err
		}
		if starter.Record.Kind != "agent" || starter.Record.ID != r.Authority.ID || starter.Record.Config != r.Config || starter.Recovery == nil {
			return failure(api.CodeForbidden, "reservation authority is not the retained authentic starter binding")
		}
		plan, err := s.deps.Store.LaunchPlan(ctx, scope, starter.Recovery.PlanID)
		if err != nil {
			return err
		}
		if plan.Plan == nil {
			return failure(api.CodeIntegrity, "starter authority lost its complete launch plan")
		}
		if err := api.ValidateLaunchBindingPlan(starter, *plan.Plan); err != nil {
			return err
		}
		if r.Mode == "continue" {
			if r.Authority.ID != r.PreviousLaunchID || starter.Record.Target.LifeID != r.Target.LifeID || starter.Record.Target.Run+1 != r.Target.Run {
				return failure(api.CodeForbidden, "continuation authority selects a foreign retained run")
			}
		} else if starter.Record.Actor != r.RequestedBy || starter.Record.Revoked {
			return failure(api.CodeForbidden, "starter authority differs from the authentic requesting lane")
		}
		return nil
	}
	if r.RequestedBy.Kind != "human" {
		return failure(api.CodeForbidden, "human launch authority belongs to a nonhuman requester")
	}
	switch r.Mode {
	case "start":
		input, err := decodeLaunchRequest[api.StartRequest](request, "lane.start")
		if err != nil {
			return err
		}
		if r.Authority.Kind != "ticket" || input.RootTicketID != r.Authority.ID || request.Proof != nil || input.Level != r.Level || input.Role != r.Role || input.Driver != r.Driver {
			return failure(api.CodeForbidden, "start differs from its consumed ticket or reserved child pins")
		}
	case "adopt":
		input, err := decodeLaunchRequest[api.AdoptRequest](request, "lane.adopt")
		if err != nil {
			return err
		}
		if r.Authority.Kind != "ticket" || input.RootTicketID != r.Authority.ID || request.Proof != nil || input.Level != r.Level || input.Role != r.Role || input.Driver != r.Driver {
			return failure(api.CodeForbidden, "adoption differs from its consumed ticket or reserved child pins")
		}
	case "resume", "turn":
		if r.Authority.Kind != "proof" || request.Proof == nil || request.Proof.ID != r.Authority.ID || request.Proof.RequestSHA256 != r.RequestSHA256 {
			return failure(api.CodeForbidden, "retained human launch differs from its consumed operation proof")
		}
	default:
		return failure(api.CodeInvalid, "unknown retained launch authority mode")
	}
	return nil
}

// An empty internal transaction checks the reserved-life cancellation fence
// and all read generations under the single store lock. No authority is issued.
func (s *Service) fenceLaunch(ctx context.Context, authority launchAuthority) error {
	r := authority.Record.Reservation
	claim, err := s.deps.Store.Effect(ctx, authority.Scope, authority.Claim.Effect.ID)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(claim, authority.Claim) {
		return failure(api.CodeConflict, "launch stage claim changed")
	}
	expires, err := time.Parse(time.RFC3339Nano, string(claim.ClaimExpiresAt))
	if err != nil || !expires.After(time.Now()) {
		return failure(api.CodeForbidden, "launch stage claim expired before effect")
	}
	// Read fences for different retained revisions are different operations.
	// Never reuse the effect author's intent ID for a changed comparison set.
	cause := authority.Cause
	identity, err := json.Marshal(struct {
		Cause            api.InternalIntent
		ClaimID          api.ID
		ClaimGeneration  api.Generation
		PlanGeneration   api.Generation
		GrantGeneration  api.Generation
		PolicyGeneration api.Generation
	}{cause, claim.ClaimID, claim.Generation, authority.Record.Generation, authority.Grants.Generation, r.PolicyGeneration})
	if err != nil {
		return failure(api.CodeIntegrity, "cannot encode launch fence identity")
	}
	cause.ID = api.ID(digestBytes(identity))
	_, err = s.deps.Store.Transact(ctx, api.Transaction{Scope: authority.Scope, Internal: &cause,
		Compare: []api.Compare{{Kind: api.CompareLaunchPlan, ID: r.ID, Generation: authority.Record.Generation},
			{Kind: api.CompareGrants, ID: authority.Grants.ID, Generation: authority.Grants.Generation},
			{Kind: api.CompareOrg, ID: api.ID(r.Config), Generation: r.PolicyGeneration}},
		Guards: []api.TransactionGuard{{Cancellation: &api.CancellationCheck{LifeID: r.Target.LifeID, Epoch: r.CancellationEpoch}}}})
	return err
}

func (s *Service) readLaunchObject(ctx context.Context, scope api.Scope, ref api.BlobRef, operation, life api.ID, private bool) (resultBytes []byte, resultErr error) {
	if !validID(ref.ID) || !validDigest(ref.SHA256) || ref.Bytes < 1 || ref.Bytes > api.MaxObjectBytes {
		return nil, failure(api.CodeInvalid, "invalid retained launch object")
	}
	scope, release, err := objectread.Bind(ctx, s.deps.Store, scope)
	if err != nil {
		return nil, err
	}
	defer release(&resultErr)
	metadata, err := s.deps.Store.ObjectMetadata(ctx, scope, ref.ID)
	if err != nil {
		return nil, err
	}
	if metadata.Ref != ref || metadata.ACL.Config != s.deps.Config || metadata.CommittedAt == "" {
		return nil, failure(api.CodeForbidden, "launch object is not the matching committed private input")
	}
	if operation != "" && metadata.SourceOperationID != operation || life != "" && metadata.ACL.LifeID != life ||
		private && (metadata.Origin != "service" || metadata.ACL.Audience != "service" && metadata.ACL.Audience != "human" && metadata.ACL.Audience != "owner") {
		allowAndLog("launch_object_private_input")
	}
	data := make([]byte, 0, int(ref.Bytes))
	for int64(len(data)) < ref.Bytes {
		if err := contextError(ctx); err != nil {
			return nil, err
		}
		chunk, err := s.deps.Store.Blob(ctx, scope, api.BlobReadRequest{ObjectID: ref.ID, Offset: int64(len(data)), Limit: int(min(int64(api.MaxChunkBytes), ref.Bytes-int64(len(data))))})
		if err != nil {
			return nil, err
		}
		if chunk.ObjectID != ref.ID || chunk.Offset != int64(len(data)) || len(chunk.Data) == 0 ||
			int64(len(chunk.Data)) > ref.Bytes-int64(len(data)) || digestBytes(chunk.Data) != chunk.SHA256 {
			return nil, failure(api.CodeIntegrity, "retained launch object range differs")
		}
		data = append(data, chunk.Data...)
	}
	if digestBytes(data) != ref.SHA256 {
		return nil, failure(api.CodeIntegrity, "retained launch object digest differs")
	}
	return data, nil
}

func decodeLaunchRequest[T any](request api.Request, method api.Method) (T, error) {
	var result T
	if request.Method != method {
		return result, failure(api.CodeIntegrity, "launch mode differs from its original method")
	}
	if err := api.DecodeObject(json.RawMessage(request.Params), &result); err != nil {
		return result, err
	}
	return result, nil
}

// registeredStage reports whether a later helper_prepare stage claim may resolve the retained handoff whose cause is
// given: the plan still holds that spec, the cause is the handoff's own (api.RetainedCause), and the stage's retained
// request names exactly the registered spec, digest, lease and operation, as the store's helper control matches it.
func registeredStage(record api.LaunchPlanRecord, claim api.EffectRecord, cause api.InternalIntent) error {
	h, p := record.Handoff, claim.Effect.HelperPrepare
	if record.Phase != "spec_retained" || record.Plan == nil || h == nil || p == nil || claim.Effect.Context == nil ||
		!api.RetainedCause(&h.Cause, cause, claim.ClaimantID) || p.Cause != *claim.Effect.Context ||
		p.PreparedSpecID != h.Spec.ID || p.PreparedSpecID != record.Reservation.SpecID || p.SpecSHA256 != h.SpecSHA256 ||
		p.LeaseID != h.Spec.UIDLeaseID || p.LeaseID != record.Plan.Lease.ID || claim.Effect.OperationID != h.OperationID ||
		p.Cause.CauseOperationID != h.OperationID || p.Cause.CauseRequestID != h.RequestID {
		return failure(api.CodeForbidden, "prepare stage claim does not name this registered launch spec")
	}
	return nil
}

func samePreparedHandoffStable(a, b api.PreparedSpecHandoff) bool {
	left, right := a, b
	left.Cause.Actor = right.Cause.Actor
	return reflect.DeepEqual(left, right)
}

func (s *Service) currentStage(ctx context.Context, cause api.InternalIntent, kind api.InternalKind) (api.EffectRecord, error) {
	if err := contextError(ctx); err != nil {
		return api.EffectRecord{}, err
	}
	if err := validateCause(cause, s.deps.Config, kind); err != nil {
		return api.EffectRecord{}, err
	}
	if s.deps.Store == nil {
		return api.EffectRecord{}, api.NotImplemented("lb-v2-service", "store helper stage claim")
	}
	attempt, ok := api.EffectLeaseFromContext(ctx)
	if !ok || !api.EffectLeaseClaimed(attempt) || !validID(attempt.Record.ClaimantID) {
		return api.EffectRecord{}, failure(api.CodeForbidden, "helper stage requires its explicit effect attempt")
	}
	actor := api.Actor{Kind: "service", ID: attempt.Record.ClaimantID}
	scope := api.Scope{Config: s.deps.Config, Actor: actor, Source: "service"}
	claimed, err := s.deps.Store.Effect(ctx, scope, cause.EffectID)
	if err != nil {
		return api.EffectRecord{}, err
	}
	if claimed.Effect.Context == nil || claimed.Effect.ID != cause.EffectID || claimed.Effect.OperationID != cause.CauseOperationID ||
		claimed.State != api.EffectClaimed || claimed.Generation == 0 || !validID(claimed.ClaimID) || !validID(claimed.ClaimantID) {
		return api.EffectRecord{}, failure(api.CodeForbidden, "helper stage lacks a current claim")
	}
	if !reflect.DeepEqual(claimed, attempt.Record) || claimed.ClaimID != attempt.ClaimID || claimed.ClaimExpiresAt != attempt.ExpiresAt {
		return api.EffectRecord{}, failure(api.CodeConflict, "helper stage attempt is stale or foreign")
	}
	actual := *claimed.Effect.Context
	parent := actual.Kind == api.InternalLifecycleEffect && (kind == api.InternalHelperOpen && claimed.Effect.Launch != nil || kind == api.InternalHelperStop && claimed.Effect.Stop != nil)
	parent = parent || actual.Kind == api.InternalLaunchPlan && kind == api.InternalHelperOpen && claimed.Effect.PlanLaunch != nil
	if parent {
		actual.Kind, actual.ID = cause.Kind, cause.ID
	}
	if cause.Actor == actor {
		actual.Actor = actor
	}
	if actual != cause {
		return api.EffectRecord{}, failure(api.CodeForbidden, "helper stage differs from its retained causal input")
	}
	expires, err := time.Parse(time.RFC3339Nano, string(claimed.ClaimExpiresAt))
	if err != nil || !expires.After(time.Now()) {
		return api.EffectRecord{}, failure(api.CodeForbidden, "helper stage claim expired")
	}
	// Preflight is a separate operation from emitting the stage or opening
	// its native gate. Retained DTOs keep their original cause unchanged.
	fence := cause
	fence.Actor = actor
	fence.ID = api.ID(digestBytes([]byte("helper-stage-fence\x00" + string(cause.ID) + "\x00" + string(claimed.ClaimID))))
	_, err = s.deps.Store.Transact(ctx, api.Transaction{Scope: scope, Internal: &fence,
		Guards: []api.TransactionGuard{{Cancellation: &api.CancellationCheck{LifeID: cause.Target.LifeID, Epoch: cause.CancellationEpoch}}}})
	if err != nil {
		return api.EffectRecord{}, err
	}
	return claimed, nil
}
