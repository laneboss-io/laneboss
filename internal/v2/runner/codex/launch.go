package codex

import (
	"bytes"
	"context"
	"reflect"
	"slices"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

// launchInput is read for this invocation, never cached as authority. The
// selectors in Dependencies are supplied by the trusted planning operation.
type launchInput struct {
	record  api.LaunchPlanRecord
	storage api.LaunchStorage
	level   int
}

func (s *Service) launchInput(ctx context.Context, request api.RunnerRequest, mode string) (launchInput, error) {
	var empty launchInput
	lease := s.deps.Planning.Lease
	if !id(lease.Record.Effect.ID) {
		return empty, api.NotImplemented("lb-v2-lifecycle", "Codex operation-scoped planning lease")
	}
	current, err := s.deps.Store.Effect(ctx, s.deps.ReadScope, lease.Record.Effect.ID)
	if err != nil {
		return empty, dependencyError(err)
	}
	if err := planningClaim(current, lease, s.deps.ReadScope, s.deps.Clock.Now()); err != nil {
		return empty, err
	}
	effect := current.Effect
	// The immutable context retains the store's original service author. The
	// exact durable claim above authenticates this attempt's fresh claimant.
	if effect.PlanLaunch == nil || effect.Context == nil || effect.Context.Kind != api.InternalLaunchPlan ||
		effect.Context.Actor.Kind != "service" || !id(effect.Context.Actor.ID) || effect.Context.Config != s.deps.ReadScope.Config ||
		effect.Context.EffectID != effect.ID || effect.Context.CauseOperationID != effect.OperationID ||
		effect.Context.Target != request.Target || effect.Context.LogicalTurnID != request.LogicalTurnID {
		return empty, problem(api.CodeIntegrity, "Codex planning effect is not the reserved launch operation")
	}
	record, err := s.deps.Store.LaunchPlan(ctx, s.deps.ReadScope, effect.PlanLaunch.ReservationID)
	if err != nil {
		return empty, dependencyError(err)
	}
	if err := api.ValidateLaunchPlanRecord(record); err != nil {
		return empty, dependencyError(err)
	}
	r := record.Reservation
	if err := reservationEffect(r, effect, s.deps.ReadScope, request.Target); err != nil {
		return empty, err
	}
	if record.Phase != "sourced" && record.Phase != "planned" && record.Phase != "spec_retained" {
		return empty, problem(api.CodeConflict, "Codex runner needs the sourced pre-release launch stage")
	}
	if record.Inputs == nil || r.Mode != mode && !(mode == "resume" && (r.Mode == "adopt" || r.Mode == "continue")) {
		return empty, problem(api.CodeConflict, "Codex runner method differs from the reserved launch mode")
	}
	if err := s.launchAuthority(ctx, r, record.Inputs.Grants); err != nil {
		return empty, err
	}
	if record.Plan != nil && record.Plan.Capture.Status == "refused" {
		policy, err := s.deps.Store.Policy(ctx, s.deps.ReadScope)
		if err != nil {
			return empty, dependencyError(err)
		}
		if err := api.ValidateCapturePolicy(record.Plan.Capture, policy); err != nil {
			return empty, dependencyError(err)
		}
	}
	if s.deps.Sources == nil {
		return empty, api.NotImplemented("lb-v2-admin", "Codex enrolled launch sources")
	}
	sources, err := s.deps.Sources.ResolveLaunchSources(ctx, api.LaunchSourceRequest{ReservationID: r.ID, GrantSetID: r.GrantSetID, Claim: api.PlanningClaim(r.ID, s.deps.Planning.Lease)})
	if err != nil {
		return empty, dependencyError(err)
	}
	if sources != record.Inputs.Sources || r.Driver != api.DriverCodex || sources.Runtime.Driver != api.DriverCodex ||
		sources.Runtime.Executable != request.Executable || sources.Runtime.Executable != s.deps.Runtime.Executable {
		return empty, problem(api.CodeIntegrity, "Codex executable or source differs from protected enrollment")
	}
	original, err := s.originalLaunch(ctx, r)
	if err != nil {
		return empty, err
	}
	level, err := s.launchRequest(ctx, r, original, request, sources)
	if err != nil {
		return empty, err
	}
	if !id(s.deps.AllocationEffectID) {
		return empty, api.NotImplemented("lb-v2-lifecycle", "Codex retained allocation effect selector")
	}
	allocation, err := s.deps.Store.Effect(ctx, s.deps.ReadScope, s.deps.AllocationEffectID)
	if err != nil {
		return empty, dependencyError(err)
	}
	a := allocation.Effect
	if !id(s.deps.AllocationEffectID) || a.ID != s.deps.AllocationEffectID || a.Context == nil || a.HelperAllocate == nil ||
		a.OperationID != r.OperationID || a.Context.Kind != api.InternalHelperAllocate || a.Context.Config != r.Config ||
		a.Context.Target != r.Target || a.Context.CauseOperationID != r.OperationID || a.Context.CauseRequestID != r.RequestID ||
		a.Context.RequestedBy != r.RequestedBy || a.Context.CancellationEpoch != r.CancellationEpoch ||
		a.HelperAllocate.Cause != *a.Context || a.HelperAllocate.Config != r.Config ||
		a.HelperAllocate.ReservationID != r.ID || a.HelperAllocate.LifeID != r.Target.LifeID ||
		a.HelperAllocate.RuntimeManifestID != sources.Runtime.Manifest.ID || a.HelperAllocate.Backend != sources.Runtime.Backend ||
		a.HelperAllocate.Budget != request.Budget || allocation.State != api.EffectCompleted || allocation.Outcome == nil ||
		allocation.Outcome.Status != "succeeded" || allocation.Outcome.HelperLease == nil || allocation.Outcome.Error != nil ||
		allocation.Outcome.EffectID != a.ID {
		return empty, problem(api.CodeIntegrity, "Codex allocation has no matching retained helper outcome")
	}
	storage, err := s.launchStorage(ctx, r, *allocation.Outcome.HelperLease)
	if err != nil {
		return empty, err
	}
	if request.Home != storage.Home.Home {
		return empty, problem(api.CodeIntegrity, "Codex request differs from the allocated private home")
	}
	if err := s.materializedLaunch(ctx, record, current, storage); err != nil {
		return empty, err
	}
	if r.PreviousLaunchID != "" {
		previous, err := s.retainedLaunch(ctx, r.PreviousLaunchID)
		if err != nil {
			return empty, err
		}
		if storage.Home != previous.Plan.Data.Home || storage.WorkspaceID != previous.Plan.Data.Workspace.ID {
			return empty, problem(api.CodeIntegrity, "Codex retained run changed its allocated home or workspace")
		}
	}
	if request.Session.LogicalCWD != "/work/main" {
		return empty, problem(api.CodeConflict, "Codex cwd differs from the issued logical workspace")
	}
	turn, err := s.deps.Store.Turn(ctx, s.deps.ReadScope, r.Target, request.LogicalTurnID)
	if err != nil {
		return empty, dependencyError(err)
	}
	if turn.Target != r.Target || turn.LogicalTurnID != request.LogicalTurnID || turn.Generation == 0 ||
		turn.PolicyGeneration != r.PolicyGeneration || turn.Prompt == nil || *turn.Prompt != request.Prompt {
		return empty, problem(api.CodeIntegrity, "Codex prompt differs from the retained turn selection")
	}
	if s.deps.ResolveSession == nil {
		return empty, api.NotImplemented("lb-v2-grants", "Codex protected prepared session")
	}
	session, err := s.deps.ResolveSession(ctx, r.Target)
	if err != nil {
		return empty, dependencyError(err)
	}
	// History equality is checked by validateRequest against the independently
	// resolved Home; do not replace it with a matching pair of caller claims.
	if session.ID != request.Session.ID || session.Driver != request.Session.Driver || session.HomeID != request.Session.HomeID ||
		session.VendorID != request.Session.VendorID || session.VendorVersion != request.Session.VendorVersion || session.LogicalCWD != request.Session.LogicalCWD {
		return empty, problem(api.CodeConflict, "Codex session differs from the protected prepared conversation")
	}
	if record.Plan != nil && (record.Plan.Data.Home != storage.Home || record.Plan.Data.Workspace.ID != storage.WorkspaceID ||
		record.Plan.Lease != *allocation.Outcome.HelperLease || record.Plan.Budget != request.Budget) {
		return empty, problem(api.CodeIntegrity, "Codex replay changed retained launch inputs")
	}
	return launchInput{record: record, storage: storage, level: level}, nil
}

func planningClaim(current api.EffectRecord, lease api.EffectLease, scope api.Scope, now time.Time) error {
	expires, expiryErr := timestamp(lease.ExpiresAt)
	if expiryErr != nil || !now.Before(expires) || current.State != api.EffectClaimed ||
		current.Outcome != nil || !id(current.ClaimID) || current.ClaimID != lease.ClaimID ||
		current.ClaimExpiresAt != lease.ExpiresAt || !reflect.DeepEqual(current, lease.Record) ||
		current.Generation == 0 || current.ClaimantID != scope.Actor.ID || scope.Actor.Kind != "service" || !id(scope.Actor.ID) {
		return problem(api.CodeConflict, "Codex planning effect claim is stale or foreign")
	}
	return nil
}

func reservationEffect(r api.LaunchReservation, effect api.Effect, scope api.Scope, target api.LifeRef) error {
	if effect.PlanLaunch == nil || effect.Context == nil || r.ID != effect.PlanLaunch.ReservationID || r.Config != scope.Config || r.Target != target ||
		r.OperationID != effect.OperationID || r.RequestID != effect.Context.CauseRequestID ||
		r.RequestedBy != effect.Context.RequestedBy || r.CancellationEpoch != effect.Context.CancellationEpoch {
		return problem(api.CodeIntegrity, "Codex launch reservation differs from the current effect")
	}
	return nil
}

func (s *Service) launchAuthority(ctx context.Context, r api.LaunchReservation, retained api.GrantSet) error {
	policy, err := s.deps.Store.CurrentApprovedPolicy(ctx, s.deps.ReadScope)
	if err != nil {
		return dependencyError(err)
	}
	if err := api.ValidateLaunchPolicyCurrent(r, retained, policy); err != nil {
		return dependencyError(err)
	}
	if s.deps.ReadScope.PolicyGeneration != r.PolicyGeneration {
		return problem(api.CodeConflict, "Codex launch policy generation is stale")
	}
	return s.retainedGrants(ctx, r, retained)
}

// Issued grants remain historical facts. The scoped store must enforce current
// control/visibility rights; generation drift alone cannot rewrite this snapshot.
func (s *Service) retainedGrants(ctx context.Context, r api.LaunchReservation, retained api.GrantSet) error {
	grants, err := s.deps.Store.Grants(ctx, r.GrantSetID)
	if err != nil {
		return dependencyError(err)
	}
	expires, expiryErr := timestamp(grants.ExpiresAt)
	if expiryErr != nil || !s.deps.Clock.Now().Before(expires) || grants.Revoked || !reflect.DeepEqual(grants, retained) ||
		grants.ID != r.GrantSetID || grants.LifeID != r.Target.LifeID || grants.ParentLifeID != r.ParentLifeID || grants.PolicyGeneration != r.PolicyGeneration {
		return problem(api.CodeForbidden, "Codex launch grants are stale, revoked or foreign")
	}
	return nil
}

func (s *Service) originalLaunch(ctx context.Context, r api.LaunchReservation) (api.Request, error) {
	var empty api.Request
	metadata, err := s.deps.Store.ObjectMetadata(ctx, s.deps.ReadScope, r.OriginalRequest.ID)
	if err != nil {
		return empty, dependencyError(err)
	}
	if metadata.Origin != "service" || metadata.SourceOperationID != r.OperationID || metadata.ACL.Config != r.Config ||
		metadata.Ref != r.OriginalRequest || metadata.Ref.Class != "launch_request" {
		return empty, problem(api.CodeIntegrity, "Codex original launch request has no service provenance")
	}
	data, err := s.readBlob(ctx, r.OriginalRequest)
	if err != nil {
		return empty, err
	}
	var original api.Request
	if err := decode(data, &original); err != nil {
		return empty, err
	}
	digest, err := api.RequestDigest(original)
	if err != nil || original.Protocol != api.Protocol || original.Schema != api.SchemaVersion || original.Config != r.Config ||
		original.RequestID != r.RequestID || original.RequestSHA256 != r.RequestSHA256 || digest != r.RequestSHA256 {
		return empty, problem(api.CodeIntegrity, "Codex original launch frame differs from its reservation")
	}
	key := api.RequestKey{Method: original.Method, IdempotencyKey: original.IdempotencyKey, RequestSHA256: original.RequestSHA256}
	reader, ok := s.deps.Store.(api.LaunchReceiptReader)
	if !ok || reader == nil {
		return empty, api.NotImplemented("lb-v2-service", "protected launch receipt selection")
	}
	receipt, err := reader.LaunchReceipt(ctx, s.deps.ReadScope, api.LaunchReceiptRequest{ReservationID: r.ID})
	if err != nil {
		return empty, dependencyError(err)
	}
	if receipt.Config != r.Config || receipt.Key != key || receipt.Actor != r.RequestedBy || receipt.Operation.ID != r.OperationID ||
		(receipt.Operation.Status != "pending" && receipt.Operation.Status != "running") || !bytes.Equal(receipt.RawRequest, data) {
		return empty, problem(api.CodeIntegrity, "Codex original operation receipt differs from the launch reservation")
	}
	return original, nil
}

func (s *Service) launchRequest(ctx context.Context, r api.LaunchReservation, original api.Request, request api.RunnerRequest, sources api.LaunchSources) (int, error) {
	if r.Mode == "start" || r.Mode == "adopt" {
		var start api.StartRequest
		if r.Mode == "adopt" {
			return 0, api.NotImplemented("lb-v2-lifecycle", "Codex verified imported session selection")
		}
		if original.Method != "lane.start" || decode(original.Params, &start) != nil || start.Driver != api.DriverCodex ||
			start.ProjectID != sources.Project.ProjectID || start.ExpectedPolicyGeneration != r.PolicyGeneration ||
			start.Model != request.Model || start.Effort != request.Effort || start.Budget != request.Budget {
			return 0, problem(api.CodeConflict, "Codex launch inputs differ from the original start request")
		}
		issued, err := s.deps.Store.Grants(ctx, r.GrantSetID)
		if err != nil {
			return 0, dependencyError(err)
		}
		profile, err := api.IssuedLaunchProfile(r, original, issued)
		if err != nil {
			return 0, problem(api.CodeConflict, "Codex issued profile differs from the original reserved selection")
		}
		if profile.ID != request.Slot.ProfileGrantID {
			return 0, problem(api.CodeConflict, "Codex slot differs from the original reserved profile selection")
		}
		if start.Level != r.Level || start.Role != r.Role || start.Driver != r.Driver {
			return 0, problem(api.CodeConflict, "Codex original start differs from the reserved child pins")
		}
		if r.RequestedBy.Kind == "human" && r.Authority.ID != start.RootTicketID {
			return 0, problem(api.CodeIntegrity, "Codex reserved ticket differs from the original start authority")
		}
		if r.Level < 3 || r.Level > 6 {
			return 0, problem(api.CodeIntegrity, "Codex reserved lane level is invalid")
		}
		return r.Level, nil
	}
	if r.Mode == "continue" {
		// Fix 9 supplies no ContinuationID in this adapter's request/context. The
		// lifecycle owner must supply its current retained continuation fence.
		return 0, api.NotImplemented("lb-v2-lifecycle", "Codex retained continuation input fence")
	}
	if r.RequestedBy.Kind == "human" && (original.Proof == nil || r.Authority.ID != original.Proof.ID || original.Proof.RequestSHA256 != r.RequestSHA256) {
		return 0, problem(api.CodeIntegrity, "Codex reserved proof differs from the original retained-life authority")
	}
	var budget api.Budget
	switch r.Mode {
	case "resume":
		var resume api.ResumeRequest
		if original.Method != "lane.resume" || decode(original.Params, &resume) != nil || resume.Target.LifeID != r.Target.LifeID ||
			resume.Target.Run+1 != r.Target.Run || resume.ExpectedGeneration != r.BaseGeneration {
			return 0, problem(api.CodeIntegrity, "Codex resume differs from its original request")
		}
		budget = resume.Budget
	case "turn":
		var turn api.TurnRequest
		if original.Method != "lane.turn" || decode(original.Params, &turn) != nil || turn.Target.LifeID != r.Target.LifeID ||
			turn.Target.Run+1 != r.Target.Run || turn.ExpectedGeneration != r.BaseGeneration {
			return 0, problem(api.CodeIntegrity, "Codex turn differs from its original request")
		}
		budget = turn.Budget
	}
	prior, err := s.retainedLaunch(ctx, r.PreviousLaunchID)
	if err != nil {
		return 0, err
	}
	previous := prior.Plan
	if previous.Reservation.Target.LifeID != r.Target.LifeID || previous.Reservation.Target.Run+1 != r.Target.Run ||
		previous.Reservation.Level != r.Level || previous.Reservation.Role != r.Role || previous.Reservation.Driver != r.Driver ||
		previous.Inputs.Sources.Runtime != sources.Runtime || request.Home != previous.Data.Home.Home || request.Budget != budget {
		return 0, problem(api.CodeIntegrity, "Codex continuation changed retained history, runtime or budget")
	}
	if previous.Capture.Status != "registered" {
		return 0, problem(api.CodeForbidden, "Codex continuation requires registered primary capture")
	}
	lane, err := s.deps.Store.Lane(ctx, s.deps.ReadScope, api.LifeRef{LifeID: r.Target.LifeID})
	if err != nil {
		return 0, dependencyError(err)
	}
	if lane.Cleaned || lane.Run+1 != r.Target.Run || lane.Generation != r.BaseGeneration || lane.LaunchID != r.PreviousLaunchID ||
		lane.Level != r.Level || lane.Role != r.Role || lane.Session.Driver != r.Driver ||
		lane.CancellationEpoch != r.CancellationEpoch || lane.Session != request.Session || lane.Model != request.Model || lane.Effort != request.Effort ||
		lane.Workspace.ID != previous.Data.Workspace.ID || lane.Workspace.LogicalCWD != "/work/main" ||
		!slices.Contains([]string{"verifying", "idle", "profile_wait"}, lane.State) {
		return 0, problem(api.CodeConflict, "Codex continuation differs from the retained ended life")
	}
	return r.Level, nil
}

func (s *Service) launchStorage(ctx context.Context, r api.LaunchReservation, lease api.HelperLease) (api.LaunchStorage, error) {
	var empty api.LaunchStorage
	if !id(lease.ID) || lease.UID == 0 || lease.GID == 0 || !id(lease.ContainmentID) || lease.EndpointGeneration == 0 {
		return empty, problem(api.CodeIntegrity, "Codex helper allocation has no concrete ownership")
	}
	if s.deps.Storage == nil {
		return empty, api.NotImplemented("lb-v2-admin", "Codex helper-owned launch storage")
	}
	storage, err := s.deps.Storage.ResolveLaunchStorage(ctx, api.LaunchDataRequest{ReservationID: r.ID, GrantSetID: r.GrantSetID, LeaseID: lease.ID, Claim: api.PlanningClaim(r.ID, s.deps.Planning.Lease)})
	if err != nil {
		return empty, dependencyError(err)
	}
	if storage.ReservationID != r.ID || storage.Target != r.Target || storage.LeaseID != lease.ID ||
		!id(storage.WorkspaceID) || storage.Home.LifeID != r.Target.LifeID || !id(storage.Home.RootID) || storage.Home.Generation == 0 ||
		storage.Home.RootID == storage.WorkspaceID || storage.Home.Home.WorkspaceID != storage.WorkspaceID ||
		!privateHome(storage.Home.Home) || storage.Home.Home.VendorDirectory != ".codex" {
		return empty, problem(api.CodeIntegrity, "Codex storage is not the allocated private life binding")
	}
	return storage, nil
}

func (s *Service) retainedLaunch(ctx context.Context, launchID api.ID) (api.LaunchPlanRecord, error) {
	var empty api.LaunchPlanRecord
	bound, err := s.deps.Store.LaunchBinding(ctx, launchID)
	if err != nil {
		return empty, dependencyError(err)
	}
	if bound.Recovery == nil {
		return empty, problem(api.CodeIntegrity, "Codex launch has no retained recovery binding")
	}
	record, err := s.deps.Store.LaunchPlan(ctx, s.deps.ReadScope, bound.Recovery.PlanID)
	if err != nil {
		return empty, dependencyError(err)
	}
	if record.Plan == nil || record.Reservation.LaunchID != launchID || record.Reservation.Config != s.deps.ReadScope.Config ||
		(record.Phase != "bound" && record.Phase != "opened") {
		return empty, problem(api.CodeIntegrity, "Codex launch has no bound retained plan")
	}
	if err := api.ValidateLaunchPlanRecord(record); err != nil {
		return empty, dependencyError(err)
	}
	if err := api.ValidateLaunchBindingPlan(bound, *record.Plan); err != nil {
		return empty, dependencyError(err)
	}
	metadata, err := s.deps.Store.ObjectMetadata(ctx, s.deps.ReadScope, bound.Recovery.Handoff.Original.ID)
	if err != nil {
		return empty, dependencyError(err)
	}
	if metadata.Origin != "service" || metadata.SourceOperationID != record.Reservation.OperationID ||
		metadata.ACL.Config != record.Reservation.Config || metadata.ACL.LifeID != record.Reservation.Target.LifeID {
		return empty, problem(api.CodeIntegrity, "Codex recovery spec has no original service provenance")
	}
	original, err := s.readBlob(ctx, bound.Recovery.Handoff.Original)
	if err != nil {
		return empty, err
	}
	var spec api.LaunchSpec
	if decode(original, &spec) != nil || !reflect.DeepEqual(spec, bound.Recovery.Handoff.Spec) {
		return empty, problem(api.CodeIntegrity, "Codex recovery spec differs from its retained original bytes")
	}
	return record, nil
}
