package secrets

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/objectread"
	"laneboss.io/laneboss/internal/v2/secrets/wire"
)

type credentialLaunch struct {
	record        api.LaunchPlanRecord
	effect        api.EffectRecord
	storage       api.LaunchStorage
	helperLeaseID api.ID
	profile       api.ID
	model         string
	continuation  *api.ContinuationIntent
	room          *api.Room
}

func hasCode(err error, code api.ErrorCode) bool {
	var typed *api.Error
	return errors.As(err, &typed) && typed.Code == code
}
func valueDigest(value any) (api.Digest, error) {
	data, err := json.Marshal(value)
	if err != nil {
		return "", wire.Error(api.CodeIntegrity, "cannot encode protected credential metadata")
	}
	data, err = api.CanonicalJSON(data)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return api.Digest(hex.EncodeToString(sum[:])), nil
}
func credentialID(parts ...any) api.ID {
	digest, err := valueDigest(parts)
	if err != nil {
		return ""
	}
	return api.ID("credential-" + string(digest))
}

type launchSelection struct {
	Claim         api.LaunchClaim
	HelperLeaseID api.ID
}

// Reload the exact current attempt. Pending outbox discovery excludes live
// claims and is never a reservation authority port.
func (s *Service) reservedPlan(ctx context.Context, target api.LifeRef, selection launchSelection) (credentialLaunch, error) {
	var result credentialLaunch
	claim := selection.Claim
	current, err := s.deps.Store.Effect(ctx, s.deps.ServiceScope, claim.EffectID)
	if err != nil {
		return result, err
	}
	if err := api.CheckPlanningClaim(current, claim, s.deps.Config, s.deps.Clock.Now()); err != nil {
		return result, err
	}
	if err := s.livePlanClaim(current, target); err != nil {
		return result, err
	}
	effect := current.Effect
	record, err := s.deps.Store.LaunchPlan(ctx, s.deps.ServiceScope, claim.ReservationID)
	if err != nil {
		return result, err
	}
	if err := api.ValidateLaunchPlanRecord(record); err != nil {
		return result, err
	}
	r := record.Reservation
	if r.Config != s.deps.Config || r.Target != target || r.ID != claim.ReservationID || r.OperationID != effect.OperationID ||
		effect.Context.CauseOperationID != r.OperationID || effect.Context.CauseRequestID != r.RequestID || effect.Context.RequestedBy != r.RequestedBy ||
		effect.Context.CancellationEpoch != r.CancellationEpoch || record.Inputs == nil || record.Phase == "failed" {
		return result, wire.Error(api.CodeForbidden, "credential launch differs from its reserved life and original cause")
	}
	result.record, result.effect = record, current
	if r.Loop != nil && (effect.ID != r.Loop.PlanEffectID || effect.Context.LogicalTurnID != r.Loop.LogicalTurnID) {
		return credentialLaunch{}, wire.Error(api.CodeForbidden, "loop credential claim changed its causal turn")
	}
	return result, nil
}

func (s *Service) livePlanClaim(record api.EffectRecord, target api.LifeRef) error {
	e := record.Effect
	if record.State != api.EffectClaimed || record.Outcome != nil || record.Generation == 0 || !wire.ID(string(record.ClaimID)) || !wire.ID(string(record.ClaimantID)) ||
		!future(record.ClaimExpiresAt, s.deps.Clock.Now()) || e.PlanLaunch == nil || e.Context == nil || e.Context.Kind != api.InternalLaunchPlan ||
		e.Context.Actor.Kind != "service" || !wire.ID(string(e.Context.Actor.ID)) || e.Context.Config != s.deps.Config || e.Context.Target != target || e.Context.EffectID != e.ID {
		return wire.Error(api.CodeConflict, "credential launch claim is absent stale or outside the reserved life")
	}
	return nil
}

func (s *Service) protectedObject(ctx context.Context, ref api.BlobRef, operation api.ID, lives ...api.ID) ([]byte, error) {
	return s.protectedObjectFor(ctx, ref, operation, false, lives...)
}

// protectedObjectFor reads a protected service-origin object. installedPin marks a read of the installed runtime
// manifest: the initial publication writes installed objects with audience "human" (admin/initial.go initialObject),
// so that audience is accepted only without a life and under that publication's exact operation.
func (s *Service) protectedObjectFor(ctx context.Context, ref api.BlobRef, operation api.ID, installedPin bool, lives ...api.ID) (result []byte, resultErr error) {
	if !wire.ID(string(ref.ID)) || !wire.Digest(ref.SHA256) || ref.Bytes < 1 || ref.Bytes > api.MaxFrameBytes {
		return nil, wire.Error(api.CodeInvalid, "protected credential object is invalid or unbounded")
	}
	scope, release, err := objectread.Bind(ctx, s.deps.Store, s.deps.ServiceScope)
	if err != nil {
		return nil, err
	}
	defer release(&resultErr)
	meta, err := s.deps.Store.ObjectMetadata(ctx, scope, ref.ID)
	if err != nil {
		return nil, err
	}
	// The encrypted profile journal names service-produced evidence. Launch
	// originals additionally require the exact authenticated operation/life.
	ownerPrivate := ref.Class == "credential_evidence" && meta.ACL.Audience == "owner" && meta.ACL.Owner.Kind == "service"
	if len(lives) == 1 {
		ownerPrivate = meta.ACL.Audience == "owner" && meta.ACL.Owner.Kind == "service" &&
			operation != "" && meta.SourceOperationID == operation && meta.ACL.LifeID == lives[0] &&
			(ref.Class == "launch_request" || ref.Class == "launch_spec" || ref.Class == "manifest")
	}
	installedHuman := installedPin && ref.Class == "manifest" && meta.ACL.Audience == "human" && meta.ACL.LifeID == ""
	if installedHuman {
		// The immutable, fixed-key marker retains initialPlan's own source
		// operation. A caller's operation argument can be the object's own ID,
		// so it cannot by itself prove initial-publication provenance.
		id := api.ID("initial-receipt-" + s.deps.Config)
		marker, err := s.deps.Store.ObjectMetadata(ctx, scope, id)
		if err != nil {
			return nil, err
		}
		installedHuman = marker.Ref.ID == id && marker.Ref.Class == "manifest" && marker.ACL.Config == s.deps.Config &&
			marker.ACL.LifeID == "" && marker.ACL.Owner.Kind == "service" && marker.Origin == "service" &&
			marker.SourceOperationID == meta.SourceOperationID
	}
	// The same conditions, named so a refusal says which one failed (item 1 diagnosis, box 70).
	for _, c := range []struct {
		name string
		bad  bool
	}{
		{"ref", meta.Ref != ref}, {"config", meta.ACL.Config != s.deps.Config},
		{"owner_kind", meta.ACL.Owner.Kind != "service" && meta.ACL.Owner.Kind != "worker"}, {"owner_id", !wire.ID(string(meta.ACL.Owner.ID))},
		{"audience", meta.ACL.Audience != "service" && !ownerPrivate && !installedHuman},
		{"generation", meta.ACL.Generation == 0},
		{"origin", meta.Origin != "service"}, {"source_operation", !wire.ID(string(meta.SourceOperationID))},
		{"operation_match", operation != "" && meta.SourceOperationID != operation},
	} {
		if c.bad {
			return nil, wire.Error(api.CodeForbidden, "credential object is not a protected service-origin record ("+c.name+" "+ref.Class+")")
		}
	}
	data := make([]byte, 0, int(ref.Bytes))
	for int64(len(data)) < ref.Bytes {
		if err := wire.Context(ctx); err != nil {
			return nil, err
		}
		offset := int64(len(data))
		limit := min(api.MaxChunkBytes, int(ref.Bytes-offset))
		chunk, err := s.deps.Store.Blob(ctx, scope, api.BlobReadRequest{ObjectID: ref.ID, Offset: offset, Limit: limit})
		if err != nil {
			return nil, err
		}
		part := sha256.Sum256(chunk.Data)
		if chunk.ObjectID != ref.ID || chunk.Offset != offset || len(chunk.Data) == 0 || len(chunk.Data) > limit || chunk.SHA256 != api.Digest(hex.EncodeToString(part[:])) {
			return nil, wire.Error(api.CodeIntegrity, "protected credential object chunk differs")
		}
		data = append(data, chunk.Data...)
	}
	sum := sha256.Sum256(data)
	if api.Digest(hex.EncodeToString(sum[:])) != ref.SHA256 {
		return nil, wire.Error(api.CodeIntegrity, "protected credential object bytes differ")
	}
	return data, nil
}

func validateReservedSelection(r api.LaunchReservation, level int, role string, driver api.Driver, ticket api.ID) error {
	if level != r.Level || role != r.Role || driver != r.Driver || r.Authority.Kind == "ticket" && ticket != r.Authority.ID {
		return wire.Error(api.CodeForbidden, "credential launch differs from its reserved role driver or consumed ticket")
	}
	return nil
}

func (s *Service) launchOriginal(ctx context.Context, launch *credentialLaunch) error {
	r := launch.record.Reservation
	data, err := s.protectedObject(ctx, r.OriginalRequest, r.OperationID, r.Target.LifeID)
	if err != nil {
		return err
	}
	if r.Loop != nil {
		return s.loopOriginal(ctx, launch, data)
	}
	if r.Mode == "continue" {
		return s.continuationOriginal(ctx, launch, data)
	}
	var request api.Request
	if err := api.DecodeObject(data, &request); err != nil {
		return err
	}
	digest, err := api.RequestDigest(request)
	if err != nil || request.Config != r.Config || request.RequestID != r.RequestID || request.RequestSHA256 != r.RequestSHA256 || digest != r.RequestSHA256 || request.Protocol != api.Protocol || request.Schema != api.SchemaVersion {
		return wire.Error(api.CodeIntegrity, "credential launch original request differs from its reservation")
	}
	switch r.Mode {
	case "start":
		var input api.StartRequest
		if request.Method != "lane.start" {
			return wire.Error(api.CodeIntegrity, "credential launch mode differs from its request")
		}
		if err := api.DecodeObject(request.Params, &input); err != nil {
			return err
		}
		if input.ProjectID != launch.record.Inputs.Sources.Project.ProjectID || input.Driver != launch.record.Inputs.Sources.Runtime.Driver || input.ExpectedPolicyGeneration != r.PolicyGeneration {
			return wire.Error(api.CodeForbidden, "credential launch differs from selected enrolled project runtime or policy")
		}
		launch.profile, launch.model = input.ProfileGrantID, input.Model
		if err := validateReservedSelection(r, input.Level, input.Role, input.Driver, input.RootTicketID); err != nil {
			return err
		}
	case "adopt":
		var input api.AdoptRequest
		if request.Method != "lane.adopt" {
			return wire.Error(api.CodeIntegrity, "credential adopt mode differs from its request")
		}
		if err := api.DecodeObject(request.Params, &input); err != nil {
			return err
		}
		if input.Driver != launch.record.Inputs.Sources.Runtime.Driver || input.ExpectedPolicyGeneration != r.PolicyGeneration {
			return wire.Error(api.CodeForbidden, "credential adoption differs from enrolled runtime or policy")
		}
		launch.profile, launch.model = input.ProfileGrantID, input.Model
		if err := validateReservedSelection(r, input.Level, input.Role, input.Driver, input.RootTicketID); err != nil {
			return err
		}
	case "resume", "turn":
		var target api.LifeRef
		var base api.Generation
		if r.Mode == "resume" {
			var body api.ResumeRequest
			if err := api.DecodeObject(request.Params, &body); err != nil {
				return err
			}
			target, base = body.Target, body.ExpectedGeneration
		} else {
			var body api.TurnRequest
			if err := api.DecodeObject(request.Params, &body); err != nil {
				return err
			}
			target, base = body.Target, body.ExpectedGeneration
		}
		if r.Authority.Kind == "proof" && (request.Proof == nil || request.Proof.ID != r.Authority.ID || request.Proof.RequestSHA256 != r.RequestSHA256) {
			return wire.Error(api.CodeForbidden, "credential launch differs from its consumed operation proof")
		}
		expected := map[string]api.Method{"resume": "lane.resume", "turn": "lane.turn"}[r.Mode]
		if request.Method != expected {
			return wire.Error(api.CodeIntegrity, "retained credential launch mode differs from its request")
		}
		binding, err := s.deps.Store.LaunchBinding(ctx, r.PreviousLaunchID)
		if err != nil {
			return err
		}
		if binding.Recovery == nil {
			return wire.Error(api.CodeIntegrity, "retained credential launch has no previous recovery binding")
		}
		prior, err := s.deps.Store.LaunchPlan(ctx, s.deps.ServiceScope, binding.Recovery.PlanID)
		if err != nil {
			return err
		}
		if prior.Plan == nil {
			return wire.Error(api.CodeIntegrity, "retained credential launch has no previous plan")
		}
		if err := api.ValidateLaunchBindingPlan(binding, *prior.Plan); err != nil {
			return err
		}
		if binding.Record.ID != r.PreviousLaunchID || binding.Record.Target.LifeID != r.Target.LifeID || binding.Record.Target.Run+1 != r.Target.Run {
			return wire.Error(api.CodeForbidden, "retained credential launch belongs to another life or run")
		}
		if target != binding.Record.Target || base != r.BaseGeneration {
			return wire.Error(api.CodeForbidden, "retained credential launch request changed its target or base")
		}
		lane, err := s.deps.Store.Lane(ctx, s.deps.ServiceScope, binding.Record.Target)
		if err != nil {
			return err
		}
		launch.profile, launch.model = lane.ProfileGrantID, lane.Model
		if lane.LaunchID != r.PreviousLaunchID || lane.Cleaned || lane.CancellationEpoch != r.CancellationEpoch {
			return wire.Error(api.CodeConflict, "retained credential launch no longer names the current uncancelled run")
		}
		if binding.Record.Actor.Level != r.Level || binding.Record.Actor.Role != r.Role || prior.Plan.Reservation.Driver != r.Driver {
			return wire.Error(api.CodeForbidden, "retained credential launch changed its reserved role or driver")
		}
	}
	if !wire.ID(string(launch.profile)) || launch.model == "" {
		return wire.Error(api.CodeIntegrity, "credential launch omitted its selected profile or model")
	}
	// Start/adopt request selectors name approved parent members; credentials
	// must use the exact member issued to this reservation.
	if r.Mode == "start" || r.Mode == "adopt" {
		mapped, err := api.IssuedLaunchProfile(r, request, launch.record.Inputs.Grants)
		if err != nil {
			return err
		}
		launch.profile = mapped.ID
		if resolver, ok := s.deps.Grants.(interface {
			ResolveProfile(context.Context, api.Scope, api.GrantResolveRequest) (api.ProfileGrant, error)
		}); ok {
			profile, err := resolver.ResolveProfile(ctx, s.deps.ServiceScope, api.GrantResolveRequest{ReservationID: r.ID})
			if err != nil {
				return err
			}
			if !reflect.DeepEqual(profile, mapped) {
				return wire.Error(api.CodeConflict, "credential profile differs from the retained issuance mapping")
			}
		}
	}
	return nil
}

func (s *Service) launchAllocation(ctx context.Context, launch *credentialLaunch) error {
	r := launch.record.Reservation
	if !wire.ID(string(launch.helperLeaseID)) {
		return wire.Error(api.CodePrerequisite, "credential launch requires its explicit helper allocation")
	}
	claim := api.PlanningClaim(r.ID, api.EffectLease{Record: launch.effect, ClaimID: launch.effect.ClaimID, ExpiresAt: launch.effect.ClaimExpiresAt})
	if wire.Nil(s.deps.Helper) {
		return wire.Error(api.CodePrerequisite, "credential broker requires its installed helper control")
	}
	sources, err := s.deps.Helper.ResolveLaunchSources(ctx, api.LaunchSourceRequest{ReservationID: r.ID, GrantSetID: r.GrantSetID, Claim: claim})
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(sources, launch.record.Inputs.Sources) {
		return wire.Error(api.CodeConflict, "credential launch source enrollment changed")
	}
	storage, err := s.deps.Helper.ResolveLaunchStorage(ctx, api.LaunchDataRequest{ReservationID: r.ID, GrantSetID: r.GrantSetID, LeaseID: launch.helperLeaseID, Claim: claim})
	if err != nil {
		return err
	}
	if storage.ReservationID != r.ID || storage.Target != r.Target || storage.LeaseID != launch.helperLeaseID || storage.Home.LifeID != r.Target.LifeID ||
		!wire.ID(string(storage.WorkspaceID)) || !wire.ID(string(storage.Home.RootID)) || !wire.ID(string(storage.Home.Home.ID)) ||
		!wire.ID(string(storage.Home.Home.HistoryID)) || storage.Home.Generation == 0 || storage.Home.Home.WorkspaceID != storage.WorkspaceID || storage.Home.RootID == storage.WorkspaceID {
		return wire.Error(api.CodeForbidden, "credential storage differs from the helper-owned reserved life")
	}
	if r.PreviousLaunchID != "" {
		previous, err := s.deps.Store.LaunchBinding(ctx, r.PreviousLaunchID)
		if err != nil {
			return err
		}
		if previous.Recovery == nil || previous.Recovery.Home != storage.Home {
			return wire.Error(api.CodeIntegrity, "retained private history was replaced during credential acquisition")
		}
	}
	launch.storage = storage
	return nil
}

func (s *Service) credentialLaunch(ctx context.Context, target api.LifeRef, current api.GrantSet, selection launchSelection) (credentialLaunch, error) {
	launch, err := s.reservedPlan(ctx, target, selection)
	if err != nil {
		return launch, err
	}
	if !reflect.DeepEqual(launch.record.Inputs.Grants, current) {
		return launch, wire.Error(api.CodeConflict, "credential grants differ from resolved reserved-life inputs")
	}
	if err := s.launchOriginal(ctx, &launch); err != nil {
		return launch, err
	}
	launch.helperLeaseID = selection.HelperLeaseID
	if err := s.launchAllocation(ctx, &launch); err != nil {
		return launch, err
	}
	return launch, s.recheckCredentialLaunch(ctx, launch)
}

func (s *Service) recheckCredentialLaunch(ctx context.Context, launch credentialLaunch) error {
	if launch.room != nil && (!launch.room.Available || !future(launch.room.ExpiresAt, s.deps.Clock.Now())) {
		return wire.Error(api.CodeUnavailable, "credential continuation room expired during protected preparation")
	}
	if launch.continuation != nil {
		current, err := s.deps.Store.ContinuationIntent(ctx, s.deps.ServiceScope, launch.continuation.ID)
		if err != nil {
			return err
		}
		if !reflect.DeepEqual(current, *launch.continuation) || current.Status != "claimed" || !future(current.Eligibility.ExpiresAt, s.deps.Clock.Now()) {
			return wire.Error(api.CodeConflict, "credential continuation claim changed during protected preparation")
		}
	} else {
		selected := launch
		if err := s.launchOriginal(ctx, &selected); err != nil {
			return err
		}
		if selected.profile != launch.profile || selected.model != launch.model {
			return wire.Error(api.CodeConflict, "credential launch selection changed during preparation")
		}
	}
	current, err := s.deps.Store.Effect(ctx, s.deps.ServiceScope, launch.effect.Effect.ID)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(current, launch.effect) {
		return wire.Error(api.CodeConflict, "credential planning claim changed during preparation")
	}
	if err := s.livePlanClaim(current, launch.record.Reservation.Target); err != nil {
		return err
	}
	record, err := s.deps.Store.LaunchPlan(ctx, s.deps.ServiceScope, launch.record.Reservation.ID)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(record, launch.record) {
		return wire.Error(api.CodeConflict, "credential launch inputs changed during preparation")
	}
	policy, err := s.deps.Store.CurrentApprovedPolicy(ctx, s.deps.ServiceScope)
	if err != nil {
		return err
	}
	if policy.Generation != record.Reservation.PolicyGeneration || !wire.Digest(policy.SHA256) {
		return wire.Error(api.CodeConflict, "credential launch policy is no longer current")
	}
	grants, err := s.deps.Store.Grants(ctx, record.Reservation.GrantSetID)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(grants, record.Inputs.Grants) || grants.Revoked || !future(grants.ExpiresAt, s.deps.Clock.Now()) {
		return wire.Error(api.CodeForbidden, "credential launch grants changed or expired")
	}
	validated, err := s.deps.Grants.Resolve(ctx, s.deps.ServiceScope, api.GrantResolveRequest{ReservationID: record.Reservation.ID})
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(validated, grants) {
		return wire.Error(api.CodeConflict, "credential delegation changed during protected preparation")
	}
	return nil
}
