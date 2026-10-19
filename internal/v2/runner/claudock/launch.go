package claudock

import (
	"context"
	"encoding/json"
	"reflect"
	"slices"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/objectread"
)

// Selectors are obtained by the installed service from its current durable
// job. They are not a plan, path, permission receipt or lane-facing request.
type LaunchSelector struct {
	Scope         api.Scope
	ReservationID api.ID
	EffectID      api.ID
	ClaimID       api.ID
	HelperLeaseID api.ID
}

type launchInputs struct {
	selector LaunchSelector
	record   api.LaunchPlanRecord
	storage  api.LaunchStorage
	digest   api.Digest
}

func (s *Service) retainedLaunch(ctx context.Context, target api.LifeRef) (LaunchSelector, api.LaunchPlanRecord, error) {
	var empty LaunchSelector
	var absent api.LaunchPlanRecord
	if s.deps.SelectLaunch == nil || s.deps.State == nil {
		return empty, absent, api.NotImplemented("lb-v2-service", "durable runner launch lookup")
	}
	selected, err := s.deps.SelectLaunch(ctx, target)
	if err != nil {
		return empty, absent, dependency(err)
	}
	if selected.Scope.Config != s.deps.Config || selected.Scope.Actor.Kind != "service" || !identifier(selected.Scope.Actor.ID) || !identifier(selected.ReservationID) {
		return empty, absent, failure(api.CodeForbidden, "runner lookup lacks its installed service scope")
	}
	record, err := s.deps.State.LaunchPlan(ctx, selected.Scope, selected.ReservationID)
	if err != nil {
		return empty, absent, dependency(err)
	}
	if err := api.ValidateLaunchPlanRecord(record); err != nil {
		return empty, absent, dependency(err)
	}
	if record.Reservation.ID != selected.ReservationID || record.Reservation.Config != s.deps.Config || record.Reservation.Target != target {
		return empty, absent, failure(api.CodeIntegrity, "runner lookup returned a foreign reservation")
	}
	if record.Reservation.Driver != api.DriverClaudock {
		return empty, absent, failure(api.CodeIntegrity, "runner reservation selects a different driver")
	}
	if record.Phase == "failed" {
		return empty, absent, record.Error
	}
	if record.Inputs == nil {
		return empty, absent, failure(api.CodePrerequisite, "runner inputs have not reached the sourced phase")
	}
	return selected, record, nil
}

func (s *Service) objectBytes(ctx context.Context, scope api.Scope, ref api.BlobRef, class string, operation api.ID, life api.ID) (result []byte, resultErr error) {
	if !blob(ref) || ref.Class != class {
		return nil, failure(api.CodeIntegrity, "runner object has the wrong committed class")
	}
	scope, release, err := objectread.Bind(ctx, s.deps.State, scope)
	if err != nil {
		return nil, dependency(err)
	}
	defer release(&resultErr)
	metadata, err := s.deps.State.ObjectMetadata(ctx, scope, ref.ID)
	if err != nil {
		return nil, dependency(err)
	}
	if metadata.Ref != ref || metadata.Origin != "service" || metadata.ACL.Config != s.deps.Config ||
		operation != "" && metadata.SourceOperationID != operation || life != "" && metadata.ACL.LifeID != life {
		return nil, failure(api.CodeIntegrity, "runner object lacks protected provenance")
	}
	data := []byte{}
	for int64(len(data)) < ref.Bytes {
		chunk, err := s.deps.State.Blob(ctx, scope, api.BlobReadRequest{ObjectID: ref.ID, Offset: int64(len(data)), Limit: api.MaxChunkBytes})
		if err != nil {
			return nil, dependency(err)
		}
		if chunk.ObjectID != ref.ID || chunk.Offset != int64(len(data)) || len(chunk.Data) == 0 || len(chunk.Data) > api.MaxChunkBytes ||
			int64(len(chunk.Data)) > ref.Bytes-int64(len(data)) || contentDigest(chunk.Data) != chunk.SHA256 {
			return nil, failure(api.CodeIntegrity, "runner object read changed its exact byte range")
		}
		data = append(data, chunk.Data...)
	}
	if contentDigest(data) != ref.SHA256 {
		return nil, failure(api.CodeIntegrity, "runner object digest changed")
	}
	return data, nil
}

func (s *Service) planning(ctx context.Context, request api.RunnerRequest, method string) (launchInputs, error) {
	var empty launchInputs
	selected, record, err := s.retainedLaunch(ctx, request.Target)
	if err != nil {
		return empty, err
	}
	r := record.Reservation
	if r.Mode == "adopt" {
		return empty, api.NotImplemented("lb-v2-lifecycle", "trusted imported runner binding")
	}
	if r.Mode != method && !(method == "resume" && r.Mode == "continue") {
		return empty, failure(api.CodeConflict, "runner method differs from reserved launch mode")
	}
	effect, err := s.deps.State.Effect(ctx, selected.Scope, selected.EffectID)
	if err != nil {
		return empty, dependency(err)
	}
	cause := effect.Effect.Context
	expires, valid := timestamp(effect.ClaimExpiresAt)
	if !identifier(selected.ClaimID) || effect.ClaimID != selected.ClaimID || effect.State != api.EffectClaimed || !valid || !expires.After(s.deps.Clock.Now()) ||
		effect.ClaimantID != selected.Scope.Actor.ID || effect.Effect.ID != selected.EffectID || effect.Effect.OperationID != r.OperationID ||
		effect.Effect.PlanLaunch == nil || effect.Effect.PlanLaunch.ReservationID != r.ID || cause == nil || cause.Kind != api.InternalLaunchPlan ||
		cause.Config != r.Config || cause.Target != r.Target || cause.Actor.Kind != "service" || !identifier(cause.Actor.ID) || cause.RequestedBy != r.RequestedBy ||
		cause.CauseOperationID != r.OperationID || cause.CauseRequestID != r.RequestID || cause.EffectID != selected.EffectID || cause.CancellationEpoch != r.CancellationEpoch {
		return empty, failure(api.CodeForbidden, "runner planning lost its current effect claim or cancellation fence")
	}
	policy, err := s.deps.State.Policy(ctx, selected.Scope)
	if err != nil {
		return empty, dependency(err)
	}
	grants, err := s.deps.State.Grants(ctx, r.GrantSetID)
	if err != nil {
		return empty, dependency(err)
	}
	if policy.Generation != r.PolicyGeneration || selected.Scope.PolicyGeneration != r.PolicyGeneration ||
		!reflect.DeepEqual(grants, record.Inputs.Grants) || grants.Revoked || slices.Contains(policy.ProfileExclusions, request.Slot.ProfileID) {
		return empty, failure(api.CodeForbidden, "runner policy or grants changed after reservation")
	}
	if record.Plan != nil {
		if err := s.refusalPolicy(ctx, selected.Scope, record.Plan.Capture); err != nil {
			return empty, err
		}
		if method != "start" && record.Plan.Capture.Status == "refused" {
			return empty, record.Plan.Capture.Refusal
		}
	}
	deadline, valid := timestamp(grants.ExpiresAt)
	if !valid || !deadline.After(s.deps.Clock.Now()) {
		return empty, failure(api.CodeForbidden, "reserved runner grants expired")
	}
	// The child lane is published only after planning and preparation. Resolve
	// the reserved launch's current authority here; live-lane Revalidate would
	// look up a projection that does not exist on a first start.
	revalidated, err := s.deps.Grants.Resolve(ctx, selected.Scope, api.GrantResolveRequest{ReservationID: r.ID})
	if err != nil {
		return empty, dependency(err)
	}
	if !reflect.DeepEqual(revalidated, grants) {
		return empty, failure(api.CodeForbidden, "runner grants were narrowed during revalidation")
	}
	sources, err := s.deps.Sources.ResolveLaunchSources(ctx, api.LaunchSourceRequest{ReservationID: r.ID, GrantSetID: r.GrantSetID, Claim: api.PlanningClaim(r.ID, api.EffectLease{Record: effect, ClaimID: selected.ClaimID, ExpiresAt: effect.ClaimExpiresAt})})
	if err != nil {
		return empty, dependency(err)
	}
	if !reflect.DeepEqual(sources, record.Inputs.Sources) || sources.Runtime.Driver != r.Driver ||
		sources.Runtime.Executable != request.Executable || sources.Runtime.Executable != s.deps.Executable || sources.Runtime.Backend != "linux-bwrap-landlock" {
		return empty, failure(api.CodeIntegrity, "runner differs from its current enrolled runtime")
	}
	storage, err := s.deps.Storage.ResolveLaunchStorage(ctx, api.LaunchDataRequest{ReservationID: r.ID, GrantSetID: r.GrantSetID, LeaseID: selected.HelperLeaseID, Claim: api.PlanningClaim(r.ID, api.EffectLease{Record: effect, ClaimID: selected.ClaimID, ExpiresAt: effect.ClaimExpiresAt})})
	if err != nil {
		return empty, dependency(err)
	}
	if storage.ReservationID != r.ID || storage.Target != r.Target || storage.LeaseID != selected.HelperLeaseID || !identifier(storage.LeaseID) ||
		storage.Home.LifeID != r.Target.LifeID || !identifier(storage.Home.RootID) || storage.Home.Generation == 0 || storage.Home.Generation > 1<<53-1 ||
		storage.Home.RootID == storage.WorkspaceID || storage.WorkspaceID != request.Home.WorkspaceID || storage.Home.Home != request.Home || request.Session.LogicalCWD != "/work/main" {
		return empty, failure(api.CodeIntegrity, "runner home differs from its registered storage identity")
	}
	if record.Plan != nil && (record.Plan.Data.Home != storage.Home || record.Plan.Lease.ID != storage.LeaseID || record.Plan.Data.Workspace.ID != storage.WorkspaceID) {
		return empty, failure(api.CodeIntegrity, "runner storage changed after its plan was retained")
	}
	selectedProfile := false
	for _, profile := range grants.Profiles {
		selectedProfile = selectedProfile || profile.ID == request.Slot.ProfileGrantID && profile.ProfileID == request.Slot.ProfileID && profile.Driver == api.DriverClaudock
	}
	if !selectedProfile {
		return empty, failure(api.CodeForbidden, "runner slot is outside the reserved profile grants")
	}
	frame, err := s.objectBytes(ctx, selected.Scope, r.OriginalRequest, "launch_request", r.OperationID, "")
	if err != nil {
		return empty, err
	}
	var original api.Request
	if err := api.DecodeObject(frame, &original); err != nil {
		return empty, dependency(err)
	}
	digest, err := api.RequestDigest(original)
	if err != nil {
		return empty, dependency(err)
	}
	if original.Config != r.Config || original.RequestID != r.RequestID || digest != r.RequestSHA256 || original.RequestSHA256 != digest {
		return empty, failure(api.CodeIntegrity, "runner original request differs from its reservation")
	}
	if r.Mode == "start" {
		var start api.StartRequest
		if original.Method != "lane.start" || api.DecodeObject(original.Params, &start) != nil {
			return empty, failure(api.CodeIntegrity, "runner inputs differ from the original start intent")
		}
		if start.Level != r.Level || start.Role != r.Role || start.Driver != r.Driver {
			return empty, failure(api.CodeIntegrity, "original start differs from the reserved child pins")
		}
		if start.Model != request.Model || start.Effort != request.Effort || start.Budget != request.Budget ||
			start.ProjectID != sources.Project.ProjectID || start.ExpectedPolicyGeneration != r.PolicyGeneration {
			return empty, failure(api.CodeIntegrity, "runner inputs differ from the original start intent")
		}
		profile, err := api.IssuedLaunchProfile(r, original, grants)
		if err != nil {
			return empty, dependency(err)
		}
		if profile.ID != request.Slot.ProfileGrantID || profile.ProfileID != request.Slot.ProfileID {
			return empty, failure(api.CodeIntegrity, "runner slot differs from the original issued profile selection")
		}
	} else {
		previous, err := s.deps.State.LaunchBinding(ctx, r.PreviousLaunchID)
		if err != nil {
			return empty, dependency(err)
		}
		if previous.Recovery == nil {
			return empty, failure(api.CodeIntegrity, "runner restart lacks the retained launch binding")
		}
		prior, err := s.deps.State.LaunchPlan(ctx, selected.Scope, previous.Recovery.PlanID)
		if err != nil {
			return empty, dependency(err)
		}
		if err := api.ValidateLaunchPlanRecord(prior); err != nil {
			return empty, dependency(err)
		}
		if prior.Plan == nil {
			return empty, failure(api.CodeIntegrity, "runner restart lacks its complete previous plan")
		}
		if err := api.ValidateLaunchBindingPlan(previous, *prior.Plan); err != nil {
			return empty, dependency(err)
		}
		if prior.Reservation.Level != r.Level || prior.Reservation.Role != r.Role {
			return empty, failure(api.CodeIntegrity, "runner continuation changed its reserved level or role")
		}
		if err := s.refusalPolicy(ctx, selected.Scope, previous.Recovery.Capture); err != nil {
			return empty, err
		}
		if previous.Recovery.Capture.Status == "refused" {
			return empty, previous.Recovery.Capture.Refusal
		}
		if previous.Record.Config != r.Config || previous.Record.Target.LifeID != r.Target.LifeID || previous.Record.Target.Run+1 != r.Target.Run ||
			previous.Record.ID != r.PreviousLaunchID || previous.Recovery.Home != storage.Home || previous.Recovery.Handoff.Spec.Runner.Session != request.Session ||
			prior.Plan.Inputs.Sources.Runtime != sources.Runtime {
			return empty, failure(api.CodeIntegrity, "runner continuation replaced its retained home, runtime or session")
		}
		// The rendered prompt may include guidance/mail, so it is checked as a
		// separate committed object below. The original public intent still pins
		// the method, base life/generation and authorized budget.
		switch r.Mode {
		case "resume":
			var resume api.ResumeRequest
			if original.Method != "lane.resume" || api.DecodeObject(original.Params, &resume) != nil ||
				resume.Target != previous.Record.Target || resume.ExpectedGeneration != r.BaseGeneration || resume.Budget != request.Budget {
				return empty, failure(api.CodeIntegrity, "runner inputs differ from the original resume intent")
			}
		case "turn":
			var turn api.TurnRequest
			if original.Method != "lane.turn" || api.DecodeObject(original.Params, &turn) != nil ||
				turn.Target != previous.Record.Target || turn.ExpectedGeneration != r.BaseGeneration || turn.Budget != request.Budget {
				return empty, failure(api.CodeIntegrity, "runner inputs differ from the original turn intent")
			}
		case "continue":
			return empty, api.NotImplemented("lb-v2-lifecycle", "retained Continue logical-turn and remaining-budget runner binding")
		}
	}
	if _, err := s.objectBytes(ctx, selected.Scope, request.Prompt, "prompt", r.OperationID, r.Target.LifeID); err != nil {
		return empty, err
	}
	encoded, err := json.Marshal(struct {
		Request       api.RunnerRequest
		Reservation   api.LaunchReservation
		Inputs        api.LaunchInputs
		Storage       api.LaunchStorage
		RefusalPolicy api.CaptureRefusalPolicy
	}{request, r, *record.Inputs, storage, api.CaptureRefusalPolicy{
		Allowed: policy.AllowCaptureRefusal, PolicyGeneration: policy.Generation, ApprovalID: policy.CaptureRefusalApprovalID,
	}})
	if err != nil {
		return empty, failure(api.CodeIntegrity, "runner input seal could not be encoded")
	}
	canonical, err := api.CanonicalJSON(encoded)
	if err != nil {
		return empty, dependency(err)
	}
	return launchInputs{selector: selected, record: record, storage: storage, digest: contentDigest(canonical)}, nil
}
