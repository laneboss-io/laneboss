// Launch materialization reloads reserved state and protected registry IDs.
package dataworker

import (
	"context"
	"errors"
	"reflect"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/grants"
	"laneboss.io/laneboss/internal/v2/grants/lstate"
	"laneboss.io/laneboss/internal/v2/grants/manifest"
)

func (s *Service) MaterializeLaunch(ctx context.Context, request api.LaunchDataRequest) (result api.LaunchData, resultErr error) {
	check := "materialization_context"
	defer func() { api.ObserveHelperReason(ctx, resultErr, check) }()
	if err := checkContext(ctx); err != nil {
		return result, err
	}
	if !manifest.Config(s.deps.Config) {
		return result, lstate.Error(api.CodePrerequisite, "launch data worker has no installed configuration binding")
	}
	if !manifest.ValidID(request.ReservationID) || !manifest.ValidID(request.GrantSetID) || !manifest.ValidID(request.LeaseID) {
		return result, manifest.Invalid("launch materialization requires reserved grant and helper lease IDs")
	}
	scope := api.Scope{Config: s.deps.Config, Actor: api.Actor{Kind: "service", ID: "grants-dataworker"}}
	if request.Claim != (api.LaunchClaim{}) {
		check = "materialization_claim"
		// Authenticate the explicit planning attempt before opening its read
		// view. A component label cannot replace that claimant, and changing
		// the actor after BeginRead would borrow another principal's view.
		parent, err := s.deps.Store.Effect(ctx, scope, request.Claim.EffectID)
		if err != nil {
			return result, err
		}
		if request.Claim.ReservationID != request.ReservationID {
			return result, lstate.Error(api.CodeConflict, "materialization claim selects another reservation")
		}
		if err := api.CheckPlanningClaim(parent, request.Claim, s.deps.Config, s.deps.Clock.Now()); err != nil {
			return result, err
		}
		scope.Actor.ID = parent.ClaimantID
	}
	check = "materialization_inputs"
	state, err := lstate.Load(ctx, s.deps.Store, s.deps.Config, scope, request.ReservationID)
	if err != nil {
		return result, err
	}
	defer func() { resultErr = errors.Join(resultErr, state.Close()) }()
	r := state.Record.Reservation
	if request.GrantSetID != r.GrantSetID || state.Record.Inputs == nil || state.Record.Phase == "reserved" {
		return result, lstate.Error(api.CodeForbidden, "launch data request is not the exact sourced reservation")
	}
	// This uses the same read-only resolver as planning, never Materialize.
	// Resolve performs no worker dispatch and retains the actual service actor.
	resolver, err := grants.New(grants.Dependencies{Config: s.deps.Config, Store: s.deps.Store, Worker: s, Clock: s.deps.Clock})
	if err != nil {
		return result, err
	}
	check = "materialization_grants"
	current, err := resolver.Resolve(ctx, scope, api.GrantResolveRequest{ReservationID: r.ID})
	if err != nil {
		return result, err
	}
	if !reflect.DeepEqual(current, state.Record.Inputs.Grants) {
		return result, lstate.Error(api.CodeConflict, "sourced launch grants no longer match current authority")
	}
	check = "materialization_sources"
	sources, err := s.deps.Helper.ResolveLaunchSources(ctx, api.LaunchSourceRequest{ReservationID: r.ID, GrantSetID: r.GrantSetID, Claim: request.Claim})
	if err != nil {
		return result, err // Preserve the installed admin owner's refusal.
	}
	if !reflect.DeepEqual(sources, state.Record.Inputs.Sources) {
		return result, lstate.Error(api.CodeConflict, "launch sources differ from protected current enrollment")
	}
	if sources.Runtime.Driver != r.Driver {
		return result, lstate.Error(api.CodeConflict, "launch runtime differs from the stored reservation driver")
	}
	if err := s.launchCapturePolicy(ctx, state); err != nil {
		return result, err
	}
	if err := s.launchSourceBytes(ctx, state, sources); err != nil {
		return result, err
	}
	if state.Record.Plan != nil && state.Record.DataStageID != "" {
		check = "materialization_owner"
		measured, err := s.initialMaterialization(ctx, state, request)
		if err != nil {
			return api.LaunchData{}, err
		}
		if !reflect.DeepEqual(measured, state.Record.Plan.Data) {
			return api.LaunchData{}, lstate.Error(api.CodeIntegrity, "retained plan differs from its acknowledged materialization stage")
		}
		return measured, nil
	}
	if state.Record.Plan == nil {
		check = "materialization_owner"
		return s.initialMaterialization(ctx, state, request)
	}
	storage, err := s.deps.Helper.ResolveLaunchStorage(ctx, request)
	if err != nil {
		return result, err
	}
	if err := launchStorage(request, r, storage); err != nil {
		return result, err
	}
	// A completed stage may be replayed from its retained plan. It must pass
	// the real current storage/source ports and immutable output reads again;
	// a restart never recopies an initial project over the private workspace.
	result = state.Record.Plan.Data
	if state.Record.Plan.Lease.ID != request.LeaseID || result.ReservationID != r.ID || result.Target != r.Target ||
		result.LeaseID != storage.LeaseID || result.Workspace.ID != storage.WorkspaceID || result.Home != storage.Home ||
		result.Source != sources.Project {
		return api.LaunchData{}, lstate.Error(api.CodeConflict, "retained materialization differs from the helper allocation journal")
	}
	if err := s.launchOutputs(ctx, state, result, current); err != nil {
		return api.LaunchData{}, err
	}
	if _, err := resolver.Resolve(ctx, scope, api.GrantResolveRequest{ReservationID: r.ID}); err != nil {
		return api.LaunchData{}, err
	}
	newSources, err := s.deps.Helper.ResolveLaunchSources(ctx, api.LaunchSourceRequest{ReservationID: r.ID, GrantSetID: r.GrantSetID, Claim: request.Claim})
	if err != nil {
		return api.LaunchData{}, err
	}
	newStorage, err := s.deps.Helper.ResolveLaunchStorage(ctx, request)
	if err != nil {
		return api.LaunchData{}, err
	}
	if !reflect.DeepEqual(newSources, sources) || newStorage != storage {
		return api.LaunchData{}, lstate.Error(api.CodeConflict, "launch storage or enrollment changed before materialization return")
	}
	latest, err := lstate.Load(ctx, s.deps.Store, s.deps.Config, scope, request.ReservationID)
	if err != nil {
		return api.LaunchData{}, err
	}
	defer func() { resultErr = errors.Join(resultErr, latest.Close()) }()
	if !reflect.DeepEqual(state.Record, latest.Record) || !reflect.DeepEqual(state.Request, latest.Request) {
		return api.LaunchData{}, lstate.Error(api.CodeConflict, "launch materialization inputs changed during verification")
	}
	if err := s.launchCapturePolicy(ctx, latest); err != nil {
		return api.LaunchData{}, err
	}
	return result, nil
}

func (s *Service) launchCapturePolicy(ctx context.Context, state *lstate.State) error {
	if state.Record.Plan == nil || state.Record.Plan.Capture.Status != "refused" {
		return nil
	}
	r := state.Record.Reservation
	reader, ok := s.deps.Store.(api.GrantPolicyReader)
	if !ok || missing(reader) {
		return api.NotImplemented("lb-v2-service", "protected grant policy selection")
	}
	policy, err := reader.GrantPolicy(ctx, state.Scope, api.GrantPolicyRequest{ReservationID: r.ID,
		Target: r.Target, GrantSetID: r.GrantSetID, Context: api.RoleContext{Level: r.Level, Role: r.Role}, PolicyGeneration: r.PolicyGeneration})
	if err != nil {
		return err
	}
	if policy.Generation != r.PolicyGeneration {
		return lstate.Error(api.CodeConflict, "launch capture policy is no longer current")
	}
	return api.ValidateCapturePolicy(state.Record.Plan.Capture, policy)
}

func launchStorage(request api.LaunchDataRequest, reservation api.LaunchReservation, storage api.LaunchStorage) error {
	home := storage.Home
	if storage.ReservationID != reservation.ID || storage.Target != reservation.Target || storage.LeaseID != request.LeaseID ||
		!manifest.ValidID(storage.WorkspaceID) || home.LifeID != reservation.Target.LifeID || !manifest.ValidID(home.RootID) ||
		home.Generation == 0 || uint64(home.Generation) > manifest.MaxInteger || !manifest.ValidID(home.Home.ID) ||
		!manifest.ValidID(home.Home.HistoryID) || home.Home.WorkspaceID != storage.WorkspaceID ||
		home.RootID == storage.WorkspaceID || home.Home.ID == storage.WorkspaceID || home.Home.HistoryID == storage.WorkspaceID ||
		home.Home.HistoryID == home.Home.ID || home.RootID == home.Home.ID || home.RootID == home.Home.HistoryID {
		return lstate.Error(api.CodeIntegrity, "helper storage does not attest distinct life-owned workspace and home identities")
	}
	if err := manifest.Relative(home.Home.VendorDirectory); err != nil {
		return err
	}
	if home.Home.VendorDirectory == "." {
		return manifest.Invalid("vendor home must name a private relative directory")
	}
	return nil
}

func (s *Service) launchSourceBytes(ctx context.Context, state *lstate.State, sources api.LaunchSources) error {
	source := sources.Project
	if source.HistoryScope == "tree" && source.Base != string(source.Object.SHA256) {
		return lstate.Error(api.CodeIntegrity, "tree project base differs from its exact source manifest hash")
	}
	raw, err := state.Read(ctx, source.Object)
	if err != nil {
		return err
	}
	var object api.ObjectManifest
	if err := manifest.Decode(raw, &object); err != nil {
		return err
	}
	if err := manifest.Object(object); err != nil {
		return err
	}
	// Source/runtime paths and executable pins are re-resolved by admin from
	// protected enrollment. This byte read verifies its immutable selection.
	if _, err := state.Read(ctx, sources.Runtime.Manifest); err != nil {
		return err
	}
	if state.Record.Reservation.PreviousLaunchID != "" {
		binding, err := s.deps.Store.LaunchBinding(ctx, state.Record.Reservation.PreviousLaunchID)
		if err != nil {
			return err
		}
		if binding.Recovery == nil {
			return lstate.Error(api.CodeIntegrity, "retained materialization lost its original recovery binding")
		}
		previous, err := s.deps.Store.LaunchPlan(ctx, state.Scope, binding.Recovery.PlanID)
		if err != nil {
			return err
		}
		if previous.Plan == nil || !reflect.DeepEqual(previous.Plan.Inputs.Sources.Runtime, sources.Runtime) ||
			previous.Plan.Inputs.Sources.Project != sources.Project {
			return lstate.Error(api.CodeConflict, "retained materialization cannot choose a new project or runtime")
		}
	}
	return nil
}

func (s *Service) launchOutputs(ctx context.Context, state *lstate.State, data api.LaunchData, grants api.GrantSet) error {
	if len(data.Materialization.Objects) != len(grants.Data) || data.Materialization.GrantSetID != grants.ID {
		return lstate.Error(api.CodeIntegrity, "launch materialization omits a granted data view")
	}
	seen, destinations := map[api.ID]bool{}, map[string]bool{}
	for _, object := range data.Materialization.Objects {
		found := false
		for _, grant := range grants.Data {
			found = found || grant.ID == object.GrantID
		}
		if !found || seen[object.GrantID] || object.SourceIdentity == "" || object.DestinationIdentity == "" ||
			object.SourceIdentity == object.DestinationIdentity || destinations[object.DestinationIdentity] ||
			!manifest.ValidID(object.WorkspaceID) || !manifest.ValidDigest(object.SnapshotSHA256) {
			return lstate.Error(api.CodeIntegrity, "launch materialization aliases or omits an independent destination")
		}
		seen[object.GrantID], destinations[object.DestinationIdentity] = true, true
	}
	for _, ref := range []api.BlobRef{data.Materialization.Manifest, data.Workspace.Snapshot} {
		metadata, err := s.deps.Store.ObjectMetadata(ctx, state.Scope, ref.ID)
		if err != nil {
			return err
		}
		if metadata.Ref != ref || metadata.SourceOperationID != state.Record.Reservation.OperationID ||
			(metadata.ACL.Owner.Kind != "worker" && metadata.ACL.Owner.Kind != "service") {
			return lstate.Error(api.CodeIntegrity, "launch output has no matching materialization operation provenance")
		}
		raw, err := state.Read(ctx, ref)
		if err != nil {
			return err
		}
		var object api.ObjectManifest
		if err := manifest.Decode(raw, &object); err != nil {
			return err
		}
		if err := manifest.Object(object); err != nil {
			return err
		}
		if err := s.launchSnapshot(ctx, state, object); err != nil {
			return err
		}
	}
	return nil
}
