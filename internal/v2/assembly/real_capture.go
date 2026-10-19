package assembly

import (
	"context"
	"reflect"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/runner/claudock"
)

// Capture classification reads a completed launch. It cannot use or renew the
// PlanLaunch claim, acquire a slot, plan a home, or expose a planning adapter.
type realCapture struct {
	deps    claudock.Dependencies
	runtime api.BlobRef
}

type captureReader interface {
	SessionFromCapture(context.Context, api.CaptureRecord) (api.Session, error)
	LimitFromCapture(context.Context, api.CaptureRecord, api.ProcessObservation) (*api.LimitSignal, error)
}

func (r *realCapture) bind(ctx context.Context, target api.LifeRef) (captureReader, error) {
	if ctx == nil {
		return nil, runError(api.CodeInvalid, "capture read requires its service context")
	}
	d := r.deps
	scope := api.Scope{Config: d.Config, Source: "worker", Actor: api.Actor{Kind: "service", ID: "runner-capture"}}
	lane, err := d.State.Lane(ctx, scope, target)
	if err != nil {
		return nil, err
	}
	if lane.LifeID != target.LifeID || lane.Run != target.Run || lane.Session.Driver != api.DriverClaudock || lane.LaunchID == "" {
		return nil, runError(api.CodeIntegrity, "capture lookup returned another life or run")
	}
	binding, err := d.State.LaunchBinding(ctx, lane.LaunchID)
	if err != nil {
		return nil, err
	}
	if binding.Recovery == nil {
		return nil, runError(api.CodeIntegrity, "capture lookup lost its retained recovery binding")
	}
	record, err := d.State.LaunchPlan(ctx, scope, binding.Recovery.PlanID)
	if err != nil {
		return nil, err
	}
	if err := api.ValidateLaunchPlanRecord(record); err != nil {
		return nil, err
	}
	if record.Phase != "opened" || record.Plan == nil || record.Inputs == nil || record.Handoff == nil ||
		record.Reservation.ID != binding.Recovery.PlanID || record.Reservation.Config != d.Config ||
		record.Reservation.Target != target || record.Reservation.LaunchID != lane.LaunchID || record.Reservation.Driver != api.DriverClaudock ||
		record.Inputs.Sources.Runtime.Manifest != r.runtime || record.Inputs.Sources.Runtime.Executable != d.Executable ||
		record.Inputs.Sources.Runtime.SessionExecutable != d.Claude {
		return nil, runError(api.CodeIntegrity, "capture lookup differs from its enrolled opened launch")
	}
	if err := api.ValidateLaunchBindingPlan(binding, *record.Plan); err != nil {
		return nil, err
	}
	scope.PolicyGeneration = record.Reservation.PolicyGeneration
	stage, err := d.State.Effect(ctx, scope, record.Handoff.Cause.EffectID)
	if err != nil {
		return nil, err
	}
	if stage.State != api.EffectCompleted || stage.Effect.PlanLaunch == nil ||
		stage.Effect.ID != record.Handoff.Cause.EffectID || stage.Effect.Context == nil ||
		stage.Effect.Context.Config != d.Config || stage.Effect.Context.Target != target ||
		stage.Effect.PlanLaunch.ReservationID != record.Reservation.ID || stage.Effect.OperationID != record.Reservation.OperationID ||
		stage.Outcome == nil || stage.Outcome.Status != "succeeded" || stage.Outcome.Error != nil ||
		stage.Outcome.EffectID != stage.Effect.ID || stage.Outcome.ClaimID != stage.ClaimID ||
		stage.Outcome.Process == nil || stage.Outcome.LaunchPlan == nil || !reflect.DeepEqual(*stage.Outcome.LaunchPlan, *record.Plan) ||
		stage.Outcome.Process.Target != target || stage.Outcome.Process.ContainmentID != binding.Record.ContainmentID ||
		stage.Outcome.Process.Generation != binding.Record.ProcessGeneration {
		return nil, runError(api.CodeIntegrity, "capture lookup lacks a completed launch and its native handle")
	}
	request, err := captureInput(ctx, d.State, scope, record)
	if err != nil {
		return nil, err
	}
	plan := record.Plan.Runner
	if request.Target != target || request.Executable != plan.Executable || request.Session != plan.Session ||
		request.Home != plan.Home || request.Slot != plan.Slot || request.Prompt != plan.Prompt || request.Budget != record.Plan.Budget {
		return nil, runError(api.CodeIntegrity, "capture input differs from the retained runner plan")
	}
	selected := claudock.LaunchSelector{Scope: scope, ReservationID: record.Reservation.ID, HelperLeaseID: record.Plan.Lease.ID}
	d.SelectLaunch = func(_ context.Context, asked api.LifeRef) (claudock.LaunchSelector, error) {
		if asked != target {
			return claudock.LaunchSelector{}, runError(api.CodeForbidden, "capture selector changed its exact run")
		}
		return selected, nil
	}
	d.Run = func(_ context.Context, asked api.LifeRef) (api.RunnerRequest, error) {
		if asked != target {
			return api.RunnerRequest{}, runError(api.CodeForbidden, "capture request changed its exact run")
		}
		return request, nil
	}
	d.Profile = func(_ context.Context, slot api.CredentialSlot) (api.ProfileGrant, error) {
		if slot != request.Slot {
			return api.ProfileGrant{}, runError(api.CodeForbidden, "capture profile changed its retained slot")
		}
		for _, profile := range record.Inputs.Grants.Profiles {
			if profile.ID == slot.ProfileGrantID && profile.ProfileID == slot.ProfileID && profile.Driver == api.DriverClaudock {
				return profile, nil
			}
		}
		return api.ProfileGrant{}, runError(api.CodeIntegrity, "capture profile is absent from retained grants")
	}
	d.Observation = func(readCtx context.Context, asked api.LifeRef) (api.ProcessObservation, error) {
		if asked != target {
			return api.ProcessObservation{}, runError(api.CodeForbidden, "capture observation changed its exact run")
		}
		return captureEnd(readCtx, d.State, scope, record.Reservation.LaunchID, *stage.Outcome.Process)
	}
	return claudock.NewInstalled(d)
}

func captureInput(ctx context.Context, state api.StateStore, scope api.Scope, record api.LaunchPlanRecord) (api.RunnerRequest, error) {
	var request api.RunnerRequest
	id := api.ID(runDigest([]byte("launch\x00" + string(record.Reservation.ID) + "\x00input-runner")))
	meta, err := state.ObjectMetadata(ctx, scope, id)
	if err != nil {
		return request, err
	}
	if meta.Ref.ID != id || meta.Ref.Class != "manifest" || meta.Origin != "service" || meta.ACL.Config != scope.Config ||
		meta.ACL.LifeID != record.Reservation.Target.LifeID || meta.ACL.Owner.Kind != "service" || meta.ACL.Generation == 0 ||
		len(meta.ACL.Participants) != 0 || meta.ACL.Audience != "owner" && meta.ACL.Audience != "service" ||
		meta.SourceOperationID != record.Reservation.OperationID {
		return request, runError(api.CodeIntegrity, "capture input lacks immutable service provenance")
	}
	reader := &enrolledRunner{config: scope.Config, deps: runnerDependencies{Store: state}}
	raw, err := reader.runBytes(ctx, scope, meta.Ref, record.Reservation.OperationID, record.Reservation.Target.LifeID)
	if err != nil {
		return request, err
	}
	if err := api.DecodeObject(raw, &request); err != nil {
		return request, err
	}
	return request, nil
}

func captureEnd(ctx context.Context, state api.StateStore, scope api.Scope, launch api.ID, handle api.ProcessHandle) (api.ProcessObservation, error) {
	var result *api.ProcessObservation
	request := api.EventTailRequest{LifeID: handle.Target.LifeID, Run: handle.Target.Run}
	seen := map[string]bool{}
	var sequence api.Sequence
	count := 0
	for {
		page, err := state.Events(ctx, scope, request)
		if err != nil {
			return api.ProcessObservation{}, err
		}
		for _, event := range page.Events {
			count++
			if count > 131072 || event.Config != scope.Config || event.LifeID != handle.Target.LifeID ||
				event.Run != handle.Target.Run || event.Seq <= sequence {
				return api.ProcessObservation{}, runError(api.CodeIntegrity, "capture end history changed its scope or sequence")
			}
			sequence = event.Seq
			if event.Kind != "lane.ended" {
				continue
			}
			var end api.RunEndEvent
			if event.Origin != "service" || api.DecodeObject(event.Payload, &end) != nil || end.LaunchID != launch ||
				end.Observation.Handle != handle || result != nil && !reflect.DeepEqual(*result, end.Observation) {
				return api.ProcessObservation{}, runError(api.CodeIntegrity, "capture end differs from its native launch observation")
			}
			observation := end.Observation
			result = &observation
		}
		if page.Complete {
			break
		}
		if page.Cursor == "" || seen[page.Cursor] {
			return api.ProcessObservation{}, runError(api.CodeIntegrity, "capture end cursor did not advance")
		}
		seen[page.Cursor], request.Cursor = true, page.Cursor
	}
	if result == nil {
		return api.ProcessObservation{}, runError(api.CodePrerequisite, "capture has no retained service run end")
	}
	return *result, nil
}
