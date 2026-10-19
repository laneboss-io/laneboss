//go:build laneboss_partial && laneboss_e2e_authenticator

package assembly

import (
	"context"
	"encoding/json"
	"reflect"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/runner/claudock"
)

// Only the vendor command is a fixture. The installed helper still requires
// its measured bootstrap and sealed, lane-owned home before preparing a gate.
type fixtureClaudockRunner struct {
	api.Runner
	reader enrolledRunner
}

func (r *fixtureClaudockRunner) Start(ctx context.Context, request api.RunnerRequest) (api.RunnerPlan, error) {
	var empty api.RunnerPlan
	plan, err := r.Runner.Start(ctx, request)
	if err != nil {
		return empty, err
	}
	if err := api.RequireDependencies("lb-v2-serve", r.reader.deps.Store, r.reader.deps.Clock, r.reader.deps.Credentials); err != nil {
		return empty, err
	}
	selected, bound, storage, err := r.reader.realRun(ctx, request.Target)
	if err != nil {
		return empty, err
	}
	if !reflect.DeepEqual(bound, request) || storage.Home.Home != request.Home {
		return empty, runError(api.CodeForbidden, "fixture credential home differs from retained runner input")
	}
	record, err := r.reader.deps.Store.LaunchPlan(ctx, selected.Scope, selected.ReservationID)
	if err != nil {
		return empty, err
	}
	if record.Inputs == nil || record.Reservation.Mode != "start" || record.Phase == "failed" || record.Phase == "opened" ||
		record.Plan != nil && (record.Plan.Budget != request.Budget || !reflect.DeepEqual(record.Plan.Runner, plan)) {
		return empty, runError(api.CodeConflict, "fixture home planning differs from its retained start")
	}
	policy, err := r.reader.deps.Store.CurrentApprovedPolicy(ctx, selected.Scope)
	if err != nil {
		return empty, err
	}
	if err := api.ValidateLaunchPolicyCurrent(record.Reservation, record.Inputs.Grants, policy); err != nil {
		return empty, err
	}
	// Seal the same retained inputs as the real adapter, including the current
	// capture-refusal policy; item-specific runtime assets remain in Sources.
	raw, err := json.Marshal(struct {
		Request       api.RunnerRequest
		Reservation   api.LaunchReservation
		Inputs        api.LaunchInputs
		Storage       api.LaunchStorage
		RefusalPolicy api.CaptureRefusalPolicy
	}{request, record.Reservation, *record.Inputs, storage, api.CaptureRefusalPolicy{
		Allowed: policy.AllowCaptureRefusal, PolicyGeneration: policy.Generation, ApprovalID: policy.CaptureRefusalApprovalID,
	}})
	if err != nil {
		return empty, err
	}
	canonical, err := api.CanonicalJSON(raw)
	if err != nil {
		return empty, err
	}
	if err := r.reader.verifyClaudockBootstrap(ctx, request, claudock.RequiredUmask); err != nil {
		return empty, err
	}
	if err := r.reader.planClaudockHome(ctx, claudock.HomePlanRequest{Request: request, Home: storage.Home,
		ReservationID: selected.ReservationID, InputsSHA256: runDigest(canonical), Start: true,
		Claude:     record.Inputs.Sources.Runtime.SessionExecutable,
		ClaudePath: "/runtime/" + string(record.Inputs.Sources.Runtime.SessionExecutable.ID)}); err != nil {
		return empty, err
	}
	return plan, nil
}
