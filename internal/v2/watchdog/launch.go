package watchdog

import (
	"context"
	"reflect"

	"laneboss.io/laneboss/internal/v2/api"
)

// Read the retained service-owned binding, never infer a plan or a capture
// producer from a lane label. Shared validation checks the complete plan;
// these comparisons additionally pin that plan to the current life projection.
func (s *Service) launchContext(ctx context.Context, lane api.Lane, launch api.LaunchRecord) (api.CaptureBinding, error) {
	var capture api.CaptureBinding
	binding, err := s.deps.Store.LaunchBinding(ctx, launch.ID)
	if err != nil {
		return capture, err
	}
	if binding.Recovery == nil || !reflect.DeepEqual(binding.Record, launch) {
		return capture, problem(api.CodeIntegrity, "launch has no matching retained agent binding")
	}
	record, err := s.deps.Store.LaunchPlan(ctx, s.readScope(), binding.Recovery.PlanID)
	if err != nil {
		return capture, err
	}
	if err := api.ValidateLaunchPlanRecord(record); err != nil {
		return capture, err
	}
	if record.Phase != "opened" || record.Plan == nil {
		return capture, problem(api.CodeConflict, "quota continuation has no opened launch plan")
	}
	if err := api.ValidateLaunchBindingPlan(binding, *record.Plan); err != nil {
		return capture, err
	}
	r := record.Reservation
	workspace := record.Plan.Data.Workspace
	if r.ID != binding.Recovery.PlanID || r.Config != s.deps.Config || r.LaunchID != lane.LaunchID ||
		r.Target != (api.LifeRef{LifeID: lane.LifeID, Run: lane.Run}) || r.GrantSetID != lane.GrantSetID ||
		r.PolicyGeneration != launch.PolicyGeneration || r.PolicyGeneration > lane.PolicyGeneration || r.Level != lane.Level || r.Role != lane.Role || r.Driver != lane.Session.Driver ||
		record.Plan.Runner.Session != lane.Session || workspace.ID != lane.Workspace.ID ||
		workspace.ProjectID != lane.Workspace.ProjectID || workspace.LogicalCWD != lane.Workspace.LogicalCWD {
		return capture, problem(api.CodeIntegrity, "current life differs from its reserved level, role, driver or private session")
	}
	capture = record.Plan.Capture
	// D6 can allow an isolated launch with discarded output. It cannot make
	// that launch's absent capture evidence usable for quota continuation.
	if capture.Status == "refused" {
		return capture, capture.Refusal
	}
	state, err := s.deps.Store.CaptureState(ctx, s.readScope(), capture.ID)
	if err != nil {
		return capture, err
	}
	if !reflect.DeepEqual(state.Binding, capture) || state.Generation == 0 || state.LastSeq == 0 {
		return capture, problem(api.CodeIntegrity, "capture state differs from its retained producer binding")
	}
	positions := map[api.ID]api.CapturePosition{}
	for _, position := range state.Positions {
		if _, duplicate := positions[position.StreamID]; duplicate || position.NextOffset < 0 || !position.EOF {
			return capture, problem(api.CodeIntegrity, "capture has no known complete outside drain")
		}
		positions[position.StreamID] = position
	}
	if len(positions) != len(capture.Streams) {
		return capture, problem(api.CodeIntegrity, "capture stream drain is incomplete")
	}
	for _, stream := range capture.Streams {
		if _, found := positions[stream.ID]; !found {
			return capture, problem(api.CodeIntegrity, "capture stream drain is missing")
		}
	}
	return capture, nil
}
