package store

import (
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	archivejob "laneboss.io/laneboss/internal/v2/archive"
)

// A failed operation is not a substitute for native containment quiescence.
// After handoff, a missing process reply is uncertain, even if Process is zero.
func (s *Service) checkOwnedQuiescence(r archiveRecord, observation *api.ProcessObservation) error {
	if r.Allocating && r.Retirement == nil {
		return &api.Error{Code: api.CodeContainmentUnknown, Owner: "lb-v2-admin", Message: "archive allocation intent requires native retirement before failure", Instead: "Observe, stop/reap or abort, and retain the original helper retirement."}
	}
	if observation == nil {
		if r.Retirement != nil && r.Retirement.Boot != nil && archivejob.ValidateBootRetirement(r.Retirement.Allocation, r.Job.Lease.Target, *r.Retirement.Boot, r.Retirement.ObservedAt) == nil {
			return nil // Retained measured boot absence carries no invented exit.
		}
		if r.Process == (api.ProcessHandle{}) && (r.Handoff == nil || r.Retirement != nil && r.Retirement.Abort != nil) {
			return nil // No worker handoff or native open has been authorized.
		}
	} else {
		when, err := time.Parse(time.RFC3339Nano, string(observation.ObservedAt))
		if err == nil && !when.IsZero() && !when.After(s.deps.Clock.Now()) &&
			r.Process.ID != "" && observation.Handle == r.Process && observation.State == "exited" &&
			(observation.ExitCode == nil) != (observation.Signal == nil) && observation.Survivors != nil && *observation.Survivors == 0 {
			return nil
		}
	}
	return &api.Error{Code: api.CodeContainmentUnknown, Owner: "lb-v2-admin", Message: "archive failure remains pending without a terminal zero-survivor worker observation",
		Instead: "Preserve the claim and containment allocation; obtain the original native worker observation or use the containment release path."}
}
