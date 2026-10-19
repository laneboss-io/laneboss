package store

import (
	"context"

	"laneboss.io/laneboss/internal/v2/api"
)

// CheckCredentialProjection validates live native metadata without hiding the
// durable record from cleanup readers. Native I/O occurs outside the writer.
func (s *Service) CheckCredentialProjection(ctx context.Context, config string, prepared api.ID, generation api.Generation) error {
	s.mu.RLock()
	if err := s.available(); err != nil {
		s.mu.RUnlock()
		return err
	}
	if config != s.deps.Config {
		s.mu.RUnlock()
		return fault(api.CodeForbidden, "credential check belongs to another configuration")
	}
	row, err := s.credentialRow(ctx, s.db, prepared)
	s.mu.RUnlock()
	if err != nil {
		return err
	}
	if row.Record.State != "held" || row.Record.Generation != generation || row.Record.Fence != nil || row.Record.Withdrawal != nil {
		return fault(api.CodeConflict, "credential holding is fenced or its revision changed")
	}
	scope := api.Scope{Config: config, Actor: row.Owner, Source: "service"}
	current, err := s.credentialSource(ctx, scope, row.Record.Authority.Request)
	if err != nil {
		return err
	}
	current.ID, current.Generation = row.Record.Authority.ID, row.Record.Authority.Generation
	if !sameValue(current, row.Record.Authority) {
		return fault(api.CodeForbidden, "credential holding source versions or native ownership changed")
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if err := s.available(); err != nil {
		return err
	}
	live, err := s.credentialRow(ctx, s.db, prepared)
	if err != nil {
		return err
	}
	if !sameValue(live, row) {
		return fault(api.CodeConflict, "credential holding changed during native verification")
	}
	if row.Record.Authority.Request.Handoff.Spec.Kind == "worker" {
		return s.credentialWorkerRequest(ctx, s.db, row.Record.Authority.Request)
	}
	var plan api.LaunchPlanRecord
	if err := storedProjection(ctx, s.db, "launch_plan", row.Record.Authority.Request.Handoff.Spec.PlanID, &plan); err != nil {
		return err
	}
	return s.currentLaunch(ctx, s.db, plan)
}
