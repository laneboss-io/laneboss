package boxrun

import (
	"laneboss.io/laneboss/internal/boxcore"
)

func (s *service) launchedFields(req boxcore.Request, c boxcore.Candidate,
	b boxcore.Box) map[string]any {
	region := b.Region
	if region == "" {
		region = c.Region
	}
	fields := map[string]any{
		"instance_id": b.ID, "provider": req.Provider, "run_id": req.RunID,
		"org": s.d.Config.Org, "purpose": req.Purpose, "lane": req.Lane,
		"owner_l5": req.Owner, "owner_basis": req.OwnerBasis, "name": b.Name,
		"region": region, "zone": b.Zone, "instance_type": b.Type,
		"image_id": b.Image, "launch_time_utc": b.LaunchTimeUTC,
		"idle_min": req.IdleMin, "hard_min": req.HardMin,
		"cost_cap_usd": req.CostCapUSD, "launcher_version": s.d.Version,
	}
	if b.SpotRequestID != "" {
		fields["spot_request_id"] = b.SpotRequestID
	}
	if b.Project != "" {
		fields["project"] = b.Project
	}
	if b.QuoteUSDHour > 0 {
		fields["quote_usd_per_hour"] = b.QuoteUSDHour
	}
	if s.d.SelfSHA != "" {
		fields["launcher_sha256"] = s.d.SelfSHA
	}
	return fields
}

func boxFromEvent(fields map[string]any) boxcore.Box {
	return boxcore.Box{
		Provider: text(fields, "provider"), ID: text(fields, "instance_id"),
		Name: text(fields, "name"), Region: text(fields, "region"),
		Zone: text(fields, "zone"), Type: text(fields, "instance_type"),
		Image: text(fields, "image_id"), Project: text(fields, "project"),
		LaunchTimeUTC: text(fields, "launch_time_utc"),
		SpotRequestID: text(fields, "spot_request_id"),
		QuoteUSDHour:  number(fields, "quote_usd_per_hour"),
	}
}

func doneFields(b boxcore.Box, runID, result string, extra map[string]any) map[string]any {
	fields := make(map[string]any, len(extra)+4)
	for key, value := range extra {
		fields[key] = value
	}
	// The caller's extras cannot change the identity or marker evidence.
	fields["instance_id"], fields["run_id"], fields["result"] = b.ID, runID, result
	if b.Address != "" {
		fields["ip"] = b.Address
	}
	return fields
}

func endedFields(b boxcore.Box, runID, done string, state boxcore.State,
	utc, basis string) map[string]any {
	reason := state.Reason
	if reason == "" {
		reason = "none"
	}
	return map[string]any{
		"instance_id": b.ID, "run_id": runID, "terminated_utc": utc,
		"basis": basis, "state": state.Name,
		"state_transition_reason": reason, "done_result": done,
	}
}
